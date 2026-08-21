"""Agent 编排层:AgentConfig + 单 Agent 执行 + 报告渲染。

三 Agent 只差配置(系统提示词/工具集/工件名),循环逻辑共用 run_react_agent
(agents.md §四:不拆 Agent 子类)。runner 负责:
  1. 按 cfg 过滤工具集、拼系统提示词与任务简报
  2. 跑 ReAct 循环(transcript 落 process/agent/<name>/transcript.jsonl)
  3. Final Answer → 工件落盘(JSON 失败降级 .md)
  4. verification 阶段额外确定性渲染 report.md(不依赖 LLM 格式)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .data.artifacts import load_artifact, parse_artifact, save_artifact
from .data.prompts import (
    ANALYSIS_SYSTEM,
    RECON_SYSTEM,
    VERIFY_SYSTEM,
    build_analysis_brief,
    build_recon_brief,
    build_system_prompt,
    build_verify_brief,
)
from .engine.display import make_display
from .engine.react_loop import ReactResult, run_react_agent
from .providers.llm_client import LLMClient, LLMError
from .providers.tools import ToolContext, make_tools

AGENT_DIR = "agent"   # process/agent/


@dataclass
class AgentConfig:
    name: str
    system_prompt: str
    tool_names: tuple[str, ...]
    output_name: str                 # process/agent/<output_name>
    max_iters: int = 20
    model: str | None = None         # None = 跟随环境变量默认模型
    build_brief: object = None       # (process_dir, upstream) -> str
    label: str = ""                  # 控制台进度展示用


RECON_CFG = AgentConfig(
    name="recon",
    label="侦察",
    system_prompt=RECON_SYSTEM,
    tool_names=("checksec", "cve_bin_tool_scan", "strings_query", "imports_query",
                "read_file", "semgrep_scan", "gitleaks_scan", "binwalk_rescan"),
    output_name="attack_surface.json",
    max_iters=20,
    build_brief=lambda process_dir, up: build_recon_brief(process_dir),
)

ANALYSIS_CFG = AgentConfig(
    name="analysis",
    label="深度分析",
    system_prompt=ANALYSIS_SYSTEM,
    tool_names=("find_decompiled_function", "xref_query", "strings_query",
                "imports_query", "read_file", "cve_lookup", "checksec",
                "semgrep_scan", "gitleaks_scan", "web_search"),
    output_name="findings.json",
    max_iters=24,
    build_brief=build_analysis_brief,
)

VERIFY_CFG = AgentConfig(
    name="verification",
    label="复核",
    system_prompt=VERIFY_SYSTEM,
    tool_names=("find_decompiled_function", "xref_query", "cve_lookup", "checksec",
                "read_file", "strings_query", "imports_query", "sandbox_verify"),
    output_name="verified_findings.json",
    max_iters=24,
    build_brief=build_verify_brief,
)

ALL_CONFIGS = (RECON_CFG, ANALYSIS_CFG, VERIFY_CFG)


@dataclass
class AgentRunResult:
    cfg: AgentConfig
    artifact_path: Path | None = None
    react: ReactResult | None = None
    usage: dict = field(default_factory=dict)
    skipped: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.skipped or (self.artifact_path is not None and not self.error)


def make_llm(cfg: AgentConfig, base: LLMClient) -> LLMClient:
    """默认共享一个客户端(用量可累计);cfg.model 覆盖时另建实例。"""
    if cfg.model and cfg.model != base.model:
        return LLMClient(api_key=base.api_key, base_url=base.base_url, model=cfg.model)
    return base


def run_agent(cfg: AgentConfig, process_dir: Path,
              base_llm: LLMClient, upstream_path: Path | None = None) -> AgentRunResult:
    """跑单个 Agent:构建 → ReAct 循环 → 工件落盘。异常不抛,记入 error。"""
    result = AgentRunResult(cfg=cfg)
    try:
        ctx = ToolContext(process_dir=process_dir)
        all_tools = make_tools(ctx)
        missing = [n for n in cfg.tool_names if n not in all_tools]
        if missing:
            raise ValueError(f"工具未注册: {missing}")

        tools = {n: all_tools[n] for n in cfg.tool_names}
        system_prompt = build_system_prompt(cfg.system_prompt, tools, max_iters=cfg.max_iters)
        brief = cfg.build_brief(process_dir, upstream_path)  # type: ignore[operator]

        agent_dir = process_dir / AGENT_DIR
        agent_dir.mkdir(parents=True, exist_ok=True)
        transcript = agent_dir / cfg.name / "transcript.jsonl"
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text("", encoding="utf-8")  # 重跑覆盖旧记录

        llm = make_llm(cfg, base_llm)
        # 终端监控(STEP5_DISPLAY/STEP5_COLOR 配置);关闭时回退旧式单行日志
        disp = make_display()
        if disp.enabled:
            disp.stage(cfg.name, cfg.label, len(tools), llm.model, cfg.max_iters)
        else:
            print(f"[step5:{cfg.name}] 开始({cfg.label},工具 {len(tools)},模型 {llm.model})")
        react = run_react_agent(
            llm, tools, system_prompt, brief,
            max_iters=cfg.max_iters, transcript=transcript, display=disp,
        )
        result.react = react
        result.usage = dict(llm.total_usage)

        parsed = parse_artifact(react.final_answer) if react.final_answer else None
        out_path = agent_dir / cfg.output_name
        result.artifact_path = save_artifact(out_path, cfg.name, parsed, react.final_answer or "")
        findings_n = len((parsed or {}).get("findings", []))

        if not react.ok:
            result.error = "" if parsed else "未产出可解析 Final Answer(工件已降级 .md)"
        if disp.enabled:
            disp.done(cfg.name, result.artifact_path.name, findings_n,
                      react.steps, result.usage)
        else:
            print(f"[step5:{cfg.name}] 完成: {result.artifact_path.name}"
                  f"({findings_n} 条 finding,"
                  f"{react.steps} 轮,工具 {len(react.tool_calls)} 次,usage={result.usage})")
    except LLMError:
        raise  # API 调用失败:立即终止,不降级(向上传播中止 Step5)
    except Exception as e:  # 配置错/工具未注册等:记下不崩,由上层决定
        result.error = f"{type(e).__name__}: {e}"
        print(f"[step5:{cfg.name}] 失败: {result.error}")
    return result


# ---- 最终报告(确定性渲染,不依赖 LLM 输出格式) ----

def render_report(process_dir: Path, agent_note: str = "") -> Path:
    """verified_findings.json → report.md。工件缺失/降级时也给出说明版报告。"""
    agent_dir = process_dir / AGENT_DIR
    verified = agent_dir / "verified_findings.json"
    obj = load_artifact(verified)

    lines = ["# 固件安全审计报告(Step5)", ""]
    if agent_note:
        lines += [f"> {agent_note}", ""]
    if obj is None:
        lines += ["verified_findings.json 缺失或不可解析,详见 process/agent/ 下各 transcript 与降级工件。"]
        report = agent_dir / "report.md"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return report

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = [f for f in obj.get("findings", []) if f.get("verified") is not False]
    findings.sort(key=lambda f: sev_rank.get(f.get("severity", "info"), 9))
    rejected = [f for f in obj.get("findings", []) if f.get("verified") is False]

    lines += ["## 概要", "", obj.get("summary", ""), ""]
    lines += [f"成立/保留 {len(findings)} 条,误报剔除 {len(rejected)} 条。", "", "## 发现", ""]
    for i, f in enumerate(findings, 1):
        mark = "✓" if f.get("verified") is True else "?"
        loc = f.get("file", "")
        if f.get("func"):
            loc += f" :: {f['func']}"
        if f.get("addr"):
            loc += f" @ {f['addr']}"
        cve = f" [{f['cve']}]" if f.get("cve") else ""
        lines += [f"### {i}. [{f.get('severity', 'info')}] {mark} {f.get('title', '?')}{cve}",
                  f"- 位置: {loc or '(未定位)'}",
                  f"- 置信度: {f.get('confidence', '') or '未标注'}"]
        if f.get("evidence"):
            lines += ["- 证据:", "", "```", str(f["evidence"])[:2000], "```", ""]
        if f.get("rationale"):
            lines += [f"- 复核意见: {f['rationale']}", ""]
    if rejected:
        lines += ["## 误报剔除(verified=false)", ""]
        for f in rejected:
            # rationale 可能空串(LLM 把理由写进 evidence),回退证据截断,再兜底默认
            reason = f.get("rationale") or str(f.get("evidence", ""))[:300] or "无理由"
            lines += [f"- [{f.get('severity', 'info')}] {f.get('title', '?')}"
                      f" — {reason}"]
        lines.append("")

    report = agent_dir / "report.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report

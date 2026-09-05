"""Agent 编排层:AgentConfig + 单 Agent 执行。

三 Agent 只差配置(系统提示词/工具集/工件名),循环逻辑共用 run_react_agent
(agents.md §四:不拆 Agent 子类)。runner 负责:
  1. 按 cfg 过滤工具集、拼系统提示词与任务简报
  2. 跑 ReAct 循环(transcript 落 process/agent/<name>/transcript.jsonl)
  3. Final Answer → 工件落盘(JSON 失败降级 .md)

最终报告(v3,2026-08-28):由 orchestrator 的 summarize 动作产出
(orchestrator/report.md);runner 不再渲染报告(原 render_report 已删除)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os

from .data.artifacts import parse_artifact, parse_survey_artifact, save_artifact, save_survey
from .data.prompts import (
    ANALYSIS_SYSTEM,
    RECON_SYSTEM,
    VERIFY_SYSTEM,
    build_analysis_brief,
    build_recon_brief,
    build_system_prompt,
    build_verify_brief,
    save_system_prompt,
)
from .engine.display import make_display
from .engine.react_loop import ReactResult, run_react_agent
from .engine.transcript import reset_transcript
from .providers.llm_client import LLMClient, LLMError
from .providers.tools import ToolContext, make_tools

AGENT_DIR = "agent"   # process/agent/


def resolve_max_iters(name: str, default: int) -> int:
    """env STEP5_<NAME>_MAX_ITERS 覆盖轮次上限(缺失/非法回落默认,下限 1)。

    消费点解析而非 import 时固化:改 env 后新建 Orchestrator 即生效,
    模块级 AgentConfig 常量不被污染(测试可逐用例设/删 env)。
    """
    raw = os.environ.get(f"STEP5_{name.upper()}_MAX_ITERS", "").strip()
    try:
        v = int(raw) if raw else default
    except ValueError:
        return default
    return max(1, v)


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
    tool_names=("list_files", "read_file", "cve_bin_tool_scan", "semgrep_scan",
                "gitleaks_scan", "binwalk_rescan"),
    output_name="survey.json",     # recon v3 工件(2026-08-29,原 attack_surface.json→survey.json)
    max_iters=20,
    build_brief=lambda process_dir, up: build_recon_brief(process_dir),
)

ANALYSIS_CFG = AgentConfig(
    name="analysis",
    label="深度分析",
    system_prompt=ANALYSIS_SYSTEM,
    tool_names=("list_files", "search_code", "find_decompiled_function", "xref_query",
                "strings_query", "imports_query", "read_file", "cve_lookup",
                "checksec", "semgrep_scan", "gitleaks_scan", "web_search"),
    output_name="findings.json",
    max_iters=30,
    build_brief=build_analysis_brief,
)

VERIFY_CFG = AgentConfig(
    name="verification",
    label="复核",
    system_prompt=VERIFY_SYSTEM,
    tool_names=("list_files", "search_code", "find_decompiled_function", "xref_query",
                "cve_lookup", "checksec", "read_file", "strings_query",
                "imports_query", "sandbox_verify"),
    output_name="verified_findings.json",
    max_iters=8,   # ADR-0003:每疑点一实例,单条复核轮次需求 ≤8(原 24 多疑点摊薄)
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


def post_run_status(ares: AgentRunResult) -> str:
    """执行后状态三岔判定(单一出处,T6 收编):success / degraded / failed。

    判据:ok 且有工件 → success;仅 .md 降级工件(JSON 解析失败,ok=False)
    → degraded;其余 → failed。返回 DispatchStatus 值域字符串(值即落盘值,
    见 orchestration/state;runner 不 import orchestration——ADR-0009 分层,
    故以字符串契约返回,消费方自行包装)。消费点:actions 调度回填、
    verify_phase 单实例。
    """
    if ares.ok and ares.artifact_path:
        return "success"
    if ares.artifact_path and ares.artifact_path.suffix == ".md":
        return "degraded"
    return "failed"


def run_agent(cfg: AgentConfig, process_dir: Path, base_llm: LLMClient,
              upstream_path: Path | None = None,
              output_dir: Path | None = None,
              extra_brief: str = "") -> AgentRunResult:
    """跑单个 Agent:构建 → ReAct 循环 → 工件落盘。异常不抛,记入 error。

    output_dir 传入时,该 Agent 的 transcript/obs/工件统一写入 output_dir
    (orchestrator 按 <seq>_<type> 指定);None 时沿用历史位置
    process/agent/<name>/ + process/agent/<output_name>,兼容既有调用与测试。
    extra_brief 追加到任务简报尾部——orchestrator 每次真实调度注入交接块
    (前序任务状态/同类型前次结果/累计发现/任务上下文);补跑(同类型第 2/3 次
    调度)时会额外注入 handoff(前序实例 summary + 已覆盖 findings 清单 +
    差分 task),由 orchestrator 侧组装,本函数只透传不解析。
    """
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
        if extra_brief:
            brief = f"{brief}\n{extra_brief}"

        agent_dir = process_dir / AGENT_DIR
        if output_dir is not None:
            transcript = output_dir / "transcript.jsonl"
            out_base = output_dir
        else:
            transcript = agent_dir / cfg.name / "transcript.jsonl"
            out_base = agent_dir
        reset_transcript(transcript)  # 重跑覆盖旧记录(engine 统一入口,T6 收编)
        save_system_prompt(transcript.parent, system_prompt)  # 系统提示词留档(复现用)

        llm = make_llm(cfg, base_llm)
        # 终端监控(STEP5_DISPLAY/STEP5_COLOR 配置);关闭时回退旧式单行日志
        disp = make_display()
        if disp.enabled:
            disp.stage(cfg.name, cfg.label, len(tools), llm.model, cfg.max_iters)
        else:
            print(f"[step5:{cfg.name}] 开始({cfg.label},工具 {len(tools)},模型 {llm.model})", flush=True)
        react = run_react_agent(
            llm, tools, system_prompt, brief,
            max_iters=cfg.max_iters, transcript=transcript, display=disp,
        )
        result.react = react
        result.usage = dict(llm.total_usage)

        # 解析与落盘:recon 用 v3 survey 工件(schema_version=3,无 findings/判级);
        # analysis/verification 沿用既有 findings 容器
        parsed = None
        if react.final_answer:
            parsed = (parse_survey_artifact(react.final_answer) if cfg.name == "recon"
                      else parse_artifact(react.final_answer))
        out_path = out_base / cfg.output_name
        if cfg.name == "recon":
            result.artifact_path = save_survey(out_path, cfg.name, parsed,
                                               react.final_answer or "")
            findings_n = len((parsed or {}).get("high_risk_areas", []))
        else:
            result.artifact_path = save_artifact(out_path, cfg.name, parsed,
                                                 react.final_answer or "")
            findings_n = len((parsed or {}).get("findings", []))

        if not react.ok:
            result.error = "" if parsed else "未产出可解析 Final Answer(工件已降级 .md)"
        if disp.enabled:
            disp.done(cfg.name, result.artifact_path.name, findings_n,
                      react.steps, result.usage)
        else:
            print(f"[step5:{cfg.name}] 完成: {result.artifact_path.name}"
                  f"({findings_n} 条 finding,"
                  f"{react.steps} 轮,工具 {len(react.tool_calls)} 次,usage={result.usage})", flush=True)
    except LLMError:
        raise  # API 调用失败:立即终止,不降级(向上传播中止 Step5)
    except Exception as e:  # 配置错/工具未注册等:记下不崩,由上层决定
        result.error = f"{type(e).__name__}: {e}"
        print(f"[step5:{cfg.name}] 失败: {result.error}", flush=True)
    return result

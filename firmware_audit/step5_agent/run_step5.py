"""Step5 入口:三 Agent 串行控制流 + 断点续跑 + 无 key/API 失败立即终止。

控制流(agents.md §二,Python 硬编码不用 LLM 调度):
    recon → attack_surface.json → analysis → findings.json → verification
          → verified_findings.json → report.md

断点续跑:工件存在(.json 成功或 .md 降级均算)即跳过该 Agent;
上游失败则中止链条(下游没输入,跑了也是空转)。

用法:
    python -m firmware_audit.step5_agent.run_step5 <dir> [--force]
    <dir> 可以是 target/<N>(内含 process/)或工作区本身(process/ 等价目录)
环境变量:见 llm_client(FIRMWARE_AUDIT_LLM_API_KEY 等;无 key 或 API 调用失败均立即终止,不做降级)。
密钥文件:firmware_audit/.env(LLMClient 构造时自动加载,环境变量优先于文件)。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .providers.llm_client import LLMClient, LLMError
from .runner import ALL_CONFIGS, AgentRunResult, render_report, run_agent


def resolve_workspace(path: Path) -> Path:
    """<dir> → 工作区目录:含 process/ 子目录则取之(普通 target),
    否则 dir 本身即工作区(分区子工作区 / 直接传 process/)。

    一律返回绝对路径:CLI 常以相对路径调用(如 run_step5 target/1),
    相对路径流入 docker -v 会被 Docker 当命名卷 → daemon 报
    create <path>: invalid characters → exit 125(2026-08-19 实发)。"""
    process = path / "process"
    return (process if process.is_dir() else path).resolve()


def artifact_done(path: Path) -> bool:
    """工件已产出:.json(可解析)或 .md(降级)均算完成。"""
    return path.is_file() or path.with_suffix(".md").is_file()


def _tool_stats(r: AgentRunResult) -> dict[str, int]:
    """阶段工具调用统计:{工具名: 次数}(无 react 的跳过阶段给空表)。"""
    counts: dict[str, int] = {}
    for c in (r.react.tool_calls if r.react else []):
        counts[c["tool"]] = counts.get(c["tool"], 0) + 1
    return counts


def _no_key_error() -> LLMError:
    """构造带 .env 定位与指引的报错(.env 自动加载已生效后仍无 key 的诊断)。"""
    from .providers.llm_client import load_env_file
    env_file = load_env_file()
    head = ("无 API key,Step5 审计终止(不执行降级)。\n"
            "已检查:环境变量 FIRMWARE_AUDIT_LLM_API_KEY / DEEPSEEK_API_KEY / "
            "LLM_API_KEY,以及 .env 自动加载")
    if env_file is not None:
        return LLMError(
            f"{head}\n"
            f"已加载 {env_file},但其中没有有效的 API key 行——"
            f"请打开该文件确认存在 FIRMWARE_AUDIT_LLM_API_KEY=sk-... 一行"
            f"(等号两边勿加引号或多余空格),修正后保存重跑即可")
    pkg_root = Path(__file__).resolve().parents[1]  # firmware_audit/(.env 规范位置)
    return LLMError(
        f"{head}\n"
        f"未找到 .env(已搜索 firmware_audit 包根与当前目录及上级)。\n"
        f"请在 {pkg_root} 下创建 .env,写入:\n"
        f"  FIRMWARE_AUDIT_LLM_BASE_URL=https://api.deepseek.com\n"
        f"  FIRMWARE_AUDIT_LLM_API_KEY=sk-你的密钥\n"
        f"  FIRMWARE_AUDIT_LLM_MODEL=deepseek-v4-flash\n"
        f"保存后直接重跑即可(自动加载,无需手动导出环境变量)")


def step5_run(target_dir: Path, force: bool = False, llm=None) -> dict:
    """跑完整 Step5。返回摘要 dict(mode/stages/report)。
    无 API key 或 API 调用失败时抛 LLMError(立即终止,不做降级)。
    llm 用于测试注入(ScriptedLLM);None 时按环境变量建 LLMClient。"""
    process_dir = resolve_workspace(Path(target_dir))
    if not (process_dir / "analysis").is_dir() and not (process_dir / "agent").is_dir():
        raise FileNotFoundError(f"工作区无 analysis/ 工件: {process_dir}(先跑 Step1-4)")

    base = llm or LLMClient()
    if not base.available:
        raise _no_key_error()

    agent_dir = process_dir / "agent"
    stages: dict[str, AgentRunResult] = {}
    upstream_path: Path | None = None

    for cfg in ALL_CONFIGS:
        out_path = agent_dir / cfg.output_name
        if not force and artifact_done(out_path):
            print(f"[step5:{cfg.name}] 工件已存在,跳过({out_path.name})")
            stages[cfg.name] = AgentRunResult(cfg=cfg, artifact_path=out_path, skipped=True)
            upstream_path = out_path
            continue

        if upstream_path is not None and not artifact_done(upstream_path):
            # 前序失败且无降级产物:链条中止
            stages[cfg.name] = AgentRunResult(
                cfg=cfg, error=f"上游工件缺失({upstream_path.name}),中止")
            break

        result = run_agent(cfg, process_dir, base, upstream_path)
        stages[cfg.name] = result
        if result.artifact_path is None and not result.skipped:
            break  # 该阶段彻底失败,下游无输入
        upstream_path = result.artifact_path or out_path

    note = "" if all(r.ok for r in stages.values()) else "部分阶段失败/降级,结论可能不完整"
    report = render_report(process_dir, agent_note=note)

    usage_total = {"prompt_tokens": 0, "completion_tokens": 0}
    tool_total: dict[str, int] = {}
    for r in stages.values():
        for k in usage_total:
            usage_total[k] += r.usage.get(k, 0)
        for tool, n in _tool_stats(r).items():
            tool_total[tool] = tool_total.get(tool, 0) + n
    print(f"[step5] 完成,报告: {report}(LLM 用量: {usage_total},工具调用: {tool_total})")
    return {
        "mode": "llm",
        "stages": {
            name: {
                "ok": r.ok,
                "error": r.error,
                "steps": r.react.steps if r.react else 0,
                "tool_calls": _tool_stats(r),
            } for name, r in stages.items()
        },
        "usage": usage_total,
        "tool_calls": tool_total,
        "report": str(report),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Step5 Agent 审计(可独立于 Step1-4 复跑)")
    ap.add_argument("target_dir", type=Path,
                    help="target/<N> 目录或工作区目录(含 process/ 或本身即 process 等价)")
    ap.add_argument("--force", action="store_true", help="忽略已有工件,全部重跑")
    args = ap.parse_args(argv)

    try:
        summary = step5_run(args.target_dir, force=args.force)
    except LLMError as e:
        print(f"[step5] 终止: {e}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError) as e:
        print(f"[step5] 无法启动: {e}", file=sys.stderr)
        return 2
    print(f"[step5] mode={summary['mode']} report={summary['report']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

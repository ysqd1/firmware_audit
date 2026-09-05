"""Step5 入口:Orchestrator 统一编排三 Agent + 断点续跑 + 无 key/API 失败立即终止。

控制流(v3,2026-08-28,参考 deepaudit OrchestratorAgent 精简版):
    Orchestrator(轻量 LLM 驱动,ReAct 循环)
      → dispatch recon → survey.json(v3) → dispatch analysis
      → findings.json → dispatch verification → verified_findings.json
      → summarize(取报告素材)→ Final Answer = 最终报告 → orchestrator/report.md

编排痕迹:
    process/agent/orchestrator/  {transcript, dispatch_log, handoff_*, report.md, result.json}
    process/agent/<seq>_<type>/   子 Agent 的 transcript/obs/工件(如 0_recon/)

最终报告: 由 orchestrator 的 summarize 动作产出(orchestrator/report.md);
未产出时明确告警,不静默降级(原 render_report 已删除)。

断点续跑:某子 Agent .json 工件存在即跳过;仅 .md 降级工件 → degraded(默认重跑,
STEP5_RESUME_DEGRADED=0 关闭);上游缺件时下游被链路守卫拒绝(不空转)。

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

from .orchestration.orchestrator import Orchestrator
from .providers.llm_client import LLMClient, LLMError


def resolve_workspace(path: Path) -> Path:
    """<dir> → 工作区目录:含 process/ 子目录则取之(普通 target),
    否则 dir 本身即工作区(分区子工作区 / 直接传 process/)。

    一律返回绝对路径:CLI 常以相对路径调用(如 run_step5 target/1),
    相对路径流入 docker -v 会被 Docker 当命名卷 → daemon 报
    create <path>: invalid characters → exit 125(2026-08-19 实发)。"""
    process = path / "process"
    return (process if process.is_dir() else path).resolve()


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


def _tool_counts(tool_calls: list) -> dict[str, int]:
    """子 Agent 工具调用统计:{工具名: 次数}(无工具给空表)。"""
    counts: dict[str, int] = {}
    for c in tool_calls:
        counts[c.get("tool", "?")] = counts.get(c.get("tool", "?"), 0) + 1
    return counts


def step5_run(target_dir: Path, force: bool = False, llm=None) -> dict:
    """跑完整 Step5(Orchestrator 统一编排)。返回摘要 dict(stages/report)。
    无 API key 或 API 调用失败时抛 LLMError(立即终止,不做降级)。
    llm 用于测试注入(ScriptedLLM);None 时按环境变量建 LLMClient。
    唯一路径=LLM 编排(ADR-0006:pipeline 快速模式已删,所有运行都产报告)。"""
    process_dir = resolve_workspace(Path(target_dir))
    if not (process_dir / "analysis").is_dir() and not (process_dir / "agent").is_dir():
        raise FileNotFoundError(f"工作区无 analysis/ 工件: {process_dir}(先跑 Step1-4)")

    base = llm or LLMClient()
    if not base.available:
        raise _no_key_error()

    orch = Orchestrator(process_dir, base, force=force)
    orch.run()

    stages = {
        name: {
            "ok": sub.ok,
            "error": sub.error,
            "steps": sub.steps,
            "tool_calls": _tool_counts(sub.tool_calls),
        } for name, sub in orch.agent_results.items()
    }

    # LLM 用量:编排器与子 Agent 共享 base_llm,total_usage 已累计全部调用
    # (2026-08-29 B2:此前仅按 sub.usage 累加,skipped/degraded 实例 usage 为空,
    # 且 orchestrator 自身轮次从不计入——打印误导为 0)
    usage_total = dict(getattr(base, "total_usage", {}))
    tool_total: dict[str, int] = {}
    for sub in orch.dispatches:  # 全部实际执行的调度(含同类型多次调用)均计入
        for tool, n in _tool_counts(sub.tool_calls).items():
            tool_total[tool] = tool_total.get(tool, 0) + n

    report = orch.report_path
    if report is None:
        print("[step5] 警告: 编排未产出总结报告(orchestrator 未调用 summarize "
              "或 Final Answer 为空);报告生成不完整。findings 与各阶段统计已完整"
              "保留在 process/agent/orchestrator/result.json,可补跑再编排",
              file=sys.stderr)
    else:
        print(f"[step5] 完成,报告: {report}"
              f"(LLM 用量: {usage_total},工具调用: {tool_total})")
    return {
        "mode": "llm",
        "stages": stages,
        "usage": usage_total,
        "tool_calls": tool_total,
        "report": str(report) if report else None,
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

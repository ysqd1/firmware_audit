"""Step5 入口:Host 控制的逐 Candidate 调查生命周期(ADR-0012,票 14 公开切换)。

控制流(RunDriver,唯一真实循环):
    世代选择/活动锁/配置快照/共享预算
      → Recon(攻击面 survey + Candidate proposals + coverage gaps)
      → Candidate Store(精确指纹去重 + 语义比较 + 评分双队列)
      → 逐 Candidate Analysis(独立 Investigation,Claim/假设门槛,案卷冻结)
      → Verification(独立复核会话,逐 Claim Result,Host 聚合 verdict)
      → confirmed → Finding → 确定性事实报告 → manifest seal → completed

工件根:工作区 generations/gen-XXXX/(manifest/run_state/config/candidates/
investigations/<cand>/、verifications/<cand>/、findings.json、report.md)。
旧版 survey.json / findings.json / verified_findings.json 语义不迁移也不读取;
旧工作区显式新建运行世代重跑(AC:新流程不读写旧三种结果工件)。

断点续跑:默认恢复唯一未完成世代(running/finalizing);completed 只读;
--force = 创建新运行世代(兼容既有操作习惯,不再原地覆盖)。

用法:
    python -m firmware_audit.step5_agent.run_step5 <dir> [--force]
    <dir> 可以是 target/<N>(内含 process/)或工作区本身(process/ 等价目录)
环境变量:模型见 llm_client(FIRMWARE_AUDIT_LLM_*);预算/轮次见 host/budget
(STEP5_RECON/ANALYSIS/VERIFICATION_MAX_ITERS、STEP5_MAX_LLM_CALLS 等)。
无 API key 或 API 调用失败立即终止,不产出降级工件、不做 CVE 缓存预检
(Blind Discovery,ADR-0012)。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine.context import ContextManager
from .host import ANALYSIS_SESSION_SYSTEM, RunDriver, RunSummary
from .host.recon import RECON_SESSION_SYSTEM
from .host.session import AgentSession
from .host.verification import VERIFICATION_SESSION_SYSTEM
from .providers.llm_client import LLMClient, LLMError
from .providers.tools import make_tools
from .providers.tools.base import ToolContext

# 角色 → (系统提示词, transcript 所在权威树)。目录形状与各 runner 的
# Investigation/Verification 布局同构:recon → investigations/recon/;
# analysis → investigations/<cand>/;verification → verifications/<cand>/。
_ROLE_WIRING = {
    "recon": (RECON_SESSION_SYSTEM, "investigations"),
    "analysis": (ANALYSIS_SESSION_SYSTEM, "investigations"),
    "verification": (VERIFICATION_SESSION_SYSTEM, "verifications"),
}


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


def _transcript_path(run_dir: Path | None, role: str,
                     candidate_id: str | None) -> Path | None:
    """各 Session 的 transcript 落在各自权威目录内(与 Evidence 同根;
    ADR-0012:复核目录保存 Transcript)。recon 无 candidate_id,固定
    investigations/recon/。"""
    if run_dir is None:
        return None
    _, tree = _ROLE_WIRING[role]
    owner = candidate_id if candidate_id is not None else "recon"
    return Path(run_dir) / tree / owner / "transcript.jsonl"


def _session_factory(llm):
    """生产 Session 工厂:角色系统提示词 + 世代内 transcript 路径。

    每个 Candidate/案卷一个独立 Agent Session(上下文隔离铁律);
    工具授权由 Host 按角色契约逐动作把关,工厂不做权限过滤。"""
    def factory(role: str, candidate_id: str | None = None,
                run_dir: Path | None = None) -> AgentSession:
        system, _ = _ROLE_WIRING[role]
        return AgentSession(
            role, llm,
            ContextManager(system, ""),
            transcript=_transcript_path(run_dir, role, candidate_id),
        )
    return factory


def _print_summary(summary: RunSummary, report: Path) -> None:
    lines = [
        f"[step5] 世代 {summary.generation}({summary.gen_dir})",
        f"[step5] 状态: {summary.status}"
        + (f"(停止原因: {summary.stop_reason})" if summary.stop_reason else ""),
        f"[step5] Candidate {summary.candidates} 条,Finding {summary.findings} 条",
    ]
    if summary.status == "completed":
        lines.append(f"[step5] 完成,报告: {report}")
    print("\n".join(lines))


def step5_run(target_dir: Path, force: bool = False, llm=None) -> dict:
    """跑完整 Step5(Host 控制生命周期)。返回摘要 dict(mode/generation/
    status/stop_reason/report/findings/candidates);判读细节以世代目录内
    工件为准。无 API key 或 API 调用失败时抛 LLMError(立即终止,不降级);
    llm 用于测试注入(ScriptedLLM);None 时按环境变量建 LLMClient。

    Blind Discovery(ADR-0012):启动不做 CVE 缓存预检,不带 cve_cache_warning。
    """
    process_dir = resolve_workspace(Path(target_dir))
    # 启动门(ADR-0011):只需解包产物——Agent 直接面向解包树工作,反编译
    # 边车由 ghidra_decompile 按需产出;老工作区已有 analysis/ 照样放行(当缓存)
    if not (process_dir / "extracted").is_dir():
        raise FileNotFoundError(f"工作区无 extracted/ 解包产物: {process_dir}(先跑 Step1 解包)")

    base = llm or LLMClient()
    if not base.available:
        raise _no_key_error()

    driver = RunDriver(
        process_dir,
        tools=make_tools(ToolContext(process_dir=process_dir)),
        session_factory=_session_factory(base),
        llm=base,
        process_dir=process_dir,
    )
    summary = driver.run(force=force)
    report = summary.gen_dir / "report.md"  # 报告路径单一出处(host/reporting 布局)
    _print_summary(summary, report)
    return {
        "mode": "host",
        "generation": summary.generation,
        "gen_dir": str(summary.gen_dir),
        "created": summary.created,
        "status": summary.status,
        "stop_reason": summary.stop_reason,
        "report": str(report) if report.exists() else None,
        "findings": summary.findings,
        "candidates": summary.candidates,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Step5 Agent 审计(可独立于 Step1-4 复跑)")
    ap.add_argument("target_dir", type=Path,
                    help="target/<N> 目录或工作区目录(含 process/ 或本身即 process 等价)")
    ap.add_argument("--force", action="store_true",
                    help="创建新运行世代(默认恢复未完成世代,已完成世代只读)")
    args = ap.parse_args(argv)

    try:
        summary = step5_run(args.target_dir, force=args.force)
    except LLMError as e:
        print(f"[step5] 终止: {e}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError) as e:
        print(f"[step5] 无法启动: {e}", file=sys.stderr)
        return 2
    print(f"[step5] mode={summary['mode']} generation={summary['generation']} "
          f"report={summary['report']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

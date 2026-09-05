"""DispatchLog 直测(ADR-0009 T3:调度日志收类)。

四动词接口(start/finish/interrupted/attempt)的状态变迁、status_history
与 dispatch_log.json 落盘内容,零 Orchestrator 零 LLM——调度留痕是独立小类,
"为测一个日志类构造整个编排器"正是本票要消灭的耦合。字段结构与落盘内容
与收类前完全不变(编排级断言仍在 test_orchestrator.py,照绿即回归锁定)。
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.orchestration.dispatch_log import DispatchLog


def _log(td: Path) -> tuple[DispatchLog, Path]:
    orch_dir = td / "process" / "agent" / "orchestrator"
    return DispatchLog(orch_dir), orch_dir


def _read(orch_dir: Path) -> list[dict]:
    return json.loads((orch_dir / "dispatch_log.json").read_text(encoding="utf-8"))


def test_start_running_record_and_persist() -> list[str]:
    """start:登记 running 记录(全字段,status_history 只有首跳),整表落盘。

    orchestrator/ 目录不存在时 start 自建(含 mkdir)——被拒尝试先于
    Orchestrator.run() 落盘的路径依赖这一点。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        log, orch_dir = _log(td)
        rec = log.start(3, "analysis", "取证", {"agent": "analysis", "task": "取证"})
        if rec.get("status") != "running":
            fails.append(f"start 应登记 running: {rec.get('status')}")
        for k in ("seq", "agent", "task", "request", "started_at",
                  "finished_at", "duration_ms", "artifact_path", "summary",
                  "error", "status_history"):
            if k not in rec:
                fails.append(f"running 记录缺字段 {k}")
        if rec.get("finished_at") is not None or rec.get("duration_ms") is not None:
            fails.append("running 记录的终态字段应为 None(未回填)")
        hist = [h.get("status") for h in rec.get("status_history", [])]
        if hist != ["running"]:
            fails.append(f"status_history 应只有首跳 running: {hist}")
        if not all(h.get("ts") for h in rec.get("status_history", [])):
            fails.append("status_history 应带时间戳")
        if not (orch_dir / "dispatch_log.json").is_file():
            fails.append("start 应落盘 dispatch_log.json(含目录创建)")
        else:
            disk = _read(orch_dir)
            if len(disk) != 1 or disk[0].get("seq") != 3:
                fails.append(f"落盘内容应为记录整表: {disk}")
    return fails


def test_finish_backfills_terminal_state() -> list[str]:
    """finish:running→终态回填(状态/耗时/工件/摘要/错误/budget_state),
    status_history 追加终态跳,落盘同步;budget_state=None 不写该键。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        log, orch_dir = _log(td)
        rec = log.start(0, "recon", "侦察", {"agent": "recon", "task": "侦察"})
        log.finish(rec, "success", duration_ms=1234, artifact="recon/survey.json",
                   summary="攻击面", error="",
                   budget_state={"agent": "recon", "exhausted": False})
        if rec["status"] != "success" or rec["finished_at"] is None:
            fails.append(f"finish 应回填终态: {rec['status']}/{rec['finished_at']}")
        if rec["duration_ms"] != 1234 or rec["artifact_path"] != "recon/survey.json":
            fails.append(f"finish 应回填耗时与工件: {rec}")
        hist = [h.get("status") for h in rec["status_history"]]
        if hist != ["running", "success"]:
            fails.append(f"状态变迁应为 running→success: {hist}")
        if rec.get("budget_state") != {"agent": "recon", "exhausted": False}:
            fails.append(f"budget_state 应原样附加: {rec.get('budget_state')}")
        rec2 = log.start(1, "analysis", "t", {})
        log.finish(rec2, "failed", error="boom")
        if "budget_state" in rec2:
            fails.append("budget_state 缺省时不应写入该键")
        disk = _read(orch_dir)
        if not disk or disk[0].get("status") != "success":
            fails.append("finish 后落盘应同步终态")
        if disk[-1].get("status") != "failed" or disk[-1].get("duration_ms") is not None:
            fails.append(f"第二条 finish 落盘不符(duration_ms 缺省 None): {disk[-1]}")
    return fails


def test_interrupted_backfills_running_only() -> list[str]:
    """interrupted:running 记录回填 interrupted(默认错误文案+终态跳);
    已终态记录不再改写(finish 后误回填会伪造中断)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        log, orch_dir = _log(td)
        rec = log.start(0, "recon", "侦察", {})
        log.interrupted(rec)
        if rec["status"] != "interrupted":
            fails.append(f"running 记录应回填 interrupted: {rec['status']}")
        if rec.get("error") != "子 Agent 执行中断(异常向上传播)":
            fails.append(f"中断应带默认错误文案: {rec.get('error')}")
        if rec.get("finished_at") is None:
            fails.append("interrupted 应回填 finished_at(不留悬挂 running)")
        hist = [h.get("status") for h in rec["status_history"]]
        if hist != ["running", "interrupted"]:
            fails.append(f"状态变迁应为 running→interrupted: {hist}")
        done = log.start(1, "analysis", "t", {})
        log.finish(done, "success")
        log.interrupted(done)
        if done["status"] != "success" or len(done["status_history"]) != 2:
            fails.append("已终态记录不应被 interrupted 改写")
        disk = _read(orch_dir)
        if [r["status"] for r in disk] != ["interrupted", "success"]:
            fails.append(f"落盘状态序列不符: {[r['status'] for r in disk]}")
    return fails


def test_attempt_one_shot_record() -> list[str]:
    """attempt:不经 running 阶段的一次性留痕(拒绝/重复/跳过);条件键
    duplicate_of/budget_state 仅在传参时出现,seq 缺省 null(被拒不占实例位)。
    """
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        log, orch_dir = _log(td)
        t0 = time.time()
        log.attempt("verification", "越序", {"agent": "verification"},
                    "rejected", t0, error="顺序违规")
        rec = _read(orch_dir)[0]
        if rec["status"] != "rejected" or rec["error"] != "顺序违规":
            fails.append(f"attempt 应原样留痕: {rec}")
        if rec["started_at"] is None or rec["finished_at"] is None:
            fails.append("attempt 记录 started_at/finished_at 应齐备")
        if not isinstance(rec["duration_ms"], int) or rec["duration_ms"] < 0:
            fails.append(f"attempt 应按 t0 计耗时: {rec['duration_ms']}")
        if "duplicate_of" in rec or "budget_state" in rec:
            fails.append("未传条件键时不应出现 duplicate_of/budget_state")
        if rec.get("seq") is not None:
            fails.append(f"attempt 缺省 seq 应为 null: {rec.get('seq')}")
        hist = [h.get("status") for h in rec["status_history"]]
        if hist != ["rejected"]:
            fails.append(f"attempt 无状态变迁,history 单跳: {hist}")
        log.attempt("analysis", "重复任务", {}, "duplicate", t0,
                    duplicate_of=2, budget_state={"agent": "analysis"})
        rec2 = _read(orch_dir)[1]
        if rec2.get("duplicate_of") != 2 or "budget_state" not in rec2:
            fails.append(f"传参时条件键应写入: {rec2}")
    return fails


def test_status_literals_match_dispatchstatus() -> list[str]:
    """漂移守护:模块内字面量与编排主体 DispatchStatus 同值域(值即落盘契约;
    state 模块 T4 落地后由此收编,收编前靠本测试防两处人肉对齐漂移)。"""
    from firmware_audit.step5_agent.orchestration.orchestrator import DispatchStatus
    from firmware_audit.step5_agent.orchestration import dispatch_log

    fails: list[str] = []
    if dispatch_log._RUNNING != DispatchStatus.RUNNING:
        fails.append(f"_RUNNING 应与 DispatchStatus.RUNNING 同值: "
                     f"{dispatch_log._RUNNING!r} != {DispatchStatus.RUNNING!r}")
    if dispatch_log._INTERRUPTED != DispatchStatus.INTERRUPTED:
        fails.append(f"_INTERRUPTED 应与 DispatchStatus.INTERRUPTED 同值: "
                     f"{dispatch_log._INTERRUPTED!r} != {DispatchStatus.INTERRUPTED!r}")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("start_running_record_and_persist", test_start_running_record_and_persist),
        ("finish_backfills_terminal_state", test_finish_backfills_terminal_state),
        ("interrupted_backfills_running_only", test_interrupted_backfills_running_only),
        ("attempt_one_shot_record", test_attempt_one_shot_record),
        ("status_literals_match_dispatchstatus", test_status_literals_match_dispatchstatus),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())

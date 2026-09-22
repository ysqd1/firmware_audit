"""会话强制收口与遗留容器恢复(票 17;Host 侧义务,不依赖 agent 自觉)。

两条路径,同一权威语义:
- ``seal_open_sessions``:调查终态(正常完成/预算耗尽/中断)由 Host 强制
  停机封存全部开启会话——容器权威拆除(``docker rm -f``,杀 PRoot/QEMU 及
  全部派生,含后台/脱离进程组子孙),台账落终态;拆除未确认留 seal_failed,
  不伪装封存成功。
- ``reap_leftover_sessions``:Host 死亡后的恢复路径,先于任何处理收割
  遗留会话容器。中断即会话死亡:会话标 interrupted,不可复活,运行产物
  仅留档;清理结果与中断状态分开记录,只有拆除仍不能确认才留
  cleanup.verdict="uncertain"。

Docker 客户端死亡不等于清理完成——唯一权威是 ``docker rm -f`` 的结果;
"No such container" 视为 absent(无容器可清理,不是不确定)。遗留会话的
识别以台账为准:占位记账先于容器创建,故台账必然先于容器存在。
"""
from __future__ import annotations

import time
from pathlib import Path

from ....docker.docker_utils import docker_exec
from .qemu_session import (
    LEDGER_SCHEMA_VERSION,
    LLSCAN_BIN,
    LedgerError,
    SessionLedger,
    SESSIONS_DIRNAME,
    remove_session_container,
)

# 会话终态里"仍有容器需要处置"的状态:running(Host 死于会话开启后)、
# seal_failed(上次拆除未确认);interrupted 仅在清理不确定时重试。
_REAPABLE_STATUSES = ("running", "seal_failed")


def _ledger_path(base: Path) -> Path:
    return Path(base) / SESSIONS_DIRNAME / "ledger.json"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _best_effort_reap_scan(container: str) -> None:
    """拆除前尽力清扫残留进程(容器已死则静默跳过;拆除才是权威)。"""
    try:
        rc, out, _ = docker_exec(container, [LLSCAN_BIN, "count"], timeout=15)
    except Exception:
        return
    if rc != 0 or int((out or "0").strip() or 0) == 0:
        return
    try:
        docker_exec(container, [LLSCAN_BIN, "kill"], timeout=15)
    except Exception:
        pass  # 升级清扫失败不阻断拆除(rm -f 兜底)


def _needs_reap(entry: dict) -> bool:
    status = entry.get("status")
    if status in _REAPABLE_STATUSES:
        return True
    if status == "interrupted":
        return (entry.get("cleanup") or {}).get("verdict") == "uncertain"
    return False


def reap_leftover_sessions(base: Path) -> dict:
    """恢复路径:识别并收割遗留会话容器,记录清理结果。

    返回 ``{"reaped": [session_id...], "uncertain": [session_id...],
    "unreadable": str|None}``;台账不存在视为无遗留。对每个遗留会话:
    状态标 interrupted(会话死亡,不可继续),``sealed`` 与
    ``cleanup.verdict`` 如实记录拆除结果,``seal_kind="recovery_reap"``。
    """
    report: dict = {"reaped": [], "uncertain": [], "unreadable": None}
    path = _ledger_path(base)
    if not path.exists():
        return report
    try:
        ledger = SessionLedger(path)
    except LedgerError as exc:
        report["unreadable"] = str(exc)
        return report
    for entry in ledger.data["sessions"]:
        if not isinstance(entry, dict) or not _needs_reap(entry):
            continue
        container = (entry.get("container") or {}).get("name") or ""
        if container:
            _best_effort_reap_scan(container)
        verdict, detail = remove_session_container(container)
        session_id = entry.get("session_id") or "?"
        entry["status"] = "interrupted"
        entry["seal_kind"] = "recovery_reap"
        entry["sealed"] = verdict in ("container_removed", "absent")
        entry["sealed_at"] = _now()
        entry["cleanup"] = {"verdict": verdict, "detail": detail}
        entry["recovery"] = {
            "reaped_at": entry["sealed_at"],
            "note": ("Host 恢复路径强制收割:中断即会话死亡,运行产物仅留档,"
                     "不进入新会话,已持久化执行不重复扣名额"),
        }
        ledger.replace(session_id, entry)
        (report["reaped"] if entry["sealed"] else report["uncertain"]).append(
            session_id)
    return report


def seal_open_sessions(base: Path, *, kind: str) -> dict:
    """调查终态强制停机:封存全部开启会话(Host 义务,不依赖 agent)。

    ``kind`` 记录入台账 seal_kind(host_finalize / host_interrupt),与
    恢复收割的 recovery_reap 区分。返回
    ``{"sealed": [...], "failed": [...], "unreadable": str|None}``;
    拆除未确认的会话留 seal_failed,由后续恢复路径强制收割。
    """
    report: dict = {"sealed": [], "failed": [], "unreadable": None}
    path = _ledger_path(base)
    if not path.exists():
        return report
    try:
        ledger = SessionLedger(path)
    except LedgerError as exc:
        report["unreadable"] = str(exc)
        return report
    for entry in ledger.data["sessions"]:
        if not isinstance(entry, dict) or entry.get("status") not in (
                "running", "seal_failed"):
            continue
        container = (entry.get("container") or {}).get("name") or ""
        if container:
            _best_effort_reap_scan(container)
        verdict, detail = remove_session_container(container)
        session_id = entry.get("session_id") or "?"
        sealed = verdict in ("container_removed", "absent")
        entry["status"] = "sealed" if sealed else "seal_failed"
        entry["sealed"] = sealed
        entry["seal_kind"] = kind
        entry["sealed_at"] = _now()
        entry["cleanup"] = {"verdict": verdict, "detail": detail}
        ledger.replace(session_id, entry)
        (report["sealed"] if sealed else report["failed"]).append(session_id)
    return report


# 供测试/调用方断言的 schema 版本(单一出处再导出)。
__all__ = ["LEDGER_SCHEMA_VERSION", "reap_leftover_sessions",
           "seal_open_sessions"]

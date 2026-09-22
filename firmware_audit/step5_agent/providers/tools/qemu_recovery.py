"""会话强制收口与遗留容器恢复(票 17;Host 侧义务,不依赖 agent 自觉)。

两条路径,同一处置骨架(``_dispose_sessions``):
- ``seal_open_sessions``:调查终态(正常完成/预算耗尽/中断)由 Host 强制
  停机封存全部开启会话——容器权威拆除(``docker rm -f``,杀 PRoot/QEMU 及
  全部派生,含后台/脱离进程组子孙),台账落终态;拆除未确认留 seal_failed,
  不伪装封存成功。
- ``reap_leftover_sessions``:Host 死亡后的恢复路径,先于任何处理收割
  遗留会话容器。中断即会话死亡:会话标 interrupted,不可复活,运行产物
  仅留档;清理结果与中断状态分开记录,只有拆除仍不能确认才留
  cleanup.verdict="uncertain"。

处置规则(状态机,单一出处):
- running → 本次处置的终态(seal 路径 = sealed;恢复路径 = interrupted);
- seal_failed → 拆除确认即 sealed(封存终于完成),仍失败保持 seal_failed;
- interrupted(清理不确定的重试)→ 死亡事实不变,状态与 seal_kind 不动,
  只刷新 sealed/cleanup(最新清理事实)。

Docker 客户端死亡不等于清理完成——唯一权威是 ``docker rm -f`` 的结果;
"No such container" 视为 absent(无容器可清理,不是不确定)。遗留会话的
识别以台账为准:占位记账先于容器创建,故台账必然先于容器存在。单个台账
条目异常只跳过该条并记录,不中断其余遗留容器的处置。
"""
from __future__ import annotations

from pathlib import Path

from ....docker.docker_utils import docker_exec
from .qemu_base import timestamp
from .qemu_session import (
    LLSCAN_BIN,
    LedgerError,
    SessionLedger,
    SESSIONS_DIRNAME,
    remove_session_container,
)


def _ledger_path(base: Path) -> Path:
    return Path(base) / SESSIONS_DIRNAME / "ledger.json"


def _parse_count(out: str) -> int | None:
    """llscan count 输出 → 整数;解析失败返回 None(调用方按不可确认处理)。"""
    try:
        return int((out or "").strip() or 0)
    except ValueError:
        return None


def _best_effort_reap_scan(container: str) -> None:
    """拆除前尽力清扫残留进程(容器已死则静默跳过;拆除才是权威)。"""
    try:
        rc, out, _ = docker_exec(container, [LLSCAN_BIN, "count"], timeout=15)
    except Exception:
        return
    if rc != 0 or _parse_count(out) == 0:
        return
    try:
        docker_exec(container, [LLSCAN_BIN, "kill"], timeout=15)
    except Exception:
        pass  # 升级清扫失败不阻断拆除(rm -f 兜底)


def _needs_disposal(entry: dict) -> bool:
    status = entry.get("status")
    if status in ("running", "seal_failed"):
        return True
    if status == "interrupted":
        return (entry.get("cleanup") or {}).get("verdict") == "uncertain"
    return False


def _dispose_sessions(base: Path, *, kind: str, interrupted: bool) -> dict:
    """共享处置骨架:识别待处置会话 → 清扫 → 权威拆除 → 状态机回写。

    ``interrupted`` 决定 running 会话的去向(True=恢复收割/中断收口,会话
    标 interrupted;False=调查终态封存,确认即 sealed、未确认留
    seal_failed)。返回 ``{"sealed": [...], "failed": [...],
    "unreadable": str|None}``;failed 收集拆除未确认的会话(含清理不确定
    的 interrupted 重试)。
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
        if not isinstance(entry, dict) or not _needs_disposal(entry):
            continue
        session_id = entry.get("session_id") or "?"
        previous_status = entry.get("status")
        container = (entry.get("container") or {}).get("name") or ""
        if container:
            _best_effort_reap_scan(container)
        try:
            verdict, detail = remove_session_container(container)
        except Exception as exc:  # 单条失败不断收口:如实记录后继续
            verdict, detail = "uncertain", f"{type(exc).__name__}: {exc}"
        confirmed = verdict in ("container_removed", "absent")
        entry["cleanup"] = {"verdict": verdict, "detail": detail}
        entry["sealed"] = confirmed
        entry["sealed_at"] = timestamp()
        entry["recovery"] = {
            "reaped_at": entry["sealed_at"],
            "seal_kind": kind,
            "note": ("Host 恢复路径强制收割:中断即会话死亡,运行产物仅留档,"
                     "不进入新会话,已持久化执行不重复扣名额"),
        }
        if previous_status == "running":
            if interrupted:
                # Host 死亡/中断:会话死亡与清理确认是两件事
                entry["status"] = "interrupted"
            else:
                entry["status"] = "sealed" if confirmed else "seal_failed"
            entry["seal_kind"] = kind
        elif previous_status == "seal_failed":
            # 封存失败的重试:拆除确认即完成封存(恢复路径确认同样算,
            # 会话并非死于中断,死亡形态是"封存完成")。
            entry["status"] = "sealed" if confirmed else "seal_failed"
            entry["seal_kind"] = kind
        # interrupted:死亡标记(seal_kind/sealed_at 首判)不动,只刷新清理事实
        (report["sealed"] if confirmed else report["failed"]).append(session_id)
        try:
            ledger.replace(session_id, entry)
        except Exception:
            report["failed"].append(session_id)
    return report


def reap_leftover_sessions(base: Path) -> dict:
    """恢复路径:识别并收割遗留会话容器,记录清理结果。

    返回 ``{"reaped": [session_id...], "uncertain": [session_id...],
    "unreadable": str|None}``;台账不存在视为无遗留。对每个遗留会话:
    状态标 interrupted(会话死亡,不可继续),``sealed`` 与
    ``cleanup.verdict`` 如实记录拆除结果,``seal_kind="recovery_reap"``。
    """
    disposed = _dispose_sessions(base, kind="recovery_reap", interrupted=True)
    return {"reaped": disposed["sealed"], "uncertain": disposed["failed"],
            "unreadable": disposed["unreadable"]}


def seal_open_sessions(base: Path, *, kind: str) -> dict:
    """调查终态强制停机:封存全部开启会话(Host 义务,不依赖 agent)。

    ``kind`` 记录入台账 seal_kind(host_finalize / host_interrupt),与
    恢复收割的 recovery_reap 区分。返回
    ``{"sealed": [...], "failed": [...], "unreadable": str|None}``;
    拆除未确认的会话留 seal_failed,由后续恢复路径强制收割。
    """
    return _dispose_sessions(base, kind=kind, interrupted=False)


# 供调用方断言的 schema 版本(单一出处再导出)。
__all__ = ["reap_leftover_sessions", "seal_open_sessions"]

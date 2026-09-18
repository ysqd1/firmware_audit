"""工作区活动锁:同一工作区同一时刻只允许一个活动运行(ADR-0012 L77)。

锁记录进程身份(pid、hostname、启动时间与进程启动标记);原持有进程仍
活动时拒绝第二运行,仅确认进程不活动后接管 stale lock。锁文件损坏或来自
另一台主机时拒绝并引导人工检查——不自动删除用户可见状态(删除先问)。

互斥由"独占创建 + 失败重判"保证:新建与接管都用 ``atomic_json(exclusive=
True)``(同目录硬链接,存在即败),失败者重读锁文件按持有者身份判定;
接管前二次读取确认仍是同一把死锁再删除,避免删掉并发接管者刚写入的新锁。
平台边界:进程判活依赖 POSIX 信号与 /proc;非 POSIX 平台无法安全确认
持有者状态,存在锁文件时拒绝并引导人工处理(接线生产入口前显式决策)。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import time
import warnings

from .store import StoreError, atomic_json, read_json_object

LOCK_SCHEMA_VERSION = 1


class LockActiveError(RuntimeError):
    """另一个运行仍在活动或锁无法判定;拒绝并发写入。"""


def _process_start_marker(pid: int) -> int | None:
    """/proc 下的进程启动时钟拍数;防 PID 复用把旧锁误判成活进程。"""
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            # 字段 22(starttime)在 comm 字段(可含空格/括号)之后,按右括号切分
            tail = handle.read().rpartition(b")")[2].split()
            return int(tail[19])
    except (OSError, ValueError, IndexError):
        return None


def _default_alive(pid: int, start_marker: int | None) -> bool:
    if type(pid) is not int or pid < 1:
        return False  # os.kill 对 -1 等进程组语义不适用,非法 PID 直接判死
    if os.name != "posix":
        # Windows 的 os.kill 走 TerminateProcess(信号 0 也会终止目标),
        # 不能用作存在性探测;保守交由调用方拒绝。
        raise LockActiveError(
            "当前平台无法确认锁持有进程状态;请人工检查后处理锁文件")
    if isinstance(start_marker, int) and os.path.exists("/proc"):
        current = _process_start_marker(pid)
        return current is not None and current == start_marker
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # 进程存在但属他人:保守判活
    except OSError:
        return False
    return True


def hostname() -> str:
    """本机主机名;进程身份三件套之一(与 pid/start_marker 同级)。"""
    if hasattr(os, "uname"):
        return os.uname().nodename
    return os.environ.get("COMPUTERNAME") or "unknown-host"


# acquire_lock 的形参 hostname(公开关键字)遮蔽本模块同名函数,
# 默认值经此别名取用;generation.py 也从这里导入主机名默认值。
HOSTNAME_DEFAULT = hostname


class LockHandle:
    """已持有的工作区锁;release 只删除仍属于自己的锁文件。"""

    def __init__(self, path: Path, identity: dict):
        self.path = Path(path)
        self._identity = dict(identity)
        self._released = False

    def _owns(self, document: dict) -> bool:
        return (document.get("pid") == self._identity["pid"]
                and document.get("hostname") == self._identity["hostname"])

    def release(self) -> None:
        if self._released:
            return
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return  # 锁文件已消失或被替换:无事可做
        if isinstance(document, dict) and self._owns(document):
            self.path.unlink(missing_ok=True)
        self._released = True

    def __enter__(self) -> "LockHandle":
        return self

    def __exit__(self, *exc_info) -> None:
        self.release()


def _read_lock(path: Path) -> dict | None:
    """读取锁文件;缺失返回 None,损坏按 Store 语义拒绝。"""
    if not path.exists():
        return None
    held = read_json_object(
        path, "活动锁",
        guidance="无法判定是否有并发运行,请人工检查后处理")
    if (type(held.get("pid")) is not int
            or not isinstance(held.get("hostname"), str)
            or held.get("schema_version") != LOCK_SCHEMA_VERSION):
        raise StoreError(f"活动锁结构损坏;请人工检查后处理: {path}")
    return held


def acquire_lock(
    root: Path,
    *,
    pid: int | None = None,
    hostname: str | None = None,
    alive_checker=None,
) -> LockHandle:
    """获取工作区活动锁;stale lock 在确认原进程不活动后接管。"""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "lock.json"
    identity = {
        "pid": os.getpid() if pid is None else int(pid),
        "hostname": hostname if hostname is not None else HOSTNAME_DEFAULT(),
        "started_at": float(time.time()),
    }
    document = {
        "schema_version": LOCK_SCHEMA_VERSION,
        **identity,
        "start_marker": _process_start_marker(identity["pid"]),
    }
    checker = alive_checker or _default_alive
    while True:
        held = _read_lock(path)
        if held is None:
            # 冷启动竞争:独占创建,输者转入下一轮按持有者身份重判。
            try:
                atomic_json(path, document, exclusive=True)
                return LockHandle(path, identity)
            except FileExistsError:
                continue
        if held["hostname"] != identity["hostname"]:
            raise LockActiveError(
                f"工作区锁由另一台主机持有(hostname={held['hostname']!r});"
                "跨主机无法确认进程状态,请人工检查后处理")
        held_marker = held.get("start_marker")
        if checker(held["pid"], held_marker if isinstance(held_marker, int) else None):
            raise LockActiveError(
                f"另一运行仍在活动(pid={held['pid']});同一工作区同一时刻"
                "只允许一个活动运行,请等待其结束或检查进程状态")
        warnings.warn(
            f"接管 stale lock:原持有进程 pid={held['pid']} 已不活动",
            RuntimeWarning)
        # 接管竞态收敛:仅在文件仍是刚判定的那把死锁时删除,再独占重建;
        # 内容已变说明并发接管者赢了,回到重判循环。
        if _read_lock(path) != held:
            continue
        path.unlink()
        try:
            atomic_json(path, document, exclusive=True)
            return LockHandle(path, identity)
        except FileExistsError:
            continue

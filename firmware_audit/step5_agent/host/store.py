"""Append-only Investigation history and atomically published state projection.

Each event stores the complete next projection, so replay is deterministic without
depending on future domain policy. Events are authoritative; snapshots only save
projection replay work. Run locking and generation management belong to ticket 11.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import tempfile
import warnings

from .json_values import clone_json_value

SCHEMA_VERSION = 1
EVENT_VERSION = 1

# Candidate 身份的单一格式出处(Candidate Store 与 Investigation Store 共用)。
CANDIDATE_ID_PATTERN = re.compile(r"cand-[0-9]{4,}")


class StoreError(ValueError):
    """History cannot be safely recovered; preserve it for manual inspection."""


@contextmanager
def store_error_boundary(message: str):
    """恢复边界:非 Store 错误按 ``message`` 统一包装,StoreError 原样穿透。

    StoreError 继承 ValueError,若与 ValueError 一起被兜底捕获,同一结论会被
    二次包装成双层恢复指引(S7)。各恢复入口共用本上下文管理器,不各写一份
    "先 re-raise" 的拷贝。
    """
    try:
        yield
    except StoreError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise StoreError(f"{message}: {exc}") from exc


def _decode(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"重复键 {key}")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("工件必须为 object")
    return clone_json_value(value, "持久化工件")


def _version(value: dict, field: str, expected: int) -> None:
    if type(value.get(field)) is not int or value[field] != expected:
        raise StoreError(f"{field} 不兼容；请创建新运行世代，保留原目录供检查")


def read_json_object(
    path: Path, label: str, *, guidance: str = "请检查原运行目录",
) -> dict:
    """读取 JSON 文件并要求顶层为 object;损坏按 Store 语义拒绝。

    世代 manifest/run_state、活动锁、recon 检查点、Candidate Store 等运行
    元数据的共用解码形状;结构/版本校验仍归各调用方,此处只保证"能拿到
    一个 object"。guidance 是损坏时的下一步动作指引(错误文案即文档)。
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError, OSError) as exc:
        raise StoreError(f"{label}损坏;{guidance}: {path} ({exc})") from exc
    if not isinstance(payload, dict):
        raise StoreError(f"{label}必须是 JSON object;{guidance}: {path}")
    return payload


def sync_directory(directory: Path) -> None:
    """On POSIX, persist directory entries as well as file contents."""
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def atomic_json(path: Path, payload: dict, *, exclusive: bool = False) -> None:
    """Flush before publication; exclusive Evidence must never replace an existing file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            # Same-directory hard link publishes complete bytes atomically and
            # fails if the immutable Evidence name already exists.
            os.link(temporary_path, path)
        else:
            os.replace(temporary_path, path)
        sync_directory(path.parent)
    finally:
        temporary_path.unlink(missing_ok=True)


class InvestigationStore:
    """One Candidate's durable history; callers save only fully validated states."""

    def __init__(self, run_dir: Path, candidate_id: str, *, root: str = "investigations"):
        if not CANDIDATE_ID_PATTERN.fullmatch(candidate_id):
            raise StoreError("非法 Candidate ID；请检查运行目录")
        # root 区分事件树归属:investigations(Analysis)或 verifications(独立复核)。
        self.directory = Path(run_dir) / root / candidate_id
        self.events_path = self.directory / "events.jsonl"
        self.snapshot_path = self.directory / "state.json"
        self._seq = 0
        self._state: dict | None = None
        self._recover()

    def _recover(self) -> None:
        snapshot = None
        if self.snapshot_path.exists():
            try:
                snapshot = _decode(self.snapshot_path.read_bytes())
            except (ValueError, UnicodeError) as exc:
                raise StoreError(f"快照损坏；请检查原运行目录: {exc}") from exc
            _version(snapshot, "schema_version", SCHEMA_VERSION)
            if (type(snapshot.get("last_event_seq")) is not int
                    or snapshot["last_event_seq"] < 1
                    or not isinstance(snapshot.get("state"), dict)):
                raise StoreError("快照 seq/state 非法；请检查原运行目录")
            self._seq = snapshot["last_event_seq"]
            self._state = snapshot["state"]
        raw = self.events_path.read_bytes() if self.events_path.exists() else b""
        lines = raw.splitlines(keepends=True)
        events = []
        tail = b""
        for index, line in enumerate(lines):
            try:
                event = _decode(line)
            except (ValueError, UnicodeError) as exc:
                if index == len(lines) - 1 and not line.endswith(b"\n"):
                    tail = line
                    break
                raise StoreError(f"事件 {index + 1} 损坏；拒绝跳过，请检查日志: {exc}") from exc
            _version(event, "event_version", EVENT_VERSION)
            if type(event.get("seq")) is not int or event["seq"] != index + 1:
                raise StoreError(f"事件 seq 不连续；请检查事件 {index + 1}")
            if not isinstance(event.get("state"), dict) or not isinstance(event.get("kind"), str):
                raise StoreError(f"事件 {index + 1} 结构损坏；请检查日志")
            events.append(event)
        if self._seq > len(events):
            raise StoreError("快照超出权威事件历史；请检查原运行目录")
        if snapshot and events[self._seq - 1]["state"] != self._state:
            raise StoreError("快照与权威事件历史不一致；请检查原运行目录")
        # Verify all history before modifying a torn tail, including events already
        # represented by the snapshot. Never silently skip middle corruption.
        if tail:
            descriptor, quarantine = tempfile.mkstemp(prefix="events.tail-", suffix=".bin", dir=self.directory)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(tail)
                handle.flush()
                os.fsync(handle.fileno())
            sync_directory(self.directory)
            with self.events_path.open("r+b") as handle:
                handle.truncate(len(raw) - len(tail))
                handle.flush()
                os.fsync(handle.fileno())
            warnings.warn(f"事件尾部不完整，已隔离至 {quarantine}", RuntimeWarning)
        elif raw and not raw.endswith(b"\n"):
            with self.events_path.open("ab") as handle:
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        for event in events[self._seq:]:
            self._state = event["state"]
            self._seq = event["seq"]

    def load(self) -> dict | None:
        return deepcopy(self._state)

    def save(self, kind: str, state: dict) -> None:
        state = clone_json_value(state, "Investigation State")
        if not isinstance(state, dict) or not isinstance(kind, str) or not kind:
            raise StoreError("事件必须有非空 kind 与 object state")
        event = {"event_version": EVENT_VERSION, "seq": self._seq + 1,
                 "kind": kind, "state": state}
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        sync_directory(self.directory)
        self._seq += 1
        self._state = state
        atomic_json(self.snapshot_path, {
            "schema_version": SCHEMA_VERSION,
            "last_event_seq": self._seq,
            "state": state,
        })

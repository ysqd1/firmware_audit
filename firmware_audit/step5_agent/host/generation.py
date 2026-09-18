"""运行世代与驱动元状态:manifest 只读身份 + run_state 原子投影。

一个工作区按 ``generations/gen-XXXX/`` 组织世代;世代目录本身就是三角色
runner 的 run_dir,机器工件布局零改动。manifest 在创建时写入后不再修改
(封存语义归票 12);``run_state.json`` 是驱动自己的元状态投影,原子替换。

run_state.status 词汇:
- ``running``:未完成,默认恢复目标(含停止后仍可续跑的预算/中断现场);
- ``finalizing``:处理责任全部收束,等待票 12 的报告与封存;
- ``completed``:已封存(票 12 写入),只读,拒绝继续;
- ``abandoned``:被显式 force 顶替,不再默认恢复。
"""
from __future__ import annotations

import re
import time
from pathlib import Path

from .locking import hostname as default_hostname
from .store import StoreError, atomic_json, read_json_object

MANIFEST_SCHEMA_VERSION = 1
RUN_STATE_SCHEMA_VERSION = 1

GENERATION_PATTERN = re.compile(r"gen-[0-9]{4,}")
RUN_STATUSES = ("running", "finalizing", "completed", "abandoned")


def generations_root(root: Path) -> Path:
    return Path(root) / "generations"


def read_manifest(gen_dir: Path) -> dict:
    """读取并校验世代 manifest;版本不兼容引导新建世代(票 11 AC5)。"""
    gen_dir = Path(gen_dir)
    manifest_path = gen_dir / "manifest.json"
    if not manifest_path.exists():
        raise StoreError(f"世代目录缺少 manifest: {gen_dir}；请检查原运行目录")
    payload = read_json_object(manifest_path, "世代 manifest")
    generation = payload.get("generation")
    if (type(payload.get("schema_version")) is not int
            or payload["schema_version"] != MANIFEST_SCHEMA_VERSION):
        raise StoreError(
            "manifest schema_version 不兼容；请创建新运行世代，保留原目录供检查")
    if (not isinstance(generation, str)
            or generation != gen_dir.name
            or not GENERATION_PATTERN.fullmatch(generation)):
        raise StoreError("manifest 世代身份损坏；请检查原运行目录")
    return payload


def list_generations(root: Path) -> list[tuple[str, Path]]:
    """按世代序升序返回 (名字, 目录);只接纳 manifest 完整可读的世代。

    缺 manifest 的 gen-* 目录按损坏拒绝而不是静默跳过——静默跳过会让
    "恢复唯一未完成世代"的判定漏掉一个真实存在过的运行。
    """
    root = generations_root(root)
    if not root.is_dir():
        return []
    found: list[tuple[str, Path]] = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or not GENERATION_PATTERN.fullmatch(directory.name):
            continue
        read_manifest(directory)
        found.append((directory.name, directory))
    return found


def create_generation(
    root: Path, *, hostname: str | None = None, now: float | None = None,
) -> tuple[str, Path]:
    """创建下一世代并写入只读 manifest;序号取自目录名最大值 + 1。"""
    root = generations_root(root)
    root.mkdir(parents=True, exist_ok=True)
    highest = 0
    for directory in root.iterdir():
        match = GENERATION_PATTERN.fullmatch(directory.name) if directory.is_dir() else None
        if match:
            highest = max(highest, int(directory.name[len("gen-"):]))
    name = f"gen-{highest + 1:04d}"
    gen_dir = root / name
    gen_dir.mkdir()
    atomic_json(gen_dir / "manifest.json", {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generation": name,
        "created_at": float(now if now is not None else _wall_clock()),
        "hostname": hostname if hostname is not None else default_hostname(),
    })
    save_run_state(gen_dir, status="running")
    return name, gen_dir


def _wall_clock() -> float:
    return time.time()


def load_run_state(gen_dir: Path) -> dict | None:
    """读取 run_state;缺失返回 None(由调用方按新建 running 处理)。"""
    path = Path(gen_dir) / "run_state.json"
    if not path.exists():
        return None
    payload = read_json_object(path, "run_state")
    if (type(payload.get("schema_version")) is not int
            or payload["schema_version"] != RUN_STATE_SCHEMA_VERSION
            or payload.get("status") not in RUN_STATUSES
            or not (payload.get("phase") is None or isinstance(payload.get("phase"), str))
            or not (payload.get("stop_reason") is None
                    or isinstance(payload.get("stop_reason"), str))):
        raise StoreError("run_state 结构或版本损坏；请检查原运行目录")
    return payload


def save_run_state(
    gen_dir: Path, *, status: str, phase: str | None = None,
    stop_reason: str | None = None,
) -> dict:
    """原子写 run_state 投影;status 枚举失约按 Store 语义拒绝。"""
    if status not in RUN_STATUSES:
        raise StoreError(f"run_state.status 非法: {status!r}；请检查驱动状态写入")
    payload = {
        "schema_version": RUN_STATE_SCHEMA_VERSION,
        "status": status,
        "phase": phase,
        "stop_reason": stop_reason,
    }
    atomic_json(Path(gen_dir) / "run_state.json", payload)
    return payload

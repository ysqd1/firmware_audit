"""Integrity receipts for interrupted Ghidra calls (ADR-0012).

Legacy C-only caches remain readable by ordinary calls, but cannot prove that
all three artifacts belong to the current input. A receipt is published only
after a complete generation, with input and artifact digests. It is a cache
validation aid, not Investigation history or Evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

from .base import resolve_within

SIDECAR_SUFFIXES = (".c", ".imports.json", ".strings.json")
CACHE_SCHEMA_VERSION = 1


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(analysis_dir: Path, rel: str, input_digest: str) -> dict:
    artifacts = []
    for suffix in SIDECAR_SUFFIXES:
        path = resolve_within(analysis_dir, f"{rel}{suffix}")
        if path is None or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("Ghidra 缓存三件套缺失")
        if suffix.endswith(".json"):
            value = json.loads(path.read_text(encoding="utf-8"))
            expected = list if suffix == ".imports.json" else dict
            if not isinstance(value, expected):
                raise ValueError("Ghidra 边车 JSON 结构无效")
        artifacts.append({"path": f"analysis/{rel}{suffix}",
                          "size": path.stat().st_size, "digest": sha256_of(path)})
    return {"schema_version": CACHE_SCHEMA_VERSION, "input_digest": input_digest,
            "artifacts": artifacts}


def validated_manifest(analysis_dir: Path, rel: str, input_digest: str) -> dict | None:
    """Missing, malformed, stale, or incomplete cache is a miss, never a hit."""
    path = resolve_within(analysis_dir, f"{rel}.cache.json")
    if path is None:
        return None
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        actual = _manifest(analysis_dir, rel, input_digest)
        if (isinstance(receipt, dict) and type(receipt.get("schema_version")) is int
                and receipt == actual):
            return actual
    except (OSError, ValueError):
        pass
    return None


def publish_receipt(analysis_dir: Path, rel: str, input_digest: str) -> None:
    """Flush artifact contents before atomically publishing their receipt."""
    manifest = _manifest(analysis_dir, rel, input_digest)
    path = resolve_within(analysis_dir, f"{rel}.cache.json")
    if path is None:
        raise ValueError("非法 Ghidra 缓存路径")
    for suffix in SIDECAR_SUFFIXES:
        artifact = resolve_within(analysis_dir, f"{rel}{suffix}")
        if artifact is None:
            raise ValueError("非法 Ghidra 边车路径")
        with artifact.open("rb") as handle:
            os.fsync(handle.fileno())
    descriptor, temporary = tempfile.mkstemp(prefix=".cache-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, ensure_ascii=False, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)

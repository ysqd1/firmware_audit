"""Evidence 身份、完整性、落盘与 Observation View 的内部深模块。

Host 循环只需在工具执行前 ``reserve``，并在得到 ToolResult 后 ``record``。
本模块保证每个逻辑调用身份独立、原文 digest 可复算、Evidence 文件不可覆盖，
以及送入 Session 的视图有界；恢复时按 Store 的权威引用校验身份与 digest。
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from ..providers.tools.base import MAX_TEXT_CHARS, ToolResult, truncate_text
from .json_values import JsonValueError, clone_json_value
from .store import StoreError, atomic_json

EVIDENCE_SCHEMA_VERSION = 1
# Evidence Index 摘要与协议 decision summary 共用 500 字可审阅粒度；原文不受此限。
SUMMARY_LIMIT = 500
# 原始 ToolResult 允许达到默认 Observation View 的 1024 倍，既保留常见扫描
# 全文又给内存/磁盘写入设硬上界；更大产物按 ADR-0012 必须由工具独立落盘。
DEFAULT_TOOL_RESULT_LIMIT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class EvidenceReference:
    """指向一次真实工具 Observation 的稳定 Evidence Reference。"""

    evidence_id: str
    tool: str
    arguments: dict[str, Any]
    summary: str
    location: str
    digest: str
    candidate_id: str
    investigation_id: str
    sequence: int


@dataclass(frozen=True)
class _EvidenceSlot:
    """执行工具前预留的运行内 Evidence 身份与不可变位置。"""

    evidence_id: str
    location: Path
    sequence: int


def _observation_text(result: ToolResult) -> str:
    if result.raw != "":
        return result.raw
    if result.text != "":
        return result.text
    if result.ok:
        return ""
    return f"Error: {result.error or '工具执行失败且未提供错误详情'}"


def _summary(observation: str) -> str:
    stripped = observation.strip()
    if not stripped:
        return "(empty Observation)"
    first_line = stripped.splitlines()[0]
    return first_line if len(first_line) <= SUMMARY_LIMIT else first_line[:SUMMARY_LIMIT]


class EvidenceRecorder:
    """运行内 Evidence 序列及其不可变文件的唯一写入者。"""

    def __init__(
        self,
        run_dir: Path,
        *,
        observation_view_limit: int = MAX_TEXT_CHARS,
        tool_result_limit_bytes: int = DEFAULT_TOOL_RESULT_LIMIT_BYTES,
    ):
        if observation_view_limit < 1:
            raise ValueError("observation_view_limit 必须大于 0")
        if tool_result_limit_bytes < 1:
            raise ValueError("tool_result_limit_bytes 必须大于 0")
        self.run_dir = Path(run_dir)
        self.observation_view_limit = observation_view_limit
        self.tool_result_limit_bytes = tool_result_limit_bytes
        self._sequence = 0

    def reserve(self, candidate_id: str) -> _EvidenceSlot:
        """在真实工具调用前分配身份，并提前拒绝既有不可变位置。"""
        sequence = self._sequence + 1
        evidence_id = f"ev-{sequence:06d}"
        location = (
            Path("investigations")
            / candidate_id
            / "evidence"
            / f"{evidence_id}.json"
        )
        evidence_path = self.run_dir / location
        if evidence_path.exists():
            raise FileExistsError(f"Evidence 已存在且不可覆盖: {evidence_path}")
        self._sequence = sequence
        return _EvidenceSlot(evidence_id, location, sequence)

    def restore_sequence(self, sequence: int) -> None:
        """Restore the high-water mark from authoritative Investigation events."""
        self._sequence = max(self._sequence, sequence)

    def seed_sequence_from_files(self) -> None:
        """抬升运行内 Evidence 序列至盘上既有不可变文件的最高水位。

        Recon 阶段没有事件投影,唯一持久的序列消耗痕迹是 Evidence 文件本身;
        新 Recorder 实例据此播种,保证跨实例/跨进程的 Evidence ID 唯一,
        绝不重号覆盖既有不可变文件。
        """
        for path in self.run_dir.glob("investigations/*/evidence/ev-*.json"):
            try:
                sequence = int(path.name[len("ev-"):-len(".json")])
            except ValueError:
                continue
            self.restore_sequence(sequence)

    def restore_slot(self, candidate_id: str, sequence: int) -> _EvidenceSlot:
        self.restore_sequence(sequence)
        evidence_id = f"ev-{sequence:06d}"
        return _EvidenceSlot(evidence_id, Path("investigations") / candidate_id /
                             "evidence" / f"{evidence_id}.json", sequence)

    def recover(self, slot: _EvidenceSlot) -> tuple[EvidenceReference, str] | None:
        """Accept only a complete, schema-compatible Observation with a valid digest."""
        path = self.run_dir / slot.location
        if not path.exists():
            return None
        try:
            payload = clone_json_value(json.loads(path.read_text(encoding="utf-8")), "Evidence")
            if type(payload.get("schema_version")) is not int or payload["schema_version"] != EVIDENCE_SCHEMA_VERSION:
                raise StoreError("Evidence schema 不兼容；请创建新运行世代")
            reference = EvidenceReference(**{key: payload[key] for key in EvidenceReference.__dataclass_fields__})
            result = ToolResult(**payload["tool_result"])
            observation = payload["observation"]
            if (reference.evidence_id != slot.evidence_id or reference.sequence != slot.sequence
                    or reference.location != slot.location.as_posix()
                    or reference.candidate_id != slot.location.parts[1]
                    or observation != _observation_text(result)
                    or reference.digest != hashlib.sha256(observation.encode("utf-8")).hexdigest()):
                raise ValueError("Evidence 身份或 digest 不匹配")
            return reference, self._observation_view(reference, observation, result.ok, result.error)
        except (ValueError, KeyError, TypeError) as exc:
            raise StoreError(f"Evidence 无法恢复；请检查原工件或创建新运行世代: {exc}") from exc

    def record(
        self,
        slot: _EvidenceSlot,
        *,
        candidate_id: str,
        investigation_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        result: ToolResult,
    ) -> tuple[EvidenceReference, str]:
        """完整保存合约内结果，并返回 Reference 与有界 Observation View。"""
        result, tool_result = self._bounded_tool_result(result)
        observation = _observation_text(result)
        digest = hashlib.sha256(observation.encode("utf-8")).hexdigest()
        reference = EvidenceReference(
            evidence_id=slot.evidence_id,
            tool=tool_name,
            arguments=deepcopy(arguments),
            summary=_summary(observation),
            location=slot.location.as_posix(),
            digest=digest,
            candidate_id=candidate_id,
            investigation_id=investigation_id,
            sequence=slot.sequence,
        )
        payload = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            **asdict(reference),
            "observation": observation,
            "tool_result": tool_result,
        }
        evidence_path = self.run_dir / slot.location
        # Evidence 原文写入后不可修改；恢复编号来自权威事件，碰撞须通过
        # recover 校验接纳，绝不能静默覆盖。
        atomic_json(evidence_path, payload, exclusive=True)
        error = result.error if not result.ok else None
        return reference, self._observation_view(reference, observation, result.ok, error)

    def _bounded_tool_result(self, result: ToolResult) -> tuple[ToolResult, dict[str, Any]]:
        """完整接纳合约内结果；失约结果转为小型、可追溯的失败结果。"""
        invalid_fields: list[str] = []
        if not isinstance(result.ok, bool):
            invalid_fields.append("ok:bool")
        if not isinstance(result.text, str):
            invalid_fields.append("text:str")
        if not isinstance(result.raw, str):
            invalid_fields.append("raw:str")
        if result.error is not None and not isinstance(result.error, str):
            invalid_fields.append("error:str|null")
        if (
            not isinstance(result.elapsed, (int, float))
            or isinstance(result.elapsed, bool)
            or (isinstance(result.elapsed, float) and not math.isfinite(result.elapsed))
        ):
            invalid_fields.append("elapsed:number")
        if result.data is not None and not isinstance(result.data, (dict, list)):
            invalid_fields.append("data:object|array|null")
        if invalid_fields:
            return self._failure_result(
                "ToolResult 字段类型失约: " + ", ".join(invalid_fields)
            )

        try:
            # Do not recursively copy unvalidated adapter data with asdict:
            # strict JSON validation must see cycles and unsupported values first.
            tool_result = clone_json_value({
                "ok": result.ok,
                "text": result.text,
                "raw": result.raw,
                "data": result.data,
                "error": result.error,
                "elapsed": result.elapsed,
            }, "ToolResult")
            encoded_result = json.dumps(
                tool_result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except JsonValueError as exc:
            return self._failure_result(
                f"ToolResult 不符合 JSON 合约: {exc}",
            )
        if len(encoded_result) <= self.tool_result_limit_bytes:
            return result, tool_result

        return self._failure_result(
            (
                f"ToolResult 共 {len(encoded_result)} bytes，超过 Host 上界 "
                f"{self.tool_result_limit_bytes} bytes；"
                "请让工具把大型产物独立落盘并返回指针"
            ),
            data={
                "returned_bytes": len(encoded_result),
                "returned_sha256": hashlib.sha256(encoded_result).hexdigest(),
            },
            elapsed=result.elapsed,
        )

    @staticmethod
    def _failure_result(
        error: str,
        *,
        data: dict[str, Any] | None = None,
        elapsed: float = 0.0,
    ) -> tuple[ToolResult, dict[str, Any]]:
        failure = ToolResult(
            ok=False,
            text="",
            data=data,
            error=error,
            elapsed=elapsed,
        )
        return failure, clone_json_value(asdict(failure), "bounded ToolResult failure")

    def _observation_view(
        self,
        reference: EvidenceReference,
        observation: str,
        ok: bool,
        error: str | None,
    ) -> str:
        body = truncate_text(observation, self.observation_view_limit)
        status = "Tool status: ok\n" if ok else (
            f"Tool status: error; {error or '工具执行失败且未提供错误详情'}\n"
        )
        return (
            f"Observation View [{reference.evidence_id}]\n{status}{body}\n"
            f"Evidence Reference: {reference.evidence_id}; "
            f"original={reference.location}; sha256={reference.digest}"
        )

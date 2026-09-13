"""Host 驱动的单 Candidate Analysis tracer。

这是 ADR-0012 新控制层的第一条最小纵向路径：调用方注册 Candidate 后，只需
提供逐步 Agent Session，Host 便负责完整 Proposal 守卫、工具执行、Evidence
留存、Observation View 回传与主动关闭。当前只保存本进程内的 Investigation
状态；追加事件、原子快照和崩溃恢复属于后续持久化工单。

模块的公开 interface 刻意只有 ``add_candidate``、``investigation_for`` 和
``run_analysis``。Session 与工具都是注入的 adapter，测试和生产调用走同一 seam。
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any

from ..providers.tools import ToolAuthorizationError, authorize_tool
from ..providers.tools.base import (
    MAX_TEXT_CHARS,
    ToolResult,
    truncate_text,
    validate_params,
)
from .session import ActionProposal, FinalProposal, ProposalError, parse_proposal

EVIDENCE_SCHEMA_VERSION = 1
SUMMARY_LIMIT = 500
DEFAULT_TOOL_RESULT_LIMIT_BYTES = 16 * 1024 * 1024


class ProposalRejectedError(ValueError):
    """Proposal 未通过完整守卫；本轮不得产生 Host 或工具副作用。"""


@dataclass(frozen=True)
class Candidate:
    """已分配运行内稳定身份的合法 Candidate。"""

    candidate_id: str
    proposal: dict[str, Any]


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


@dataclass
class Investigation:
    """单个 Candidate 的当前 Investigation 投影。"""

    investigation_id: str
    candidate_id: str
    lifecycle_status: str = "queued"
    disposition: str | None = None
    stop_reason: str | None = None
    closure_reason: str | None = None
    closure_evidence: tuple[str, ...] = ()
    state: dict[str, Any] = field(default_factory=dict)
    evidence: list[EvidenceReference] = field(default_factory=list)


def _json_clone(value: Any, label: str) -> Any:
    """校验并复制纯 JSON 值，同时让 object key 顺序规范化。"""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ProposalRejectedError(f"{label} 必须是标准 JSON 值: {exc}") from exc


def _observation_text(result: ToolResult) -> str:
    """取得 Evidence digest 与 Observation View 共用的原始字面文本。"""
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


class HostAnalysisTracer:
    """Host 唯一循环：逐 Proposal 推进相互隔离的 Analysis Investigation。"""

    def __init__(
        self,
        run_dir: Path,
        tools: dict[str, object],
        *,
        observation_view_limit: int = MAX_TEXT_CHARS,
        tool_result_limit_bytes: int = DEFAULT_TOOL_RESULT_LIMIT_BYTES,
    ):
        if observation_view_limit < 1:
            raise ValueError("observation_view_limit 必须大于 0")
        if tool_result_limit_bytes < 1:
            raise ValueError("tool_result_limit_bytes 必须大于 0")
        self.run_dir = Path(run_dir)
        self.tools = dict(tools)
        self.observation_view_limit = observation_view_limit
        self.tool_result_limit_bytes = tool_result_limit_bytes
        self._candidate_seq = 0
        self._evidence_seq = 0
        self._candidates: dict[str, Candidate] = {}
        self._investigations: dict[str, Investigation] = {}
        self._claimed_sessions: list[object] = []

    def add_candidate(self, proposal: dict[str, Any]) -> Candidate:
        """分配 Candidate ID，并一一创建隔离的 queued Investigation。"""
        if not isinstance(proposal, dict):
            raise ValueError("Candidate proposal 必须是 JSON object")
        normalized = _json_clone(proposal, "Candidate proposal")
        self._candidate_seq += 1
        sequence = self._candidate_seq
        candidate = Candidate(f"cand-{sequence:04d}", normalized)
        investigation = Investigation(f"inv-{sequence:04d}", candidate.candidate_id)
        self._candidates[candidate.candidate_id] = candidate
        self._investigations[candidate.candidate_id] = investigation
        return deepcopy(candidate)

    def investigation_for(self, candidate_id: str) -> Investigation:
        """返回只供调用方检查的快照，避免外部改写 Host 当前状态。"""
        try:
            return deepcopy(self._investigations[candidate_id])
        except KeyError as exc:
            raise KeyError(f"未知 Candidate ID: {candidate_id}") from exc

    def run_analysis(self, candidate_id: str, session) -> Investigation:
        """驱动一个 Analysis Session，直到其主动关闭 Investigation。"""
        investigation = self._current_investigation(candidate_id)
        if getattr(session, "role", None) != "analysis":
            raise ValueError("HostAnalysisTracer 只接受 role='analysis' 的 Agent Session")
        if any(claimed is session for claimed in self._claimed_sessions):
            raise ValueError("每个 Candidate 必须使用独立 Agent Session，不得跨调查复用")
        self._claimed_sessions.append(session)

        input_message: str | None = self._candidate_context(candidate_id)
        while True:
            proposal = self._validated_proposal(session.step(input_message))
            if isinstance(proposal, ActionProposal):
                state_delta, arguments, tool = self._validate_action(proposal)
                slot = self._reserve_evidence(investigation)
                result = self._execute_tool(tool, arguments)
                evidence, input_message = self._record_evidence(
                    investigation,
                    proposal.tool,
                    arguments,
                    result,
                    slot,
                )
                investigation.lifecycle_status = "investigating"
                investigation.state.update(state_delta)
                investigation.evidence.append(evidence)
                continue
            if isinstance(proposal, FinalProposal):
                if proposal.kind != "close_investigation":
                    raise ProposalRejectedError(
                        "单 Candidate Analysis tracer 当前只接受 close_investigation"
                    )
                state_delta, closure_reason, closure_evidence = self._validate_close(
                    proposal.state_delta,
                    investigation,
                )
                investigation.state.update(state_delta)
                investigation.lifecycle_status = "finished"
                investigation.disposition = "closed"
                investigation.stop_reason = "decisive_refutation"
                investigation.closure_reason = closure_reason
                investigation.closure_evidence = closure_evidence
                return deepcopy(investigation)

    def _candidate_context(self, candidate_id: str) -> str:
        candidate = self._candidates[candidate_id]
        payload = {
            "candidate_id": candidate.candidate_id,
            "investigation_id": self._investigations[candidate_id].investigation_id,
            "proposal": candidate.proposal,
        }
        return (
            "Analysis Candidate（本 Session 只调查此 Candidate）：\n"
            + json.dumps(payload, ensure_ascii=False, sort_keys=True)
        )

    @staticmethod
    def _validated_proposal(proposal: object) -> ActionProposal | FinalProposal:
        """不信任 Session adapter：按纯 JSON 协议重新校验整份 Proposal。"""
        if isinstance(proposal, ProposalError):
            raise ProposalRejectedError(
                f"Agent Proposal 校验失败: {proposal.feedback_message()}"
            )
        if isinstance(proposal, ActionProposal):
            next_value = {
                "kind": proposal.kind,
                "tool": proposal.tool,
                "arguments": proposal.arguments,
            }
        elif isinstance(proposal, FinalProposal):
            next_value = {"kind": proposal.kind}
        else:
            raise ProposalRejectedError(
                f"Agent Session 返回了未知 Proposal 类型: {type(proposal).__name__}"
            )
        try:
            raw = json.dumps({
                "decision_summary": proposal.decision_summary,
                "state_delta": proposal.state_delta,
                "next": next_value,
            }, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ProposalRejectedError(f"Agent Proposal 必须是标准 JSON: {exc}") from exc
        checked = parse_proposal(raw, "analysis")
        if isinstance(checked, ProposalError):
            raise ProposalRejectedError(
                f"Agent Proposal 校验失败: {checked.feedback_message()}"
            )
        return checked

    def _current_investigation(self, candidate_id: str) -> Investigation:
        try:
            investigation = self._investigations[candidate_id]
        except KeyError as exc:
            raise KeyError(f"未知 Candidate ID: {candidate_id}") from exc
        if investigation.lifecycle_status != "queued":
            raise ValueError(
                f"Investigation {investigation.investigation_id} 已处于 "
                f"{investigation.lifecycle_status}，不可重新运行"
            )
        return investigation

    def _validate_action(
        self,
        proposal: ActionProposal,
    ) -> tuple[dict[str, Any], dict[str, Any], object]:
        """整份 action 通过 Host 守卫后才把任何 delta 交给循环应用。"""
        state_delta = self._validate_state_delta(proposal.state_delta)
        arguments = _json_clone(proposal.arguments, "tool arguments")
        try:
            contract = authorize_tool("analysis", proposal.tool)
        except ToolAuthorizationError as exc:
            raise ProposalRejectedError(str(exc)) from exc
        checked_arguments, argument_error = validate_params(
            contract.tool_type.params,
            arguments,
        )
        if argument_error is not None:
            raise ProposalRejectedError(
                f"工具 {proposal.tool} 参数未通过接口契约: {argument_error}"
            )
        assert checked_arguments is not None
        arguments = _json_clone(checked_arguments, "normalized tool arguments")
        tool = self.tools.get(proposal.tool)
        if tool is None:
            raise ProposalRejectedError(
                f"Analysis 工具 {proposal.tool!r} 已授权但未由 Host 配置"
            )
        if not callable(getattr(tool, "execute", None)):
            raise TypeError(f"工具 adapter {proposal.tool!r} 缺少 execute")
        return state_delta, arguments, tool

    @staticmethod
    def _validate_state_delta(state_delta: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(state_delta, dict):
            raise ProposalRejectedError("state_delta 必须是 JSON object")
        return _json_clone(state_delta, "state_delta")

    @classmethod
    def _validate_close(
        cls,
        state_delta: dict[str, Any],
        investigation: Investigation,
    ) -> tuple[dict[str, Any], str, tuple[str, ...]]:
        """关闭必须说明决定性反证，并只引用本 Investigation 的 Evidence。"""
        remaining = cls._validate_state_delta(state_delta)
        reason = remaining.pop("closure_reason", None)
        refs = remaining.pop("evidence_refs", None)
        if not isinstance(reason, str) or not reason.strip():
            raise ProposalRejectedError(
                "close_investigation 要求 state_delta.closure_reason 为非空字符串"
            )
        if (
            not isinstance(refs, list)
            or not refs
            or any(not isinstance(item, str) or not item for item in refs)
        ):
            raise ProposalRejectedError(
                "close_investigation 要求 state_delta.evidence_refs 为非空 Evidence ID 数组"
            )
        owned = {reference.evidence_id for reference in investigation.evidence}
        unknown = [evidence_id for evidence_id in refs if evidence_id not in owned]
        if unknown:
            raise ProposalRejectedError(
                "close_investigation 引用了不属于当前 Investigation 的 Evidence: "
                + ", ".join(unknown)
            )
        return remaining, reason.strip(), tuple(refs)

    def _reserve_evidence(self, investigation: Investigation) -> _EvidenceSlot:
        """在真实工具调用前分配身份，并提前拒绝既有不可变位置。"""
        sequence = self._evidence_seq + 1
        evidence_id = f"ev-{sequence:06d}"
        location = (
            Path("investigations")
            / investigation.candidate_id
            / "evidence"
            / f"{evidence_id}.json"
        )
        evidence_path = self.run_dir / location
        if evidence_path.exists():
            raise FileExistsError(f"Evidence 已存在且不可覆盖: {evidence_path}")
        self._evidence_seq = sequence
        return _EvidenceSlot(evidence_id, location, sequence)

    @staticmethod
    def _execute_tool(tool: object, arguments: dict[str, Any]) -> ToolResult:
        """工具 adapter 失约也转为失败 ToolResult，保留本次逻辑调用身份。"""
        try:
            result = tool.execute(**arguments)
        except Exception as exc:
            return ToolResult(
                ok=False,
                text="",
                error=f"工具 adapter 抛出 {type(exc).__name__}: {exc}",
            )
        if isinstance(result, ToolResult):
            return result
        return ToolResult(
            ok=False,
            text="",
            error=f"工具 adapter 必须返回 ToolResult，实际为 {type(result).__name__}",
        )

    def _bounded_tool_result(self, result: ToolResult) -> tuple[ToolResult, dict[str, Any]]:
        """完整接纳合约内结果；失约结果转为小型、可追溯的失败结果。"""
        try:
            tool_result = _json_clone(asdict(result), "ToolResult")
            encoded_result = json.dumps(
                tool_result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except ProposalRejectedError as exc:
            failure = ToolResult(
                ok=False,
                text="",
                error=f"ToolResult 不符合 JSON 合约: {exc}",
                elapsed=result.elapsed,
            )
            return failure, _json_clone(asdict(failure), "bounded ToolResult failure")
        if len(encoded_result) <= self.tool_result_limit_bytes:
            return result, tool_result

        failure = ToolResult(
            ok=False,
            text="",
            data={
                "returned_bytes": len(encoded_result),
                "returned_sha256": hashlib.sha256(encoded_result).hexdigest(),
            },
            error=(
                f"ToolResult 共 {len(encoded_result)} bytes，超过 Host 上界 "
                f"{self.tool_result_limit_bytes} bytes；"
                "请让工具把大型产物独立落盘并返回指针"
            ),
            elapsed=result.elapsed,
        )
        return failure, _json_clone(asdict(failure), "bounded ToolResult failure")

    def _record_evidence(
        self,
        investigation: Investigation,
        tool_name: str,
        arguments: dict[str, Any],
        result: ToolResult,
        slot: _EvidenceSlot,
    ) -> tuple[EvidenceReference, str]:
        """每次逻辑调用都分配新身份；digest 相同也写独立 Evidence。"""
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
            candidate_id=investigation.candidate_id,
            investigation_id=investigation.investigation_id,
            sequence=slot.sequence,
        )
        payload = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            **asdict(reference),
            "observation": observation,
            "tool_result": tool_result,
        }
        evidence_path = self.run_dir / slot.location
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        # Evidence 原文写入后不可修改；恢复编号由后续 Store 工单负责，当前
        # tracer 遇到碰撞必须显式失败，绝不能用 write_text 静默覆盖。
        with evidence_path.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            )
        error = result.error if not result.ok else None
        view = self._observation_view(reference, observation, error)
        return reference, view

    def _observation_view(
        self,
        reference: EvidenceReference,
        observation: str,
        error: str | None,
    ) -> str:
        body = truncate_text(observation, self.observation_view_limit)
        status = f"Tool status: error; {error}\n" if error else "Tool status: ok\n"
        return (
            f"Observation View [{reference.evidence_id}]\n{status}{body}\n"
            f"Evidence Reference: {reference.evidence_id}; "
            f"original={reference.location}; sha256={reference.digest}"
        )

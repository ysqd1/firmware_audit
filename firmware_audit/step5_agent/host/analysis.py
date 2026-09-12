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
from ..providers.tools.base import MAX_TEXT_CHARS, ToolResult, truncate_text
from .session import ActionProposal, FinalProposal, ProposalError

EVIDENCE_SCHEMA_VERSION = 1
SUMMARY_LIMIT = 500


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


@dataclass
class Investigation:
    """单个 Candidate 的当前 Investigation 投影。"""

    investigation_id: str
    candidate_id: str
    lifecycle_status: str = "queued"
    disposition: str | None = None
    stop_reason: str | None = None
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
    if result.ok:
        return result.raw if result.raw != "" else result.text
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
    ):
        if observation_view_limit < 1:
            raise ValueError("observation_view_limit 必须大于 0")
        self.run_dir = Path(run_dir)
        self.tools = dict(tools)
        self.observation_view_limit = observation_view_limit
        self._candidate_seq = 0
        self._evidence_seq = 0
        self._candidates: dict[str, Candidate] = {}
        self._investigations: dict[str, Investigation] = {}

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

        input_message: str | None = None
        while True:
            proposal = session.step(input_message)
            if isinstance(proposal, ProposalError):
                detail = proposal.feedback_message()
                raise ProposalRejectedError(f"Agent Proposal 校验失败: {detail}")
            if isinstance(proposal, ActionProposal):
                state_delta, arguments, tool = self._validate_action(proposal)
                result = tool.execute(**arguments)
                if not isinstance(result, ToolResult):
                    raise TypeError("工具 adapter 必须返回 ToolResult")
                evidence, input_message = self._record_evidence(
                    investigation,
                    proposal.tool,
                    arguments,
                    result,
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
                state_delta = self._validate_state_delta(proposal.state_delta)
                investigation.state.update(state_delta)
                investigation.lifecycle_status = "finished"
                investigation.disposition = "closed"
                investigation.stop_reason = "completed"
                return deepcopy(investigation)
            raise ProposalRejectedError(
                f"Agent Session 返回了未知 Proposal 类型: {type(proposal).__name__}"
            )

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
            authorize_tool("analysis", proposal.tool)
        except ToolAuthorizationError as exc:
            raise ProposalRejectedError(str(exc)) from exc
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

    def _record_evidence(
        self,
        investigation: Investigation,
        tool_name: str,
        arguments: dict[str, Any],
        result: ToolResult,
    ) -> tuple[EvidenceReference, str]:
        """每次逻辑调用都分配新身份；digest 相同也写独立 Evidence。"""
        self._evidence_seq += 1
        sequence = self._evidence_seq
        evidence_id = f"ev-{sequence:06d}"
        observation = _observation_text(result)
        digest = hashlib.sha256(observation.encode("utf-8")).hexdigest()
        location = (
            Path("investigations")
            / investigation.candidate_id
            / "evidence"
            / f"{evidence_id}.json"
        )
        reference = EvidenceReference(
            evidence_id=evidence_id,
            tool=tool_name,
            arguments=deepcopy(arguments),
            summary=_summary(observation),
            location=location.as_posix(),
            digest=digest,
            candidate_id=investigation.candidate_id,
            investigation_id=investigation.investigation_id,
            sequence=sequence,
        )
        payload = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            **asdict(reference),
            "tool_result": _json_clone(asdict(result), "ToolResult"),
        }
        evidence_path = self.run_dir / location
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        view = self._observation_view(reference, observation)
        return reference, view

    def _observation_view(self, reference: EvidenceReference, observation: str) -> str:
        body = truncate_text(observation, self.observation_view_limit)
        return (
            f"Observation View [{reference.evidence_id}]\n{body}\n"
            f"Evidence Reference: {reference.evidence_id}; "
            f"original={reference.location}; sha256={reference.digest}"
        )

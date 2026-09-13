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
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any

from ..providers.tools import ToolAuthorizationError, authorize_tool
from ..providers.tools.base import MAX_TEXT_CHARS, ToolResult, validate_params
from .evidence import (
    DEFAULT_TOOL_RESULT_LIMIT_BYTES,
    EvidenceRecorder,
    EvidenceReference,
)
from .json_values import JsonValueError, clone_json_value
from .session import ActionProposal, FinalProposal, ProposalError, parse_proposal

_PATH_ARGUMENTS = frozenset(("path", "file_ref", "directory", "target_dir"))


class ProposalRejectedError(ValueError):
    """Proposal 未通过完整守卫；本轮不得产生 Host 或工具副作用。"""


@dataclass(frozen=True)
class Candidate:
    """已分配运行内稳定身份的合法 Candidate。"""

    candidate_id: str
    proposal: dict[str, Any]


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
    """校验并复制纯 JSON 值，把共享边界错误转换为 Proposal 拒绝。"""
    try:
        return clone_json_value(value, label)
    except JsonValueError as exc:
        raise ProposalRejectedError(str(exc)) from exc


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
        self.tools = dict(tools)
        self._evidence_store = EvidenceRecorder(
            run_dir,
            observation_view_limit=observation_view_limit,
            tool_result_limit_bytes=tool_result_limit_bytes,
        )
        self._candidate_seq = 0
        self._candidates: dict[str, Candidate] = {}
        self._investigations: dict[str, Investigation] = {}
        self._claimed_sessions: list[tuple[object, str]] = []

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
        bound_candidate = next(
            (bound for claimed, bound in self._claimed_sessions if claimed is session),
            None,
        )
        if bound_candidate is not None and bound_candidate != candidate_id:
            raise ValueError("每个 Candidate 必须使用独立 Agent Session，不得跨调查复用")
        if bound_candidate is None:
            self._claimed_sessions.append((session, candidate_id))

        input_message: str | None = self._candidate_context(candidate_id)
        while True:
            proposal = self._validated_proposal(session.step(input_message))
            if isinstance(proposal, ActionProposal):
                state_delta, arguments, tool = self._validate_action(proposal)
                slot = self._evidence_store.reserve(investigation.candidate_id)
                result = self._execute_tool(tool, arguments)
                evidence, input_message = self._evidence_store.record(
                    slot,
                    candidate_id=investigation.candidate_id,
                    investigation_id=investigation.investigation_id,
                    tool_name=proposal.tool,
                    arguments=arguments,
                    result=result,
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
        payload = _json_clone({
            "decision_summary": proposal.decision_summary,
            "state_delta": proposal.state_delta,
            "next": next_value,
        }, "Agent Proposal")
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        checked = parse_proposal(raw, "analysis")
        if isinstance(checked, ProposalError):
            raise ProposalRejectedError(
                f"Agent Proposal 校验失败: {checked.feedback_message()}"
            )
        # parse_proposal 为重复键检测保留了内部 dict 子类；Host 边界已经在上面
        # 严格校验并复制 payload，这里用该纯 dict/list 副本承载已通过的 Proposal。
        if isinstance(checked, ActionProposal):
            return ActionProposal(
                decision_summary=checked.decision_summary,
                state_delta=payload["state_delta"],
                tool=checked.tool,
                arguments=payload["next"]["arguments"],
                kind=checked.kind,
            )
        return FinalProposal(
            decision_summary=checked.decision_summary,
            state_delta=payload["state_delta"],
            kind=checked.kind,
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
        arguments = self._normalize_arguments(
            contract.tool_type.params,
            checked_arguments,
        )
        tool = self.tools.get(proposal.tool)
        if tool is None:
            raise ProposalRejectedError(
                f"Analysis 工具 {proposal.tool!r} 已授权但未由 Host 配置"
            )
        if not callable(getattr(tool, "execute", None)):
            raise TypeError(f"工具 adapter {proposal.tool!r} 缺少 execute")
        return state_delta, arguments, tool

    @staticmethod
    def _normalize_arguments(
        params: dict[str, dict],
        checked: dict[str, Any],
    ) -> dict[str, Any]:
        """固化默认值及声明枚举，并按工具实际规则规范化路径参数。"""
        normalized: dict[str, Any] = {}
        for name, declaration in params.items():
            if name in checked:
                value = checked[name]
            elif "default" in declaration:
                value = deepcopy(declaration["default"])
            else:
                continue
            if isinstance(value, str):
                value = value.strip()
                enum = declaration.get("enum") or ()
                canonical = next(
                    (item for item in enum if str(item).lower() == value.lower()),
                    None,
                )
                if canonical is not None:
                    value = canonical
                if name in _PATH_ARGUMENTS:
                    value = value.replace("\\", "/")
            normalized[name] = value
        return _json_clone(normalized, "normalized tool arguments")

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

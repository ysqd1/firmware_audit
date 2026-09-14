"""Host 驱动的单 Candidate Analysis tracer。

这是 ADR-0012 新控制层的第一条最小纵向路径：调用方注册 Candidate 后，只需
提供逐步 Agent Session，Host 便负责完整 Proposal 守卫、工具执行、Evidence
留存、Observation View 回传与主动关闭。追加事件保存权威状态，原子快照为
可重建投影；恢复只使用当前状态和证据，不重放对话历史。

模块的公开 interface 刻意只有 ``add_candidate``、``investigation_for`` 和
``run_analysis``。Session 与工具都是注入的 adapter，测试和生产调用走同一 seam。
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any

from ..providers.tools import ReplayPolicy, ToolAuthorizationError, authorize_tool
from ..providers.tools.base import MAX_TEXT_CHARS, ToolResult, validate_params
from .evidence import (
    DEFAULT_TOOL_RESULT_LIMIT_BYTES,
    EvidenceRecorder,
    EvidenceReference,
)
from .json_values import JsonValueError, clone_json_value
from .session import (
    ActionProposal,
    FinalProposal,
    ProposalError,
    ProposalRejectedError,
    revalidate_proposal,
)
from .store import InvestigationStore, StoreError
from .tooling import execute_tool, normalize_tool_arguments


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
    tool_attempts: int = 0
    logical_tool_calls: int = 0


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
        remaining_budget: dict[str, Any] | None = None,
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
        self._stores: dict[str, InvestigationStore] = {}
        self._runtime: dict[str, dict] = {}
        self._resumed: set[str] = set()
        self._initial_budget = _json_clone(remaining_budget or {}, "remaining_budget")
        for directory in sorted((Path(run_dir) / "investigations").glob("cand-*")):
            store = InvestigationStore(run_dir, directory.name)
            try:
                self._restore_investigation(store, directory.name)
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise StoreError(
                    f"Investigation 恢复失败；请检查原运行目录或创建新运行世代: {exc}"
                ) from exc

    def _restore_investigation(self, store: InvestigationStore, candidate_id: str) -> None:
        """Hydrate only identity-consistent domain projections and referenced Evidence."""
        saved = store.load()
        if saved is None:
            raise StoreError("Investigation 缺少权威历史")
        candidate = Candidate(**saved["candidate"])
        data = saved["investigation"]
        runtime = saved["runtime"]
        if (candidate.candidate_id != candidate_id
                or not isinstance(candidate.proposal, dict)
                or data["candidate_id"] != candidate_id
                or data["investigation_id"] != "inv-" + candidate_id.removeprefix("cand-")
                or not isinstance(data["state"], dict)
                or not isinstance(data["evidence"], list)
                or not isinstance(data["closure_evidence"], list)
                or not isinstance(runtime, dict)
                or not isinstance(runtime["remaining_budget"], dict)
                or not isinstance(runtime["last_action"], (dict, type(None)))
                or not isinstance(runtime["observation_view"], (str, type(None)))):
            raise StoreError("Investigation 状态结构或身份损坏")
        pending = runtime["pending"]
        if pending is not None:
            if not isinstance(pending, dict) or not isinstance(pending["proposal"], dict):
                raise StoreError("待执行 Proposal 结构损坏")
            proposal_type = ActionProposal if pending["proposal"]["kind"] == "tool_action" else FinalProposal
            self._validated_proposal(proposal_type(**pending["proposal"]))
            if proposal_type is ActionProposal:
                if (type(pending["sequence"]) is not int or pending["sequence"] < 1
                        or type(pending["executing"]) is not bool):
                    raise StoreError("待执行工具身份损坏")
                self._evidence_store.restore_sequence(pending["sequence"])
        data["evidence"] = [EvidenceReference(**item) for item in data["evidence"]]
        data["closure_evidence"] = tuple(data["closure_evidence"])
        investigation = Investigation(**data)
        for reference in investigation.evidence:
            if type(reference.sequence) is not int or reference.sequence < 1:
                raise StoreError("Evidence sequence 非法")
            slot = self._evidence_store.restore_slot(candidate_id, reference.sequence)
            recovered = self._evidence_store.recover(slot)
            if recovered is None or recovered[0] != reference:
                raise StoreError("已引用 Evidence 缺失或与事件不一致")
        self._validate_saved_call(runtime, data, candidate_id)
        self._candidates[candidate_id] = candidate
        self._investigations[candidate_id] = investigation
        self._stores[candidate_id] = store
        self._runtime[candidate_id] = runtime
        self._resumed.add(candidate_id)
        self._candidate_seq = max(self._candidate_seq, int(candidate_id.split("-")[1]))

    def _validate_saved_call(self, runtime: dict, data: dict, candidate_id: str) -> None:
        """Never derive replay permission or cost from an unvalidated projection."""
        call = runtime["last_tool_call"]
        pending = runtime["pending"]
        active = pending is not None and pending["proposal"]["kind"] == "tool_action"
        logical, attempts = data["logical_tool_calls"], data["tool_attempts"]
        if (type(logical) is not int or type(attempts) is not int
                or attempts < 0 or logical != len(data["evidence"]) + int(active)):
            raise StoreError("工具调用计数损坏")
        if call is None:
            if logical or attempts:
                raise StoreError("缺少逻辑调用记录")
            return
        if not isinstance(call, dict):
            raise StoreError("逻辑调用记录结构损坏")
        if active:
            sequence = pending["sequence"]
            proposal = pending["proposal"]
            tool_name, arguments = proposal["tool"], proposal["arguments"]
        else:
            if not data["evidence"]:
                raise StoreError("工具调用缺少 Evidence")
            reference = data["evidence"][-1]
            sequence, tool_name, arguments = reference.sequence, reference.tool, reference.arguments
        contract = authorize_tool("analysis", tool_name)
        checked, error = validate_params(contract.tool_type.params, arguments)
        if error:
            raise StoreError("持久化工具参数失约")
        arguments = self._normalize_arguments(contract.tool_type.params, checked)
        attempt, status, finished = call["attempt"], call["status"], call["finished"]
        if (call["call_id"] != f"call-{sequence:06d}"
                or call["evidence_id"] != f"ev-{sequence:06d}"
                or call["tool"] != tool_name or call["arguments"] != arguments
                or call["replay_policy"] != contract.replay_policy.value
                or type(attempt) is not int or not 0 <= attempt <= attempts
                or type(finished) is not bool
                or status not in ("prepared", "started", "finished", "interrupted")
                or (attempt == 0) != (status == "prepared")
                or (status == "finished" and not finished)
                or (finished and status not in ("finished", "interrupted"))
                or (status == "interrupted" and contract.replay_policy is not ReplayPolicy.NEVER)
                or (active and pending["executing"] != (attempt > 0))
                or (not active and not finished)):
            raise StoreError("工具调用身份、状态或 replay policy 损坏")
        if finished:
            slot = self._evidence_store.restore_slot(candidate_id, sequence)
            if self._evidence_store.recover(slot) is None:
                raise StoreError("tool_finished 缺少持久化 Observation")

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
        self._stores[candidate.candidate_id] = InvestigationStore(
            self._evidence_store.run_dir, candidate.candidate_id,
        )
        self._runtime[candidate.candidate_id] = {
            "pending": None, "last_action": None, "observation_view": None,
            "last_tool_call": None,
            "remaining_budget": deepcopy(self._initial_budget),
        }
        self._checkpoint(candidate.candidate_id, "candidate_created")
        return deepcopy(candidate)

    def _checkpoint(self, candidate_id: str, kind: str) -> None:
        data = asdict(self._investigations[candidate_id])
        data["closure_evidence"] = list(data["closure_evidence"])
        self._stores[candidate_id].save(kind, {
            "candidate": asdict(self._candidates[candidate_id]),
            "investigation": data, "runtime": self._runtime[candidate_id],
        })

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

        runtime = self._runtime[candidate_id]
        input_message: str | None = self._candidate_context(candidate_id)
        needs_recovery_context = candidate_id in self._resumed
        if candidate_id in self._resumed:
            reset = getattr(session, "reset_for_resume", None)
            if callable(reset):
                reset()
            self._resumed.remove(candidate_id)
        while True:
            pending = runtime["pending"]
            if pending:
                cls = ActionProposal if pending["proposal"]["kind"] == "tool_action" else FinalProposal
                proposal = self._validated_proposal(cls(**pending["proposal"]))
            else:
                if needs_recovery_context:
                    input_message = self._candidate_context(candidate_id)
                    needs_recovery_context = False
                proposal = self._validated_proposal(session.step(input_message))
            if isinstance(proposal, ActionProposal):
                state_delta, arguments, tool = self._validate_action(proposal)
                if not pending:
                    slot = self._evidence_store.reserve(candidate_id)
                    pending = {"proposal": asdict(proposal), "sequence": slot.sequence, "executing": False}
                    runtime["pending"] = pending
                    runtime["last_tool_call"] = {
                        "call_id": f"call-{slot.sequence:06d}",
                        "evidence_id": slot.evidence_id,
                        "tool": proposal.tool, "arguments": arguments,
                        "replay_policy": authorize_tool("analysis", proposal.tool).replay_policy.value,
                        "attempt": 0, "status": "prepared", "finished": False,
                    }
                    investigation.logical_tool_calls += 1
                    self._checkpoint(candidate_id, "proposal_accepted")
                else:
                    slot = self._evidence_store.restore_slot(candidate_id, pending["sequence"])
                recovered = self._evidence_store.recover(slot)
                call = runtime["last_tool_call"]
                if recovered is None:
                    result = None
                    execute_method = "execute"
                    if pending["executing"] and call["replay_policy"] == ReplayPolicy.NEVER.value:
                        if call["status"] != "interrupted":
                            call["status"] = "interrupted"
                            self._checkpoint(candidate_id, "tool_interrupted")
                        result = ToolResult(
                            ok=False, text="", data={"status": "interrupted", "call_id": call["call_id"]},
                            error="interrupted：工具执行已中断，结果未知；禁止自动重放，请选择替代取证动作。",
                        )
                    elif pending["executing"] and call["replay_policy"] == ReplayPolicy.CACHE_VALIDATED.value:
                        execute_method = "execute_after_interruption"
                        result = self._recover_cached_tool(tool, arguments)
                    if result is None:
                        kind = "tool_attempt" if pending["executing"] else "tool_started"
                        pending["executing"] = True
                        call["attempt"] += 1
                        call["status"] = "started"
                        investigation.tool_attempts += 1
                        self._checkpoint(candidate_id, kind)
                        result = self._execute_tool(tool, arguments, method=execute_method)
                    recovered = self._evidence_store.record(
                        slot, candidate_id=candidate_id,
                        investigation_id=investigation.investigation_id,
                        tool_name=proposal.tool, arguments=arguments, result=result,
                    )
                evidence, input_message = recovered
                if (evidence.tool != proposal.tool or evidence.arguments != arguments
                        or evidence.investigation_id != investigation.investigation_id):
                    raise StoreError("Evidence 与待执行动作不匹配；请检查工件")
                if not call["finished"]:
                    if call["status"] != "interrupted":
                        call["status"] = "finished"
                    call["finished"] = True
                    self._checkpoint(candidate_id, "tool_finished")
                investigation.lifecycle_status = "investigating"
                investigation.state.update(state_delta)
                investigation.evidence.append(evidence)
                runtime.update(pending=None, last_action=asdict(proposal), observation_view=input_message)
                self._checkpoint(candidate_id, "action_completed")
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
                if not pending:
                    runtime["pending"] = {"proposal": asdict(proposal)}
                    self._checkpoint(candidate_id, "proposal_accepted")
                investigation.state.update(state_delta)
                investigation.lifecycle_status = "finished"
                investigation.disposition = "closed"
                investigation.stop_reason = "decisive_refutation"
                investigation.closure_reason = closure_reason
                investigation.closure_evidence = closure_evidence
                runtime.update(pending=None, last_action=asdict(proposal))
                self._checkpoint(candidate_id, "analysis_closed")
                return deepcopy(investigation)

    def _candidate_context(self, candidate_id: str) -> str:
        candidate = self._candidates[candidate_id]
        payload = {
            "candidate_id": candidate.candidate_id,
            "investigation_id": self._investigations[candidate_id].investigation_id,
            "proposal": candidate.proposal,
            "current_state": asdict(self._investigations[candidate_id]),
            "last_action": self._runtime[candidate_id]["last_action"],
            "observation_view": self._runtime[candidate_id]["observation_view"],
            "remaining_budget": self._runtime[candidate_id]["remaining_budget"],
        }
        return (
            "Analysis Candidate（本 Session 只调查此 Candidate）：\n"
            + json.dumps(payload, ensure_ascii=False, sort_keys=True)
        )

    @staticmethod
    def _validated_proposal(proposal: object) -> ActionProposal | FinalProposal:
        """不信任 Session adapter：按纯 JSON 协议重新校验整份 Proposal。"""
        return revalidate_proposal(proposal, "analysis")

    def _current_investigation(self, candidate_id: str) -> Investigation:
        try:
            investigation = self._investigations[candidate_id]
        except KeyError as exc:
            raise KeyError(f"未知 Candidate ID: {candidate_id}") from exc
        if investigation.lifecycle_status not in ("queued", "investigating"):
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

    _normalize_arguments = staticmethod(normalize_tool_arguments)

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
    def _recover_cached_tool(tool: object, arguments: dict[str, Any]) -> ToolResult | None:
        """Cache-aware adapters must explicitly support both probe and safe retry."""
        try:
            if not callable(getattr(tool, "execute_after_interruption", None)):
                raise TypeError("缓存工具缺少 execute_after_interruption")
            result = tool.recover_cached_result(**arguments)
            if result is not None and not isinstance(result, ToolResult):
                raise TypeError("缓存校验必须返回 ToolResult 或 None")
            return result
        except Exception as exc:
            return ToolResult(ok=False, text="", error=(
                f"缓存恢复失败: {type(exc).__name__}: {exc}；未自动重放，请选择替代取证动作"
            ))

    _execute_tool = staticmethod(execute_tool)

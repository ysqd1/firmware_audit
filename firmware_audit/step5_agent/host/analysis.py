"""Host 驱动的单 Candidate Analysis tracer。

这是 ADR-0012 新控制层的第一条最小纵向路径：调用方注册 Candidate 后，只需
提供逐步 Agent Session，Host 便负责完整 Proposal 守卫、工具执行、Evidence
留存、Observation View 回传与主动关闭。追加事件保存权威状态，原子快照为
可重建投影；恢复只使用当前状态和证据，不重放对话历史。

Claim/假设/缺口等语义状态的门槛与案卷冻结策略见 ``claims`` 模块；本模块
在唯一循环里接线：动作增量先整份校验后应用，close 派生 rejected/closed，
submit_case 以 trial 状态过 ready gate 再冻结 Verification Case，连续五个
无进展的已完成动作以 no_progress 收束。模块的公开 interface 刻意只有
``add_candidate``、``investigation_for`` 和 ``run_analysis``。Session 与工具
都是注入的 adapter，测试和生产调用走同一 seam。
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any

from ..providers.tools import ReplayPolicy, ToolAuthorizationError, authorize_tool
from ..providers.tools.base import MAX_TEXT_CHARS, ToolResult, validate_params
from .candidates import CLAIM_PROFILES
from .claims import (
    ADMISSION_REASONS,
    NO_PROGRESS_LIMIT,
    action_progressed,
    apply_delta_plan,
    assert_lifecycle_transition,
    assert_terminal,
    build_case_payload,
    evaluate_ready_gate,
    profile_claim_document,
    validate_analysis_delta,
)
from .evidence import (
    DEFAULT_TOOL_RESULT_LIMIT_BYTES,
    EvidenceRecorder,
    EvidenceReference,
)
from .session import (
    ActionProposal,
    FinalProposal,
    ProposalError,
    ProposalRejectedError,
    revalidate_proposal,
)
from .store import InvestigationStore, StoreError, atomic_json
from .tooling import (
    execute_tool,
    json_clone_or_reject,
    normalize_tool_arguments,
    recover_cached_tool,
    validate_saved_tool_call,
)


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
    claim_profile: str = "generic"
    no_progress_count: int = 0
    state: dict[str, Any] = field(default_factory=dict)
    evidence: list[EvidenceReference] = field(default_factory=list)
    tool_attempts: int = 0
    logical_tool_calls: int = 0


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
        self._initial_budget = json_clone_or_reject(remaining_budget or {}, "remaining_budget")
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
        if "claim_profile" not in data and isinstance(candidate.proposal, dict):
            # 票 08 之前的快照没有该字段;从 Candidate proposal 回填保真。
            data["claim_profile"] = candidate.proposal.get("claim_profile", "generic")
        if (candidate.candidate_id != candidate_id
                or not isinstance(candidate.proposal, dict)
                or data["candidate_id"] != candidate_id
                or data["investigation_id"] != "inv-" + candidate_id.removeprefix("cand-")
                or data.get("claim_profile") not in CLAIM_PROFILES
                or type(data.get("no_progress_count", 0)) is not int
                or data["no_progress_count"] < 0
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
        validate_saved_tool_call(
            self._evidence_store, candidate_id,
            call=runtime["last_tool_call"], pending=runtime["pending"],
            logical_tool_calls=data["logical_tool_calls"],
            tool_attempts=data["tool_attempts"],
            evidence=data["evidence"], role="analysis",
        )

    def add_candidate(self, proposal: dict[str, Any]) -> Candidate:
        """分配 Candidate ID，并一一创建隔离的 queued Investigation。"""
        if not isinstance(proposal, dict):
            raise ValueError("Candidate proposal 必须是 JSON object")
        normalized = json_clone_or_reject(proposal, "Candidate proposal")
        claim_profile = normalized.get("claim_profile", "generic")
        if claim_profile not in CLAIM_PROFILES:
            raise ValueError(
                f"Candidate proposal 含未知 Claim Profile {claim_profile!r};"
                f"允许值: {', '.join(CLAIM_PROFILES)}")
        self._candidate_seq += 1
        sequence = self._candidate_seq
        candidate = Candidate(f"cand-{sequence:04d}", normalized)
        investigation = Investigation(
            f"inv-{sequence:04d}", candidate.candidate_id,
            claim_profile=claim_profile,
        )
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

    def candidate_for(self, candidate_id: str) -> Candidate:
        """返回只供检查的 Candidate 快照(复核简报的调查目标来源)。"""
        try:
            return deepcopy(self._candidates[candidate_id])
        except KeyError as exc:
            raise KeyError(f"未知 Candidate ID: {candidate_id}") from exc

    def begin_verification(self, candidate_id: str) -> Investigation:
        """ready_for_verification → verifying;恢复重入对 verifying 幂等。"""
        investigation = self._live_investigation(candidate_id)
        if investigation.lifecycle_status == "verifying":
            return deepcopy(investigation)
        if investigation.lifecycle_status != "ready_for_verification":
            raise ValueError(
                f"Investigation {investigation.investigation_id} 处于 "
                f"{investigation.lifecycle_status}，只有已提交案卷的调查才能进入复核")
        self._advance_lifecycle(investigation, "verifying")
        self._checkpoint(candidate_id, "verification_started")
        return deepcopy(investigation)

    def finish_verification(
        self,
        candidate_id: str,
        *,
        disposition: str,
        stop_reason: str,
    ) -> Investigation:
        """verifying → finished 并落账复核 verdict;同值重放幂等,异值拒绝。"""
        investigation = self._live_investigation(candidate_id)
        if investigation.lifecycle_status == "finished":
            if (investigation.disposition, investigation.stop_reason) != (
                    disposition, stop_reason):
                raise ValueError(
                    f"Investigation {investigation.investigation_id} 复核终态已落账为 "
                    f"{investigation.disposition}/{investigation.stop_reason}，"
                    f"与新结果 {disposition}/{stop_reason} 不一致；请检查原运行目录")
            return deepcopy(investigation)
        if investigation.lifecycle_status != "verifying":
            raise ValueError(
                f"Investigation {investigation.investigation_id} 处于 "
                f"{investigation.lifecycle_status}，不能直接落账复核终态")
        if disposition not in ("confirmed", "rejected", "inconclusive"):
            raise ValueError(
                "复核 disposition 只允许 confirmed/rejected/inconclusive，"
                f"实际为 {disposition!r}")
        self._finish_investigation(
            investigation, disposition=disposition, stop_reason=stop_reason)
        self._checkpoint(candidate_id, "verification_finished")
        return deepcopy(investigation)

    def _live_investigation(self, candidate_id: str) -> Investigation:
        try:
            return self._investigations[candidate_id]
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
        # 会话开始前从两棵 Evidence 树抬水位:独立复核可能已在 verifications/
        # 占号,保证本 Investigation 的 Evidence ID 全运行唯一(ADR-0012)。
        self._evidence_store.seed_sequence_from_files()

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
                # 动作执行块与 verification.py run_case 的对应块刻意逐行平行
                # (票 05 恢复语义的安全关键路径);修改必须同步另一侧。
                upcoming_evidence_id = (
                    f"ev-{pending['sequence']:06d}" if pending
                    else self._evidence_store.peek_next_evidence_id()
                )
                plan, arguments, tool = self._validate_action(
                    proposal, candidate_id, upcoming_evidence_id)
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
                        result = recover_cached_tool(tool, arguments)
                    if result is None:
                        kind = "tool_attempt" if pending["executing"] else "tool_started"
                        pending["executing"] = True
                        call["attempt"] += 1
                        call["status"] = "started"
                        investigation.tool_attempts += 1
                        self._checkpoint(candidate_id, kind)
                        result = execute_tool(tool, arguments, method=execute_method)
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
                prior_digests = {reference.digest for reference in investigation.evidence}
                self._advance_lifecycle(investigation, "investigating")
                investigation.evidence.append(evidence)
                effects = apply_delta_plan(investigation.state, plan)
                if action_progressed(effects, evidence.digest, prior_digests):
                    investigation.no_progress_count = 0
                else:
                    investigation.no_progress_count += 1
                runtime.update(pending=None, last_action=asdict(proposal), observation_view=input_message)
                if investigation.no_progress_count >= NO_PROGRESS_LIMIT:
                    self._finish_investigation(
                        investigation, disposition="unresolved", stop_reason="no_progress")
                    self._checkpoint(candidate_id, "no_progress_stop")
                    return deepcopy(investigation)
                self._checkpoint(candidate_id, "action_completed")
                continue
            if isinstance(proposal, FinalProposal):
                if proposal.kind == "close_investigation":
                    plan, closure_reason, closure_evidence = self._validate_close(
                        proposal.state_delta,
                        investigation,
                    )
                    if not pending:
                        runtime["pending"] = {"proposal": asdict(proposal)}
                        self._checkpoint(candidate_id, "proposal_accepted")
                    apply_delta_plan(investigation.state, plan)
                    gate = evaluate_ready_gate(
                        investigation.state,
                        profile=investigation.claim_profile,
                        evidence_ids=self._evidence_ids(investigation),
                    )
                    if gate.decisive_refuted:
                        disposition, stop_reason = "rejected", "decisive_refutation"
                    else:
                        disposition, stop_reason = "closed", "agent_closed"
                    self._finish_investigation(
                        investigation, disposition=disposition, stop_reason=stop_reason)
                    investigation.closure_reason = closure_reason
                    investigation.closure_evidence = closure_evidence
                    runtime.update(pending=None, last_action=asdict(proposal))
                    self._checkpoint(candidate_id, "analysis_closed")
                    return deepcopy(investigation)
                if proposal.kind == "submit_case":
                    plan, admission_reason = self._validate_submission(proposal, investigation)
                    trial = deepcopy(investigation.state)
                    apply_delta_plan(trial, plan)
                    gate = evaluate_ready_gate(
                        trial,
                        profile=investigation.claim_profile,
                        evidence_ids=self._evidence_ids(investigation),
                    )
                    self._assert_admission_consistent(admission_reason, gate)
                    if not pending:
                        runtime["pending"] = {"proposal": asdict(proposal)}
                        self._checkpoint(candidate_id, "proposal_accepted")
                    apply_delta_plan(investigation.state, plan)
                    payload = build_case_payload(
                        candidate_id=candidate_id,
                        investigation_id=investigation.investigation_id,
                        profile=investigation.claim_profile,
                        state=investigation.state,
                        evidence_references=[
                            asdict(reference) for reference in investigation.evidence
                        ],
                        gate=gate,
                        admission_reason=admission_reason,
                    )
                    atomic_json(
                        Path(self._evidence_store.run_dir)
                        / "verifications" / candidate_id / "case.json",
                        payload,
                    )
                    # evidence_gap 与 ready 都停在"案卷已冻结待复核"的进度位;
                    # ADR-0012"不伪装成 ready"落在案卷内容上(admission_reason、
                    # pending_claims、blocking_gaps),生命周期不新增第六个值。
                    self._advance_lifecycle(investigation, "ready_for_verification")
                    assert_terminal(
                        investigation.lifecycle_status,
                        investigation.disposition,
                        investigation.stop_reason,
                    )
                    runtime.update(pending=None, last_action=asdict(proposal))
                    self._checkpoint(candidate_id, "case_submitted")
                    return deepcopy(investigation)
                raise ProposalRejectedError(
                    "单 Candidate Analysis tracer 只接受 close_investigation/submit_case"
                )

    def _candidate_context(self, candidate_id: str) -> str:
        candidate = self._candidates[candidate_id]
        investigation = self._investigations[candidate_id]
        payload = {
            "candidate_id": candidate.candidate_id,
            "investigation_id": investigation.investigation_id,
            "proposal": candidate.proposal,
            "claim_profile": investigation.claim_profile,
            "claim_schema": profile_claim_document(investigation.claim_profile),
            "current_state": asdict(investigation),
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
        candidate_id: str,
        upcoming_evidence_id: str,
    ) -> tuple[object, dict[str, Any], object]:
        """整份 action 通过 Host 守卫后才把任何 delta 交给循环应用。"""
        investigation = self._investigations[candidate_id]
        plan = validate_analysis_delta(
            investigation.state,
            proposal.state_delta,
            evidence_ids=self._evidence_ids(investigation) | {upcoming_evidence_id},
            profile=investigation.claim_profile,
        )
        arguments = json_clone_or_reject(proposal.arguments, "tool arguments")
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
        return plan, arguments, tool

    _normalize_arguments = staticmethod(normalize_tool_arguments)

    @staticmethod
    def _validate_state_delta(state_delta: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(state_delta, dict):
            raise ProposalRejectedError("state_delta 必须是 JSON object")
        return json_clone_or_reject(state_delta, "state_delta")

    @classmethod
    def _validate_close(
        cls,
        state_delta: dict[str, Any],
        investigation: Investigation,
    ) -> tuple[object, str, tuple[str, ...]]:
        """关闭必须说明决定性反证,并只引用本 Investigation 的 Evidence。"""
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
        plan = validate_analysis_delta(
            investigation.state, remaining,
            evidence_ids=frozenset(owned), profile=investigation.claim_profile,
        )
        return plan, reason.strip(), tuple(refs)

    @classmethod
    def _validate_submission(
        cls,
        proposal: FinalProposal,
        investigation: Investigation,
    ) -> tuple[object, str]:
        """submit_case 只声明 admission reason;案卷内容由 Host 从状态冻结。"""
        delta = cls._validate_state_delta(proposal.state_delta)
        admission_reason = delta.pop("admission_reason", None)
        if admission_reason not in ADMISSION_REASONS:
            raise ProposalRejectedError(
                "submit_case 要求 state_delta.admission_reason 为 "
                + " 或 ".join(ADMISSION_REASONS)
            )
        plan = validate_analysis_delta(
            investigation.state, delta,
            evidence_ids=cls._evidence_ids(investigation),
            profile=investigation.claim_profile,
        )
        return plan, admission_reason

    @staticmethod
    def _assert_admission_consistent(admission_reason: str, gate) -> None:
        """拒绝路径零副作用:伪装 ready 或伪装降级都在落 pending 之前拦截。"""
        if gate.decisive_refuted:
            raise ProposalRejectedError("; ".join(gate.failures()))
        if admission_reason == "ready":
            if not gate.ok:
                raise ProposalRejectedError(
                    "ready 案卷提交被拒:ready gate 未满足: " + "; ".join(gate.failures()))
            return
        if gate.ok:
            raise ProposalRejectedError(
                "ready gate 已满足;请提交 admission_reason=ready 案卷,"
                "不要降级为 evidence_gap")
        if not (gate.unassessed or gate.invalid or gate.open_blocking_gaps):
            raise ProposalRejectedError(
                "evidence_gap 案卷提交被拒:没有可冻结的缺失项"
                "(unassessed 必填 Claim 或 blocking gap)")

    @staticmethod
    def _evidence_ids(investigation: Investigation) -> frozenset[str]:
        return frozenset(reference.evidence_id for reference in investigation.evidence)

    @staticmethod
    def _advance_lifecycle(investigation: Investigation, target: str) -> None:
        assert_lifecycle_transition(investigation.lifecycle_status, target)
        investigation.lifecycle_status = target

    @staticmethod
    def _finish_investigation(
        investigation: Investigation, *, disposition: str, stop_reason: str,
    ) -> None:
        assert_lifecycle_transition(investigation.lifecycle_status, "finished")
        investigation.lifecycle_status = "finished"
        investigation.disposition = disposition
        investigation.stop_reason = stop_reason
        assert_terminal(
            investigation.lifecycle_status,
            investigation.disposition,
            investigation.stop_reason,
        )


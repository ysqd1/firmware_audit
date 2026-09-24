"""Host 驱动的单 Candidate Analysis tracer。

这是 ADR-0012 新控制层的第一条最小纵向路径：调用方注册 Candidate 后，只需
提供逐步 Agent Session，Host 便负责完整 Proposal 守卫、工具执行、Evidence
留存、Observation View 回传与主动关闭。追加事件保存权威状态，原子快照为
可重建投影；恢复只使用当前状态和证据，不重放对话历史。

Claim/假设/缺口等语义状态的门槛与案卷冻结策略见 ``claims`` 模块；本模块
在唯一循环里接线：动作增量先整份校验后应用，close 派生 rejected/closed，
submit_case 以 trial 状态过 ready gate 再冻结 Verification Case，连续五个
无进展的已完成动作以 no_progress 收束；无效回复整份重生成（连续三次按
unresolved/protocol_error 收束，不阻断后续队列），局部轮次与运行总预算
（票 10）经 ``budget.RunBudget`` 守卫，运行级耗尽在 runner 内保存现场不落
终态——收束由运行驱动统一执行（票 21：剩余 queued 标 not_started，进行中
调查按 unresolved/budget_exhausted 终结，随后正常封存）。模块的公开
interface 刻意只有 ``add_candidate``、``investigation_for``、
``candidate_for``、``begin_verification``、``finish_verification``、
``mark_not_started``、``in_flight_ids``、``close_budget_exhausted``、
``queued_ids``、``runnable_ids`` 和 ``run_analysis``。
Session 与工具
都是注入的 adapter，测试和生产调用走同一 seam。
"""
from __future__ import annotations

import os
from copy import deepcopy
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any

from ..providers.tools import (
    ReplayPolicy, ToolAuthorizationError, authorize_tool, role_tool_contract,
)
from ..providers.tools.base import MAX_TEXT_CHARS, ToolResult, validate_params
from .budget import RunBudget
from .candidates import (
    CLAIM_PROFILES,
    RelatedOrigin,
    related_candidate_contract,
)
from .claims import (
    ADMISSION_REASONS,
    IN_FLIGHT_LIFECYCLES,
    NO_PROGRESS_LIMIT,
    PolicyError,
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
    MAX_PROTOCOL_ATTEMPTS,
    ActionProposal,
    FinalProposal,
    ProposalRejectedError,
    revalidate_proposal,
)
from .store import (
    CANDIDATE_ID_PATTERN,
    InvestigationStore,
    StoreError,
    atomic_json,
    store_error_boundary,
)
from .tooling import (
    compact_session_context,
    execute_tool,
    json_clone_or_reject,
    normalize_tool_arguments,
    recover_cached_tool,
    regeneration_feedback,
    validate_saved_tool_call,
)

DEFAULT_ANALYSIS_MAX_ROUNDS = 30


def resolve_analysis_max_rounds() -> int:
    """STEP5_ANALYSIS_MAX_ITERS 覆盖轮次上限(缺失/非法回落默认,下限 1)。

    变量名沿用 legacy runner.resolve_max_iters 同名旋钮(默认同为 30,迁移期
    同名双消费,legacy 随公开切换退役);与 budget.ENV_KEYS 的键名单一纪律
    由测试钉住,防止两处漂移。
    """
    raw = os.environ.get("STEP5_ANALYSIS_MAX_ITERS", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_ANALYSIS_MAX_ROUNDS
    except ValueError:
        return DEFAULT_ANALYSIS_MAX_ROUNDS
    return max(1, value)


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
    # 票 26:protocol_error 收束时的最终拒绝原因(可审计,不回喂已收束调查)。
    protocol_error_detail: str | None = None
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
        max_rounds: int | None = None,
        observation_view_limit: int = MAX_TEXT_CHARS,
        tool_result_limit_bytes: int = DEFAULT_TOOL_RESULT_LIMIT_BYTES,
        remaining_budget: dict[str, Any] | None = None,
        budget: RunBudget | None = None,
    ):
        self.tools = dict(tools)
        self.max_rounds = (resolve_analysis_max_rounds() if max_rounds is None
                           else max(1, int(max_rounds)))
        # 运行级预算 seam:默认解析环境层并落 config.json 快照;测试注入
        # 定制 RunBudget(小时钟/小上限)覆盖每个预算边界。
        self._budget = budget if budget is not None else RunBudget.load(run_dir)
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
            with store_error_boundary(
                    "Investigation 恢复失败；请检查原运行目录或创建新运行世代"):
                self._restore_investigation(store, directory.name)

    def _restore_investigation(self, store: InvestigationStore, candidate_id: str) -> None:
        """Hydrate only identity-consistent domain projections and referenced Evidence."""
        saved = store.load()
        if saved is None:
            raise StoreError("Investigation 缺少权威历史；请检查原运行目录")
        candidate = Candidate(**saved["candidate"])
        data = saved["investigation"]
        runtime = saved["runtime"]
        if "claim_profile" not in data and isinstance(candidate.proposal, dict):
            # 票 08 之前的快照没有该字段;从 Candidate proposal 回填保真。
            data["claim_profile"] = candidate.proposal.get("claim_profile", "generic")
        detail = data.get("protocol_error_detail")
        if not (detail is None or (isinstance(detail, str) and detail.strip())):
            # 票 26:审计字段自身失真按损坏处理,不做推测规整。
            raise StoreError(
                "protocol_error_detail 必须为非空字符串或省略;请检查原运行目录")
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
                or not isinstance(runtime["observation_view"], (str, type(None)))
                or type(runtime.get("max_rounds")) is not int
                or runtime["max_rounds"] < 1
                or type(runtime.get("rounds_used")) is not int
                or not 0 <= runtime["rounds_used"] <= runtime["max_rounds"]):
            raise StoreError("Investigation 状态结构或身份损坏；请检查原运行目录")
        pending = runtime["pending"]
        if pending is not None:
            if not isinstance(pending, dict) or not isinstance(pending["proposal"], dict):
                raise StoreError("待执行 Proposal 结构损坏；请检查原运行目录")
            proposal_type = ActionProposal if pending["proposal"]["kind"] == "tool_action" else FinalProposal
            self._validated_proposal(proposal_type(**pending["proposal"]))
            if proposal_type is ActionProposal:
                if (type(pending["sequence"]) is not int or pending["sequence"] < 1
                        or type(pending["executing"]) is not bool):
                    raise StoreError("待执行工具身份损坏；请检查原运行目录")
                self._evidence_store.restore_sequence(pending["sequence"])
        data["evidence"] = [EvidenceReference(**item) for item in data["evidence"]]
        data["closure_evidence"] = tuple(data["closure_evidence"])
        investigation = Investigation(**data)
        self._assert_restorable_lifecycle(investigation)
        for reference in investigation.evidence:
            if type(reference.sequence) is not int or reference.sequence < 1:
                raise StoreError("Evidence sequence 非法；请检查原运行目录")
            slot = self._evidence_store.restore_slot(candidate_id, reference.sequence)
            recovered = self._evidence_store.recover(slot)
            if recovered is None or recovered[0] != reference:
                raise StoreError("已引用 Evidence 缺失或与事件不一致；请检查原运行目录")
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

    @staticmethod
    def _assert_restorable_lifecycle(investigation: Investigation) -> None:
        """恢复期生命周期契约:生命周期/处置/停止原因三轴取值与组合,关闭记录只属于已结束的调查。

        queued+confirmed 之类不是"结构损坏"而是领域非法:接受它会让模型在错误
        前提下请求工具,或让缺引用的 Claim 直接生成 Finding。拒绝发生在任何
        模型请求、工具执行与 Finding 写入之前,原工件保留供检查。
        生命周期进度闸门(ready/verifying 等)由各自入口的转换守卫另行把关。
        """
        try:
            assert_terminal(
                investigation.lifecycle_status,
                investigation.disposition,
                investigation.stop_reason,
            )
        except PolicyError as exc:
            raise StoreError(f"生命周期投影非法；请检查原运行目录: {exc}") from exc
        owned = {reference.evidence_id for reference in investigation.evidence}
        closure_evidence = investigation.closure_evidence
        if any(not isinstance(item, str) or not item for item in closure_evidence):
            raise StoreError("关闭证据必须是 Evidence ID 字符串；请检查原运行目录")
        if investigation.closure_reason is None:
            if closure_evidence:
                raise StoreError("关闭证据缺少关闭原因；请检查原运行目录")
            return
        if (not isinstance(investigation.closure_reason, str)
                or not investigation.closure_reason.strip()):
            raise StoreError("关闭原因必须是非空字符串；请检查原运行目录")
        if investigation.lifecycle_status != "finished":
            raise StoreError("关闭记录只属于已结束的调查；请检查原运行目录")
        if not closure_evidence:
            raise StoreError("关闭记录缺少关闭证据；请检查原运行目录")
        unknown = [item for item in closure_evidence if item not in owned]
        if unknown:
            raise StoreError(
                "关闭证据引用不属于本 Investigation: " + ", ".join(unknown)
                + "；请检查原运行目录")

    def add_candidate(
        self, proposal: dict[str, Any], *, candidate_id: str | None = None,
    ) -> Candidate:
        """分配 Candidate ID，并一一创建隔离的 queued Investigation。

        运行驱动按 Candidate Store 已分配的显式 ID 注册(两处权威不对齐会直接
        拒绝);不传 ID 时沿用运行内递增分配,行为与独立使用 tracer 一致。
        """
        if not isinstance(proposal, dict):
            raise ValueError("Candidate proposal 必须是 JSON object")
        normalized = json_clone_or_reject(proposal, "Candidate proposal")
        claim_profile = normalized.get("claim_profile", "generic")
        if claim_profile not in CLAIM_PROFILES:
            raise ValueError(
                f"Candidate proposal 含未知 Claim Profile {claim_profile!r};"
                f"允许值: {', '.join(CLAIM_PROFILES)}")
        if candidate_id is None:
            self._candidate_seq += 1
            sequence = self._candidate_seq
        else:
            if not CANDIDATE_ID_PATTERN.fullmatch(candidate_id):
                raise ValueError(f"非法 Candidate ID: {candidate_id!r}")
            sequence = int(candidate_id.split("-")[1])
            if sequence <= self._candidate_seq:
                raise ValueError(
                    f"显式 Candidate ID 必须高于当前水位 "
                    f"cand-{self._candidate_seq:04d}: {candidate_id}")
            self._candidate_seq = sequence
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
            "rounds_used": 0, "max_rounds": self.max_rounds,
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

    def mark_not_started(
        self, candidate_id: str, *, stop_reason: str = "budget_exhausted",
    ) -> Investigation:
        """queued → finished/not_started:运行总预算耗尽时未处理项的落账原语。

        只有从未开始的 Candidate 可标 not_started(不得计作已检查);已进入
        investigating 的调查由调用方按"保存现场"路径处理,不能用本方法收束。
        """
        investigation = self._live_investigation(candidate_id)
        if investigation.lifecycle_status != "queued":
            raise ValueError(
                f"Investigation {investigation.investigation_id} 处于 "
                f"{investigation.lifecycle_status},只有未开始的 Candidate 才能标记 not_started")
        self._finish_investigation(
            investigation, disposition="not_started", stop_reason=stop_reason)
        self._checkpoint(candidate_id, "marked_not_started")
        return deepcopy(investigation)

    def in_flight_ids(self) -> tuple[str, ...]:
        """按创建序返回进行中的 Candidate(investigating/ready/verifying)。

        运行总预算耗尽的收束入口,与 queued_ids(not_started 收账)并列:
        覆盖轮次中途、案卷已冻结未派发复核、复核中途三种现场(票 21)。
        """
        return tuple(
            candidate_id for candidate_id, investigation in self._investigations.items()
            if investigation.lifecycle_status in IN_FLIGHT_LIFECYCLES
        )

    def close_budget_exhausted(self, candidate_id: str) -> Investigation:
        """运行总预算耗尽时进行中调查的收束原语:finished/unresolved/budget_exhausted。

        三种现场(轮次中途 investigating、案卷已冻结未复核
        ready_for_verification、复核中途 verifying)统一按票 21(ADR-0012
        2026-09-19)收束;复核会话的既有 Claim Result 不在此聚合——运行级
        耗尽不产生复核结论,与案卷轮次耗尽的聚合路径(verification 级
        budget_exhausted)分属两条口径。同值重放幂等(恢复续跑可能再次收束);
        queued 必须走 mark_not_started,不得计作已检查。
        """
        investigation = self._live_investigation(candidate_id)
        if investigation.lifecycle_status == "finished":
            if (investigation.disposition, investigation.stop_reason) != (
                    "unresolved", "budget_exhausted"):
                raise ValueError(
                    f"Investigation {investigation.investigation_id} 已以 "
                    f"{investigation.disposition}/{investigation.stop_reason} 收束,"
                    "不得改按预算耗尽收束;请检查原运行目录")
            return deepcopy(investigation)
        if investigation.lifecycle_status not in IN_FLIGHT_LIFECYCLES:
            raise ValueError(
                f"Investigation {investigation.investigation_id} 处于 "
                f"{investigation.lifecycle_status},只有进行中的调查才能按预算耗尽收束")
        self._finish_investigation(
            investigation, disposition="unresolved", stop_reason="budget_exhausted")
        self._checkpoint(candidate_id, "budget_exhausted_closed")
        return deepcopy(investigation)

    def queued_ids(self) -> tuple[str, ...]:
        """按创建序返回仍处于 queued 的 Candidate(队列驱动的收账入口)。"""
        return tuple(
            candidate_id for candidate_id, investigation in self._investigations.items()
            if investigation.lifecycle_status == "queued"
        )

    def runnable_ids(self) -> tuple[str, ...]:
        """按创建序返回可继续驱动的 Candidate(queued + investigating)。

        服务中断的调查停在 investigating(首个动作完成即推进),恢复时
        运行驱动从这里继续"当前 Investigation",而不是只看 queued——否则
        未完成责任会被静默跳过甚至误封 finalizing(票 11 验收补充)。
        """
        return tuple(
            candidate_id for candidate_id, investigation in self._investigations.items()
            if investigation.lifecycle_status in ("queued", "investigating")
        )

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
        # 运行总预算的活动时段:离开本循环(正常返回/异常传播)即封段,停机与
        # 等待恢复的间隔不进 active time;协议重生成只计 llm_calls,不计
        # 工具调用或 no-progress(ADR-0012 L73)。
        self._budget.start_active()
        strikes = 0
        try:
            while True:
                # 一个语义轮 = 一个 episode:无效回复(协议形状或 Host 守卫拒绝)
                # 整份重生成,连续 MAX_PROTOCOL_ATTEMPTS 次按 unresolved/
                # protocol_error 收束且不阻断后续队列;服务中断等其他异常不是
                # 无效回复,原样传播、现场由既有 checkpoint 保存。
                try:
                    pending = runtime["pending"]
                    if pending:
                        cls = ActionProposal if pending["proposal"]["kind"] == "tool_action" else FinalProposal
                        proposal = self._validated_proposal(cls(**pending["proposal"]))
                    else:
                        # 局部轮次上限计本单元模型请求(含重生成,recon 票 06 先例);
                        # 耗尽按未收束收尾,unresolved 语义与 no_progress 同款。
                        if runtime["rounds_used"] >= runtime["max_rounds"]:
                            self._finish_investigation(
                                investigation, disposition="unresolved",
                                stop_reason="budget_exhausted")
                            self._checkpoint(candidate_id, "round_budget_exhausted")
                            return deepcopy(investigation)
                        # Host 显式上下文压缩(ADR-0012 D3):过预算闸、计入
                        # 台账与 Transcript,不占语义轮次;预算不足在此耗尽。
                        compact_session_context(session, self._budget)
                        self._budget.require_llm()
                        if needs_recovery_context:
                            input_message = self._candidate_context(candidate_id)
                            needs_recovery_context = False
                        runtime["rounds_used"] += 1
                        raw = session.step(input_message)
                        self._budget.record_llm_call(getattr(session, "last_usage", None))
                        proposal = self._validated_proposal(raw)
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
                            self._budget.record_logical_tool_call()
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
                                self._budget.require_tool()
                                pending["executing"] = True
                                call["attempt"] += 1
                                call["status"] = "started"
                                investigation.tool_attempts += 1
                                self._budget.record_tool_execution()
                                self._checkpoint(candidate_id, kind)
                                result = execute_tool(
                                    tool, arguments, method=execute_method,
                                    investigation_ref=investigation.investigation_id,
                                    budget=self._budget, role="analysis")
                            recovered = self._evidence_store.record(
                                slot, candidate_id=candidate_id,
                                investigation_id=investigation.investigation_id,
                                tool_name=proposal.tool, arguments=arguments, result=result,
                            )
                        evidence, input_message = recovered
                        if (evidence.tool != proposal.tool or evidence.arguments != arguments
                                or evidence.investigation_id != investigation.investigation_id):
                            raise StoreError("Evidence 与待执行动作不匹配；请检查原运行目录")
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
                            self._budget.record_validated_round()
                            return deepcopy(investigation)
                        self._checkpoint(candidate_id, "action_completed")
                        self._budget.record_validated_round()
                        strikes = 0
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
                            self._budget.record_validated_round()
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
                            self._budget.record_validated_round()
                            return deepcopy(investigation)
                        raise ProposalRejectedError(
                            "单 Candidate Analysis tracer 只接受 close_investigation/submit_case"
                        )
                except ProposalRejectedError as exc:
                    strikes += 1
                    if strikes >= MAX_PROTOCOL_ATTEMPTS:
                        self._finish_investigation(
                            investigation, disposition="unresolved",
                            stop_reason="protocol_error")
                        # 票 26:最终拒绝原因落权威投影(events + 快照)供
                        # 审计;已收束的调查不再回喂,契约次数不变。
                        investigation.protocol_error_detail = str(exc)
                        self._checkpoint(candidate_id, "protocol_error")
                        return deepcopy(investigation)
                    input_message = regeneration_feedback(str(exc))
        finally:
            self._budget.stop_active()

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
            "remaining_rounds": (
                self._runtime[candidate_id]["max_rounds"]
                - self._runtime[candidate_id]["rounds_used"]
            ),
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
            related_origin=self._related_origin(investigation),
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
            related_origin=cls._related_origin(investigation),
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
            related_origin=cls._related_origin(investigation),
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
    def _related_origin(investigation: Investigation) -> RelatedOrigin:
        """Related Candidate 的来源身份由 Host 盖章,模型无法冒充。"""
        return RelatedOrigin(
            "analysis", investigation.candidate_id, investigation.investigation_id)

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


ANALYSIS_RELATED_CANDIDATE_CONTRACT = related_candidate_contract()

_ANALYSIS_SESSION_SYSTEM = """## 1 角色与使命
你是固件安全审计的调查 Agent(analysis)。Host 为你分配唯一一个 Candidate
(可疑线索或覆盖目标),你对它做深度取证:逐条推进 Claim、维护一个工作
假设,直到案卷成熟提交复核,或以决定性反证关闭调查。你的结论必须建立在
本 Investigation 的 Evidence 之上;最终是否成立由独立复核与 Host 聚合决定,
不要提前宣称"已确认漏洞"。

## 2 工具纪律(角色契约强制)
- 可用深挖工具:list_files / read_file / search_code / strings_query /
  imports_query / checksec / semgrep_scan / gitleaks_scan / binwalk_rescan /
  find_decompiled_function(读已有反编译边车,毫秒级,不发起 Ghidra)/
  r2_list_functions / r2_disassemble_function / r2_xref_query /
  ghidra_decompile(按需,优先 r2 与边车)/ sandbox_verify /
  qemu_precheck(动态实验前静态预检:ELF 架构/解释器/依赖/模板适用性/
  路径边界;只读检查,不执行目标不创建会话。仅当静态证据不足、确需观察
  真实程序行为时评估可行性;预检通过不代表子进程链可用,更不代表漏洞
  成立或不存在)/ qemu_execute(多步执行会话:开启会话后真实执行原固件
  程序及其自主派生链并返回 Observation;keep_open=true 保持会话开启,
  后继调用传 session_id 在同一会话内继续执行,运行目录内前序写入的文件
  后继可读;会话内执行次数有限(默认 4,以工具返回为准),对照/异常/复现
  逐次计数;不再需要时传 stop=true 停机封存,或仅传 session_id+stop=true
  只停机不执行。每个新会话消耗一个会话名额,每调查名额有限(默认 3,以
  工具返回为准);调查结束/预算耗尽/中断时 Host 强制停机封存全部会话,
  中断即会话死亡,续跑开启新会话。仅在预检可行且静态证据确有缺口时使用;
  调查归属由 Host 绑定到当前 Investigation(无需自行填写归属参数)。
  动态 Observation 只是 Evidence,
  正常退出/崩溃/超时都不构成漏洞成立或不存在)。
- 二进制深挖升级纪律:先 r2/边车等低成本工具收窄目标,信息仍不足才
  ghidra_decompile;每次工具调用都会形成本 Investigation 的 Evidence
  (Observation View 中的 ev-xxxxxx)。
- 单个工具失败是正常 Observation,换路取证,不要编造结果。

{{TOOL_CONTRACT}}

## 3 state_delta 结构化状态
随每个动作提交增量(只写变化,不重发全量)。可选字段只在本轮有变化时出现;
未变化的字段整体省略,空数组占位(如 gaps_opened: []、gaps_resolved: []、
path_nodes: [])会被整份拒绝。
- hypothesis: {"statement": "...", "note": "..."} 设置/替换当前唯一工作假设
  (换假设前先给旧假设一个 hypothesis_outcome)。
- hypothesis_outcome: {"outcome": "supported|refuted", "note": "..."} 收束
  当前假设进简短历史。
- claims: {Claim 名: {"status": "supported|refuted|not_applicable",
  "evidence_ids": ["ev-xxxxxx"], "note": "..."}} 逐项推进必填 Claim
  (见上下文 claim_schema;决定性 Claim 不允许 not_applicable;
  supported 必须引用本 Investigation 的 Evidence)。未评估的 Claim 以
  省略表达:unassessed 是 Host 读侧缺省,显式提交会被整份拒绝。
- path_nodes: ["source-to-sink 链条上的节点"] 记录路径进展。
- gaps_opened: [{"id": "...", "description": "...", "blocking": bool}] /
  gaps_resolved: ["gap-id"] 管理证据缺口(blocking 缺口会阻止 ready)。
- related_candidates: 只在出现独立入口、处理位置或问题机制时提出新线索;
  {{RELATED_CANDIDATE_CONTRACT}}

## 4 终止动作
- submit_case: 必填 Claim 全部有状态、支撑引用真实、反证已处理且无 blocking
  gap 时,以 {"admission_reason": "ready"} 提交复核;高优先级但缺关键材料
  的调查以 {"admission_reason": "evidence_gap"} 提交补证复核(案卷会冻结
  缺失项,不伪装 ready)。ready gate 未满足会被整份拒绝。
- close_investigation: 决定性反证成立时关闭,必须带 closure_reason 与
  evidence_refs(引用本 Investigation 的 Evidence)。

## 5 红线
- Evidence ID 只能来自本轮 Observation View,禁止编造或复用其他调查的 ID。
- Blind Discovery 证据纪律:版本号、配置开关、服务启动字符串只是观察信号,
  禁止把它们与公开已知问题做版本映射推断(如按版本区间认定存在公开漏洞);
  仅凭这类材料不能支撑任何决定性 Claim。supported 需要本 Investigation
  观察到的机制证据:根因(问题机制本身)、可达性(入口/触发路径)、所需
  权限或认证材料逐项落实;证据不足的项保持 unassessed 或以 gaps_opened
  逐项列出缺失材料,不要猜 supported。有真实证据的静态缺陷链不要求动态
  PoC 才能提交复核。
- 无效回复会收到字段级问题清单并被要求从头重生成整份 JSON(最多三次,
  之后本调查按 protocol_error 收束)。
- 连续五个动作无新证据/Claim/假设/路径/gap 变化会以 no_progress 停止,
  每个动作尽量推进实质调查。"""

# 提示正文含 JSON 花括号,不能用 str.format;占位符替换嵌入共享契约。
# 工具参数契约由注册表生成(票 27,ADR-0004 声明侧 A 送达),与执行校验
# 同源;拼入常量即被 prompt_version_document 指纹覆盖。
ANALYSIS_SESSION_SYSTEM = _ANALYSIS_SESSION_SYSTEM.replace(
    "{{RELATED_CANDIDATE_CONTRACT}}", ANALYSIS_RELATED_CANDIDATE_CONTRACT
).replace("{{TOOL_CONTRACT}}", role_tool_contract("analysis"))


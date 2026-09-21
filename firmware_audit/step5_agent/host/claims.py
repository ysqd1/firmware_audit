"""Analysis Investigation 的 Claim、假设、生命周期门槛与案卷冻结策略。

本模块是 ADR-0012 的 Host 语义控制层:Claim Profile 的必填项与决定性、
Claim 状态与 Evidence 依据、单一 working hypothesis 与简短历史、lifecycle/
disposition/stop reason 守卫、ready gate 与 evidence-gap 案卷冻结,全部在这里
以纯函数表达。LLM 只能通过 state_delta 提交结构化增量;是否允许提交、如何
收束由本模块与 tracer 决定。除 JSON 校验外没有任何 IO,表驱动测试直接覆盖。
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from .candidates import (
    CLAIM_PROFILES,
    CandidateIntakeError,
    RelatedOrigin,
    related_candidate_conflicts,
    related_candidate_records,
)
from .json_values import JsonValueError, clone_json_value
from .store import unknown_keys
from .session import ProposalRejectedError

# ---- Claim Profile:共同必填项 + 各 Profile 额外决定性项(ADR-0012)----

CLAIM_STATUSES = ("unassessed", "supported", "refuted", "not_applicable")
# delta 只能把 Claim 推进到后三种;unassessed 是未触达缺省。
ASSESSABLE_STATUSES = ("supported", "refuted", "not_applicable")

COMMON_DECISIVE_CLAIMS = (
    "target_exists", "root_cause", "trigger_or_exposure", "actual_impact",
)
COMMON_NON_DECISIVE_CLAIMS = ("preconditions", "mitigations")
PROFILE_EXTRA_CLAIMS: dict[str, tuple[str, ...]] = {
    "generic": (),
    "data_propagation": (
        "input_source", "key_processing_relation",
        "reaches_high_impact_operation",
    ),
    "config": ("config_value_effective", "config_scope"),
    "credentials": ("material_valid", "access_boundary", "actual_usage"),
    "memory": (
        "input_or_index_controlled", "boundary_check_missing",
        "related_operation_reachable",
    ),
}

CLAIM_LABELS: dict[str, str] = {
    "target_exists": "目标存在",
    "root_cause": "根因成立",
    "trigger_or_exposure": "触发或暴露关系成立",
    "actual_impact": "确有实际影响",
    "preconditions": "前置条件",
    "mitigations": "缓解因素",
    "input_source": "输入来源",
    "key_processing_relation": "关键处理关系",
    "reaches_high_impact_operation": "到达高影响操作",
    "config_value_effective": "配置值真实生效",
    "config_scope": "配置作用范围",
    "material_valid": "凭据材料有效",
    "access_boundary": "访问边界",
    "actual_usage": "实际使用关系",
    "input_or_index_controlled": "输入或索引可控",
    "boundary_check_missing": "边界条件缺失",
    "related_operation_reachable": "相关操作可达",
}

HYPOTHESIS_OUTCOMES = ("supported", "refuted", "replaced")


def required_claims(profile: str) -> tuple[str, ...]:
    """所选 Profile 的全部必填 Claim:共同项 + 额外决定性项。"""
    _known_profile(profile)
    return COMMON_DECISIVE_CLAIMS + COMMON_NON_DECISIVE_CLAIMS + PROFILE_EXTRA_CLAIMS[profile]


def is_decisive(profile: str, claim: str) -> bool:
    """决定性 Claim 被反驳即 rejected;非决定性只修正条件或 severity。"""
    _known_profile(profile)
    if claim in COMMON_NON_DECISIVE_CLAIMS:
        return False
    if claim in COMMON_DECISIVE_CLAIMS or claim in PROFILE_EXTRA_CLAIMS[profile]:
        return True
    raise PolicyError(f"未知 Claim {claim!r}(Profile {profile!r})")


def _known_profile(profile: str) -> None:
    if profile not in CLAIM_PROFILES:
        raise PolicyError(
            f"未知 Claim Profile {profile!r};允许值: {', '.join(CLAIM_PROFILES)}")


def profile_claim_document(profile: str) -> dict[str, Any]:
    """渲染进 Agent 上下文的该 Profile Claim 模式(名称/决定性/释义)。

    票 26:statuses 显式拆读侧/写侧——unassessed 是 Host 状态的未评估缺省,
    只在读侧出现;delta 写侧只允许三值,未评估以省略该 Claim 表达,避免
    模型照抄读侧全集显式提交 unassessed 被整份拒绝。
    """
    _known_profile(profile)
    return {
        "profile": profile,
        "claims": [
            {
                "name": name,
                "decisive": is_decisive(profile, name),
                "label": CLAIM_LABELS[name],
            }
            for name in required_claims(profile)
        ],
        "statuses": {
            "read_side": list(CLAIM_STATUSES),
            "write_side": list(ASSESSABLE_STATUSES),
            "note": (
                "unassessed 是未评估缺省,只在读侧状态出现;"
                "state_delta 不允许显式提交,未评估的 Claim 以省略表达"
            ),
        },
    }


# ---- lifecycle / disposition / stop reason 三轴独立守卫 ----

LIFECYCLE_STATUSES = (
    "queued", "investigating", "ready_for_verification", "verifying", "finished",
)
DISPOSITIONS = (
    "confirmed", "rejected", "inconclusive", "closed", "unresolved", "not_started",
)
STOP_REASONS = (
    "completed", "decisive_refutation", "no_progress", "budget_exhausted",
    "input_failure", "protocol_error", "agent_closed",
)

LEGAL_LIFECYCLE_TRANSITIONS: dict[str, frozenset[str]] = {
    "queued": frozenset({"investigating", "finished"}),
    "investigating": frozenset({"ready_for_verification", "finished"}),
    "ready_for_verification": frozenset({"verifying", "finished"}),
    "verifying": frozenset({"finished"}),
    "finished": frozenset(),
}

# 运行总预算耗尽时"进行中"的现场集合(票 21):轮次中途、案卷已冻结未
# 复核、复核中途;queued 不在内——未开始项走 not_started 收账,不得计作
# 已检查。收束统一落 finished/unresolved/budget_exhausted。
IN_FLIGHT_LIFECYCLES = (
    "investigating", "ready_for_verification", "verifying",
)


class PolicyError(ValueError):
    """Host 内部违反固定策略;不是模型反馈,不应回喂 Agent。"""


def assert_lifecycle_transition(current: str, target: str) -> None:
    """拒绝一切非法 lifecycle 转换;同值赋值视为 no-op 放行。"""
    for status in (current, target):
        if status not in LIFECYCLE_STATUSES:
            raise PolicyError(f"未知 lifecycle status {status!r}")
    if current == target:
        return
    if target not in LEGAL_LIFECYCLE_TRANSITIONS[current]:
        raise PolicyError(
            f"非法 lifecycle 转换 {current!r} → {target!r};"
            f"允许目标: {', '.join(sorted(LEGAL_LIFECYCLE_TRANSITIONS[current]))} 或保持原值")


def assert_terminal(lifecycle: str, disposition: str | None, stop_reason: str | None) -> None:
    """disposition 只在结束时表达;结束时必须同时给出停止原因。"""
    if lifecycle not in LIFECYCLE_STATUSES:
        raise PolicyError(f"未知 lifecycle status {lifecycle!r}")
    if lifecycle == "finished":
        if disposition not in DISPOSITIONS:
            raise PolicyError(
                f"finished 要求合法 disposition(允许值: {', '.join(DISPOSITIONS)})")
        if stop_reason not in STOP_REASONS:
            raise PolicyError(
                f"finished 要求合法 stop reason(允许值: {', '.join(STOP_REASONS)})")
        return
    if disposition is not None or stop_reason is not None:
        raise PolicyError(
            f"lifecycle {lifecycle!r} 尚未结束,disposition 与 stop reason 必须为空")


# ---- state_delta 的两阶段处理:先整份校验成计划,再免校验幂等应用 ----

# 策略拥有的 state 键;只能经对应 delta 键结构化写入,直写即拒绝。
# 这里是被直写即拒的状态键;related_candidates 同样由 Host 管理,但走专门的
# 校验分支(见 _validate_related_candidate_updates),故不列在此处。
OWNED_STATE_KEYS = frozenset({"hypothesis", "claims", "path_nodes", "evidence_gaps"})


def _reject(message: str) -> None:
    raise ProposalRejectedError(message)


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _reject(f"{label} 必须为非空字符串")
    return value


def _optional_string(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        _reject(f"{label} 必须为非空字符串或省略")
    return value


def _known_keys(value: Mapping, allowed: frozenset[str] | set[str], label: str) -> None:
    unknown = unknown_keys(value, allowed)
    if unknown:
        _reject(f"{label} 含未知字段: {', '.join(unknown)};"
                f"允许字段: {', '.join(sorted(allowed))}")


def _hypothesis_state(state: dict[str, Any]) -> dict[str, Any]:
    hypothesis = state.get("hypothesis")
    if (not isinstance(hypothesis, dict)
            or (hypothesis.get("working") is not None
                and not isinstance(hypothesis.get("working"), dict))
            or not isinstance(hypothesis.get("history"), list)):
        return {"working": None, "history": []}
    return hypothesis


def _gaps_state(state: dict[str, Any]) -> list[dict[str, Any]]:
    gaps = state.get("evidence_gaps")
    if not isinstance(gaps, list):
        return []
    return [gap for gap in gaps if isinstance(gap, dict)]


def _validate_claim_updates(
    updates: Any,
    state: dict[str, Any],
    evidence_ids: frozenset[str],
    profile: str,
) -> tuple[tuple[tuple[str, dict[str, Any]], ...], frozenset[str]]:
    if not isinstance(updates, dict):
        _reject("state_delta.claims 必须为 JSON object")
    allowed_claims = required_claims(profile)
    planned: list[tuple[str, dict[str, Any]]] = []
    for name, value in updates.items():
        if name not in allowed_claims:
            _reject(
                f"state_delta.claims 含未知 Claim {name!r}(Profile {profile!r} "
                f"必填项之外不允许自由扩张 schema)")
        if not isinstance(value, dict):
            _reject(f"state_delta.claims.{name} 必须为 JSON object")
        _known_keys(value, {"status", "evidence_ids", "note"}, f"state_delta.claims.{name}")
        status = value.get("status")
        if status not in ASSESSABLE_STATUSES:
            _reject(
                f"state_delta.claims.{name}.status 只允许 "
                f"{', '.join(ASSESSABLE_STATUSES)}"
                "(unassessed 是未评估缺省,不可显式提交,未评估请省略该 Claim)")
        if status == "not_applicable" and is_decisive(profile, name):
            _reject(
                f"决定性 Claim {name!r} 不允许 not_applicable;"
                "若整条线索不适用,请 close_investigation 并说明")
        raw_refs = value.get("evidence_ids", [])
        if not isinstance(raw_refs, list) or any(
                not isinstance(item, str) or not item for item in raw_refs):
            _reject(f"state_delta.claims.{name}.evidence_ids 必须为 Evidence ID 字符串数组")
        if status == "supported" and not raw_refs:
            _reject(
                f"supported Claim {name!r} 必须引用至少一个本 Investigation 的 Evidence ID")
        missing_refs = [item for item in raw_refs if item not in evidence_ids]
        if missing_refs:
            _reject(
                f"state_delta.claims.{name}.evidence_ids 引用了不存在的 Evidence: "
                + ", ".join(missing_refs))
        record: dict[str, Any] = {"status": status, "evidence_ids": list(raw_refs)}
        note = _optional_string(value.get("note"), f"state_delta.claims.{name}.note")
        if note is not None:
            record["note"] = note
        planned.append((name, record))
    changed = frozenset(
        name for name, record in planned
        if not (isinstance(state.get("claims"), dict)
                and isinstance(state["claims"].get(name), dict)
                and state["claims"][name].get("status") == record["status"])
    )
    return tuple(planned), changed


def _related_state(state: dict[str, Any]) -> list[dict[str, Any]]:
    related = state.get("related_candidates")
    if not isinstance(related, list):
        return []
    return [item for item in related if isinstance(item, dict)]


def _validate_related_candidate_updates(
    entries: Any,
    state: dict[str, Any],
    evidence_ids: frozenset[str],
    origin: RelatedOrigin,
) -> tuple[dict[str, Any], ...]:
    """Related Candidate 与 Claim 同级:整份校验后才进计划与状态。

    校验规则来自 candidates.related_candidate_records(与 verification 共用);
    同来源重复提交同一 proposal_id 幂等跳过,同 ID 异内容拒绝——绝不静默覆盖
    已入册的线索。
    """
    try:
        records = related_candidate_records(
            entries, evidence_ids=evidence_ids, origin=origin)
    except CandidateIntakeError as exc:
        raise ProposalRejectedError(str(exc)) from exc
    conflicts = related_candidate_conflicts(records, _related_state(state))
    if conflicts:
        raise ProposalRejectedError(
            f"proposal_id {', '.join(conflicts)} 已按不同内容入册,拒绝复用;"
            "同一线索补充信息请沿用原内容或另起 proposal_id")
    return records


@dataclass(frozen=True)
class DeltaPlan:
    """已整份校验的状态增量计划;应用阶段不再校验,按构造幂等。"""

    passthrough: tuple[tuple[str, Any], ...] = ()
    hypothesis_set: Mapping[str, Any] | None = None
    hypothesis_outcome: Mapping[str, Any] | None = None
    claim_updates: tuple[tuple[str, dict[str, Any]], ...] = ()
    claim_changes: frozenset[str] = frozenset()
    path_nodes: tuple[str, ...] = ()
    gaps_opened: tuple[dict[str, Any], ...] = ()
    gaps_resolved: tuple[str, ...] = ()
    related_candidates: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class AppliedEffects:
    """本次增量产生的进展信号(no-progress 判据)。"""

    claims_changed: tuple[str, ...] = ()
    hypothesis_changed: bool = False
    path_nodes_added: tuple[str, ...] = ()
    gaps_resolved: tuple[str, ...] = ()

    def any_progress(self) -> bool:
        return bool(
            self.claims_changed or self.hypothesis_changed
            or self.path_nodes_added or self.gaps_resolved
        )


def validate_analysis_delta(
    state: dict[str, Any],
    delta: dict[str, Any],
    *,
    evidence_ids: frozenset[str],
    profile: str,
    related_origin: RelatedOrigin,
) -> DeltaPlan:
    """整份校验 analysis state_delta;任何字段失约都拒绝,不做局部应用。

    ``evidence_ids`` 是允许被引用的全部 Evidence(已拥有的加上本次动作将要
    产生的预留 ID);计划对同一状态的重复应用保持幂等,供崩溃恢复重放。
    """
    _known_profile(profile)
    if not isinstance(delta, dict):
        _reject("state_delta 必须为 JSON object")
    passthrough: list[tuple[str, Any]] = []
    hypothesis_set: dict[str, Any] | None = None
    hypothesis_outcome: dict[str, Any] | None = None
    claim_updates: tuple[tuple[str, dict[str, Any]], ...] = ()
    claim_changes: frozenset[str] = frozenset()
    path_nodes: tuple[str, ...] = ()
    gaps_opened: list[dict[str, Any]] = []
    gaps_resolved: list[str] = []
    related_candidates: tuple[dict[str, Any], ...] = ()

    hypothesis = _hypothesis_state(state)
    for key, value in delta.items():
        if key == "hypothesis":
            if not isinstance(value, dict):
                _reject("state_delta.hypothesis 必须为 JSON object")
            _known_keys(value, {"statement", "note"}, "state_delta.hypothesis")
            statement = _nonempty_string(
                value.get("statement"), "state_delta.hypothesis.statement")
            hypothesis_set = {
                "statement": statement,
                **({"note": note} if (note := _optional_string(
                    value.get("note"), "state_delta.hypothesis.note")) is not None else {}),
            }
        elif key == "hypothesis_outcome":
            if not isinstance(value, dict):
                _reject("state_delta.hypothesis_outcome 必须为 JSON object")
            _known_keys(
                value, {"outcome", "note"}, "state_delta.hypothesis_outcome")
            outcome = value.get("outcome")
            if outcome not in ("supported", "refuted"):
                _reject("state_delta.hypothesis_outcome.outcome 只允许 supported/refuted")
            if hypothesis["working"] is None:
                history = hypothesis["history"]
                last = history[-1] if history else None
                if not (isinstance(last, dict) and last.get("outcome") == outcome):
                    _reject(
                        "当前没有 working hypothesis,无法提交 hypothesis_outcome;"
                        "请先在 state_delta.hypothesis 设置新假设")
                hypothesis_outcome = None  # 恢复重放的幂等 no-op
            else:
                hypothesis_outcome = {
                    "outcome": outcome,
                    **({"note": note} if (note := _optional_string(
                        value.get("note"),
                        "state_delta.hypothesis_outcome.note")) is not None else {}),
                }
        elif key == "claims":
            claim_updates, claim_changes = _validate_claim_updates(
                value, state, evidence_ids, profile)
        elif key == "path_nodes":
            if not isinstance(value, list) or not value:
                _reject("state_delta.path_nodes 必须为非空字符串数组;"
                        "未变化请整体省略该字段")
            for item in value:
                _nonempty_string(item, "state_delta.path_nodes[]")
            path_nodes = tuple(value)
        elif key == "gaps_opened":
            if not isinstance(value, list) or not value:
                _reject("state_delta.gaps_opened 必须为非空数组;"
                        "未变化请整体省略该字段")
            existing_ids = {gap.get("id") for gap in _gaps_state(state)}
            for item in value:
                if not isinstance(item, dict):
                    _reject("state_delta.gaps_opened[] 必须为 JSON object")
                _known_keys(item, {"id", "description", "blocking"},
                            "state_delta.gaps_opened[]")
                gap_id = _nonempty_string(item.get("id"), "state_delta.gaps_opened[].id")
                _nonempty_string(
                    item.get("description"), "state_delta.gaps_opened[].description")
                if type(item.get("blocking")) is not bool:
                    _reject("state_delta.gaps_opened[].blocking 必须为布尔值")
                if gap_id not in existing_ids:  # 恢复重放对既有 id 跳过
                    gaps_opened.append({
                        "id": gap_id,
                        "description": item["description"],
                        "blocking": item["blocking"],
                    })
        elif key == "gaps_resolved":
            if not isinstance(value, list) or not value:
                _reject("state_delta.gaps_resolved 必须为非空 Gap ID 数组;"
                        "未变化请整体省略该字段")
            known_ids = {gap.get("id") for gap in _gaps_state(state)}
            for item in value:
                gap_id = _nonempty_string(item, "state_delta.gaps_resolved[]")
                if gap_id not in known_ids:
                    _reject(f"state_delta.gaps_resolved 含未知 Gap ID {gap_id!r}")
                gaps_resolved.append(gap_id)
        elif key == "related_candidates":
            related_candidates = _validate_related_candidate_updates(
                value, state, evidence_ids, related_origin)
        elif key in OWNED_STATE_KEYS:
            _reject(
                f"state_delta.{key} 是 Host 管理的结构化状态,不能直写;"
                "请使用对应的 hypothesis/claims/path_nodes/gaps_* 增量字段")
        else:
            passthrough.append((key, deepcopy(value)))
    try:
        cloned = [(key, clone_json_value(value, f"state_delta.{key}"))
                  for key, value in passthrough]
    except JsonValueError as exc:
        raise ProposalRejectedError(str(exc)) from exc
    return DeltaPlan(
        passthrough=tuple(cloned),
        hypothesis_set=hypothesis_set,
        hypothesis_outcome=hypothesis_outcome,
        claim_updates=claim_updates,
        claim_changes=claim_changes,
        path_nodes=path_nodes,
        gaps_opened=tuple(gaps_opened),
        gaps_resolved=tuple(gaps_resolved),
        related_candidates=related_candidates,
    )


def apply_delta_plan(state: dict[str, Any], plan: DeltaPlan) -> AppliedEffects:
    """把已校验计划应用到 state;免校验,重复应用幂等,返回进展信号。"""
    for key, value in plan.passthrough:
        state[key] = deepcopy(value)

    claims_changed: list[str] = []
    if plan.claim_updates:
        claims = state.setdefault("claims", {})
        for name, record in plan.claim_updates:
            prior = claims.get(name)
            prior_status = prior.get("status") if isinstance(prior, dict) else None
            claims[name] = deepcopy(record)
            if prior_status != record["status"]:
                claims_changed.append(name)

    hypothesis_changed = False
    if plan.hypothesis_outcome is not None or plan.hypothesis_set is not None:
        # 恢复出的畸形结构按空结构规整,绝不因深损坏在循环中途崩溃。
        hypothesis = _hypothesis_state(state)
        state["hypothesis"] = hypothesis
        if plan.hypothesis_outcome is not None:
            working = hypothesis["working"]
            if working is not None:
                retired = {**deepcopy(working),
                           "outcome": plan.hypothesis_outcome["outcome"]}
                if "note" in plan.hypothesis_outcome:
                    retired["note"] = plan.hypothesis_outcome["note"]
                hypothesis["history"].append(retired)
                hypothesis["working"] = None
                hypothesis_changed = True
        if plan.hypothesis_set is not None:
            working = hypothesis["working"]
            if working is None or working.get("statement") != plan.hypothesis_set["statement"]:
                if working is not None:
                    hypothesis["history"].append({**deepcopy(working), "outcome": "replaced"})
                hypothesis["working"] = deepcopy(dict(plan.hypothesis_set))
                hypothesis_changed = True

    path_added: list[str] = []
    if plan.path_nodes:
        nodes = state.setdefault("path_nodes", [])
        for node in plan.path_nodes:
            if node not in nodes:
                nodes.append(node)
                path_added.append(node)

    if plan.related_candidates:
        related = _related_state(state)
        state["related_candidates"] = related
        known = {item.get("proposal_id") for item in related}
        for item in plan.related_candidates:
            if item["proposal_id"] not in known:
                related.append(deepcopy(item))
                known.add(item["proposal_id"])

    gaps_resolved: list[str] = []
    if plan.gaps_opened or plan.gaps_resolved:
        gaps = _gaps_state(state)
        state["evidence_gaps"] = gaps
        for gap in plan.gaps_opened:
            if not any(existing.get("id") == gap["id"] for existing in gaps):
                gaps.append({**deepcopy(gap), "status": "open"})
        for gap_id in plan.gaps_resolved:
            for existing in gaps:
                if existing.get("id") == gap_id and existing.get("status") == "open":
                    existing["status"] = "resolved"
                    gaps_resolved.append(gap_id)

    return AppliedEffects(
        claims_changed=tuple(claims_changed),
        hypothesis_changed=hypothesis_changed,
        path_nodes_added=tuple(path_added),
        gaps_resolved=tuple(gaps_resolved),
    )


def apply_analysis_delta(
    state: dict[str, Any],
    delta: dict[str, Any],
    *,
    evidence_ids: frozenset[str],
    profile: str,
    related_origin: RelatedOrigin,
) -> AppliedEffects:
    """Evidence 集合不变时的一次性校验+应用便捷路径。

    Host 循环里的动作/close/submit 需要在校验与应用之间插入工具执行或
    trial gate,必须走 validate_analysis_delta + apply_delta_plan 两段式;
    本函数只服务不需要中段的调用方。
    """
    plan = validate_analysis_delta(
        state, delta, evidence_ids=evidence_ids, profile=profile,
        related_origin=related_origin)
    return apply_delta_plan(state, plan)


# ---- ready gate:必填项、反证处理与 blocking gap 的确定性门槛 ----

@dataclass(frozen=True)
class GateResult:
    """ready gate 评审结果;failures 逐条可回喂。"""

    unassessed: tuple[str, ...] = ()
    decisive_refuted: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    invalid: tuple[str, ...] = ()
    open_blocking_gaps: tuple[dict[str, Any], ...] = ()

    @property
    def ok(self) -> bool:
        return not (self.unassessed or self.decisive_refuted
                    or self.unsupported or self.invalid or self.open_blocking_gaps)

    def failures(self) -> list[str]:
        messages: list[str] = []
        if self.decisive_refuted:
            messages.append(
                "决定性 Claim 已被反驳: " + ", ".join(self.decisive_refuted)
                + ";正确出路是 close_investigation 结束为 rejected,而不是送复核")
        if self.unassessed:
            messages.append("必填 Claim 尚未评估: " + ", ".join(self.unassessed))
        if self.unsupported:
            messages.append(
                "supported Claim 缺少真实 Evidence 支撑: " + ", ".join(self.unsupported))
        if self.invalid:
            messages.append("Claim 记录损坏或非法: " + ", ".join(self.invalid))
        if self.open_blocking_gaps:
            messages.append(
                "存在未消解的 blocking evidence gap: "
                + ", ".join(str(gap.get("id")) for gap in self.open_blocking_gaps))
        return messages


def evaluate_ready_gate(
    state: dict[str, Any],
    *,
    profile: str,
    evidence_ids: frozenset[str],
) -> GateResult:
    """必填项全有合法状态、支撑引用真实 Evidence、决定性反驳已分流、无 blocking gap。"""
    _known_profile(profile)
    claims = state.get("claims")
    if not isinstance(claims, dict):
        claims = {}
    unassessed: list[str] = []
    decisive_refuted: list[str] = []
    unsupported: list[str] = []
    invalid: list[str] = []
    for name in required_claims(profile):
        record = claims.get(name)
        if record is None:
            unassessed.append(name)
            continue
        if not isinstance(record, dict):
            invalid.append(name)
            continue
        status = record.get("status")
        if status == "unassessed":
            unassessed.append(name)
            continue
        if status not in ASSESSABLE_STATUSES:
            invalid.append(name)
            continue
        # 决定性反驳的分流不依赖引用是否完好:无论如何正确出路都是
        # close_investigation 结束为 rejected,而不是送复核。
        if status == "refuted" and is_decisive(profile, name):
            decisive_refuted.append(name)
        refs = record.get("evidence_ids", [])
        if not isinstance(refs, list) or any(
                not isinstance(item, str) for item in refs):
            invalid.append(name)
            continue
        if any(item not in evidence_ids for item in refs):
            unsupported.append(name)
            continue
        if status == "supported" and not refs:
            unsupported.append(name)
            continue
        if status == "not_applicable" and is_decisive(profile, name):
            invalid.append(name)
            continue

    gaps = state.get("evidence_gaps")
    if gaps is None:
        gaps = []
    if not isinstance(gaps, list):
        invalid.append("evidence_gaps")
        gaps = []
    open_blocking = tuple(
        deepcopy(gap) for gap in gaps
        if isinstance(gap, dict) and gap.get("status") == "open"
        and gap.get("blocking") is True
    )
    return GateResult(
        unassessed=tuple(unassessed),
        decisive_refuted=tuple(decisive_refuted),
        unsupported=tuple(unsupported),
        invalid=tuple(invalid),
        open_blocking_gaps=open_blocking,
    )


# ---- 冻结 Verification Case:提交即快照,内容确定性可重放 ----

CASE_SCHEMA_VERSION = 1
ADMISSION_REASONS = ("ready", "evidence_gap")


def build_case_payload(
    *,
    candidate_id: str,
    investigation_id: str,
    profile: str,
    state: dict[str, Any],
    evidence_references: list[dict[str, Any]],
    gate: GateResult,
    admission_reason: str,
) -> dict[str, Any]:
    """冻结提交时刻的 Claim 快照、Evidence 引用与缺失项;不含任何 verdict 语义。"""
    _known_profile(profile)
    if admission_reason not in ADMISSION_REASONS:
        raise PolicyError(
            f"未知 admission reason {admission_reason!r};"
            f"允许值: {', '.join(ADMISSION_REASONS)}")
    claims = state.get("claims")
    if not isinstance(claims, dict):
        claims = {}
    frozen: dict[str, Any] = {}
    for name in required_claims(profile):
        record = claims.get(name)
        if isinstance(record, dict) and record.get("status") in ASSESSABLE_STATUSES:
            frozen[name] = deepcopy(record)
        else:
            frozen[name] = {"status": "unassessed", "evidence_ids": []}
    pending = tuple(
        name for name in required_claims(profile)
        if name in gate.unassessed or name in gate.invalid
    )
    blocking = [{"id": gap.get("id"), "description": gap.get("description")}
                for gap in gate.open_blocking_gaps]
    if admission_reason == "ready" and (pending or blocking):
        raise PolicyError("ready 案卷不允许携带缺失项;请先通过 ready gate 或改提 evidence_gap")
    if admission_reason == "evidence_gap" and not (pending or blocking):
        raise PolicyError(
            "evidence_gap 案卷必须冻结至少一项缺失(unassessed 必填 Claim 或 blocking gap)")
    return {
        "schema_version": CASE_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "investigation_id": investigation_id,
        "claim_profile": profile,
        "admission_reason": admission_reason,
        "claims": frozen,
        "evidence_references": deepcopy(evidence_references),
        "pending_claims": list(pending),
        "blocking_gaps": blocking,
    }


# ---- no-progress:只看已完成语义动作的进展信号 ----

NO_PROGRESS_LIMIT = 5


def action_progressed(effects: AppliedEffects, new_digest: str, prior_digests) -> bool:
    """新增非重复 Evidence、Claim/假设变化、路径节点或 gap 消解都算进展。"""
    if effects.any_progress():
        return True
    return new_digest not in prior_digests

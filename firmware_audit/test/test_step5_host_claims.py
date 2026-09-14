"""Host Claim/生命周期策略表驱动测试:零 IO,直接穷举状态机与门槛。"""
from __future__ import annotations

import pytest

from firmware_audit.step5_agent.host.candidates import CLAIM_PROFILES
from firmware_audit.step5_agent.host.claims import (
    ADMISSION_REASONS,
    ASSESSABLE_STATUSES,
    CLAIM_STATUSES,
    COMMON_DECISIVE_CLAIMS,
    COMMON_NON_DECISIVE_CLAIMS,
    DISPOSITIONS,
    LEGAL_LIFECYCLE_TRANSITIONS,
    LIFECYCLE_STATUSES,
    NO_PROGRESS_LIMIT,
    PROFILE_EXTRA_CLAIMS,
    STOP_REASONS,
    AppliedEffects,
    GateResult,
    PolicyError,
    action_progressed,
    apply_analysis_delta,
    apply_delta_plan,
    assert_lifecycle_transition,
    assert_terminal,
    build_case_payload,
    evaluate_ready_gate,
    is_decisive,
    profile_claim_document,
    required_claims,
    validate_analysis_delta,
)
from firmware_audit.step5_agent.host.session import ProposalRejectedError

EV = frozenset({"ev-000001", "ev-000002"})


def _supported(evidence_ids: list[str] | None = None) -> dict:
    return {"status": "supported", "evidence_ids": evidence_ids or ["ev-000001"]}


def _apply(delta: dict, state: dict | None = None, *,
           evidence_ids: frozenset[str] = EV, profile: str = "generic"):
    state = {} if state is None else state
    return state, apply_analysis_delta(
        state, delta, evidence_ids=evidence_ids, profile=profile)


# ---- S1:Profile 与 Claim 名单 ----

def test_profile_claim_sources_are_consistent() -> None:
    assert set(PROFILE_EXTRA_CLAIMS) == set(CLAIM_PROFILES)


@pytest.mark.parametrize("profile,extras", [
    ("generic", ()),
    ("data_propagation", ("input_source", "key_processing_relation",
                          "reaches_high_impact_operation")),
    ("config", ("config_value_effective", "config_scope")),
    ("credentials", ("material_valid", "access_boundary", "actual_usage")),
    ("memory", ("input_or_index_controlled", "boundary_check_missing",
                "related_operation_reachable")),
])
def test_required_claims_are_common_plus_profile_extras(
    profile: str, extras: tuple[str, ...],
) -> None:
    assert required_claims(profile) == (
        COMMON_DECISIVE_CLAIMS + COMMON_NON_DECISIVE_CLAIMS + extras)


@pytest.mark.parametrize("claim", COMMON_DECISIVE_CLAIMS)
@pytest.mark.parametrize("profile", CLAIM_PROFILES)
def test_common_decisive_claims_are_decisive_in_every_profile(
    profile: str, claim: str,
) -> None:
    assert is_decisive(profile, claim)


@pytest.mark.parametrize("claim", COMMON_NON_DECISIVE_CLAIMS)
@pytest.mark.parametrize("profile", CLAIM_PROFILES)
def test_preconditions_and_mitigations_stay_non_decisive(
    profile: str, claim: str,
) -> None:
    assert not is_decisive(profile, claim)


@pytest.mark.parametrize("profile,claim", [
    (profile, claim)
    for profile, extras in PROFILE_EXTRA_CLAIMS.items()
    for claim in extras
])
def test_profile_extra_claims_are_all_decisive(profile: str, claim: str) -> None:
    assert is_decisive(profile, claim)


@pytest.mark.parametrize("profile", CLAIM_PROFILES)
def test_profile_claim_document_lists_schema(profile: str) -> None:
    document = profile_claim_document(profile)
    assert document["profile"] == profile
    assert [item["name"] for item in document["claims"]] == list(required_claims(profile))
    assert all(item["label"] for item in document["claims"])
    assert document["statuses"] == list(CLAIM_STATUSES)


def test_unknown_profile_is_policy_error() -> None:
    with pytest.raises(PolicyError, match="未知 Claim Profile"):
        required_claims("injected")
    with pytest.raises(PolicyError, match="未知 Claim Profile"):
        is_decisive("injected", "root_cause")


# ---- S2:state_delta 两阶段校验/应用 ----

def test_hypothesis_set_archives_previous_as_replaced() -> None:
    state, effects = _apply({"hypothesis": {"statement": "固件校验被跳过"}})
    assert state["hypothesis"]["working"]["statement"] == "固件校验被跳过"
    assert state["hypothesis"]["history"] == []
    assert effects.hypothesis_changed

    state, effects = _apply({"hypothesis": {"statement": "校验存在但被绕过"}},
                            state=state)
    assert state["hypothesis"]["working"]["statement"] == "校验存在但被绕过"
    assert state["hypothesis"]["history"] == [
        {"statement": "固件校验被跳过", "outcome": "replaced"},
    ]
    assert effects.hypothesis_changed


def test_hypothesis_same_statement_replay_is_idempotent_noop() -> None:
    state, _ = _apply({"hypothesis": {"statement": "同一假设", "note": "初设"}})
    state, effects = _apply({"hypothesis": {"statement": "同一假设"}}, state=state)
    assert state["hypothesis"]["working"] == {
        "statement": "同一假设", "note": "初设",
    }
    assert state["hypothesis"]["history"] == []
    assert not effects.hypothesis_changed


def test_hypothesis_outcome_retires_working_into_history() -> None:
    state, _ = _apply({"hypothesis": {"statement": "未授权升级可行"}})
    state, effects = _apply(
        {"hypothesis_outcome": {"outcome": "refuted", "note": "签名强制"}},
        state=state)
    assert state["hypothesis"]["working"] is None
    assert state["hypothesis"]["history"] == [
        {"statement": "未授权升级可行", "outcome": "refuted", "note": "签名强制"},
    ]
    assert effects.hypothesis_changed


def test_hypothesis_outcome_replay_after_retire_is_idempotent() -> None:
    state, _ = _apply({"hypothesis": {"statement": "假设甲"}})
    state, _ = _apply({"hypothesis_outcome": {"outcome": "supported"}}, state=state)
    # 恢复重放:working 已空,但史册末条 outcome 一致 → no-op 而非报错。
    state, effects = _apply(
        {"hypothesis_outcome": {"outcome": "supported"}}, state=state)
    assert state["hypothesis"]["working"] is None
    assert len(state["hypothesis"]["history"]) == 1
    assert not effects.hypothesis_changed


def test_hypothesis_outcome_without_working_is_rejected() -> None:
    with pytest.raises(ProposalRejectedError, match="没有 working hypothesis"):
        _apply({"hypothesis_outcome": {"outcome": "supported"}})


def test_hypothesis_outcome_mismatched_replay_is_rejected() -> None:
    state, _ = _apply({"hypothesis": {"statement": "假设甲"}})
    state, _ = _apply({"hypothesis_outcome": {"outcome": "supported"}}, state=state)
    with pytest.raises(ProposalRejectedError, match="没有 working hypothesis"):
        _apply({"hypothesis_outcome": {"outcome": "refuted"}}, state=state)


@pytest.mark.parametrize("value", [
    {"statement": ""},
    {"statement": 7},
    {},
    {"statement": "合法", "invented": 1},
    {"outcome": "supported"},
    "假设",
])
def test_malformed_hypothesis_delta_is_rejected(value: object) -> None:
    with pytest.raises(ProposalRejectedError):
        _apply({"hypothesis": value})


@pytest.mark.parametrize("value", [
    {"outcome": "replaced"},
    {"outcome": "same"},
    {"outcome": None},
    {"outcome": "supported", "extra": True},
])
def test_malformed_hypothesis_outcome_is_rejected(value: object) -> None:
    with pytest.raises(ProposalRejectedError):
        _apply({"hypothesis_outcome": value})


def test_supported_claim_requires_owned_evidence() -> None:
    state, effects = _apply({"claims": {"root_cause": _supported()}})
    assert state["claims"]["root_cause"] == _supported()
    assert effects.claims_changed == ("root_cause",)

    with pytest.raises(ProposalRejectedError, match="不存在"):
        _apply({"claims": {"root_cause": _supported(["ev-999999"])}})
    with pytest.raises(ProposalRejectedError, match="至少一个"):
        _apply({"claims": {"root_cause": {"status": "supported", "evidence_ids": []}}})


def test_refuted_claim_may_cite_evidence_but_must_be_owned() -> None:
    state, _ = _apply({"claims": {
        "root_cause": {"status": "refuted", "evidence_ids": ["ev-000002"]}}})
    assert state["claims"]["root_cause"]["status"] == "refuted"

    with pytest.raises(ProposalRejectedError, match="不存在"):
        _apply({"claims": {
            "root_cause": {"status": "refuted", "evidence_ids": ["ev-999999"]}}})


def test_not_applicable_only_for_non_decisive_claims() -> None:
    state, _ = _apply({"claims": {"mitigations": {"status": "not_applicable"}}})
    assert state["claims"]["mitigations"]["status"] == "not_applicable"

    for decisive in COMMON_DECISIVE_CLAIMS:
        with pytest.raises(ProposalRejectedError, match="决定性"):
            _apply({"claims": {decisive: {"status": "not_applicable"}}})


def test_unknown_claim_name_rejected_per_profile() -> None:
    with pytest.raises(ProposalRejectedError, match="未知 Claim"):
        _apply({"claims": {"input_source": _supported()}})  # generic 无此项

    state, _ = _apply({"claims": {"input_source": _supported()}},
                      profile="data_propagation")
    assert state["claims"]["input_source"]["status"] == "supported"


@pytest.mark.parametrize("status", ["unassessed", "maybe", True, None])
def test_claim_status_enum_is_strict(status: object) -> None:
    with pytest.raises(ProposalRejectedError):
        _apply({"claims": {"root_cause": {"status": status}}})


def test_claim_update_with_same_status_is_not_progress() -> None:
    state, _ = _apply({"claims": {"root_cause": _supported()}})
    state, effects = _apply(
        {"claims": {"root_cause": {
            "status": "supported", "evidence_ids": ["ev-000001"],
            "note": "补充说明"}}},
        state=state)
    assert state["claims"]["root_cause"]["note"] == "补充说明"
    assert effects.claims_changed == ()


def test_path_nodes_append_once_and_dedupe() -> None:
    state, effects = _apply({"path_nodes": ["升级入口", "签名校验"]})
    assert state["path_nodes"] == ["升级入口", "签名校验"]
    assert effects.path_nodes_added == ("升级入口", "签名校验")

    state, effects = _apply({"path_nodes": ["签名校验", "解包写入"]}, state=state)
    assert state["path_nodes"] == ["升级入口", "签名校验", "解包写入"]
    assert effects.path_nodes_added == ("解包写入",)


@pytest.mark.parametrize("value", [[], ["ok", 7], ["ok", ""], "节点", [None]])
def test_malformed_path_nodes_rejected(value: object) -> None:
    with pytest.raises(ProposalRejectedError):
        _apply({"path_nodes": value})


def test_gap_lifecycle_open_resolve_and_replay() -> None:
    state, effects = _apply({"gaps_opened": [{
        "id": "gap-1", "description": "缺少运行时配置证据", "blocking": True}]})
    assert state["evidence_gaps"] == [{
        "id": "gap-1", "description": "缺少运行时配置证据",
        "blocking": True, "status": "open"}]

    # 恢复重放:同 id 已存在 → 跳过而非报错。
    state, effects = _apply({"gaps_opened": [{
        "id": "gap-1", "description": "缺少运行时配置证据", "blocking": True}]},
        state=state)
    assert len(state["evidence_gaps"]) == 1
    assert not effects.any_progress()

    state, effects = _apply({"gaps_resolved": ["gap-1"]}, state=state)
    assert state["evidence_gaps"][0]["status"] == "resolved"
    assert effects.gaps_resolved == ("gap-1",)

    state, effects = _apply({"gaps_resolved": ["gap-1"]}, state=state)
    assert state["evidence_gaps"][0]["status"] == "resolved"
    assert not effects.gaps_resolved


def test_resolving_unknown_gap_is_rejected() -> None:
    with pytest.raises(ProposalRejectedError, match="未知 Gap ID"):
        _apply({"gaps_resolved": ["gap-404"]})


@pytest.mark.parametrize("value", [
    [], [{"id": "gap-1", "description": "缺", "blocking": "yes"}],
    [{"id": "", "description": "缺", "blocking": True}],
    [{"id": "gap-1", "blocking": True}],
    [{"id": "gap-1", "description": "缺", "blocking": True, "extra": 1}],
])
def test_malformed_gap_openings_rejected(value: object) -> None:
    with pytest.raises(ProposalRejectedError):
        _apply({"gaps_opened": value})


def test_direct_writes_to_owned_gap_store_are_rejected() -> None:
    with pytest.raises(ProposalRejectedError, match="Host 管理"):
        _apply({"evidence_gaps": "直写"})


@pytest.mark.parametrize("key", ["hypothesis", "claims", "path_nodes"])
def test_non_structured_values_for_domain_keys_are_rejected(key: str) -> None:
    with pytest.raises(ProposalRejectedError):
        _apply({key: "非结构化直写"})


def test_unknown_keys_pass_through_as_agent_notes() -> None:
    state, _ = _apply({"checked_paths": ["extracted/etc"], "closure_note": "备注"})
    assert state == {"checked_paths": ["extracted/etc"], "closure_note": "备注"}


def test_corrupted_owned_structures_are_normalized_not_crashed() -> None:
    state: dict = {"hypothesis": "garbage", "evidence_gaps": "garbage"}
    state, effects = _apply({"hypothesis": {"statement": "重建假设"}}, state=state)
    assert state["hypothesis"] == {
        "working": {"statement": "重建假设"}, "history": []}
    assert effects.hypothesis_changed
    # 无 gap 操作时不触碰既有结构(即使它是畸形的)。
    assert state["evidence_gaps"] == "garbage"

    state, _ = _apply({"gaps_opened": [
        {"id": "gap-1", "description": "缺证据", "blocking": False}]}, state=state)
    assert state["evidence_gaps"] == [
        {"id": "gap-1", "description": "缺证据", "blocking": False, "status": "open"}]


def test_claim_delta_may_cite_this_actions_reserved_evidence() -> None:
    evidence_with_reserved = frozenset({"ev-000003"})
    state, effects = _apply(
        {"claims": {"target_exists": {"status": "supported",
                                      "evidence_ids": ["ev-000003"]}}},
        evidence_ids=evidence_with_reserved)
    assert effects.claims_changed == ("target_exists",)


def test_plan_apply_round_trip_is_idempotent() -> None:
    delta = {
        "hypothesis": {"statement": "令牌硬编码"},
        "claims": {"target_exists": _supported()},
        "path_nodes": ["配置读取"],
        "gaps_opened": [{"id": "gap-1", "description": "缺调用点", "blocking": False}],
        "note": "自由笔记",
    }
    state: dict = {}
    plan = validate_analysis_delta(state, delta, evidence_ids=EV, profile="generic")
    first = apply_delta_plan(state, plan)
    snapshot = {key: (list(value) if isinstance(value, list) else dict(value) if isinstance(value, dict) else value)
                for key, value in state.items()}
    second = apply_delta_plan(state, plan)
    assert not second.any_progress()
    assert snapshot == state
    assert first.any_progress()


# ---- S3:lifecycle / disposition / stop reason 守卫 ----

def test_legal_transition_table_matches_acceptance() -> None:
    assert LEGAL_LIFECYCLE_TRANSITIONS == {
        "queued": frozenset({"investigating", "finished"}),
        "investigating": frozenset({"ready_for_verification", "finished"}),
        "ready_for_verification": frozenset({"verifying", "finished"}),
        "verifying": frozenset({"finished"}),
        "finished": frozenset(),
    }


@pytest.mark.parametrize("current", LIFECYCLE_STATUSES)
@pytest.mark.parametrize("target", LIFECYCLE_STATUSES)
def test_transition_matrix(current: str, target: str) -> None:
    legal = current == target or target in LEGAL_LIFECYCLE_TRANSITIONS[current]
    if legal:
        assert_lifecycle_transition(current, target)
    else:
        with pytest.raises(PolicyError, match="非法 lifecycle 转换"):
            assert_lifecycle_transition(current, target)


@pytest.mark.parametrize("current,target", [
    ("queued", "verifying"),
    ("investigating", "queued"),
    ("investigating", "verifying"),
    ("ready_for_verification", "investigating"),
    ("finished", "investigating"),
    ("finished", "queued"),
])
def test_representative_illegal_transitions_rejected(
    current: str, target: str,
) -> None:
    with pytest.raises(PolicyError):
        assert_lifecycle_transition(current, target)


def test_unknown_lifecycle_status_rejected() -> None:
    with pytest.raises(PolicyError, match="未知 lifecycle"):
        assert_lifecycle_transition("queued", "done")
    with pytest.raises(PolicyError, match="未知 lifecycle"):
        assert_lifecycle_transition("done", "finished")


@pytest.mark.parametrize("lifecycle", [s for s in LIFECYCLE_STATUSES if s != "finished"])
def test_disposition_requires_finished(lifecycle: str) -> None:
    assert_terminal(lifecycle, None, None)
    with pytest.raises(PolicyError, match="尚未结束"):
        assert_terminal(lifecycle, "closed", "agent_closed")
    with pytest.raises(PolicyError, match="尚未结束"):
        assert_terminal(lifecycle, None, "no_progress")


@pytest.mark.parametrize("disposition", DISPOSITIONS)
@pytest.mark.parametrize("stop_reason", STOP_REASONS)
def test_finished_accepts_every_declared_pair(
    disposition: str, stop_reason: str,
) -> None:
    assert_terminal("finished", disposition, stop_reason)


@pytest.mark.parametrize("disposition,stop_reason", [
    (None, "completed"),
    ("confirmed", None),
    ("maybe", "completed"),
    ("confirmed", "because"),
])
def test_finished_rejects_incomplete_or_unknown_terminal_fields(
    disposition: str | None, stop_reason: str | None,
) -> None:
    with pytest.raises(PolicyError):
        assert_terminal("finished", disposition, stop_reason)


# ---- S4:ready gate ----

def _ready_state(profile: str = "generic") -> dict:
    state: dict = {"claims": {}}
    delta = {name: _supported() for name in required_claims(profile)}
    apply_analysis_delta(state, {"claims": delta}, evidence_ids=EV, profile=profile)
    return state


@pytest.mark.parametrize("profile", CLAIM_PROFILES)
def test_gate_passes_when_all_required_claims_supported(profile: str) -> None:
    gate = evaluate_ready_gate(_ready_state(profile), profile=profile, evidence_ids=EV)
    assert gate.ok
    assert gate.failures() == []


@pytest.mark.parametrize("profile", CLAIM_PROFILES)
def test_gate_fails_while_any_required_claim_unassessed(profile: str) -> None:
    state = _ready_state(profile)
    del state["claims"][required_claims(profile)[-1]]
    gate = evaluate_ready_gate(state, profile=profile, evidence_ids=EV)
    assert not gate.ok
    assert gate.unassessed == (required_claims(profile)[-1],)
    assert any("尚未评估" in message for message in gate.failures())


@pytest.mark.parametrize("claim", COMMON_DECISIVE_CLAIMS)
def test_decisive_refutation_directs_to_rejected_closure(claim: str) -> None:
    state = _ready_state()
    apply_analysis_delta(
        state, {"claims": {claim: {"status": "refuted"}}},
        evidence_ids=EV, profile="generic")
    gate = evaluate_ready_gate(state, profile="generic", evidence_ids=EV)
    assert not gate.ok
    assert gate.decisive_refuted == (claim,)
    assert any("rejected" in message for message in gate.failures())


def test_decisive_refutation_directs_rejection_even_with_broken_refs() -> None:
    # 恢复态防御:决定性 refuted 的记录引用失实时,仍必须给出"结束为
    # rejected"的指引,而不是退化为普通 unsupported 失败。
    state = {"claims": {"root_cause": {
        "status": "refuted", "evidence_ids": ["ev-999999"]}}}
    gate = evaluate_ready_gate(state, profile="generic", evidence_ids=EV)
    assert gate.decisive_refuted == ("root_cause",)
    assert "root_cause" in gate.unsupported
    assert any("rejected" in message for message in gate.failures())


@pytest.mark.parametrize("claim", COMMON_NON_DECISIVE_CLAIMS)
def test_non_decisive_states_do_not_block_ready(claim: str) -> None:
    state = _ready_state()
    apply_analysis_delta(
        state, {"claims": {claim: {"status": "not_applicable"}}},
        evidence_ids=EV, profile="generic")
    assert evaluate_ready_gate(state, profile="generic", evidence_ids=EV).ok

    apply_analysis_delta(
        state, {"claims": {claim: {"status": "refuted"}}},
        evidence_ids=EV, profile="generic")
    assert evaluate_ready_gate(state, profile="generic", evidence_ids=EV).ok


def test_supported_claim_without_real_evidence_fails_gate() -> None:
    state = _ready_state()
    # 模拟恢复出的失约状态:引用了不存在的 Evidence。
    state["claims"]["root_cause"] = {"status": "supported",
                                     "evidence_ids": ["ev-999999"]}
    gate = evaluate_ready_gate(state, profile="generic", evidence_ids=EV)
    assert not gate.ok
    assert gate.unsupported == ("root_cause",)


def test_open_blocking_gap_blocks_ready_until_resolved() -> None:
    state = _ready_state()
    apply_analysis_delta(state, {"gaps_opened": [
        {"id": "gap-1", "description": "缺运行时证据", "blocking": True},
        {"id": "gap-2", "description": "备注性缺口", "blocking": False},
    ]}, evidence_ids=EV, profile="generic")
    gate = evaluate_ready_gate(state, profile="generic", evidence_ids=EV)
    assert not gate.ok
    assert [gap["id"] for gap in gate.open_blocking_gaps] == ["gap-1"]

    apply_analysis_delta(state, {"gaps_resolved": ["gap-1"]},
                         evidence_ids=EV, profile="generic")
    assert evaluate_ready_gate(state, profile="generic", evidence_ids=EV).ok


def test_corrupted_claim_records_fail_gate_instead_of_crashing() -> None:
    state = {"claims": {"root_cause": "garbage", "target_exists": {"status": "maybe"}}}
    gate = evaluate_ready_gate(state, profile="generic", evidence_ids=EV)
    assert not gate.ok
    assert set(gate.invalid) == {"root_cause", "target_exists"}
    assert gate.unassessed == tuple(
        name for name in required_claims("generic")
        if name not in ("root_cause", "target_exists"))


# ---- S5:冻结案卷 ----

def _references() -> list[dict]:
    return [{
        "evidence_id": "ev-000001", "tool": "read_file",
        "arguments": {"path": "extracted/etc/device.conf"},
        "summary": "token=...", "location": "investigations/cand-0001/evidence/ev-000001.json",
        "digest": "a" * 64, "candidate_id": "cand-0001",
        "investigation_id": "inv-0001", "sequence": 1,
    }]


def test_ready_case_freezes_full_claim_snapshot() -> None:
    state = _ready_state("config")
    gate = evaluate_ready_gate(state, profile="config", evidence_ids=EV)
    payload = build_case_payload(
        candidate_id="cand-0001", investigation_id="inv-0001",
        profile="config", state=state, evidence_references=_references(),
        gate=gate, admission_reason="ready")
    assert payload["schema_version"] == 1
    assert payload["admission_reason"] == "ready"
    assert list(payload["claims"]) == list(required_claims("config"))
    assert payload["pending_claims"] == []
    assert payload["blocking_gaps"] == []
    assert payload["evidence_references"][0]["evidence_id"] == "ev-000001"
    assert build_case_payload(
        candidate_id="cand-0001", investigation_id="inv-0001",
        profile="config", state=state, evidence_references=_references(),
        gate=gate, admission_reason="ready") == payload  # 内容确定性


def test_evidence_gap_case_freezes_pending_and_gaps() -> None:
    state: dict = {}
    apply_analysis_delta(state, {
        "claims": {"target_exists": _supported()},
        "gaps_opened": [{"id": "gap-1", "description": "缺调用点证据",
                         "blocking": True}],
    }, evidence_ids=EV, profile="generic")
    gate = evaluate_ready_gate(state, profile="generic", evidence_ids=EV)
    assert not gate.ok
    payload = build_case_payload(
        candidate_id="cand-0002", investigation_id="inv-0002",
        profile="generic", state=state, evidence_references=[],
        gate=gate, admission_reason="evidence_gap")
    assert payload["admission_reason"] == "evidence_gap"
    assert payload["claims"]["target_exists"] == _supported()
    assert payload["claims"]["root_cause"]["status"] == "unassessed"
    assert payload["pending_claims"] == [
        name for name in required_claims("generic")
        if name != "target_exists"]
    assert payload["blocking_gaps"] == [
        {"id": "gap-1", "description": "缺调用点证据"}]


def test_case_payload_rejects_disguised_submissions() -> None:
    ready = _ready_state()
    gate = evaluate_ready_gate(ready, profile="generic", evidence_ids=EV)
    with pytest.raises(PolicyError, match="不允许携带缺失项"):
        build_case_payload(
            candidate_id="c", investigation_id="i", profile="generic",
            state=ready, evidence_references=[], gate=GateResult(
                unassessed=("root_cause",)),
            admission_reason="ready")

    with pytest.raises(PolicyError, match="至少一项缺失"):
        build_case_payload(
            candidate_id="c", investigation_id="i", profile="generic",
            state=ready, evidence_references=[], gate=gate,
            admission_reason="evidence_gap")

    with pytest.raises(PolicyError, match="admission"):
        build_case_payload(
            candidate_id="c", investigation_id="i", profile="generic",
            state=ready, evidence_references=[], gate=gate,
            admission_reason="someday")


def test_admission_reason_vocabulary() -> None:
    assert ADMISSION_REASONS == ("ready", "evidence_gap")
    assert NO_PROGRESS_LIMIT == 5
    assert set(ASSESSABLE_STATUSES) < set(CLAIM_STATUSES)


# ---- no-progress 信号 ----

def test_action_progressed_combines_delta_and_digest_signals() -> None:
    no_effects = AppliedEffects()
    assert action_progressed(no_effects, "digest-new", {"digest-old"})
    assert not action_progressed(no_effects, "digest-old", {"digest-old"})
    assert action_progressed(
        AppliedEffects(claims_changed=("root_cause",)),
        "digest-old", {"digest-old"})
    assert action_progressed(
        AppliedEffects(hypothesis_changed=True), "digest-old", {"digest-old"})
    assert action_progressed(
        AppliedEffects(path_nodes_added=("node",)), "digest-old", {"digest-old"})
    assert action_progressed(
        AppliedEffects(gaps_resolved=("gap-1",)), "digest-old", {"digest-old"})

"""Host Verification 策略与动作循环测试:纯策略表驱动 + 真 Host seam。"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from firmware_audit.step5_agent.host import (
    ActionProposal,
    FinalProposal,
    HostAnalysisTracer,
    HostVerificationRunner,
    ProposalRejectedError,
    parse_proposal,
    required_claims,
)
from firmware_audit.step5_agent.host import verification as verification_module
from firmware_audit.step5_agent.host.verification import (
    CLAIM_RESULT_JUDGMENTS,
    VERIFICATION_SESSION_SYSTEM,
    DEFAULT_VERIFICATION_MAX_ROUNDS,
    FINDING_SCHEMA_VERSION,
    RESULTS_SCHEMA_VERSION,
    aggregate_verdict,
    apply_verification_delta_plan,
    build_case_brief,
    build_finding_payload,
    load_cases,
    plan_verification_queue,
    resolve_verification_max_rounds,
    validate_verification_delta,
)
from firmware_audit.step5_agent.providers.tools.base import ToolResult
from firmware_audit.step5_agent.host.store import InvestigationStore, StoreError

GENERIC_REQUIRED = (
    "target_exists", "root_cause", "trigger_or_exposure", "actual_impact",
    "preconditions", "mitigations",
)


def _frozen_claim(evidence_id: str = "ev-000001", note: str | None = None) -> dict:
    record = {"status": "supported", "evidence_ids": [evidence_id]}
    if note is not None:
        record["note"] = note
    return record


def _case_payload(
    candidate_id: str = "cand-0001",
    *,
    admission: str = "ready",
    profile: str = "generic",
    note: str | None = "analysis 阶段的说明性 rationale",
    pending: tuple[str, ...] = (),
    blocking: tuple[dict, ...] = (),
) -> dict:
    claims = {name: _frozen_claim(note=note) for name in required_claims(profile)}
    if admission == "evidence_gap":
        for name in pending or GENERIC_REQUIRED[:1]:
            claims[name] = {"status": "unassessed", "evidence_ids": []}
    return {
        "schema_version": 1,
        "candidate_id": candidate_id,
        "investigation_id": "inv-" + candidate_id.removeprefix("cand-"),
        "claim_profile": profile,
        "admission_reason": admission,
        "claims": claims,
        "evidence_references": [{
            "evidence_id": "ev-000001",
            "tool": "read_file",
            "arguments": {"path": "extracted/etc/device.conf"},
            "summary": "配置包含 token=literal",
            "location": "investigations/cand-0001/evidence/ev-000001.json",
            "digest": "a" * 64,
            "candidate_id": candidate_id,
            "investigation_id": "inv-0001",
            "sequence": 1,
        }],
        "pending_claims": list(pending or (GENERIC_REQUIRED[:1] if admission == "evidence_gap" else ())),
        "blocking_gaps": [dict(gap) for gap in blocking],
    }


def _result(judgment: str, evidence_id: str | None = "ev-000001") -> dict:
    record = {
        "judgment": judgment,
        "observed": "重新读取配置确认字段真实存在",
        "method": "read_file 独立复核",
        "evidence_ids": [evidence_id] if evidence_id else [],
    }
    if judgment == "unresolved":
        record["limitations"] = "沙箱解释器不可用,无法动态验证"
    return record


def _validate(
    state: dict | None = None,
    delta: dict | None = None,
    *,
    evidence_ids: frozenset[str] = frozenset({"ev-000001"}),
    profile: str = "generic",
    case: dict | None = None,
):
    payload = case or _case_payload()
    return validate_verification_delta(
        state or {}, delta or {},
        evidence_ids=evidence_ids, profile=profile,
        case_candidate_id=payload["candidate_id"],
        case_investigation_id=payload["investigation_id"],
    )


# ---- S1 纯策略:Claim Result 校验 ----


def test_claim_result_minimal_valid_plan() -> None:
    plan = _validate(delta={"claim_results": {"root_cause": _result("supported")}})
    assert plan.claim_results == (
        ("root_cause", {
            "judgment": "supported",
            "observed": "重新读取配置确认字段真实存在",
            "method": "read_file 独立复核",
            "evidence_ids": ["ev-000001"],
        }),
    )
    assert plan.passthrough == ()
    assert plan.related_candidates == ()


def test_claim_result_limits_and_passthrough_roundtrip() -> None:
    delta = {
        "claim_results": {"mitigations": {
            "judgment": "not_applicable", "observed": "未见缓解实现",
            "method": "search_code 全树检索", "evidence_ids": [],
            "limitations": "仅覆盖文本可检索的缓解",
        }},
        "session_note": {"kept": True},
    }
    plan = _validate(delta=delta)
    assert plan.claim_results[0][1]["limitations"].startswith("仅覆盖")
    assert plan.passthrough == (("session_note", {"kept": True}),)


def test_claim_result_unknown_name_is_rejected() -> None:
    with pytest.raises(ProposalRejectedError, match="未知 Claim"):
        _validate(delta={"claim_results": {"invented_claim": _result("supported")}})


def test_claim_result_judgment_enum_is_enforced() -> None:
    broken = _result("supported")
    broken["judgment"] = "partially"
    with pytest.raises(ProposalRejectedError, match="judgment"):
        _validate(delta={"claim_results": {"root_cause": broken}})


@pytest.mark.parametrize("judgment", CLAIM_RESULT_JUDGMENTS)
def test_claim_result_fields_required_for_every_judgment(judgment: str) -> None:
    # 非决定性 Claim 上逐判断校验 observed/method,避免与 not_applicable 红线耦合。
    with pytest.raises(ProposalRejectedError, match="observed"):
        _validate(delta={"claim_results": {
            "preconditions": {**_result(judgment), "observed": " "}}})
    with pytest.raises(ProposalRejectedError, match="method"):
        _validate(delta={"claim_results": {
            "preconditions": {**_result(judgment), "method": ""}}})


@pytest.mark.parametrize("judgment", ["supported", "refuted"])
def test_positive_judgments_require_session_evidence(judgment: str) -> None:
    with pytest.raises(ProposalRejectedError, match="独立取得的 Evidence"):
        _validate(delta={"claim_results": {name: _result(judgment, None)}
                         for name in GENERIC_REQUIRED[:1]})


def test_unresolved_and_not_applicable_allow_empty_evidence() -> None:
    plan = _validate(delta={
        "claim_results": {
            "preconditions": _result("not_applicable", None),
            "mitigations": _result("unresolved", None),
        }})
    assert [name for name, _ in plan.claim_results] == ["preconditions", "mitigations"]
    assert all(record["evidence_ids"] == [] for _, record in plan.claim_results)


def test_decisive_claim_cannot_be_not_applicable() -> None:
    with pytest.raises(ProposalRejectedError, match="决定性 Claim"):
        _validate(delta={"claim_results": {"root_cause": _result("not_applicable")}})


def test_claim_result_rejects_analysis_case_evidence() -> None:
    # 冻结案卷自带的 ev-000001 属于 analysis 会话;本会话只有 ev-000002。
    with pytest.raises(ProposalRejectedError, match="不属于本次复核会话"):
        _validate(
            delta={"claim_results": {"root_cause": _result("supported", "ev-000001")}},
            evidence_ids=frozenset({"ev-000002"}))


def test_claim_result_rejects_unknown_fields_and_non_object_updates() -> None:
    with pytest.raises(ProposalRejectedError, match="未知字段"):
        _validate(delta={"claim_results": {
            "root_cause": {**_result("supported"), "severity": "high"}}})
    with pytest.raises(ProposalRejectedError, match="claim_results 必须为"):
        _validate(delta={"claim_results": ["root_cause"]})


def test_verification_cannot_rewrite_analysis_owned_state() -> None:
    with pytest.raises(ProposalRejectedError, match="复核不可改写"):
        _validate(delta={"claims": {"root_cause": _frozen_claim()}})
    with pytest.raises(ProposalRejectedError, match="复核不可改写"):
        _validate(delta={"hypothesis": {"statement": "复核中的假设"}})


def test_apply_plan_is_idempotent_and_last_write_wins() -> None:
    state: dict = {}
    plan = _validate(delta={"claim_results": {"root_cause": _result("supported")}})
    apply_verification_delta_plan(state, plan)
    apply_verification_delta_plan(state, plan)
    assert state["claim_results"] == {"root_cause": _result("supported")}

    revised = _validate(delta={"claim_results": {
        "root_cause": _result("refuted", "ev-000001")}})
    apply_verification_delta_plan(state, revised)
    assert state["claim_results"]["root_cause"]["judgment"] == "refuted"


# ---- S1 纯策略:Related Candidate 校验 ----


def _related_entry(**overrides) -> dict:
    entry = {
        "proposal_id": "rel-0001",
        "kind": "signal",
        "target": "extracted/bin/updater",
        "signal": "升级处理器解析未校验长度字段",
        "evidence_id": "ev-000002",
        "next_action": "反编译解析函数确认边界检查",
        "anchor": "parse_header+0x42",
        "mechanism": "integer overflow",
    }
    entry.update(overrides)
    return entry


def test_related_candidate_is_normalized_with_origin() -> None:
    plan = _validate(
        delta={"related_candidates": [_related_entry()]},
        evidence_ids=frozenset({"ev-000002"}),
    )
    assert len(plan.related_candidates) == 1
    record = plan.related_candidates[0]
    assert record["origin"] == {
        "relation": "verification_related",
        "from_candidate": "cand-0001",
        "from_investigation": "inv-0001",
    }
    assert record["target"] == "extracted/bin/updater"
    assert record["claim_profile"] == "generic"


def test_related_candidate_requires_independent_anchor_or_mechanism() -> None:
    with pytest.raises(ProposalRejectedError, match="独立入口、位置或机制"):
        _validate(
            delta={"related_candidates": [
                _related_entry(anchor="", mechanism="")]},
            evidence_ids=frozenset({"ev-000002"}))


def test_coverage_related_candidate_requires_component_or_goal() -> None:
    entry = _related_entry(
        kind="coverage", anchor="", mechanism="",
        component_or_entry="", check_goal="",
    )
    with pytest.raises(ProposalRejectedError, match="独立入口、位置或机制"):
        _validate(
            delta={"related_candidates": [entry]},
            evidence_ids=frozenset({"ev-000002"}))


def test_related_candidate_must_cite_session_evidence() -> None:
    with pytest.raises(ProposalRejectedError, match="本次复核会话独立取得"):
        _validate(
            delta={"related_candidates": [
                _related_entry(evidence_id="ev-000001")]},
            evidence_ids=frozenset({"ev-000002"}))


def test_related_candidate_rejects_broken_intake_contract() -> None:
    with pytest.raises(ProposalRejectedError, match="Candidate 契约"):
        _validate(
            delta={"related_candidates": [_related_entry(target="")]},
            evidence_ids=frozenset({"ev-000002"}))


def test_apply_plan_accumulates_related_and_dedups_by_proposal_id() -> None:
    state: dict = {}
    plan = _validate(
        delta={"related_candidates": [_related_entry()]},
        evidence_ids=frozenset({"ev-000002"}),
    )
    apply_verification_delta_plan(state, plan)
    apply_verification_delta_plan(state, plan)
    assert len(state["related_candidates"]) == 1

    second = _validate(
        delta={"related_candidates": [
            _related_entry(proposal_id="rel-0002", mechanism="path traversal")]},
        evidence_ids=frozenset({"ev-000002"}),
    )
    apply_verification_delta_plan(state, second)
    assert [item["proposal_id"] for item in state["related_candidates"]] == [
        "rel-0001", "rel-0002"]


# ---- S1 纯策略:verdict 聚合 ----


def _all_supported(results: dict | None = None) -> dict:
    return results or {name: _result("supported") for name in GENERIC_REQUIRED}


def test_aggregate_confirmed_when_all_required_independently_supported() -> None:
    verdict = aggregate_verdict("generic", _all_supported())
    assert verdict.verdict == "confirmed"
    assert verdict.decisive_refuted == ()
    assert verdict.unsupported == ()


def test_aggregate_confirmed_allows_non_decisive_not_applicable() -> None:
    results = _all_supported()
    results["preconditions"] = _result("not_applicable", None)
    results["mitigations"] = _result("not_applicable", None)
    assert aggregate_verdict("generic", results).verdict == "confirmed"


def test_aggregate_rejected_on_decisive_refutation() -> None:
    results = _all_supported()
    results["root_cause"] = _result("refuted")
    verdict = aggregate_verdict("generic", results)
    assert verdict.verdict == "rejected"
    assert verdict.decisive_refuted == ("root_cause",)


def test_aggregate_decisive_refutation_directs_rejection_even_with_broken_record() -> None:
    results = _all_supported()
    results["actual_impact"] = {"judgment": "refuted"}
    verdict = aggregate_verdict("generic", results)
    assert verdict.verdict == "rejected"
    assert verdict.decisive_refuted == ("actual_impact",)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda r: r.update({"root_cause": _result("unresolved")}),
                     id="unresolved-decisive"),
        pytest.param(lambda r: r.update({"mitigations": _result("refuted")}),
                     id="refuted-non-decisive"),
        pytest.param(lambda r: r.update({"mitigations": _result("unresolved", None)}),
                     id="unresolved-non-decisive"),
        pytest.param(lambda r: r.pop("trigger_or_exposure"), id="missing-claim"),
        pytest.param(lambda r: r.update({"target_exists": "损坏记录"}),
                     id="corrupted-record"),
        pytest.param(lambda r: r.update({
            "target_exists": {**_result("supported"), "evidence_ids": []}}),
                     id="supported-without-refs"),
    ],
)
def test_aggregate_inconclusive_for_incomplete_or_tool_limited_results(mutate) -> None:
    results = _all_supported()
    mutate(results)
    verdict = aggregate_verdict("generic", results)
    assert verdict.verdict == "inconclusive"
    assert verdict.decisive_refuted == ()


def test_aggregate_uses_profile_extras_as_decisive() -> None:
    extras = ("input_source", "key_processing_relation",
              "reaches_high_impact_operation")
    results = _all_supported()
    for name in extras:
        results[name] = _result("supported")
    assert aggregate_verdict("data_propagation", results).verdict == "confirmed"

    results[extras[1]] = _result("refuted")
    verdict = aggregate_verdict("data_propagation", results)
    assert verdict.verdict == "rejected"
    assert verdict.decisive_refuted == ("key_processing_relation",)


def test_aggregate_tolerates_corrupted_container() -> None:
    assert aggregate_verdict("generic", None).verdict == "inconclusive"
    assert aggregate_verdict("generic", ["not", "a", "dict"]).verdict == "inconclusive"


# ---- S1 纯策略:案卷队列 ----


def test_queue_takes_all_ready_first_then_priority_gaps() -> None:
    cases = [
        _case_payload("cand-0003", admission="evidence_gap"),
        _case_payload("cand-0001", admission="ready"),
        _case_payload("cand-0004", admission="evidence_gap"),
        _case_payload("cand-0002", admission="ready"),
    ]
    queue = plan_verification_queue(
        cases, priority_of={"cand-0003": 5, "cand-0004": 7})
    assert queue == ("cand-0001", "cand-0002", "cand-0004", "cand-0003")


def test_queue_breaks_priority_ties_by_creation_order() -> None:
    cases = [
        _case_payload("cand-0002", admission="evidence_gap"),
        _case_payload("cand-0001", admission="evidence_gap"),
    ]
    assert plan_verification_queue(cases, priority_of={}) == ("cand-0001", "cand-0002")


def test_queue_gap_budget_never_truncates_ready() -> None:
    cases = [
        _case_payload("cand-0001", admission="ready"),
        _case_payload("cand-0002", admission="ready"),
        _case_payload("cand-0003", admission="evidence_gap"),
        _case_payload("cand-0004", admission="evidence_gap"),
    ]
    assert plan_verification_queue(
        cases, priority_of={"cand-0003": 1}, max_gap_cases=0,
    ) == ("cand-0001", "cand-0002")
    assert plan_verification_queue(
        cases, priority_of={"cand-0003": 1}, max_gap_cases=1,
    ) == ("cand-0001", "cand-0002", "cand-0003")


@pytest.mark.parametrize("bad", [-1, "2", 1.5])
def test_queue_rejects_invalid_gap_budget(bad) -> None:
    with pytest.raises(ValueError, match="max_gap_cases"):
        plan_verification_queue([], priority_of={}, max_gap_cases=bad)


def test_queue_rejects_duplicates_and_unknown_admission() -> None:
    with pytest.raises(ValueError, match="重复"):
        plan_verification_queue(
            [_case_payload("cand-0001"), _case_payload("cand-0001")],
            priority_of={})
    broken = _case_payload("cand-0001")
    broken["admission_reason"] = "urgent"
    with pytest.raises(ValueError, match="admission_reason"):
        plan_verification_queue([broken], priority_of={})


# ---- S1 纯策略:load_cases 与简报防锚定 ----


def _write_case(run_dir: Path, payload: dict) -> Path:
    path = run_dir / "verifications" / payload["candidate_id"] / "case.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


def test_load_cases_returns_sorted_valid_payloads(tmp_path: Path) -> None:
    _write_case(tmp_path, _case_payload("cand-0002"))
    _write_case(tmp_path, _case_payload("cand-0001", admission="evidence_gap",
                                        pending=("target_exists",)))
    cases = load_cases(tmp_path)
    assert [case["candidate_id"] for case in cases] == ["cand-0001", "cand-0002"]
    assert load_cases(tmp_path / "不存在") == []


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda c: c.update(schema_version=2), id="version"),
        pytest.param(lambda c: c.update(candidate_id="cand-0099"), id="identity"),
        pytest.param(lambda c: c.update(admission_reason="urgent"), id="admission"),
        pytest.param(lambda c: c.update(claim_profile="invented"), id="profile"),
        pytest.param(lambda c: c.pop("evidence_references"), id="references"),
        pytest.param(lambda c: c["claims"].pop("root_cause"), id="missing-claim"),
    ],
)
def test_load_cases_rejects_corrupt_or_incompatible_cases(tmp_path, mutate) -> None:
    payload = _case_payload()
    mutate(payload)
    # 固定写入 cand-0001 目录,使 identity 用例产生目录与 payload 不一致。
    path = tmp_path / "verifications" / "cand-0001" / "case.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(StoreError):
        load_cases(tmp_path)


def test_load_cases_rejects_broken_json(tmp_path: Path) -> None:
    path = tmp_path / "verifications" / "cand-0001" / "case.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(StoreError, match="冻结案卷损坏"):
        load_cases(tmp_path)


def test_case_brief_omits_analysis_verdicts_and_notes() -> None:
    case = _case_payload()
    brief = build_case_brief(
        case, {
            "kind": "signal", "target": "extracted/etc/device.conf",
            "signal": "管理配置包含凭据样式文本",
            "next_action": "确认配置生效路径",
            "possible_source": None, "possible_sink": "device service",
        }, remaining_rounds=12)
    assert brief["candidate"]["target"] == "extracted/etc/device.conf"
    assert brief["claim_schema"]["profile"] == "generic"
    assert brief["remaining_rounds"] == 12
    # 冻结案卷的逐项判定与说明不进简报:复核不被 analysis 结论锚定。
    serialized = json.dumps(brief, ensure_ascii=False)
    assert '"status"' not in serialized
    assert "analysis 阶段的说明性 rationale" not in serialized
    assert brief["evidence_references"] == [{
        "evidence_id": "ev-000001",
        "tool": "read_file",
        "arguments": {"path": "extracted/etc/device.conf"},
        "summary": "配置包含 token=literal",
        "location": "investigations/cand-0001/evidence/ev-000001.json",
        "digest": "a" * 64,
    }]
    assert "不可作为 Verification 的支持证据" in brief["evidence_references_note"]


def test_case_brief_carries_gap_mission() -> None:
    case = _case_payload(
        admission="evidence_gap", pending=("target_exists",),
        blocking=({"id": "gap-1", "description": "缺少运行时取证"},))
    brief = build_case_brief(case, {"target": "extracted/bin/router"})
    assert brief["admission_reason"] == "evidence_gap"
    assert brief["pending_claims"] == ["target_exists"]
    assert brief["blocking_gaps"] == [{"id": "gap-1", "description": "缺少运行时取证"}]


def test_finding_payload_is_deterministic_and_ordered() -> None:
    case = _case_payload()
    results = _all_supported()
    payload = build_finding_payload(
        finding_id="f-0001", case_payload=case, claim_results=results,
        evidence_references=[{"evidence_id": "ev-000002"}],
        related_candidates=[{"proposal_id": "rel-0001"}])
    assert payload["schema_version"] == FINDING_SCHEMA_VERSION == 1
    assert payload["verdict"] == "confirmed"
    assert set(payload["claims"]) == set(GENERIC_REQUIRED)
    assert payload["evidence_references"] == [{"evidence_id": "ev-000002"}]
    again = build_finding_payload(
        finding_id="f-0001", case_payload=case, claim_results=results,
        evidence_references=[{"evidence_id": "ev-000002"}],
        related_candidates=[{"proposal_id": "rel-0001"}])
    assert payload == again


def test_results_schema_version_pinned() -> None:
    assert RESULTS_SCHEMA_VERSION == 1


def test_default_rounds_and_env_override(monkeypatch) -> None:
    assert DEFAULT_VERIFICATION_MAX_ROUNDS == 15
    assert resolve_verification_max_rounds() == 15
    monkeypatch.setenv("STEP5_VERIFICATION_MAX_ITERS", "3")
    assert resolve_verification_max_rounds() == 3
    monkeypatch.setenv("STEP5_VERIFICATION_MAX_ITERS", "not-a-number")
    assert resolve_verification_max_rounds() == 15
    monkeypatch.setenv("STEP5_VERIFICATION_MAX_ITERS", "0")
    assert resolve_verification_max_rounds() == 1


# ---- S3/S4 Action Loop:真 tracer 提案 → 独立复核 → Host 聚合 ----


class FakeSession:
    def __init__(self, proposals: list[object], *, role: str = "verification"):
        self.role = role
        self.proposals = iter(proposals)
        self.inputs: list[str | None] = []

    def step(self, input_message: str | None = None):
        self.inputs.append(input_message)
        return next(self.proposals)


class FakeTool:
    def __init__(self, result: ToolResult):
        self.result = result
        self.calls: list[dict] = []

    def execute(self, **arguments):
        self.calls.append(arguments)
        return deepcopy(self.result)


def _submit_ready_case(
    tracer: HostAnalysisTracer,
    candidate_id: str,
    *,
    admission: str = "ready",
    evidence_id: str = "ev-000001",
) -> None:
    if admission == "ready":
        delta = {"claims": {
            name: {"status": "supported", "evidence_ids": [evidence_id]}
            for name in GENERIC_REQUIRED}}
    else:
        delta = {
            "claims": {"target_exists": {
                "status": "supported", "evidence_ids": [evidence_id]}},
            "gaps_opened": [{
                "id": "gap-1", "description": "其余必填 Claim 缺少证据",
                "blocking": True}],
        }
    replies = [
        {"decision_summary": "一轮完成全部判定",
         "state_delta": delta,
         "next": {"kind": "tool_action", "tool": "read_file",
                  "arguments": {"path": "extracted/etc/device.conf"}}},
        {"decision_summary": "提交案卷",
         "state_delta": {"admission_reason": admission},
         "next": {"kind": "submit_case"}},
    ]
    session = FakeSession(
        [parse_proposal(json.dumps(reply), "analysis") for reply in replies],
        role="analysis",
    )
    tracer.run_analysis(candidate_id, session)


def _prepared_tracer(tmp_path: Path, *, count: int = 1,
                     admission: str = "ready") -> tuple[HostAnalysisTracer, list[str]]:
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    tracer = HostAnalysisTracer(tmp_path, {"read_file": tool})
    ids = []
    for index in range(count):
        candidate = tracer.add_candidate({
            "target": f"extracted/etc/device{index + 1}.conf",
            "signal": "管理配置包含凭据样式文本",
            "next_action": "确认配置生效路径",
        })
        _submit_ready_case(tracer, candidate.candidate_id, admission=admission,
                           evidence_id=f"ev-{index + 1:06d}")
        ids.append(candidate.candidate_id)
    return tracer, ids


def _v_action(state_delta: dict) -> ActionProposal:
    return ActionProposal(
        decision_summary="独立重新取证并记录判定",
        state_delta=state_delta,
        tool="read_file",
        arguments={"path": "extracted/etc/device.conf"},
    )


def _v_complete(state_delta: dict | None = None) -> FinalProposal:
    return FinalProposal(
        decision_summary="全部必填 Claim 已有独立结果",
        state_delta=state_delta or {},
        kind="complete_verification",
    )


def _results_kinds(tmp_path: Path, candidate_id: str) -> list[str]:
    events = (tmp_path / "verifications" / candidate_id / "events.jsonl")
    return [json.loads(line)["kind"] for line in events.read_text(encoding="utf-8").splitlines()]


def _investigation_kinds(tmp_path: Path, candidate_id: str) -> list[str]:
    events = (tmp_path / "investigations" / candidate_id / "events.jsonl")
    return [json.loads(line)["kind"] for line in events.read_text(encoding="utf-8").splitlines()]


def test_confirmed_case_produces_finding_and_finished_lifecycle(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    session = FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ])

    outcome = runner.run_case(candidate_id, session)

    assert outcome.verdict == "confirmed"
    assert outcome.stop_reason == "completed"
    assert outcome.finding_id == "f-0001"
    assert outcome.rounds_used == 2
    investigation = tracer.investigation_for(candidate_id)
    assert (investigation.lifecycle_status, investigation.disposition,
            investigation.stop_reason) == ("finished", "confirmed", "completed")

    results = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert results["schema_version"] == RESULTS_SCHEMA_VERSION
    assert results["verdict"] == "confirmed"
    assert results["finding_id"] == "f-0001"
    assert set(results["claim_results"]) == set(GENERIC_REQUIRED)
    assert results["evidence_references"][0]["evidence_id"] == "ev-000002"

    findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert len(findings["findings"]) == 1
    finding = findings["findings"][0]
    assert finding["finding_id"] == "f-0001"
    assert finding["candidate_id"] == candidate_id
    assert finding["verdict"] == "confirmed"
    assert set(finding["claims"]) == set(GENERIC_REQUIRED)

    assert _results_kinds(tmp_path, candidate_id) == [
        "proposal_accepted", "tool_started", "tool_finished", "action_completed",
        "proposal_accepted", "case_finished",
    ]
    assert _investigation_kinds(tmp_path, candidate_id)[-2:] == [
        "verification_started", "verification_finished"]


def test_verification_evidence_is_namespaced_and_run_unique(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    session = FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ])

    outcome = runner.run_case(candidate_id, session)

    reference = outcome.evidence[0]
    assert reference.evidence_id == "ev-000002"  # analysis 已占 ev-000001
    assert reference.location == (
        f"verifications/{candidate_id}/evidence/ev-000002.json")
    assert reference.investigation_id == "verify-inv-0001"
    saved = json.loads(
        (tmp_path / reference.location).read_text(encoding="utf-8"))
    assert saved["candidate_id"] == candidate_id
    assert saved["investigation_id"] == "verify-inv-0001"


def test_verifier_brief_is_independent_of_analysis_conclusions(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    session = FakeSession([
        _v_action({"claim_results": {
            "root_cause": _result("supported", "ev-000002")}}),
        _v_action({"claim_results": {
            name: _result("supported", "ev-000003")
            for name in GENERIC_REQUIRED if name != "root_cause"}}),
        _v_complete(),
    ])

    runner.run_case(candidate_id, session)

    first, second = session.inputs[0], session.inputs[1]
    assert first is not None and "重新定位原始材料" in first
    assert first is not None and "不可作为 Verification 的支持证据" in first
    # 冻结案卷的逐项判定(status/note)不进简报,复核不被 analysis 结论锚定。
    assert first is not None and '"status"' not in first
    assert second is not None and "Observation View [ev-000002]" in second


def test_rejected_case_records_refutation_without_finding(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    results = {name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}
    results["root_cause"] = _result("refuted", "ev-000002")
    session = FakeSession([_v_action({"claim_results": results}), _v_complete()])

    outcome = runner.run_case(candidate_id, session)

    assert outcome.verdict == "rejected"
    assert outcome.decisive_refuted == ("root_cause",)
    assert outcome.finding_id is None
    assert not (tmp_path / "findings.json").exists()
    investigation = tracer.investigation_for(candidate_id)
    assert investigation.disposition == "rejected"
    saved = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert saved["decisive_refuted"] == ["root_cause"]


def test_inconclusive_case_does_not_return_to_analysis(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    results = {name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}
    results["actual_impact"] = _result("unresolved", None)
    session = FakeSession([_v_action({"claim_results": results}), _v_complete()])

    outcome = runner.run_case(candidate_id, session)

    assert outcome.verdict == "inconclusive"
    assert outcome.unsupported == ("actual_impact",)
    assert outcome.finding_id is None
    investigation = tracer.investigation_for(candidate_id)
    assert (investigation.disposition, investigation.stop_reason) == (
        "inconclusive", "completed")
    # inconclusive 第一版不自动返回 analysis:lifecycle 已 finished,结构性拒绝重跑。
    with pytest.raises(ValueError, match="不可重新运行"):
        tracer.run_analysis(candidate_id, FakeSession([], role="analysis"))


def test_evidence_gap_case_shares_the_same_aggregation(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path, admission="evidence_gap")
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    session = FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ])

    outcome = runner.run_case(candidate_id, session)

    assert outcome.verdict == "confirmed"
    assert outcome.finding_id == "f-0001"
    saved = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert saved["admission_reason"] == "evidence_gap"
    finding = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert finding["findings"][0]["admission_reason"] == "evidence_gap"


def test_citing_frozen_analysis_evidence_is_rejected_without_residue(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    session = FakeSession([
        _v_action({"claim_results": {
            "root_cause": _result("supported", "ev-000001")}}),
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ])

    outcome = runner.run_case(candidate_id, session)

    # 引用冻结案卷 Evidence 的动作整份拒绝并回喂:不执行工具、不留 Evidence;
    # 同一 Session 以本次复核 Evidence 重新提交后正常确认。
    assert "不属于本次复核会话" in (session.inputs[1] or "")
    assert outcome.verdict == "confirmed"
    assert tracer.investigation_for(candidate_id).lifecycle_status == "finished"
    assert len(tool.calls) == 1
    saved = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert [reference["evidence_id"] for reference in saved["evidence_references"]] == [
        "ev-000002"]


def test_complete_verification_requires_all_required_results(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    session = FakeSession([
        _v_action({"claim_results": {
            "root_cause": _result("supported", "ev-000002")}}),
        _v_complete(),
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ])

    outcome = runner.run_case(candidate_id, session)

    # 缺必填结果的收尾被拒并回喂;补齐后同一 Session 正常 complete。
    assert "尚无复核结果" in (session.inputs[2] or "")
    assert outcome.verdict == "confirmed"
    assert outcome.stop_reason == "completed"


def test_related_candidates_are_grounded_and_carried_into_finding(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    session = FakeSession([
        _v_action({
            "claim_results": {
                name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED},
            "related_candidates": [_related_entry(evidence_id="ev-000002")],
        }),
        _v_complete(),
    ])

    outcome = runner.run_case(candidate_id, session)

    assert len(outcome.related_candidates) == 1
    record = outcome.related_candidates[0]
    assert record["origin"] == {
        "relation": "verification_related",
        "from_candidate": candidate_id,
        "from_investigation": "inv-0001",
    }
    saved = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert saved["related_candidates"][0]["proposal_id"] == "rel-0001"
    finding = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert finding["findings"][0]["related_candidates"][0]["origin"][
        "from_candidate"] == candidate_id


def test_runner_guards_role_session_reuse_and_missing_case(tmp_path: Path) -> None:
    tracer, ids = _prepared_tracer(tmp_path, count=2)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)

    with pytest.raises(ValueError, match="role='verification'"):
        runner.run_case(ids[0], FakeSession([], role="analysis"))

    tracer.add_candidate({"target": "extracted/bin/never"})
    with pytest.raises(ValueError, match="没有冻结案卷"):
        runner.run_case("cand-0003", FakeSession([]))

    shared = FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000003") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ])
    runner.run_case(ids[0], shared)
    with pytest.raises(ValueError, match="独立 Agent Session"):
        runner.run_case(ids[1], shared)


def test_round_exhaustion_finalizes_inconclusive_budget_exhausted(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(
        tmp_path, {"read_file": tool}, tracer, max_rounds=1)
    session = FakeSession([_v_action({"note": "只取证不收尾"}), _v_action({})])

    outcome = runner.run_case(candidate_id, session)

    assert outcome.verdict == "inconclusive"
    assert outcome.stop_reason == "budget_exhausted"
    assert outcome.rounds_used == 1
    assert outcome.finding_id is None
    investigation = tracer.investigation_for(candidate_id)
    assert (investigation.disposition, investigation.stop_reason) == (
        "inconclusive", "budget_exhausted")
    assert len(tool.calls) == 1


def test_runner_defaults_to_fifteen_rounds_and_env_override(
        tmp_path: Path, monkeypatch) -> None:
    tracer, _ = _prepared_tracer(tmp_path)
    runner = HostVerificationRunner(tmp_path, {}, tracer)
    assert runner.max_rounds == DEFAULT_VERIFICATION_MAX_ROUNDS == 15
    monkeypatch.setenv("STEP5_VERIFICATION_MAX_ITERS", "2")
    assert HostVerificationRunner(tmp_path, {}, tracer).max_rounds == 2


def _interrupt_after_one_action(
    runner, candidate_id, evidence_id="ev-000002", names=("root_cause",),
) -> None:
    """跑完一轮动作(已持久化)后模拟服务中断,留下可恢复的复核会话。"""

    class OneThenInterrupt(FakeSession):
        def step(self, input_message=None):
            if len(self.inputs) >= 1:
                raise RuntimeError("模型服务中断")
            return super().step(input_message)

    with pytest.raises(RuntimeError, match="模型服务中断"):
        runner.run_case(candidate_id, OneThenInterrupt([
            _v_action({"claim_results": {
                name: _result("supported", evidence_id) for name in names}}),
        ]))


def test_findings_accumulate_across_confirmed_cases(tmp_path: Path) -> None:
    tracer, ids = _prepared_tracer(tmp_path, count=2)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    # analysis 已占用 ev-000001/ev-000002,两案卷复核 Evidence 依次为 3/4。
    evidence = ("ev-000003", "ev-000004")

    finding_ids = []
    for candidate_id, evidence_id in zip(ids, evidence):
        outcome = runner.run_case(candidate_id, FakeSession([
            _v_action({"claim_results": {
                name: _result("supported", evidence_id) for name in GENERIC_REQUIRED}}),
            _v_complete(),
        ]))
        finding_ids.append(outcome.finding_id)

    assert finding_ids == ["f-0001", "f-0002"]
    document = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert [item["finding_id"] for item in document["findings"]] == [
        "f-0001", "f-0002"]
    assert [item["candidate_id"] for item in document["findings"]] == ids


def test_verification_resumes_after_session_interruption(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)

    _interrupt_after_one_action(
        runner, candidate_id, names=GENERIC_REQUIRED[:3])

    # 恢复:新 runner + 新 Session,从已持久化的判定与 Evidence 序号继续。
    resumed_runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    resumed = FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000003")
            for name in GENERIC_REQUIRED[3:]}}),
        _v_complete(),
    ])
    outcome = resumed_runner.run_case(candidate_id, resumed)

    assert outcome.verdict == "confirmed"
    assert outcome.rounds_used == 3  # 中断前 1 轮已持久化,不计两次
    assert [item.evidence_id for item in outcome.evidence] == [
        "ev-000002", "ev-000003"]
    # 恢复简报携带已交判定与已得 Evidence,不重放完整 Transcript。
    assert resumed.inputs[0] is not None and "root_cause" in resumed.inputs[0]
    assert resumed.inputs[0] is not None and '"claim_results_so_far"' in resumed.inputs[0]
    assert resumed.inputs[0] is not None and "ev-000002" in resumed.inputs[0]


def test_finalize_replay_after_results_write_is_idempotent(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    session = FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ])
    first = runner.run_case(candidate_id, session)

    replay_runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    replayed = replay_runner.run_case(candidate_id, FakeSession([]))

    assert replayed.verdict == first.verdict == "confirmed"
    assert replayed.finding_id == first.finding_id == "f-0001"
    document = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert len(document["findings"]) == 1
    assert [item.evidence_id for item in replayed.evidence] == ["ev-000002"]


def test_crash_between_finding_and_results_resumes_pending_proposal(
        tmp_path: Path, monkeypatch) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)

    real_atomic_json = verification_module.atomic_json

    def crash_on_results(path, payload, **kwargs):
        if Path(path).name == "results.json":
            raise RuntimeError("崩溃:results 写入前")
        return real_atomic_json(path, payload, **kwargs)

    monkeypatch.setattr(verification_module, "atomic_json", crash_on_results)
    with pytest.raises(RuntimeError, match="results 写入前"):
        runner.run_case(candidate_id, FakeSession([
            _v_action({"claim_results": {
                name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
            _v_complete(),
        ]))

    # Finding 已追加、results 未落、lifecycle 仍在 verifying。
    document = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert len(document["findings"]) == 1
    assert not (tmp_path / "verifications" / candidate_id / "results.json").exists()
    assert tracer.investigation_for(candidate_id).lifecycle_status == "verifying"

    monkeypatch.undo()
    resumed = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    outcome = resumed.run_case(candidate_id, FakeSession([]))  # pending 重放,零模型请求

    assert outcome.verdict == "confirmed"
    assert outcome.finding_id == "f-0001"
    document = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert len(document["findings"]) == 1


def test_restore_rejects_tampered_frozen_case(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    _interrupt_after_one_action(runner, candidate_id)

    # 案卷冻结后被换内容:复核快照与盘上案卷不再逐字一致,拒绝继续旧会话。
    case_path = tmp_path / "verifications" / candidate_id / "case.json"
    payload = json.loads(case_path.read_text(encoding="utf-8"))
    payload["claims"]["root_cause"] = {"status": "unassessed", "evidence_ids": []}
    case_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(StoreError, match="不一致"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)


def test_restore_rejects_inconsistent_investigation_lifecycle(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    _interrupt_after_one_action(runner, candidate_id)

    # "复核会话存在但 Investigation 未进入复核"的不一致必须拦在恢复期。
    class StaleTracer:
        def investigation_for(self, cid):
            return replace(
                tracer.investigation_for(cid),
                lifecycle_status="ready_for_verification",
            )

    with pytest.raises(StoreError, match="不一致"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, StaleTracer())


# ---- 票 17:恢复期领域契约(Claim Result 引用、已完成结果短路) ----


def _inject_verification_projection(tmp_path: Path, candidate_id: str, mutate, kind: str) -> None:
    """以 Store.save 追加一条与投影一致的非法复核事件(不是只改快照)。"""
    store = InvestigationStore(tmp_path, candidate_id, root="verifications")
    saved = store.load()
    mutate(saved)
    store.save(kind, saved)


def _tree_snapshot(root: Path) -> dict[str, bytes]:
    """整棵运行目录的字节快照:用于断言拒绝路径零副作用(无新请求/工具/工件)。"""
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def _interrupted_case(tmp_path: Path):
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    _interrupt_after_one_action(runner, candidate_id, names=GENERIC_REQUIRED[:3])
    return tracer, candidate_id, tool


def test_restore_rejects_claim_results_citing_unknown_evidence(tmp_path: Path) -> None:
    tracer, candidate_id, tool = _interrupted_case(tmp_path)

    def mutate(saved):
        saved["session"]["claim_results"] = {
            name: _result("supported", "ev-999999") for name in GENERIC_REQUIRED}

    _inject_verification_projection(
        tmp_path, candidate_id, mutate, "injected_unknown_evidence")

    before = _tree_snapshot(tmp_path)
    with pytest.raises(StoreError, match="检查原运行目录|新运行世代"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)

    # 拒绝在聚合与 Finding 写入之前:整棵运行目录逐字节不变,生命周期停在复核中。
    assert _tree_snapshot(tmp_path) == before
    assert not (tmp_path / "findings.json").exists()
    assert tracer.investigation_for(candidate_id).lifecycle_status == "verifying"


def test_restore_rejects_claim_results_citing_analysis_evidence(tmp_path: Path) -> None:
    tracer, candidate_id, tool = _interrupted_case(tmp_path)
    analysis_evidence = (tmp_path / "investigations" / candidate_id
                         / "evidence" / "ev-000001.json")
    assert analysis_evidence.exists()  # 该 ID 真实存在,只是在另一棵 Evidence 树里

    def mutate(saved):
        saved["session"]["claim_results"] = {
            name: _result("supported", "ev-000001") for name in GENERIC_REQUIRED}

    _inject_verification_projection(
        tmp_path, candidate_id, mutate, "injected_analysis_evidence")

    with pytest.raises(StoreError, match="检查原运行目录|新运行世代"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    assert not (tmp_path / "findings.json").exists()


@pytest.mark.parametrize("claim_results", [
    {"invented_claim": _result("supported", "ev-000002")},
    {"root_cause": {**_result("supported", "ev-000002"), "judgment": "maybe"}},
    {"root_cause": {**_result("supported", "ev-000002"), "evidence_ids": []}},
    {"root_cause": {**_result("supported", "ev-000002"), "evidence_ids": [7]}},
    {"root_cause": {**_result("supported", "ev-000002"), "observed": ""}},
    {"root_cause": {**_result("supported", "ev-000002"), "judgment": "not_applicable"}},
    {"root_cause": {**_result("supported", "ev-000002"), "invented_field": 1}},
    {"root_cause": "not-an-object"},
], ids=["unknown_claim", "bad_judgment", "supported_without_reference",
        "bad_reference", "missing_observation", "decisive_not_applicable",
        "unknown_field", "bad_record"])
def test_restore_rejects_claim_results_violating_profile_or_judgment(
    tmp_path: Path, claim_results,
) -> None:
    """恢复口径与提交口径同一组规则:Profile、judgment、字段完整与独立引用。"""
    tracer, candidate_id, tool = _interrupted_case(tmp_path)

    def mutate(saved):
        saved["session"]["claim_results"] = deepcopy(claim_results)

    _inject_verification_projection(
        tmp_path, candidate_id, mutate, "injected_claim_result_contract")

    with pytest.raises(StoreError, match="检查原运行目录|新运行世代"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)


def _confirmed_results(tmp_path: Path):
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    outcome = runner.run_case(candidate_id, FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ]))
    assert outcome.verdict == "confirmed"
    return tracer, candidate_id, tool


def _tamper_results(tmp_path: Path, candidate_id: str, mutate) -> None:
    path = tmp_path / "verifications" / candidate_id / "results.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutate(payload)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


@pytest.mark.parametrize("tamper", [
    lambda payload: payload.update({"verdict": "confirmed", "claim_results": {
        name: _result("unresolved", None) for name in GENERIC_REQUIRED}}),
    lambda payload: payload.update({"claim_results": {
        name: _result("supported", "ev-999999") for name in GENERIC_REQUIRED}}),
    lambda payload: payload.update({"claim_profile": "memory"}),
    lambda payload: payload.update({"investigation_id": "inv-9999"}),
    lambda payload: payload.update({"finding_id": "f-9999"}),
    lambda payload: payload.update({"verdict": "inconclusive"}),
], ids=["verdict_mismatch", "unknown_evidence", "profile_mismatch",
        "investigation_mismatch", "finding_mismatch", "verdict_without_finding"])
def test_replay_finished_case_obeys_the_same_domain_contract(
    tmp_path: Path, tamper,
) -> None:
    tracer, candidate_id, tool = _confirmed_results(tmp_path)
    _tamper_results(tmp_path, candidate_id, tamper)
    session = FakeSession([])

    with pytest.raises(StoreError, match="检查原运行目录|新运行世代"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer).run_case(
            candidate_id, session)

    # 短路恢复的校验同样在请求模型之前:Session 一次都没被驱动。
    assert session.inputs == []


def test_replay_finished_case_requires_evidence_on_disk(tmp_path: Path) -> None:
    tracer, candidate_id, tool = _confirmed_results(tmp_path)
    (tmp_path / "verifications" / candidate_id / "evidence" / "ev-000002.json").unlink()

    with pytest.raises(StoreError, match="Evidence|检查原运行目录"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer).run_case(
            candidate_id, FakeSession([]))


def test_replay_finished_case_requires_its_finding_entry(tmp_path: Path) -> None:
    tracer, candidate_id, tool = _confirmed_results(tmp_path)
    findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    findings["findings"] = []
    (tmp_path / "findings.json").write_text(
        json.dumps(findings, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(StoreError, match="finding|Finding|检查原运行目录"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer).run_case(
            candidate_id, FakeSession([]))


def test_legal_finished_result_replay_stays_idempotent(tmp_path: Path) -> None:
    tracer, candidate_id, tool = _confirmed_results(tmp_path)

    replayed = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer).run_case(
        candidate_id, FakeSession([]))

    assert (replayed.verdict, replayed.finding_id) == ("confirmed", "f-0001")
    assert tracer.investigation_for(candidate_id).lifecycle_status == "finished"


# ---- 双轴评审补测:跨树唯一性、生命周期分支、损坏工件与提示词纪律 ----


def test_evidence_ids_stay_unique_across_interleaved_trees(tmp_path: Path) -> None:
    tracer, (first,) = _prepared_tracer(tmp_path)  # analysis 占 ev-000001
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    runner.run_case(first, FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ]))
    assert (tmp_path / "verifications" / first / "evidence"
            / "ev-000002.json").exists()

    # Analysis 回流:同一 tracer 在复核占号后新开 Investigation,编号续接。
    second = tracer.add_candidate({
        "target": "extracted/etc/device2.conf", "signal": "独立入口"})
    tracer.run_analysis(second.candidate_id, FakeSession([
        ActionProposal(
            decision_summary="取证",
            state_delta={},
            tool="read_file",
            arguments={"path": "extracted/etc/device2.conf"},
        ),
        FinalProposal(
            decision_summary="材料不足关闭",
            state_delta={"closure_reason": "反证不足",
                         "evidence_refs": ["ev-000003"]},
            kind="close_investigation",
        ),
    ], role="analysis"))
    investigation = tracer.investigation_for(second.candidate_id)
    assert [item.evidence_id for item in investigation.evidence] == ["ev-000003"]
    assert investigation.evidence[0].location == (
        f"investigations/{second.candidate_id}/evidence/ev-000003.json")

    # 复用同一 runner 复核后续案卷:Analysis 刚占的 ev-000004 不被重号。
    third = tracer.add_candidate({
        "target": "extracted/etc/device3.conf", "signal": "另一信号"})
    _submit_ready_case(tracer, third.candidate_id, evidence_id="ev-000004")
    outcome = runner.run_case(third.candidate_id, FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000005") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ]))
    assert outcome.verdict == "confirmed"
    assert [item.evidence_id for item in outcome.evidence] == ["ev-000005"]


def test_begin_verification_rejects_investigation_without_submitted_case(
        tmp_path: Path) -> None:
    tracer = HostAnalysisTracer(tmp_path, {})
    candidate = tracer.add_candidate({"target": "extracted/bin/never"})

    with pytest.raises(ValueError, match="只有已提交案卷"):
        tracer.begin_verification(candidate.candidate_id)


def test_finish_verification_rejects_mismatched_replay(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    runner.run_case(candidate_id, FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ]))

    with pytest.raises(ValueError, match="不一致"):
        tracer.finish_verification(
            candidate_id, disposition="rejected", stop_reason="completed")
    # 同值重放保持幂等。
    assert tracer.finish_verification(
        candidate_id, disposition="confirmed", stop_reason="completed",
    ).disposition == "confirmed"


def test_session_system_prompt_pins_independence_discipline() -> None:
    # 提示词是复核纪律的运行时载体:防锚定/引用红线/非反证语义必须钉住。
    assert "不能作为你的支持证据" in VERIFICATION_SESSION_SYSTEM
    assert "不接收" in VERIFICATION_SESSION_SYSTEM
    assert "不允许 not_applicable" in VERIFICATION_SESSION_SYSTEM
    assert "不是反证" in VERIFICATION_SESSION_SYSTEM
    assert "verdict 由 Host" in VERIFICATION_SESSION_SYSTEM


def test_replay_rejects_corrupted_results(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)
    outcome = runner.run_case(candidate_id, FakeSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ]))
    payload = json.loads(outcome.results_path.read_text(encoding="utf-8"))

    payload["evidence_references"] = [42]
    outcome.results_path.write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(StoreError, match="损坏"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer).run_case(
            candidate_id, FakeSession([]))

    payload["evidence_references"] = [{"evidence_id": "ev-000002"}]
    payload["decisive_refuted"] = "oops"
    outcome.results_path.write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    with pytest.raises(StoreError, match="损坏"):
        HostVerificationRunner(tmp_path, {"read_file": tool}, tracer).run_case(
            candidate_id, FakeSession([]))


def test_append_finding_rejects_corrupted_entry(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    (tmp_path / "findings.json").write_text(json.dumps({
        "schema_version": FINDING_SCHEMA_VERSION,
        "findings": [{"candidate_id": candidate_id}],
    }, ensure_ascii=False), encoding="utf-8")
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer)

    with pytest.raises(StoreError, match="Finding 条目损坏"):
        runner.run_case(candidate_id, FakeSession([
            _v_action({"claim_results": {
                name: _result("supported", "ev-000002") for name in GENERIC_REQUIRED}}),
            _v_complete(),
        ]))

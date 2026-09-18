"""Ticket 12:确定性 severity 矩阵(Host Policy 纯逻辑 seam)。

覆盖 ADR-0012 L59:四档影响范围 × 三档触发条件矩阵、已证实缓解左移一档、
完全阻断反驳决定性 Claim、关键字段缺失不得 critical。表驱动穷举矩阵,
不接触文件系统。
"""
from __future__ import annotations

import pytest

from firmware_audit.step5_agent.host.claims import PolicyError
from firmware_audit.step5_agent.host.severity import (
    IMPACT_SCOPES,
    SEVERITY_LEVELS,
    SEVERITY_MATRIX,
    TRIGGER_CONDITIONS,
    severity_assessment,
)
from firmware_audit.step5_agent.host.session import ProposalRejectedError
from firmware_audit.step5_agent.host.verification import (
    aggregate_verdict,
    build_finding_payload,
    validate_verification_delta,
)


def _result(judgment: str = "supported", **facets) -> dict:
    record = {"judgment": judgment, "observed": "x", "evidence_ids": ["ev-000001"],
              "method": "manual"}
    record.update(facets)
    return record


def _confirmed_results(impact: str | None = None, trigger: str | None = None,
                       mitigation: str | None = None,
                       preconditions_judgment: str = "supported") -> dict:
    """一份全 supported 的 confirmed 形状;facet 缺省为 None=未提供。"""
    results = {
        "target_exists": _result(),
        "root_cause": _result(),
        "trigger_or_exposure": _result(),
        "actual_impact": _result(),
        "mitigations": _result(),
        "input_source": _result(),
        "key_processing_relation": _result(),
        "reaches_high_impact_operation": _result(),
    }
    if impact is not None:
        results["actual_impact"]["impact_scope"] = impact
    if preconditions_judgment == "not_applicable":
        results["preconditions"] = _result("not_applicable")
    else:
        results["preconditions"] = _result()
        if trigger is not None:
            results["preconditions"]["trigger_condition"] = trigger
    if mitigation is not None:
        results["mitigations"]["mitigation_effect"] = mitigation
    return results


# ---- S1 矩阵穷举:12 组合逐格对表 ----


@pytest.mark.parametrize("impact", IMPACT_SCOPES)
@pytest.mark.parametrize("trigger", TRIGGER_CONDITIONS)
def test_matrix_exhaustive(impact: str, trigger: str) -> None:
    assessment = severity_assessment(
        _confirmed_results(impact=impact, trigger=trigger))
    assert assessment["severity"] == SEVERITY_MATRIX[impact][
        TRIGGER_CONDITIONS.index(trigger)]
    assert assessment["severity"] in SEVERITY_LEVELS
    assert assessment["incomplete"] is False
    assert assessment["decisive_refutation"] is None


def test_matrix_values_match_adr() -> None:
    assert SEVERITY_MATRIX == {
        "hardening": ("info", "info", "low"),
        "local": ("low", "low", "medium"),
        "component": ("medium", "medium", "high"),
        "system": ("high", "high", "critical"),
    }


# ---- S2 已证实缓解:触发条件左移一档,特殊条件为地板 ----


@pytest.mark.parametrize("trigger,expected", [
    ("loose", "limited"), ("limited", "special"), ("special", "special"),
])
def test_partial_mitigation_shifts_trigger_left(trigger: str,
                                                expected: str) -> None:
    assessment = severity_assessment(
        _confirmed_results(impact="system", trigger=trigger, mitigation="partial"))
    shifted = SEVERITY_MATRIX["system"][TRIGGER_CONDITIONS.index(expected)]
    assert assessment["severity"] == shifted
    assert assessment["mitigation_effect"] == "partial"


def test_mitigation_not_applicable_has_no_effect() -> None:
    results = _confirmed_results(impact="component", trigger="loose")
    results["mitigations"] = _result("not_applicable")
    assessment = severity_assessment(results)
    assert assessment["severity"] == "high"
    assert assessment["mitigation_effect"] is None


# ---- S3 完全阻断:反驳决定性 Claim,而不是降级 ----


def test_blocking_mitigation_refutes_decisive_claim() -> None:
    assessment = severity_assessment(
        _confirmed_results(impact="system", trigger="loose", mitigation="blocking"))
    assert assessment["decisive_refutation"] == "actual_impact"


def test_blocking_wins_over_severity_downgrade() -> None:
    """即使矩阵输入最轻,完全阻断仍表达为反驳而非 info 化。"""
    assessment = severity_assessment(
        _confirmed_results(impact="hardening", trigger="special",
                           mitigation="blocking"))
    assert assessment["decisive_refutation"] == "actual_impact"


# ---- S4 关键信息缺失:按最重档代入,但禁止 critical ----


@pytest.mark.parametrize("impact,trigger", [
    (None, "loose"),    # 缺影响范围 → system/loose=critical → 封顶 high
    ("system", None),   # 缺触发条件 → system/loose=critical → 封顶 high
    (None, None),
])
def test_missing_facets_never_critical(impact: str | None,
                                       trigger: str | None) -> None:
    assessment = severity_assessment(_confirmed_results(impact=impact,
                                                        trigger=trigger))
    assert assessment["severity"] == "high"
    assert assessment["incomplete"] is True


def test_missing_facets_still_below_critical_when_shifted() -> None:
    """缺影响范围 + 部分缓解:system/limited=high,封顶不再起作用但结果一致。"""
    assessment = severity_assessment(
        _confirmed_results(impact=None, trigger="loose", mitigation="partial"))
    assert assessment["severity"] == "high"
    assert assessment["incomplete"] is True


def test_missing_impact_with_narrow_trigger_not_capped() -> None:
    """缺影响范围但触发最窄:system/special=high,无 critical 可封。"""
    assessment = severity_assessment(_confirmed_results(impact=None,
                                                        trigger="special"))
    assert assessment["severity"] == "high"
    assert assessment["incomplete"] is True


def test_preconditions_not_applicable_is_loose_and_complete() -> None:
    """前置条件不适用 = 无前置条件 = 宽松触发,且信息完整。"""
    assessment = severity_assessment(
        _confirmed_results(impact="local", preconditions_judgment="not_applicable"))
    assert assessment["trigger_condition"] == "loose"
    assert assessment["severity"] == "medium"
    assert assessment["incomplete"] is False


# ---- S5 容错:脏记录按信息缺失处理,不崩溃 ----


def test_corrupt_records_treated_as_missing() -> None:
    assessment = severity_assessment({
        "actual_impact": {"judgment": "supported"},   # 无 facet
        "preconditions": "broken",                     # 非对象
        "mitigations": {"judgment": "supported",
                        "mitigation_effect": "nonsense"},  # 非法档位
    })
    assert assessment["incomplete"] is True
    assert assessment["severity"] == "high"
    assert assessment["mitigation_effect"] is None
    assert assessment["decisive_refutation"] is None


def test_empty_results_are_incomplete_not_critical() -> None:
    assessment = severity_assessment({})
    assert assessment["severity"] == "high"
    assert assessment["incomplete"] is True


# ---- S6 Claim Result facet 协议契约(提交路径) ----


def _delta_with(claim: str, record: dict) -> dict:
    return {"claim_results": {claim: record}}


_FACET_EVIDENCE = frozenset({"ev-000001"})


def test_facet_accepted_on_matching_claim() -> None:
    plan = validate_verification_delta(
        {}, _delta_with("actual_impact", _result(impact_scope="component")),
        evidence_ids=_FACET_EVIDENCE, profile="data_propagation",
        case_candidate_id="cand-0001", case_investigation_id="inv-0001")
    assert plan.claim_results[0][1]["impact_scope"] == "component"


@pytest.mark.parametrize("claim,facet,value", [
    ("root_cause", "trigger_condition", "loose"),      # facet 挂错 claim
    ("actual_impact", "trigger_condition", "loose"),   # 跨 claim 冒用
    ("actual_impact", "impact_scope", "planetary"),    # 非法档位
    ("mitigations", "mitigation_effect", "mild"),      # 非法效果
])
def test_facet_misplacement_or_bad_value_rejected(claim, facet, value) -> None:
    record = _result(**{facet: value})
    with pytest.raises(ProposalRejectedError):
        validate_verification_delta(
            {}, _delta_with(claim, record), evidence_ids=_FACET_EVIDENCE,
            profile="data_propagation", case_candidate_id="cand-0001",
            case_investigation_id="inv-0001")


def test_facet_requires_supported_judgment() -> None:
    with pytest.raises(ProposalRejectedError):
        validate_verification_delta(
            {}, _delta_with("mitigations", _result("not_applicable",
                                                   mitigation_effect="partial")),
            evidence_ids=_FACET_EVIDENCE, profile="data_propagation",
            case_candidate_id="cand-0001", case_investigation_id="inv-0001")


# ---- S7 聚合:完全阻断反驳决定性 Claim → rejected ----


def test_blocking_mitigation_aggregates_rejected() -> None:
    results = _confirmed_results(impact="system", trigger="loose",
                                 mitigation="blocking")
    verdict = aggregate_verdict("data_propagation", results)
    assert verdict.verdict == "rejected"
    assert "actual_impact" in verdict.decisive_refuted


def test_partial_mitigation_still_confirmed() -> None:
    results = _confirmed_results(impact="local", trigger="loose",
                                 mitigation="partial")
    verdict = aggregate_verdict("data_propagation", results)
    assert verdict.verdict == "confirmed"


def test_blocking_mitigation_recognized_from_disk_shape() -> None:
    """恢复路径的聚合复算同样把 blocking 落为 rejected。"""
    verdict = aggregate_verdict("generic", {
        "target_exists": _result(),
        "root_cause": _result(),
        "trigger_or_exposure": _result(),
        "actual_impact": _result(),
        "preconditions": _result("not_applicable"),
        "mitigations": _result(mitigation_effect="blocking"),
    })
    assert verdict.verdict == "rejected"


# ---- S8 Finding 载荷携带 severity 与依据 ----


def test_finding_payload_carries_severity_and_basis() -> None:
    case = {"candidate_id": "cand-0001", "investigation_id": "inv-0001",
            "claim_profile": "data_propagation", "admission_reason": "ready"}
    results = _confirmed_results(impact="component", trigger="loose",
                                 mitigation="partial")
    payload = build_finding_payload(
        finding_id="f-0001", case_payload=case, claim_results=results,
        evidence_references=[], related_candidates=[])
    assert payload["severity"] == "medium"  # component/limited(左移一档)
    assert payload["severity_basis"] == {
        "impact_scope": "component", "trigger_condition": "loose",
        "mitigation_effect": "partial", "incomplete": False}


def test_finding_payload_blocks_blocking_mitigation() -> None:
    case = {"candidate_id": "cand-0001", "investigation_id": "inv-0001",
            "claim_profile": "data_propagation", "admission_reason": "ready"}
    results = _confirmed_results(mitigation="blocking")
    with pytest.raises(PolicyError):
        build_finding_payload(
            finding_id="f-0001", case_payload=case, claim_results=results,
            evidence_references=[], related_candidates=[])


# ---- S9 评审修复回归:supported 必填 facet,左移规则不可绕过 ----


@pytest.mark.parametrize("claim,facet", [
    ("actual_impact", "impact_scope"),
    ("preconditions", "trigger_condition"),
    ("mitigations", "mitigation_effect"),
])
def test_supported_claim_requires_its_facet(claim: str, facet: str) -> None:
    """supported 却省略 facet = 左移/反驳规则被静默绕过,协议层整份拒绝。"""
    with pytest.raises(ProposalRejectedError, match="必填"):
        validate_verification_delta(
            {}, _delta_with(claim, _result()), evidence_ids=_FACET_EVIDENCE,
            profile="data_propagation", case_candidate_id="cand-0001",
            case_investigation_id="inv-0001")


def test_preconditions_not_applicable_needs_no_facet() -> None:
    plan = validate_verification_delta(
        {}, _delta_with("preconditions", _result("not_applicable")),
        evidence_ids=_FACET_EVIDENCE, profile="data_propagation",
        case_candidate_id="cand-0001", case_investigation_id="inv-0001")
    assert plan.claim_results[0][1].get("trigger_condition") is None

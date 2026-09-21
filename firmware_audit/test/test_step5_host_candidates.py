"""Host Candidate 去重/评分/双队列测试:fingerprint、语义比较门、ID 分配、选取。"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from firmware_audit.step5_agent.engine.context import ContextManager
from firmware_audit.step5_agent.host.candidates import (
    CLAIM_PROFILES,
    COVERAGE_FACTORS,
    DEFAULT_PROCESSING_SLOTS,
    RELATED_CANDIDATE_FIELDS,
    SIGNAL_FACTORS,
    CandidateIntakeError,
    CandidateStore,
    ComparisonOutcome,
    IntakeCandidate,
    PriorityScorer,
    RelatedOrigin,
    Selection,
    SemanticComparator,
    compute_total,
    coverage_fingerprint,
    deduplicate,
    factors_for_kind,
    grounded_factor,
    make_priority_scorer,
    normalize_intake,
    normalize_target_path,
    related_candidate_contract,
    related_candidate_records,
    related_intake,
    resolve_processing_slots,
    select_for_processing,
    signal_fingerprint,
    stored_related_proposals,
)
from firmware_audit.step5_agent.host.claims import validate_analysis_delta
from firmware_audit.step5_agent.host.recon import (
    RECON_SESSION_SYSTEM,
    HostReconRunner,
)
from firmware_audit.step5_agent.host.session import AgentSession, ProposalRejectedError
from firmware_audit.step5_agent.host.store import InvestigationStore, StoreError, atomic_json
from firmware_audit.step5_agent.host.verification import validate_verification_delta
from firmware_audit.step5_agent.providers.tools import ToolContext, make_tools
from firmware_audit.test.scripted_llm import ScriptedLLM


# ---- S1 target 规范化与两类 fingerprint ----


@pytest.mark.parametrize("raw,expected", [
    ("extracted/bin/robotd", "extracted/bin/robotd"),
    (" extracted/bin/robotd ", "extracted/bin/robotd"),
    ("extracted\\bin\\robotd", "extracted/bin/robotd"),
    ("extracted//bin///robotd", "extracted/bin/robotd"),
    ("extracted/bin/./robotd", "extracted/bin/robotd"),
    ("extracted/bin/", "extracted/bin"),
    ("extracted/bin", "extracted/bin"),
])
def test_normalize_target_path_variants(raw: str, expected: str) -> None:
    assert normalize_target_path(raw) == expected


def test_target_path_keeps_case_sensitive_segments() -> None:
    assert normalize_target_path("extracted/etc/Device.CONF") == "extracted/etc/Device.CONF"


def test_signal_fingerprint_uses_target_anchor_profile_mechanism() -> None:
    base = signal_fingerprint("extracted/bin/robotd", "handle_msg", "data_propagation", "command injection")
    assert base == signal_fingerprint(
        "extracted//bin/robotd/", " handle_msg ", "data_propagation", "command injection",
    )
    # 位置锚点、Profile、问题机制任一不同即不同 fingerprint。
    assert base != signal_fingerprint("extracted/bin/robotd", "main", "data_propagation", "command injection")
    assert base != signal_fingerprint("extracted/bin/robotd", "handle_msg", "config", "command injection")
    assert base != signal_fingerprint("extracted/bin/robotd", "handle_msg", "data_propagation", "buffer overflow")
    assert base != signal_fingerprint("extracted/bin/updater", "handle_msg", "data_propagation", "command injection")


def test_coverage_fingerprint_uses_target_component_goal() -> None:
    base = coverage_fingerprint("extracted/sbin/", "upgrade handler", "check upgrade flow")
    assert base == coverage_fingerprint("extracted/sbin", "upgrade handler", "check upgrade flow")
    assert base != coverage_fingerprint("extracted/sbin", "web ui", "check upgrade flow")
    assert base != coverage_fingerprint("extracted/sbin", "upgrade handler", "check auth flow")
    assert base != coverage_fingerprint("extracted/usr/sbin", "upgrade handler", "check upgrade flow")


def test_signal_and_coverage_fingerprints_never_collide_across_kinds() -> None:
    assert signal_fingerprint("a", "b", "generic", "c") != coverage_fingerprint("a", "b", "c")


# ---- S1 intake 归一化 ----


def _recon_proposal(**overrides) -> dict:
    record = {
        "proposal_id": "proposal-0001",
        "kind": "signal",
        "target": "extracted/bin/robotd",
        "signal": "管理接口无鉴权",
        "evidence_id": "ev-000001",
        "next_action": "核查鉴权逻辑",
        "possible_source": None,
        "possible_sink": None,
        "extras": {},
    }
    record.update(overrides)
    return record


def test_normalize_intake_minimal_recon_proposal_defaults() -> None:
    intake = normalize_intake(_recon_proposal(), source="recon")
    assert isinstance(intake, IntakeCandidate)
    assert intake.source == "recon"
    assert intake.proposal_id == "proposal-0001"
    assert intake.kind == "signal"
    assert intake.claim_profile == "generic"
    assert intake.anchor == "" and intake.mechanism == ""
    assert intake.component_or_entry == "" and intake.check_goal == ""
    assert intake.extras == {}


def test_normalize_intake_reads_fingerprint_fields_from_top_level_or_extras() -> None:
    top_level = normalize_intake(
        _recon_proposal(claim_profile="credentials", mechanism="hardcoded key", anchor="load_keys"),
        source="recon",
    )
    assert (top_level.claim_profile, top_level.mechanism, top_level.anchor) == (
        "credentials", "hardcoded key", "load_keys",
    )
    via_extras = normalize_intake(
        _recon_proposal(extras={"component_or_entry": "web ui", "check_goal": "audit upload"}),
        source="recon",
    )
    assert (via_extras.component_or_entry, via_extras.check_goal) == ("web ui", "audit upload")


def test_normalize_intake_strips_whitespace_in_fingerprint_inputs() -> None:
    intake = normalize_intake(
        _recon_proposal(
            target=" extracted/bin/robotd ",
            mechanism=" command injection ",
            anchor=" handle_msg ",
        ),
        source="recon",
    )
    assert intake.target == "extracted/bin/robotd"
    assert intake.mechanism == "command injection"
    assert intake.anchor == "handle_msg"


def test_normalize_intake_preserves_unknown_keys_in_extras() -> None:
    intake = normalize_intake(
        _recon_proposal(extras={"rationale": "gitleaks 命中", "claim_profile": "config"}),
        source="recon",
    )
    assert intake.extras == {"rationale": "gitleaks 命中"}
    assert intake.claim_profile == "config"


@pytest.mark.parametrize("mutation", [
    {"kind": "weird"},
    {"kind": None},
    {"target": "   "},
    {"target": None},
    {"signal": ""},
    {"evidence_id": "  "},
    {"next_action": None},
    {"claim_profile": "authentication"},
    {"mechanism": 42},
    {"anchor": ["handle_msg"]},
    {"component_or_entry": {"a": 1}},
    {"possible_source": 7},
])
def test_normalize_intake_rejects_invalid_records(mutation) -> None:
    with pytest.raises(CandidateIntakeError):
        normalize_intake(_recon_proposal(**mutation), source="recon")


def test_normalize_intake_rejects_invalid_source_or_proposal_id() -> None:
    with pytest.raises(CandidateIntakeError):
        normalize_intake(_recon_proposal(), source="")
    with pytest.raises(CandidateIntakeError):
        normalize_intake(_recon_proposal(proposal_id=""), source="recon")


def test_claim_profiles_match_adr_enumeration() -> None:
    assert CLAIM_PROFILES == (
        "data_propagation", "config", "credentials", "memory", "generic",
    )


def test_intake_candidate_fingerprint_matches_kind_formula() -> None:
    signal = normalize_intake(
        _recon_proposal(anchor="handle_msg", mechanism="command injection",
                        claim_profile="data_propagation"),
        source="recon",
    )
    assert signal.fingerprint() == signal_fingerprint(
        "extracted/bin/robotd", "handle_msg", "data_propagation", "command injection",
    )
    coverage = normalize_intake(
        _recon_proposal(kind="coverage", extras={
            "component_or_entry": "updater", "check_goal": "audit upgrade",
        }),
        source="recon",
    )
    assert coverage.fingerprint() == coverage_fingerprint(
        "extracted/bin/robotd", "updater", "audit upgrade",
    )


# ---- S2 去重引擎 ----

def _intake(**overrides) -> object:
    return normalize_intake(_recon_proposal(**overrides), source="recon")


class _ScriptedComparator:
    """按序回放比较结果;意外调用即失败,防去重引擎多发请求。"""

    def __init__(self, outcomes: list[ComparisonOutcome]):
        self.outcomes = list(outcomes)
        self.calls: list[tuple[object, object]] = []

    def compare(self, existing, incoming) -> ComparisonOutcome:
        self.calls.append((existing, incoming))
        assert self.outcomes, "比较次数超出预期"
        return self.outcomes.pop(0)


def _outcome(verdict: str | None, *, status: str = "ok") -> ComparisonOutcome:
    return ComparisonOutcome(status=status, verdict=verdict, rationale="测试依据")


def test_exact_fingerprint_duplicates_merge_without_llm() -> None:
    comparator = _ScriptedComparator([])
    result = deduplicate(
        [
            _intake(proposal_id="proposal-0001", mechanism="command injection", anchor="handle_msg"),
            _intake(proposal_id="proposal-0002", mechanism="command injection", anchor="handle_msg",
                    signal="同一处无鉴权入口,措辞不同"),
        ],
        comparator=comparator,
    )
    assert comparator.calls == []
    assert len(result.candidates) == 1
    record = result.candidates[0]
    assert record["candidate_id"] == "cand-0001"
    assert record["proposal_id"] == "proposal-0001"
    assert record["aliases"] == ["proposal-0002"]
    assert [item["proposal_id"] for item in record["merged_proposals"]] == ["proposal-0002"]
    assert record["merged_proposals"][0]["merged_via"] == "exact_fingerprint"
    assert result.llm_calls == 0
    assert [entry["type"] for entry in result.dedup_log] == ["created", "exact_merge"]


def test_exact_merge_normalizes_target_path_before_comparison() -> None:
    comparator = _ScriptedComparator([])
    result = deduplicate(
        [
            _intake(proposal_id="proposal-0001", target="extracted//bin/robotd/"),
            _intake(proposal_id="proposal-0002", target="extracted\\bin\\robotd"),
        ],
        comparator=comparator,
    )
    assert len(result.candidates) == 1
    assert result.candidates[0]["aliases"] == ["proposal-0002"]


@pytest.mark.parametrize("same_target,same_profile,same_fingerprint,compares", [
    (True, True, False, True),    # 门控命中:一次语义比较
    (True, False, False, False),  # Profile 不同不比(跨问题类型不误合并)
    (False, True, False, False),  # target 不同不比
    (True, True, True, False),    # fingerprint 相同走精确合并,不消耗 LLM
])
def test_semantic_gate_requires_same_target_profile_and_different_fingerprint(
    same_target: bool, same_profile: bool, same_fingerprint: bool, compares: bool,
) -> None:
    first = _intake(
        proposal_id="proposal-0001", target="extracted/bin/robotd",
        claim_profile="data_propagation", mechanism="command injection", anchor="handle_msg",
    )
    overrides = {
        "proposal_id": "proposal-0002",
        "claim_profile": "data_propagation",
        "mechanism": "command injection",
        "anchor": "handle_msg",
    }
    if not same_target:
        overrides["target"] = "extracted/bin/updater"
    if not same_profile:
        overrides["claim_profile"] = "config"
    if not same_fingerprint:
        overrides["anchor"] = "main"  # fingerprint 不同但语义可能相同
    second = _intake(**overrides)
    comparator = _ScriptedComparator([_outcome("different")])
    result = deduplicate([first, second], comparator=comparator)
    assert len(comparator.calls) == (1 if compares else 0)
    # 门控未命中或比较得 different 都保留独立;精确重复直接合并。
    assert len(result.candidates) == (1 if same_fingerprint else 2)


@pytest.mark.parametrize("verdict,merged", [
    ("same", True),
    ("different", False),
    ("uncertain", False),
])
def test_verdict_table_same_merges_others_keep_independent(verdict: str, merged: bool) -> None:
    first = _intake(proposal_id="proposal-0001", anchor="handle_msg")
    second = _intake(proposal_id="proposal-0002", anchor="main")
    comparator = _ScriptedComparator([_outcome(verdict)])
    result = deduplicate([first, second], comparator=comparator)
    assert len(result.candidates) == (1 if merged else 2)
    assert result.llm_calls == 1
    if merged:
        record = result.candidates[0]
        assert record["aliases"] == ["proposal-0002"]
        assert record["merged_proposals"][0]["merged_via"] == "semantic_same"
        assert record["merged_proposals"][0]["comparison"]["verdict"] == "same"
        assert record["merged_proposals"][0]["comparison"]["request"]["incoming_proposal"]["proposal_id"] == "proposal-0002"
    else:
        assert [entry["type"] for entry in result.dedup_log] == ["created", "kept_independent"]
        assert result.dedup_log[1]["verdict"] == verdict
        assert result.dedup_log[1]["request"]["incoming_proposal"]["proposal_id"] == "proposal-0002"
        assert result.dedup_log[1]["rationale"] == "测试依据"


@pytest.mark.parametrize("status", ["invalid_reply", "service_error"])
def test_protocol_invalid_and_service_failure_keep_independent(status: str) -> None:
    first = _intake(proposal_id="proposal-0001", anchor="handle_msg")
    second = _intake(proposal_id="proposal-0002", anchor="main")
    comparator = _ScriptedComparator([_outcome(None, status=status)])
    result = deduplicate([first, second], comparator=comparator)
    assert len(result.candidates) == 2
    assert result.llm_calls == 1
    entry = result.dedup_log[1]
    assert entry["type"] == "kept_independent"
    assert entry["reason"] == status


def test_comparison_targets_earliest_same_gate_survivor_once() -> None:
    first = _intake(proposal_id="proposal-0001", anchor="handle_msg")
    middle = _intake(proposal_id="proposal-0002", target="extracted/bin/updater")
    gated = _intake(proposal_id="proposal-0003", anchor="main")
    comparator = _ScriptedComparator([_outcome("uncertain")])
    result = deduplicate([first, middle, gated], comparator=comparator)
    assert len(comparator.calls) == 1
    assert comparator.calls[0][0].proposal_id == "proposal-0001"
    assert len(result.candidates) == 3


def test_ids_allocated_after_dedup_in_first_appearance_order() -> None:
    proposals = [
        _intake(proposal_id="proposal-0001", target="extracted/bin/robotd", anchor="a"),
        _intake(proposal_id="proposal-0002", target="extracted/bin/updater", anchor="b"),
        _intake(proposal_id="proposal-0003", target="extracted/bin/robotd", anchor="a"),  # 精确重复
        _intake(proposal_id="proposal-0004", target="extracted/bin/webui", anchor="c"),
    ]
    result = deduplicate(proposals, comparator=_ScriptedComparator([]))
    assert [record["candidate_id"] for record in result.candidates] == [
        "cand-0001", "cand-0002", "cand-0003",
    ]
    assert result.candidates[0]["aliases"] == ["proposal-0003"]


def test_existing_candidate_ids_survive_incremental_dedup() -> None:
    built = deduplicate(
        [_intake(proposal_id="proposal-0001", anchor="handle_msg")],
        comparator=_ScriptedComparator([]),
    )
    related = normalize_intake(
        _recon_proposal(proposal_id="rel-cand-0001-1", anchor="handle_msg"),
        source="related:cand-0001",
    )
    related_same_gate = normalize_intake(
        _recon_proposal(proposal_id="rel-cand-0001-2", anchor="main"),
        source="related:cand-0001",
    )
    result = deduplicate(
        [related, related_same_gate],
        existing=built.candidates,
        comparator=_ScriptedComparator([_outcome("same")]),
    )
    assert [record["candidate_id"] for record in result.candidates] == ["cand-0001"]
    assert result.candidates[0]["aliases"] == ["rel-cand-0001-1", "rel-cand-0001-2"]
    assert result.candidates[0]["merged_proposals"][0]["source"] == "related:cand-0001"


def test_known_proposal_id_is_idempotent_skip_and_conflict_raises() -> None:
    built = deduplicate(
        [_intake(proposal_id="proposal-0001", anchor="handle_msg")],
        comparator=_ScriptedComparator([]),
    )
    replay = deduplicate(
        [_intake(proposal_id="proposal-0001", anchor="handle_msg")],
        existing=built.candidates,
        comparator=_ScriptedComparator([]),
    )
    assert [record["candidate_id"] for record in replay.candidates] == ["cand-0001"]
    assert replay.dedup_log[-1]["type"] == "skipped_known_proposal"
    with pytest.raises(CandidateIntakeError):
        deduplicate(
            [_intake(proposal_id="proposal-0001", anchor="changed")],
            existing=built.candidates,
            comparator=_ScriptedComparator([]),
        )


@pytest.mark.parametrize("merged_via", ["exact_fingerprint", "semantic_same"])
def test_re_delivering_merged_proposal_is_idempotent(merged_via: str) -> None:
    """恢复/重试重投已合并的 proposal 必须幂等跳过,不得误判"内容不同"崩溃。"""
    first = _intake(proposal_id="proposal-0001", anchor="handle_msg")
    duplicate = _intake(proposal_id="proposal-0002", anchor="handle_msg")
    comparator = _ScriptedComparator([])
    if merged_via == "semantic_same":
        duplicate = _intake(proposal_id="proposal-0002", anchor="main")
        comparator = _ScriptedComparator([_outcome("same")])
    built = deduplicate([first, duplicate], comparator=comparator)

    replay = deduplicate(
        [duplicate], existing=built.candidates, comparator=_ScriptedComparator([]),
    )

    assert [record["candidate_id"] for record in replay.candidates] == ["cand-0001"]
    assert replay.dedup_log == [{"type": "skipped_known_proposal",
                                 "proposal_id": "proposal-0002"}]
    with pytest.raises(CandidateIntakeError):
        deduplicate(
            [_intake(proposal_id="proposal-0002", anchor="tampered")],
            existing=built.candidates,
            comparator=_ScriptedComparator([]),
        )


def test_semantic_merge_keeps_primary_fields_and_existing_id() -> None:
    built = deduplicate(
        [_intake(proposal_id="proposal-0001", anchor="handle_msg", signal="原始信号")],
        comparator=_ScriptedComparator([]),
    )
    later = _intake(proposal_id="proposal-0002", anchor="main", signal="后来的相近信号")
    result = deduplicate([later], existing=built.candidates,
                         comparator=_ScriptedComparator([_outcome("same")]))
    record = result.candidates[0]
    assert record["candidate_id"] == "cand-0001"
    assert record["signal"] == "原始信号"
    assert record["merged_proposals"][0]["signal"] == "后来的相近信号"


# ---- S4 评分:LLM 只交分项与依据,Host 算总分 ----

def test_factor_lists_match_adr_formulas() -> None:
    assert SIGNAL_FACTORS == (
        "external_reachability", "input_control", "high_impact_operation",
        "path_progress", "material_strength", "estimated_cost",
    )
    assert COVERAGE_FACTORS == (
        "component_value", "external_exposure", "unchecked_extent", "estimated_cost",
    )
    assert factors_for_kind("signal") == SIGNAL_FACTORS
    assert factors_for_kind("coverage") == COVERAGE_FACTORS


_EVIDENCE = frozenset({"ev-000001", "ev-000002"})


@pytest.mark.parametrize("item,expected", [
    ({"score": 0, "evidence_id": "ev-000001"}, 0),
    ({"score": 1, "evidence_id": "ev-000001"}, 1),
    ({"score": 2, "evidence_id": "ev-000002"}, 2),
    ({"score": 2}, 0),                                # 缺 evidence_id
    ({"score": 2, "evidence_id": None}, 0),
    ({"score": 2, "evidence_id": "ev-999999"}, 0),    # 未知 Evidence
    ({"score": 2, "evidence_id": "  "}, 0),
    ({"score": 3, "evidence_id": "ev-000001"}, 0),    # 超出 0/1/2
    ({"score": -1, "evidence_id": "ev-000001"}, 0),
    ({"score": "2", "evidence_id": "ev-000001"}, 0),  # 字符串分数
    ({"score": True, "evidence_id": "ev-000001"}, 0),  # 布尔不是合法分值
    ({}, 0),                                          # 整项缺失
    (None, 0),
])
def test_grounded_factor_table(item, expected: int) -> None:
    assert grounded_factor(item, _EVIDENCE)[0] == expected


def test_signal_total_subtracts_cost() -> None:
    assert compute_total("signal", {
        "external_reachability": 2, "input_control": 2, "high_impact_operation": 2,
        "path_progress": 2, "material_strength": 2, "estimated_cost": 2,
    }) == 8
    assert compute_total("signal", {"estimated_cost": 0}) == 0
    assert compute_total("signal", {"estimated_cost": 2}) == -2
    assert compute_total("signal", {}) == 0


def test_coverage_total_subtracts_cost() -> None:
    assert compute_total("coverage", {
        "component_value": 2, "external_exposure": 2,
        "unchecked_extent": 2, "estimated_cost": 1,
    }) == 5
    assert compute_total("coverage", {"estimated_cost": 2}) == -2


class _FakeLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls: list[list[dict]] = []

    def chat(self, messages, **kw):
        self.calls.append(list(messages))
        if isinstance(self.replies[0], Exception):
            raise self.replies.pop(0)
        return self.replies.pop(0), {}


def _score_reply(factors: dict) -> str:
    return json.dumps({"factors": factors}, ensure_ascii=False)


def test_priority_scorer_accepts_grounded_factors() -> None:
    llm = _FakeLLM([_score_reply({
        "external_reachability": {"score": 2, "evidence_id": "ev-000001"},
        "input_control": {"score": 1, "evidence_id": "ev-000002"},
        "high_impact_operation": {"score": 2, "evidence_id": "ev-000001"},
        "path_progress": {"score": 0, "evidence_id": "ev-000001"},
        "material_strength": {"score": 2, "evidence_id": "ev-000002"},
        "estimated_cost": {"score": 1, "evidence_id": "ev-000001"},
        "unrelated_factor": {"score": 2, "evidence_id": "ev-000001"},  # 未知分项忽略
    })])
    scorer = PriorityScorer(llm, evidence_context={
        "ev-000001": "管理接口无鉴权", "ev-000002": "命令拼接",
    })
    result = scorer.score(_intake())
    assert result["status"] == "ok"
    assert result["total"] == 2 + 1 + 2 + 0 + 2 - 1 == 6
    assert result["factors"]["estimated_cost"]["score"] == 1
    assert result["factors"]["external_reachability"]["used"] is True
    assert len(llm.calls) == 1


def test_priority_scorer_zeroes_ungrounded_factors() -> None:
    llm = _FakeLLM([_score_reply({
        "external_reachability": {"score": 2, "evidence_id": "ev-000001"},
        "input_control": {"score": 2},                       # 缺依据
        "high_impact_operation": {"score": 5, "evidence_id": "ev-000001"},  # 非法分值
        "path_progress": {"score": 2, "evidence_id": "ev-999999"},  # 未知 Evidence
        "material_strength": None,                            # 整项缺失
        # estimated_cost 未提交
    })])
    scorer = PriorityScorer(llm, evidence_context={"ev-000001": "x"})
    result = scorer.score(_intake())
    assert result["status"] == "ok"
    assert result["total"] == 2
    assert result["factors"]["input_control"] == {
        "score": 0, "evidence_id": None, "note": None, "used": False,
    }
    assert result["factors"]["estimated_cost"]["used"] is False


def test_priority_scorer_invalid_reply_falls_back_to_zero() -> None:
    llm = _FakeLLM(["这不是 JSON"])
    scorer = PriorityScorer(llm, evidence_context={"ev-000001": "x"})
    result = scorer.score(_intake())
    assert result["status"] == "invalid_reply"
    assert result["total"] == 0
    assert all(item["used"] is False for item in result["factors"].values())


def test_priority_scorer_service_error_falls_back_to_zero() -> None:
    llm = _FakeLLM([RuntimeError("模型服务中断")])
    scorer = PriorityScorer(llm, evidence_context={"ev-000001": "x"})
    result = scorer.score(_intake())
    assert result["status"] == "service_error"
    assert result["total"] == 0


def test_priority_scorer_uses_coverage_factor_list_for_coverage_kind() -> None:
    llm = _FakeLLM([_score_reply({
        "component_value": {"score": 2, "evidence_id": "ev-000001"},
        "external_exposure": {"score": 1, "evidence_id": "ev-000001"},
        "unchecked_extent": {"score": 2, "evidence_id": "ev-000001"},
        "estimated_cost": {"score": 0, "evidence_id": "ev-000001"},
    })])
    scorer = PriorityScorer(llm, evidence_context={"ev-000001": "x"})
    coverage = normalize_intake(_recon_proposal(kind="coverage"), source="recon")
    result = scorer.score(coverage)
    assert result["total"] == 5
    assert set(result["factors"]) == set(COVERAGE_FACTORS)


# ---- S5 双队列选取 ----

def _scored(candidate_id: str, kind: str, total: int) -> dict:
    return {
        "candidate_id": candidate_id,
        "kind": kind,
        "priority": {"total": total, "factors": {}, "status": "ok"},
    }


def test_signal_only_queue_uses_all_slots() -> None:
    records = [_scored(f"cand-{i:04d}", "signal", i) for i in range(1, 11)]
    selection = select_for_processing(records, slots=8)
    assert selection.selected == (
        "cand-0010", "cand-0009", "cand-0008", "cand-0007",
        "cand-0006", "cand-0005", "cand-0004", "cand-0003",
    )
    assert selection.coverage_reserved is False


def test_coverage_slot_reserved_when_coverage_exists() -> None:
    records = [_scored(f"cand-{i:04d}", "signal", 5) for i in range(1, 11)]
    records += [
        _scored("cand-0011", "coverage", 3),
        _scored("cand-0012", "coverage", 6),
    ]
    selection = select_for_processing(records, slots=8)
    assert len(selection.selected) == 8
    assert selection.selected[-1] == "cand-0012"  # 最高分 coverage 占保留名额
    assert "cand-0011" not in selection.selected
    assert selection.coverage_reserved is True
    assert selection.queue_of["cand-0012"] == "coverage"
    assert selection.rank_of["cand-0012"] == 1


def test_signal_shortfall_spills_slots_to_coverage() -> None:
    records = [
        _scored("cand-0001", "signal", 5),
        _scored("cand-0002", "signal", 1),
        _scored("cand-0003", "coverage", 4),
        _scored("cand-0004", "coverage", 2),
        _scored("cand-0005", "coverage", 6),
        _scored("cand-0006", "coverage", 1),
    ]
    selection = select_for_processing(records, slots=8)
    # 保留名额给最高分 coverage(cand-0005),signal 只有两个,余量续取其余 coverage。
    assert selection.selected == (
        "cand-0001", "cand-0002", "cand-0005", "cand-0003", "cand-0004", "cand-0006",
    )


def test_same_score_ties_break_by_creation_order() -> None:
    records = [
        _scored("cand-0001", "signal", 5),
        _scored("cand-0002", "signal", 7),
        _scored("cand-0003", "signal", 5),
        _scored("cand-0004", "signal", 7),
    ]
    selection = select_for_processing(records, slots=3)
    assert selection.selected == ("cand-0002", "cand-0004", "cand-0001")


def test_selection_marks_ranks_within_each_queue() -> None:
    records = [
        _scored("cand-0001", "signal", 5),
        _scored("cand-0002", "coverage", 3),
        _scored("cand-0003", "coverage", 6),
    ]
    selection = select_for_processing(records, slots=8)
    assert selection.rank_of == {
        "cand-0001": 1, "cand-0002": 2, "cand-0003": 1,
    }
    assert selection.queue_of == {
        "cand-0001": "signal", "cand-0002": "coverage", "cand-0003": "coverage",
    }


def test_single_slot_goes_to_reserved_coverage() -> None:
    records = [
        _scored("cand-0001", "signal", 9),
        _scored("cand-0002", "coverage", 1),
    ]
    selection = select_for_processing(records, slots=1)
    assert selection.selected == ("cand-0002",)
    assert selection.coverage_reserved is True


def test_selection_requires_positive_slots_and_records() -> None:
    with pytest.raises(ValueError):
        select_for_processing([_scored("cand-0001", "signal", 1)], slots=0)
    with pytest.raises(ValueError):
        select_for_processing(
            [{"candidate_id": "cand-0001", "kind": "signal"}], slots=8)  # 缺 priority


def test_default_slots_and_env_override(monkeypatch) -> None:
    assert DEFAULT_PROCESSING_SLOTS == 8
    assert resolve_processing_slots() == 8
    monkeypatch.setenv("STEP5_CANDIDATE_SLOTS", "3")
    assert resolve_processing_slots() == 3
    monkeypatch.setenv("STEP5_CANDIDATE_SLOTS", "not-a-number")
    assert resolve_processing_slots() == 8
    monkeypatch.setenv("STEP5_CANDIDATE_SLOTS", "0")
    assert resolve_processing_slots() == 1
    monkeypatch.delenv("STEP5_CANDIDATE_SLOTS")
    assert resolve_processing_slots() == 8


# ---- S3 Candidate Store 门面:v1→v2 升级、增量重入队、not_started ----

class _FakeScorer:
    def __init__(self, total: int = 3):
        self.total = total
        self.calls: list[object] = []

    def score(self, intake) -> dict:
        self.calls.append(intake)
        return {
            "factors": {name: {"score": 0, "evidence_id": None, "note": None, "used": False}
                        for name in factors_for_kind(intake.kind)},
            "total": self.total,
            "status": "ok",
        }


def _write_v1_store(run_dir: Path, proposals: list[dict], survey=None) -> None:
    atomic_json(run_dir / "candidates.json", {
        "schema_version": 1,
        "survey": survey or {
            "attack_surface": [{"target": "extracted/bin/robotd"}],
            "checked_scope": ["extracted/etc/"],
            "coverage_gaps": [],
        },
        "session_state": {"notes": "recon 完成"},
        "candidates": proposals,
    })


def _write_evidence(run_dir: Path, evidence_id: str, summary: str = "命中") -> None:
    atomic_json(run_dir / "investigations" / "recon" / "evidence" / f"{evidence_id}.json", {
        "schema_version": 1,
        "evidence_id": evidence_id,
        "tool": "search_code",
        "arguments": {},
        "summary": summary,
        "location": f"investigations/recon/evidence/{evidence_id}.json",
        "digest": "0" * 64,
        "candidate_id": "recon",
        "investigation_id": "recon-survey",
        "sequence": int(evidence_id.split("-")[1]),
        "observation": summary,
        "tool_result": {"ok": True, "text": "", "raw": "", "data": None,
                        "error": None, "elapsed": 0.0},
    })


def test_store_build_upgrades_v1_recon_output(tmp_path: Path) -> None:
    _write_v1_store(tmp_path, [
        _recon_proposal(proposal_id="proposal-0001", anchor="handle_msg"),
        _recon_proposal(proposal_id="proposal-0002", anchor="handle_msg"),  # 精确重复
    ])
    _write_evidence(tmp_path, "ev-000001")
    scorer = _FakeScorer(total=5)
    store = CandidateStore(tmp_path)
    payload = store.build(_ScriptedComparator([]), lambda _ctx: scorer)
    assert payload["schema_version"] == 2
    assert payload["survey"]["checked_scope"] == ["extracted/etc/"]
    assert payload["session_state"] == {"notes": "recon 完成"}
    assert len(payload["candidates"]) == 1
    record = payload["candidates"][0]
    assert record["candidate_id"] == "cand-0001"
    assert record["aliases"] == ["proposal-0002"]
    assert record["priority"]["total"] == 5
    assert record["queue"] == {"queue": "signal", "rank": 1, "selected": True}
    assert record["disposition"] is None
    assert payload["llm_calls"] == {"dedup": 0, "scoring": 1}
    assert [entry["type"] for entry in payload["dedup_log"]] == ["created", "exact_merge"]
    # 落盘后的文件与新实例重读一致
    assert CandidateStore(tmp_path).build(_ScriptedComparator([]), lambda _ctx: _FakeScorer()) == payload
    assert len(scorer.calls) == 1


def test_store_build_marks_unselected_candidates_not_started(tmp_path: Path) -> None:
    proposals = [
        _recon_proposal(proposal_id=f"proposal-{i:04d}", target=f"extracted/bin/tool{i}")
        for i in range(1, 5)
    ]
    _write_v1_store(tmp_path, proposals)
    for i in range(1, 5):
        _write_evidence(tmp_path, f"ev-{i:06d}")
    store = CandidateStore(tmp_path)
    payload = store.build(_ScriptedComparator([]), lambda _ctx: _FakeScorer(), slots=2)
    selected = [c["candidate_id"] for c in payload["candidates"]
                if c["queue"]["selected"]]
    assert selected == ["cand-0001", "cand-0002"]
    assert store.not_started_ids() == ["cand-0003", "cand-0004"]
    unselected = payload["candidates"][2]
    assert unselected["disposition"] == "not_started"
    assert unselected["priority"]["total"] == 3  # 未入选也保留评分与队列名次
    assert unselected["queue"]["selected"] is False


def test_store_incremental_related_candidate_keeps_ids_and_scores(tmp_path: Path) -> None:
    _write_v1_store(tmp_path, [_recon_proposal(proposal_id="proposal-0001", anchor="handle_msg")])
    _write_evidence(tmp_path, "ev-000001")
    store = CandidateStore(tmp_path)
    first = store.build(_ScriptedComparator([]), lambda _ctx: _FakeScorer(total=5))
    scorer = _FakeScorer()
    related = normalize_intake(
        _recon_proposal(proposal_id="rel-cand-0001-1", anchor="main"),
        source="related:cand-0001",
    )
    payload = store.build(
        _ScriptedComparator([_outcome("same")]), lambda _ctx: scorer,
        extra_intake=[related],
    )
    assert [c["candidate_id"] for c in payload["candidates"]] == ["cand-0001"]
    record = payload["candidates"][0]
    assert record["aliases"] == ["rel-cand-0001-1"]
    assert record["priority"]["total"] == 5  # 既有评分不因合并丢失
    assert scorer.calls == []                # 无新幸存者,不重复评分
    assert payload["llm_calls"] == {"dedup": 1, "scoring": 1}
    assert [entry["type"] for entry in payload["dedup_log"]] == [
        "created", "semantic_merge",
    ]


def test_store_build_without_existing_file_accepts_extra_intake(tmp_path: Path) -> None:
    _write_evidence(tmp_path, "ev-000001")
    related = normalize_intake(_recon_proposal(), source="related:cand-0001")
    payload = CandidateStore(tmp_path).build(
        _ScriptedComparator([]), lambda _ctx: _FakeScorer(), extra_intake=[related],
    )
    assert payload["schema_version"] == 2
    assert payload["survey"] == {}
    assert payload["candidates"][0]["candidate_id"] == "cand-0001"


def test_store_rejects_unknown_schema_version(tmp_path: Path) -> None:
    atomic_json(tmp_path / "candidates.json", {"schema_version": 3, "candidates": []})
    with pytest.raises(StoreError):
        CandidateStore(tmp_path).build(_ScriptedComparator([]), lambda _ctx: _FakeScorer())


def test_store_not_started_requires_deduped_store(tmp_path: Path) -> None:
    _write_v1_store(tmp_path, [_recon_proposal()])
    with pytest.raises(StoreError):
        CandidateStore(tmp_path).not_started_ids()


# ---- 票 17/S6:盘上记录损坏属 Store 语义,不得泄漏 intake 契约错误类型 ----


_CORRUPT_DISK_RECORDS = (
    {"proposal_id": ""},
    {"proposal_id": None},
    {"target": None},
    {"target": "   "},
    {"signal": ""},
    {"kind": "weird"},
    {"evidence_id": "  "},
    {"next_action": None},
    {"claim_profile": "authentication"},
)


@pytest.mark.parametrize("mutation", _CORRUPT_DISK_RECORDS,
                         ids=lambda item: next(iter(item)))
def test_store_rejects_corrupt_v1_disk_records_as_store_errors(tmp_path: Path, mutation) -> None:
    _write_v1_store(tmp_path, [_recon_proposal(**mutation)])

    with pytest.raises(StoreError) as excinfo:
        CandidateStore(tmp_path).build(_ScriptedComparator([]), lambda _ctx: _FakeScorer())

    assert not isinstance(excinfo.value, CandidateIntakeError)


@pytest.mark.parametrize("mutation", _CORRUPT_DISK_RECORDS + (
    # v2 记录带权威 source;v1 记录没有该字段(来源由调用方按 "recon" 传入)。
    {"source": None},
    {"source": "   "},
    {"candidate_id": ""},
), ids=lambda item: str(tuple(item)))
def test_store_rejects_corrupt_v2_disk_records_as_store_errors(tmp_path: Path, mutation) -> None:
    _write_v1_store(tmp_path, [_recon_proposal()])
    _write_evidence(tmp_path, "ev-000001")
    store = CandidateStore(tmp_path)
    store.build(_ScriptedComparator([]), lambda _ctx: _FakeScorer())
    payload = json.loads(store.store_path.read_text(encoding="utf-8"))
    payload["candidates"][0].update(mutation)
    store.store_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(StoreError) as excinfo:
        store.build(_ScriptedComparator([]), lambda _ctx: _FakeScorer())

    assert not isinstance(excinfo.value, CandidateIntakeError)


def test_new_intake_contract_errors_stay_model_facing(tmp_path: Path) -> None:
    """同一份契约,两种来源:模型新输入是 CandidateIntakeError,盘上记录是 StoreError。"""
    with pytest.raises(CandidateIntakeError):
        normalize_intake(_recon_proposal(target=None), source="recon")
    with pytest.raises(CandidateIntakeError):
        normalize_intake(_recon_proposal(), source="  ")
    _write_v1_store(tmp_path, [_recon_proposal(target=None)])
    with pytest.raises(StoreError):
        CandidateStore(tmp_path).build(_ScriptedComparator([]), lambda _ctx: _FakeScorer())


def test_store_build_reads_slots_from_environment(tmp_path: Path, monkeypatch) -> None:
    proposals = [
        _recon_proposal(proposal_id=f"proposal-{i:04d}", target=f"extracted/bin/t{i}")
        for i in range(1, 5)
    ]
    _write_v1_store(tmp_path, proposals)
    for i in range(1, 5):
        _write_evidence(tmp_path, f"ev-{i:06d}")
    monkeypatch.setenv("STEP5_CANDIDATE_SLOTS", "2")
    payload = CandidateStore(tmp_path).build(_ScriptedComparator([]), lambda _ctx: _FakeScorer())
    assert sum(c["queue"]["selected"] for c in payload["candidates"]) == 2


# ---- S7 端到端:Host Recon 真实产物 → Candidate Store v2 ----

def _reply(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False)


def test_recon_output_builds_deduped_scored_and_selected_store(tmp_path: Path) -> None:
    process_dir = tmp_path / "process"
    extracted_etc = process_dir / "extracted" / "etc"
    extracted_bin = process_dir / "extracted" / "bin"
    extracted_etc.mkdir(parents=True)
    extracted_bin.mkdir(parents=True)
    (extracted_etc / "device.conf").write_text("admin_token=literal-secret\n", encoding="utf-8")
    (extracted_bin / "robotd").write_bytes(b"\x7fELF" + b"x" * 60)
    run_dir = tmp_path / "run"

    recon_llm = ScriptedLLM([
        _reply({
            "decision_summary": "先枚举顶层结构",
            "state_delta": {"notes": "枚举顶层"},
            "next": {"kind": "tool_action", "tool": "list_files",
                     "arguments": {"directory": "."}},
        }),
        _reply({
            "decision_summary": "读取管理配置核实口令样式",
            "state_delta": {"focus": "extracted/etc/device.conf"},
            "next": {"kind": "tool_action", "tool": "read_file",
                     "arguments": {"path": "extracted/etc/device.conf"}},
        }),
        _reply({
            "decision_summary": "攻击面与候选齐备,提交 survey",
            "state_delta": {
                "attack_surface": [
                    {"target": "extracted/etc/device.conf", "reason": "设备管理配置"},
                    {"target": "extracted/bin/robotd", "reason": "网络守护进程"},
                ],
                "candidates": [
                    {
                        "kind": "signal",
                        "target": "extracted/etc/device.conf",
                        "signal": "管理配置含 admin_token= 硬编码样式条目",
                        "evidence_id": "ev-000002",
                        "next_action": "核实 token 实际用途",
                        "claim_profile": "credentials",
                        "mechanism": "hardcoded credentials",
                        "anchor": "device.conf:1",
                    },
                    {
                        "kind": "signal",
                        "target": "extracted/etc/device.conf",
                        "signal": "同一配置的凭据条目(重复观察)",
                        "evidence_id": "ev-000002",
                        "next_action": "核实凭据有效性",
                        "claim_profile": "credentials",
                        "mechanism": "hardcoded credentials",
                        "anchor": "device.conf:1",
                    },
                    {
                        "kind": "coverage",
                        "target": "extracted/bin/robotd",
                        "signal": "网络守护进程输入解析面,本轮未深查",
                        "evidence_id": "ev-000001",
                        "next_action": "strings/imports 后按需反编译",
                        "component_or_entry": "robotd 守护进程",
                        "check_goal": "核查外部输入解析",
                    },
                ],
                "checked_scope": ["extracted/(顶层枚举)", "extracted/etc/device.conf"],
                "coverage_gaps": [
                    {"area": "extracted/bin/robotd", "reason": "未做字符串与导入核查"},
                ],
            },
            "next": {"kind": "complete_survey"},
        }),
    ])
    tools = make_tools(ToolContext(process_dir=process_dir), role="recon")
    session = AgentSession(
        "recon", recon_llm, ContextManager(RECON_SESSION_SYSTEM, ""),
        transcript=run_dir / "recon" / "transcript.jsonl",
    )
    recon_result = HostReconRunner(run_dir, tools).run(session, process_dir)
    assert recon_result.status == "completed"

    comparator_llm = ScriptedLLM([])  # 只安排精确重复,不允许任何语义比较
    scorer_llm = ScriptedLLM([
        _reply({"factors": {
            "external_reachability": {"score": 2, "evidence_id": "ev-000002"},
            "input_control": {"score": 1, "evidence_id": "ev-000002"},
            "high_impact_operation": {"score": 2, "evidence_id": "ev-000002"},
            "path_progress": {"score": 0, "evidence_id": "ev-000002"},
            "material_strength": {"score": 2, "evidence_id": "ev-000002"},
            "estimated_cost": {"score": 1, "evidence_id": "ev-000002"},
        }}),
        _reply({"factors": {
            "component_value": {"score": 2, "evidence_id": "ev-000001"},
            "external_exposure": {"score": 2, "evidence_id": "ev-000001"},
            "unchecked_extent": {"score": 1, "evidence_id": "ev-000001"},
            "estimated_cost": {"score": 1, "evidence_id": "ev-000001"},
        }}),
    ])

    store = CandidateStore(run_dir)
    payload = store.build(
        SemanticComparator(comparator_llm), make_priority_scorer(scorer_llm),
    )

    assert comparator_llm.calls == []  # 精确重复零语义比较
    assert payload["schema_version"] == 2
    assert payload["survey"]["checked_scope"] == ["extracted/(顶层枚举)", "extracted/etc/device.conf"]
    assert [record["candidate_id"] for record in payload["candidates"]] == [
        "cand-0001", "cand-0002",
    ]
    signal_record, coverage_record = payload["candidates"]
    assert signal_record["aliases"] == ["proposal-0002"]
    assert signal_record["claim_profile"] == "credentials"
    assert signal_record["priority"]["total"] == 6  # 2+1+2+0+2-1
    assert coverage_record["priority"]["total"] == 4  # 2+2+1-1
    assert coverage_record["queue"] == {
        "queue": "coverage", "rank": 1, "selected": True,
    }
    assert all(record["disposition"] is None for record in payload["candidates"])
    assert payload["llm_calls"] == {"dedup": 0, "scoring": 2}
    assert [entry["type"] for entry in payload["dedup_log"]] == [
        "created", "exact_merge", "created",
    ]
    assert store.not_started_ids() == []
    # 评分请求以盘上 Evidence 摘要表为依据
    first_scoring_user = scorer_llm.calls[0][1]["content"]
    assert "ev-000002" in first_scoring_user
    assert "extracted/etc/device.conf" in first_scoring_user  # read_file Evidence 摘要入评分依据


# ---- 票 18:Related Candidate 契约单一出处与回队出口 ----


def _contract_examples(text: str) -> list[dict]:
    """从提示文本里抽出 JSON 示例块:提示写的样例必须真的能被机器消费。"""
    blocks = re.findall(r"```json\n(.*?)\n```", text, re.S)
    assert len(blocks) == 2
    return [json.loads(block) for block in blocks]


@pytest.mark.parametrize("index,kind", [(0, "signal"), (1, "coverage")])
def test_contract_example_passes_analysis_and_verification_validation(index: int, kind: str) -> None:
    example = _contract_examples(related_candidate_contract())[index]
    entries = example["related_candidates"]
    assert entries[0]["kind"] == kind
    for field in RELATED_CANDIDATE_FIELDS:
        assert field in entries[0], field
    evidence = frozenset({entries[0]["evidence_id"]})

    analysis = validate_analysis_delta(
        {}, example, evidence_ids=evidence, profile="generic",
        related_origin=RelatedOrigin("analysis", "cand-0001", "inv-0001"))
    verification = validate_verification_delta(
        {}, example, evidence_ids=evidence, profile="generic",
        case_candidate_id="cand-0001", case_investigation_id="inv-0001")

    assert len(analysis.related_candidates) == 1
    assert len(verification.related_candidates) == 1
    assert analysis.related_candidates[0]["proposal_id"] \
        == verification.related_candidates[0]["proposal_id"]


def test_contract_text_names_every_required_field() -> None:
    text = related_candidate_contract()

    for field in RELATED_CANDIDATE_FIELDS:
        assert field in text, field
    for field in ("anchor", "mechanism", "component_or_entry", "check_goal"):
        assert field in text, field
    assert "signal" in text and "coverage" in text


def test_related_origin_rejects_unknown_role_and_missing_identity() -> None:
    with pytest.raises(CandidateIntakeError, match="角色"):
        RelatedOrigin("recon", "cand-0001", "inv-0001")
    with pytest.raises(CandidateIntakeError, match="candidate_id"):
        RelatedOrigin("analysis", "", "inv-0001")
    assert RelatedOrigin("verification", "cand-0002", "inv-0002").source \
        == "verification:cand-0002"


def test_related_candidate_records_reject_broken_shapes() -> None:
    origin = RelatedOrigin("analysis", "cand-0001", "inv-0001")
    with pytest.raises(CandidateIntakeError, match="非空数组"):
        related_candidate_records({}, evidence_ids=frozenset(), origin=origin)
    with pytest.raises(CandidateIntakeError, match="必须为 JSON object"):
        related_candidate_records([1], evidence_ids=frozenset(), origin=origin)
    with pytest.raises(CandidateIntakeError, match="本 Investigation 的 Evidence"):
        related_candidate_records(
            [_recon_proposal(evidence_id="ev-999999")],
            evidence_ids=frozenset({"ev-000001"}), origin=origin)


def test_related_intake_restores_a_candidate_store_ready_record() -> None:
    """票 11 的入口:已校验记录 → Candidate Store 可消费的 intake,来源身份不丢。"""
    origin = RelatedOrigin("verification", "cand-0001", "inv-0001")
    record = related_candidate_records(
        [_recon_proposal(proposal_id="rel-cand-0001-1", anchor="handle_msg")],
        evidence_ids=frozenset({"ev-000001"}), origin=origin)[0]

    intake = related_intake(record)

    assert isinstance(intake, IntakeCandidate)
    assert intake.source == "verification:cand-0001"
    assert intake.proposal_id == "rel-cand-0001-1"
    assert intake.target == "extracted/bin/robotd"
    assert intake.claim_profile == "generic"


def test_stored_related_proposals_reads_both_roles_and_dedups_by_source(tmp_path: Path) -> None:
    """票 11 的入口:从权威工件读回已校验线索,不依赖 Transcript 或 Finding。"""
    origin = RelatedOrigin("analysis", "cand-0001", "inv-0001")
    record = related_candidate_records(
        [_recon_proposal(proposal_id="rel-cand-0001-1", anchor="handle_msg")],
        evidence_ids=frozenset({"ev-000001"}), origin=origin)[0]
    store = InvestigationStore(tmp_path, "cand-0001")
    store.save("candidate_created", {
        "candidate": {"candidate_id": "cand-0001", "proposal": {}},
        "investigation": {"state": {"related_candidates": [record]}},
        "runtime": {},
    })
    atomic_json(tmp_path / "verifications" / "cand-0001" / "results.json", {
        "candidate_id": "cand-0001", "related_candidates": [record],
    })

    proposals = stored_related_proposals(tmp_path)

    assert proposals == (record,)
    assert stored_related_proposals(tmp_path) == proposals  # 读取幂等


# ---- 票 25:错放进嵌套 fingerprint 对象的领域字段拒绝,不静默退化 ----


def _misplaced_via_extras() -> dict:
    """真实两例的错放形态:领域字段包进 extras.fingerprint 嵌套对象。"""
    return _recon_proposal(extras={"fingerprint": {
        "claim_profile": "data_propagation",
        "anchor": "parse_header+0x42",
        "mechanism": "integer overflow",
    }})


def test_normalize_intake_rejects_fingerprint_nested_domain_fields() -> None:
    with pytest.raises(CandidateIntakeError) as excinfo:
        normalize_intake(_misplaced_via_extras(), source="recon")
    message = str(excinfo.value)
    assert "extras.fingerprint.claim_profile" in message
    assert "平铺" in message  # 拒绝时告知正确字段位置
    # 顶层 fingerprint 对象是同一已知错误位置
    with pytest.raises(CandidateIntakeError, match="fingerprint\\.anchor"):
        normalize_intake(
            _recon_proposal(fingerprint={"anchor": "handle_msg", "mechanism": "x"}),
            source="recon",
        )


def test_normalize_intake_names_misplacement_before_missing_required_fields() -> None:
    """整份 candidate 被包进嵌套时,错放诊断优先于零散的缺字段报错。"""
    with pytest.raises(CandidateIntakeError, match="fingerprint"):
        normalize_intake({
            "proposal_id": "proposal-0001",
            "kind": "signal",
            "fingerprint": {
                "target": "extracted/bin/robotd", "signal": "s", "evidence_id": "ev-000001",
                "next_action": "n", "claim_profile": "credentials",
            },
        }, source="recon")


def test_normalize_intake_keeps_unknown_nested_metadata() -> None:
    """未知嵌套元数据不一刀切禁止;真正缺省 claim_profile 仍按 generic。"""
    intake = normalize_intake(
        _recon_proposal(extras={
            "fingerprint": {"notes": "模型自查备注"},
            "review": {"verdict": "pending"},
        }),
        source="recon",
    )
    assert intake.claim_profile == "generic"
    assert intake.anchor == "" and intake.mechanism == ""
    assert intake.extras == {
        "fingerprint": {"notes": "模型自查备注"}, "review": {"verdict": "pending"},
    }


def test_normalize_intake_stored_reproduces_misplaced_history() -> None:
    """盘上记录按已接受时刻的归一复现(stored=True),不重新审判历史。"""
    intake = normalize_intake(_misplaced_via_extras(), source="recon", stored=True)
    assert intake.claim_profile == "generic"
    assert intake.anchor == "" and intake.mechanism == ""
    assert intake.extras["fingerprint"] == {
        "claim_profile": "data_propagation",
        "anchor": "parse_header+0x42",
        "mechanism": "integer overflow",
    }


def test_related_candidate_records_reject_fingerprint_nesting() -> None:
    """Related Candidate 与 Recon 入口同规则:错放整份拒绝(票 25 AC3)。"""
    origin = RelatedOrigin("analysis", "cand-0001", "inv-0001")
    entry = _recon_proposal(
        proposal_id="rel-cand-0001-1",
        extras={"fingerprint": {"claim_profile": "credentials", "anchor": "load_keys"}},
    )
    with pytest.raises(CandidateIntakeError, match="extras\\.fingerprint\\.claim_profile"):
        related_candidate_records(
            [entry], evidence_ids=frozenset({"ev-000001"}), origin=origin)


def test_analysis_delta_rejects_misplaced_related_candidate_as_model_feedback() -> None:
    """调用边界翻译成 ProposalRejectedError:拒绝发生在任何状态应用之前。"""
    example = {"related_candidates": [{
        "proposal_id": "rel-cand-0001-1", "kind": "signal",
        "target": "extracted/bin/updater", "signal": "升级包解析未校验长度",
        "evidence_id": "ev-000001", "next_action": "反编译确认边界检查",
        "extras": {"fingerprint": {"mechanism": "integer overflow"}},
    }]}
    with pytest.raises(ProposalRejectedError, match="fingerprint"):
        validate_analysis_delta(
            {}, example, evidence_ids=frozenset({"ev-000001"}), profile="generic",
            related_origin=RelatedOrigin("analysis", "cand-0001", "inv-0001"))


def test_related_intake_reproduces_pre_fix_misplaced_history() -> None:
    """修复前入册的 Related 记录读取时按 stored 契约复现,不升格为 StoreError。"""
    origin = RelatedOrigin("analysis", "cand-0001", "inv-0001")
    record = {
        "origin": origin.record(),
        **normalize_intake(
            _recon_proposal(proposal_id="rel-cand-0001-1"), source=origin.source,
        ).as_dict(),
        "extras": {"fingerprint": {"claim_profile": "credentials"}},
    }
    intake = related_intake(record)
    assert intake.claim_profile == "generic"
    assert intake.extras["fingerprint"] == {"claim_profile": "credentials"}


def test_corrected_flat_input_keeps_dedup_dimensions() -> None:
    """票 25 AC:按指路修正后的平铺输入保留去重维度,同目标不同锚点不合并不清空。"""
    first = _intake(proposal_id="proposal-0001", claim_profile="data_propagation",
                    anchor="parse_header+0x42", mechanism="integer overflow")
    second = _intake(proposal_id="proposal-0002", claim_profile="data_propagation",
                     anchor="parse_header+0x99", mechanism="integer overflow")
    assert first.fingerprint() != second.fingerprint()
    comparator = _ScriptedComparator([_outcome("different")])
    result = deduplicate([first, second], comparator=comparator)
    assert [entry["type"] for entry in result.dedup_log] == ["created", "kept_independent"]
    assert len(result.candidates) == 2
    # coverage 维度同理:同目标同组件,check_goal 不同即不同候选
    goal_a = _intake(proposal_id="proposal-0003", kind="coverage",
                     component_or_entry="upgrade handler", check_goal="边界检查覆盖")
    goal_b = _intake(proposal_id="proposal-0004", kind="coverage",
                     component_or_entry="upgrade handler", check_goal="主题授权覆盖")
    assert goal_a.fingerprint() != goal_b.fingerprint()
    assert goal_a.check_goal == "边界检查覆盖" and goal_b.check_goal == "主题授权覆盖"


def test_normalize_intake_rejects_conflict_between_flat_and_nested_fields() -> None:
    """票 25 AC:平铺字段与嵌套 fingerprint 同时出现的冲突形态同样整份拒绝。"""
    with pytest.raises(CandidateIntakeError, match="extras\\.fingerprint\\.claim_profile"):
        normalize_intake(
            _recon_proposal(
                claim_profile="config",
                extras={"fingerprint": {"claim_profile": "credentials"}},
            ),
            source="recon",
        )


def test_contract_text_demands_flat_fingerprint_inputs() -> None:
    text = related_candidate_contract()
    assert "Host 派生" in text and "平铺" in text


def test_store_build_reproduces_pre_fix_misplaced_v1_history(tmp_path: Path) -> None:
    """修复前落盘的 v1 错放 proposal 在续跑升级时按已接受形态复现(旧恢复兼容),
    不因新契约拒之门外;已封存世代不重算、不改写语义。"""

    class _ZeroScorer:
        def score(self, candidate):
            return {"factors": {}, "total": 0, "status": "ok", "raw": None}

    misplaced = {
        "proposal_id": "proposal-0001",
        "kind": "signal",
        "target": "extracted/etc/device.conf",
        "signal": "配置含口令样式条目",
        "evidence_id": "ev-000001",
        "next_action": "核实口令用途",
        "extras": {"fingerprint": {"claim_profile": "credentials", "anchor": "device.conf:1"}},
    }
    atomic_json(tmp_path / "candidates.json", {
        "schema_version": 1, "survey": {}, "session_state": {},
        "candidates": [misplaced],
    })

    payload = CandidateStore(tmp_path).build(
        SemanticComparator(ScriptedLLM([])), lambda evidence_context: _ZeroScorer(),
    )

    record = payload["candidates"][0]
    assert record["claim_profile"] == "generic"
    assert record["extras"]["fingerprint"] == {
        "claim_profile": "credentials", "anchor": "device.conf:1",
    }

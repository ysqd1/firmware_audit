"""Host Analysis tracer tests: exercise the real Host seam with fakes only."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from firmware_audit.step5_agent.host import (
    ActionProposal,
    FinalProposal,
    HostAnalysisTracer,
    ProposalError,
    ValidationIssue,
    parse_proposal,
)
from firmware_audit.step5_agent.host.claims import CLAIM_STATUSES
from firmware_audit.step5_agent.host.evidence import EvidenceRecorder
from firmware_audit.step5_agent.host.store import InvestigationStore, StoreError
from firmware_audit.step5_agent.providers.tools.base import ToolResult


class FakeSession:
    role = "analysis"

    def __init__(self, proposals: list[object]):
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


def test_host_accepts_proposals_from_session_parser(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="observed"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/etc/device.conf"})
    replies = [
        {"decision_summary": "读取", "state_delta": {"nested": {"value": 1}},
         "next": {"kind": "tool_action", "tool": "read_file",
                  "arguments": {"path": "extracted/etc/device.conf"}}},
        {"decision_summary": "关闭", "state_delta": {
            "closure_reason": "决定性反证", "evidence_refs": ["ev-000001"]},
         "next": {"kind": "close_investigation"}},
    ]
    session = FakeSession([
        parse_proposal(json.dumps(reply), "analysis") for reply in replies
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    assert investigation.lifecycle_status == "finished"
    assert investigation.state == {"nested": {"value": 1}}
    assert len(tool.calls) == 1


def _action(state_delta: dict, arguments: dict | None = None) -> ActionProposal:
    return ActionProposal(
        decision_summary="读取候选目标并保留原始 Observation",
        state_delta=state_delta,
        tool="read_file",
        arguments=arguments or {"path": "extracted/etc/device.conf"},
    )


def _close(
    evidence_refs: tuple[str, ...] = ("ev-000001",),
    state_delta: dict | None = None,
) -> FinalProposal:
    delta = {
        "closure_reason": "工具 Evidence 构成决定性反证",
        "evidence_refs": list(evidence_refs),
        **(state_delta or {}),
    }
    return FinalProposal(
        decision_summary="现有材料足以结束本次调查",
        state_delta=delta,
        kind="close_investigation",
    )


def test_host_runs_one_candidate_and_preserves_distinct_evidence(tmp_path: Path) -> None:
    raw = "token=literal-value\n" + "A" * 120 + "\nend=literal-tail"
    tool = FakeTool(ToolResult(
        ok=True,
        text=raw,
        raw=raw,
        data={"value": "literal-value", "matches": [3, 1]},
        elapsed=0.125,
    ))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool}, observation_view_limit=90)
    candidate = host.add_candidate({
        "target": "extracted/etc/device.conf",
        "signal": "管理配置包含凭据样式文本",
    })
    session = FakeSession([
        _action({"hypothesis": {"statement": "配置可能暴露固定令牌"}}, {"path": "extracted/etc/device.conf", "limit": 40}),
        _action({"checked_paths": ["extracted/etc/device.conf"]}, {"limit": 40, "path": "extracted/etc/device.conf"}),
        _close(("ev-000001", "ev-000002"), {"closure_note": "重复读取结果一致"}),
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    assert candidate.candidate_id == "cand-0001"
    assert investigation.investigation_id == "inv-0001"
    assert investigation.lifecycle_status == "finished"
    assert investigation.disposition == "closed"
    assert investigation.stop_reason == "agent_closed"
    assert investigation.closure_reason == "工具 Evidence 构成决定性反证"
    assert investigation.closure_evidence == ("ev-000001", "ev-000002")
    assert investigation.state == {
        "hypothesis": {"working": {"statement": "配置可能暴露固定令牌"}, "history": []},
        "checked_paths": ["extracted/etc/device.conf"],
        "closure_note": "重复读取结果一致",
    }
    assert [item.evidence_id for item in investigation.evidence] == [
        "ev-000001", "ev-000002",
    ]
    assert [item.sequence for item in investigation.evidence] == [1, 2]
    assert investigation.evidence[0].digest == investigation.evidence[1].digest
    assert investigation.evidence[0].location != investigation.evidence[1].location
    assert tool.calls == [
        {"limit": 40, "offset": 0, "path": "extracted/etc/device.conf"},
        {"limit": 40, "offset": 0, "path": "extracted/etc/device.conf"},
    ]

    first_file = tmp_path / investigation.evidence[0].location
    saved = json.loads(first_file.read_text(encoding="utf-8"))
    assert saved["arguments"] == {
        "limit": 40,
        "offset": 0,
        "path": "extracted/etc/device.conf",
    }
    assert saved["tool_result"] == {
        "data": {"matches": [3, 1], "value": "literal-value"},
        "elapsed": 0.125,
        "error": None,
        "ok": True,
        "raw": raw,
        "text": raw,
    }
    assert saved["summary"].startswith("token=literal-value")
    assert saved["candidate_id"] == "cand-0001"
    assert saved["investigation_id"] == "inv-0001"

    first_view, second_view = session.inputs[1:]
    assert first_view is not None and "Observation View [ev-000001]" in first_view
    assert second_view is not None and "Observation View [ev-000002]" in second_view
    assert "token=literal-value" in first_view
    assert "end=literal-tail" in first_view
    assert "已截断" in first_view
    assert len(saved["tool_result"]["raw"]) > 90
    assert raw not in first_view
    assert not hasattr(investigation, "verification_verdict")
    assert not hasattr(investigation, "findings")


def test_candidate_ids_and_investigation_state_are_isolated(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    first = host.add_candidate({"target": "extracted/bin/one"})
    second = host.add_candidate({"target": "extracted/bin/two"})

    first_session = FakeSession([
        _action({"note": "first-only"}),
        _close(),
    ])
    second_session = FakeSession([
        _action({"note": "second-only"}),
        _close(("ev-000002",)),
    ])
    first_result = host.run_analysis(first.candidate_id, first_session)
    second_result = host.run_analysis(second.candidate_id, second_session)

    assert (first.candidate_id, second.candidate_id) == ("cand-0001", "cand-0002")
    assert (first_result.investigation_id, second_result.investigation_id) == (
        "inv-0001", "inv-0002",
    )
    assert first_result.state == {"note": "first-only"}
    assert second_result.state == {"note": "second-only"}
    assert [item.evidence_id for item in first_result.evidence] == ["ev-000001"]
    assert [item.evidence_id for item in second_result.evidence] == ["ev-000002"]
    assert first_result.evidence[0].candidate_id == first.candidate_id
    assert second_result.evidence[0].candidate_id == second.candidate_id
    assert first.candidate_id in first_session.inputs[0]
    assert "extracted/bin/one" in first_session.inputs[0]
    assert second.candidate_id in second_session.inputs[0]
    assert "extracted/bin/two" in second_session.inputs[0]


def test_one_session_cannot_be_reused_across_candidates(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    first = host.add_candidate({"target": "extracted/bin/one"})
    second = host.add_candidate({"target": "extracted/bin/two"})
    shared_session = FakeSession([
        _action({}),
        _close(),
        _action({}),
        _close(),
    ])

    host.run_analysis(first.candidate_id, shared_session)
    with pytest.raises(ValueError, match="独立 Agent Session"):
        host.run_analysis(second.candidate_id, shared_session)

    assert host.investigation_for(second.candidate_id).lifecycle_status == "queued"


def test_failed_tool_evidence_keeps_raw_literal_and_matching_digest(tmp_path: Path) -> None:
    raw = "stderr-token=literal-failure-value"
    tool = FakeTool(ToolResult(
        ok=False,
        text="short failure view",
        raw=raw,
        error="process exited 2",
        elapsed=0.5,
    ))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([_action({}), _close()])

    investigation = host.run_analysis(candidate.candidate_id, session)

    reference = investigation.evidence[0]
    saved = json.loads((tmp_path / reference.location).read_text(encoding="utf-8"))
    assert saved["observation"] == raw
    assert reference.digest == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert raw in session.inputs[1]
    assert "process exited 2" in session.inputs[1]


@pytest.mark.parametrize("error", [None, ""])
def test_failed_tool_without_error_message_is_not_shown_as_success(
    tmp_path: Path, error: str | None,
) -> None:
    tool = FakeTool(ToolResult(ok=False, text="could not open file", error=error))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/etc/device.conf"})
    session = FakeSession([_action({}), _close()])

    host.run_analysis(candidate.candidate_id, session)

    assert "Tool status: error" in session.inputs[1]
    assert "could not open file" in session.inputs[1]


def test_malformed_tool_result_fields_become_failure_evidence(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text=7, raw=7))  # type: ignore[arg-type]
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([_action({}), _close()])

    investigation = host.run_analysis(candidate.candidate_id, session)

    reference = investigation.evidence[0]
    saved = json.loads((tmp_path / reference.location).read_text(encoding="utf-8"))
    assert saved["tool_result"]["ok"] is False
    assert "字段类型" in saved["tool_result"]["error"]
    assert "字段类型" in session.inputs[1]


@pytest.mark.parametrize("elapsed", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_tool_elapsed_becomes_failure_evidence(
    tmp_path: Path,
    elapsed: float,
) -> None:
    tool = FakeTool(ToolResult(ok=True, text="literal", raw="literal", elapsed=elapsed))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})

    investigation = host.run_analysis(
        candidate.candidate_id,
        FakeSession([_action({}), _close()]),
    )

    saved = json.loads(
        (tmp_path / investigation.evidence[0].location).read_text(encoding="utf-8")
    )
    assert saved["tool_result"]["ok"] is False
    assert saved["tool_result"]["elapsed"] == 0.0
    assert "elapsed" in saved["tool_result"]["error"]


@pytest.mark.parametrize("cyclic", [False, True])
def test_non_json_native_tool_data_becomes_failure_evidence(
    tmp_path: Path, cyclic: bool,
) -> None:
    data: dict = {"items": ("silently", "coerced")}
    if cyclic:
        data["items"] = data
    tool = FakeTool(ToolResult(
        ok=True,
        text="literal",
        raw="literal",
        data=data,
    ))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})

    investigation = host.run_analysis(
        candidate.candidate_id,
        FakeSession([_action({}), _close()]),
    )

    saved = json.loads(
        (tmp_path / investigation.evidence[0].location).read_text(encoding="utf-8")
    )
    assert saved["tool_result"]["ok"] is False
    assert "标准 JSON" in saved["tool_result"]["error"]


def test_evidence_records_effective_normalized_tool_arguments(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([
        _action({}, {"path": "  extracted\\etc\\device.conf  "}),
        _close(),
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    expected = {"path": "extracted/etc/device.conf", "offset": 0, "limit": 200}
    assert investigation.evidence[0].arguments == expected
    assert tool.calls == [expected]
    saved = json.loads(
        (tmp_path / investigation.evidence[0].location).read_text(encoding="utf-8")
    )
    assert saved["arguments"] == expected


def test_oversized_tool_result_leaves_bounded_failure_evidence(tmp_path: Path) -> None:
    raw = "literal-must-remain-whole"
    tool = FakeTool(ToolResult(ok=True, text=raw, raw=raw, data={"extra": "X" * 80}))
    host = HostAnalysisTracer(
        tmp_path,
        {"read_file": tool},
        tool_result_limit_bytes=64,
    )
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([_action({}), _close()])

    investigation = host.run_analysis(candidate.candidate_id, session)

    reference = investigation.evidence[0]
    saved = json.loads((tmp_path / reference.location).read_text(encoding="utf-8"))
    assert reference.evidence_id == "ev-000001"
    assert saved["tool_result"]["ok"] is False
    assert "大型产物" in saved["tool_result"]["error"]
    assert saved["tool_result"]["data"]["returned_bytes"] > 64
    assert len(json.dumps(saved["tool_result"], ensure_ascii=False).encode("utf-8")) < 600
    assert "大型产物" in session.inputs[1]
    assert tool.calls == [{
        "limit": 200,
        "offset": 0,
        "path": "extracted/etc/device.conf",
    }]


def test_existing_evidence_file_is_never_overwritten(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="new", raw="new"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    existing = (
        tmp_path
        / "investigations"
        / candidate.candidate_id
        / "evidence"
        / "ev-000001.json"
    )
    existing.parent.mkdir(parents=True)
    existing.write_text("original immutable evidence", encoding="utf-8")

    investigation = host.run_analysis(candidate.candidate_id, FakeSession([
        _action({}), _close(("ev-000002",)),
    ]))

    # 会话开始前抬水位:已占编号被跳过而非撞号,既有不可变文件原样保留。
    assert existing.read_text(encoding="utf-8") == "original immutable evidence"
    assert investigation.lifecycle_status == "finished"
    assert [item.evidence_id for item in investigation.evidence] == ["ev-000002"]
    assert (tmp_path / "investigations" / candidate.candidate_id
            / "evidence" / "ev-000002.json").exists()


def test_reserve_refuses_concurrent_evidence_writer(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(tmp_path)
    recorder.seed_sequence_from_files()  # 此刻两棵树为空,水位 0
    appeared = (
        tmp_path / "investigations" / "cand-0001" / "evidence" / "ev-000001.json"
    )
    appeared.parent.mkdir(parents=True)
    # seed 之后才出现的并发写手由 reserve 的存在性检查兜底:宁可失败也不覆盖。
    appeared.write_text("并发写手已占用", encoding="utf-8")

    with pytest.raises(FileExistsError):
        recorder.reserve("cand-0001")


def _write_evidence_file(tmp_path: Path, payload, evidence_id: str = "ev-000001") -> None:
    path = tmp_path / "investigations" / "cand-0001" / "evidence" / f"{evidence_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


@pytest.mark.parametrize("payload", [
    {"schema_version": 999},
    {"schema_version": 1},
    [],
    "not-json-at-all",
], ids=["incompatible_schema", "missing_fields", "not_an_object", "broken_json"])
def test_evidence_recovery_failures_are_single_store_errors(tmp_path: Path, payload) -> None:
    """票 17/S7:磁盘损坏统一按 StoreError 拒绝,且不重复包装同一 StoreError。"""
    recorder = EvidenceRecorder(tmp_path)
    _write_evidence_file(tmp_path, payload)

    with pytest.raises(StoreError) as excinfo:
        recorder.recover(recorder.restore_slot("cand-0001", 1))

    message = str(excinfo.value)
    assert message.startswith("Evidence 无法恢复") or "schema 不兼容" in message
    assert message.count("请创建新运行世代") <= 1
    assert "Evidence 无法恢复；请检查原工件或创建新运行世代: Evidence schema 不兼容" not in message


def test_invalid_proposal_has_no_host_or_tool_side_effect(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="must not run", raw="must not run"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    before = deepcopy(host.investigation_for(candidate.candidate_id))
    invalid = ProposalError((ValidationIssue(
        path="$.next.kind",
        expected="role-allowed next kind",
        actual='"invented"',
        allowed_values=("tool_action", "submit_case", "close_investigation"),
    ),), raw_reply='{"next":{"kind":"invented"}}')

    session = FakeSession([invalid, _action({}), _close()])
    completed = host.run_analysis(candidate.candidate_id, session)

    # 无效回复整份重生成:拒绝理由以结构化反馈回喂同一 Session,
    # 期间零状态/工具副作用——合法动作的 Evidence 仍从 ev-000001 起,
    # 无效回复没有烧掉任何 Evidence 身份。
    assert "$.next.kind" in (session.inputs[1] or "")
    assert "从头生成一份完整 JSON" in (session.inputs[1] or "")
    assert completed.lifecycle_status == "finished"
    assert completed.evidence[0].evidence_id == "ev-000001"
    assert len(tool.calls) == 1


def test_three_consecutive_invalid_replies_close_investigation_as_protocol_error(
        tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="must not run", raw="must not run"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    invalid = ProposalError((ValidationIssue(
        path="$.next.kind", expected="role-allowed next kind", actual='"nope"',
    ),), raw_reply='{"next":{"kind":"nope"}}')

    investigation = host.run_analysis(
        candidate.candidate_id, FakeSession([invalid, invalid, invalid]))

    assert (investigation.lifecycle_status, investigation.disposition,
            investigation.stop_reason) == (
        "finished", "unresolved", "protocol_error")
    assert investigation.evidence == []
    assert tool.calls == []
    assert not (tmp_path / "investigations" / candidate.candidate_id / "evidence").exists()


def test_unauthorized_action_rejects_whole_proposal_before_state_delta(tmp_path: Path) -> None:
    web_tool = FakeTool(ToolResult(ok=True, text="must not run", raw="must not run"))
    read_tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"web_search": web_tool, "read_file": read_tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    proposal = ActionProposal(
        decision_summary="尝试越权外部查询",
        state_delta={"note": "must-not-apply"},
        tool="web_search",
        arguments={"query": "known issue"},
    )

    session = FakeSession([proposal, _action({}), _close()])
    investigation = host.run_analysis(candidate.candidate_id, session)

    # 越权动作整份拒绝并回喂;其 state_delta 不落状态,越权工具零调用。
    assert "无权调用" in (session.inputs[1] or "")
    assert investigation.state == {}
    assert len(investigation.evidence) == 1
    assert web_tool.calls == []
    assert len(read_tool.calls) == 1


@pytest.mark.parametrize(
    "proposal",
    [
        ActionProposal(
            decision_summary="非法动作类型",
            state_delta={"note": "must-not-apply"},
            tool="read_file",
            arguments={"path": "extracted/bin/router"},
            kind="invented",
        ),
        ActionProposal(
            decision_summary="非法工具参数",
            state_delta={"note": "must-not-apply"},
            tool="read_file",
            arguments={"path": 7},
        ),
    ],
)
def test_host_revalidates_directly_constructed_action_proposal(
        tmp_path: Path,
        proposal: ActionProposal,
) -> None:
    tool = FakeTool(ToolResult(ok=True, text="must not run", raw="must not run"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})

    session = FakeSession([proposal, _action({}), _close()])
    investigation = host.run_analysis(candidate.candidate_id, session)

    # 伪造/失约的 ActionProposal 整份拒绝并回喂,合法收尾不受污染。
    assert investigation.lifecycle_status == "finished"
    assert investigation.state == {}
    assert len(investigation.evidence) == 1
    assert len(tool.calls) == 1


@pytest.mark.parametrize(
    "state_delta",
    [
        {"note": ("silently", "coerced")},
        {1: "silently-stringified-key"},
    ],
)
def test_host_rejects_non_json_native_proposal_before_side_effects(
        tmp_path: Path,
        state_delta: dict,
) -> None:
    tool = FakeTool(ToolResult(ok=True, text="must not run", raw="must not run"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    proposal = _action(state_delta)

    session = FakeSession([proposal, _action({}), _close()])
    investigation = host.run_analysis(candidate.candidate_id, session)

    # 非 JSON 原生值在共享边界整份拒绝并回喂,不落任何状态。
    assert "标准 JSON" in (session.inputs[1] or "")
    assert investigation.state == {}
    assert len(investigation.evidence) == 1


@pytest.mark.parametrize(
    "state_delta",
    [
        {"closure_reason": "", "evidence_refs": ["ev-000001"]},
        {"closure_reason": "决定性反证", "evidence_refs": []},
        {"closure_reason": "决定性反证", "evidence_refs": ["ev-999999"]},
    ],
)
def test_close_requires_reason_and_owned_evidence_reference(
        tmp_path: Path,
        state_delta: dict,
) -> None:
    host = HostAnalysisTracer(tmp_path, {"read_file": FakeTool(
        ToolResult(ok=True, text="same", raw="same"))})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    close = FinalProposal(
        decision_summary="主动关闭",
        state_delta=state_delta,
        kind="close_investigation",
    )

    session = FakeSession([close, _action({}), _close()])
    investigation = host.run_analysis(candidate.candidate_id, session)

    # 失约的 close 整份拒绝并回喂;合法 close 才落 closure 字段。
    assert investigation.lifecycle_status == "finished"
    assert investigation.disposition == "closed"
    assert investigation.closure_reason == "工具 Evidence 构成决定性反证"
    assert investigation.closure_evidence == ("ev-000001",)


# ---- Ticket 08:Claim/假设状态、submit_case 与 no-progress ----

GENERIC_REQUIRED = (
    "target_exists", "root_cause", "trigger_or_exposure", "actual_impact",
    "preconditions", "mitigations",
)


def _claims_delta(statuses: dict[str, dict]) -> dict:
    return {"claims": statuses}


def _supported(evidence_id: str = "ev-000001") -> dict:
    return {"status": "supported", "evidence_ids": [evidence_id]}


def _submit(admission: str, state_delta: dict | None = None) -> FinalProposal:
    return FinalProposal(
        decision_summary="案卷成熟,提交复核",
        state_delta={"admission_reason": admission, **(state_delta or {})},
        kind="submit_case",
    )


def test_candidate_context_carries_claim_profile_and_schema(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({
        "target": "extracted/bin/router", "claim_profile": "memory"})
    captured: list[str | None] = []

    class CapturingSession(FakeSession):
        def step(self, input_message=None):
            captured.append(input_message)
            return super().step(input_message)

    session = CapturingSession([_action({}), _close()])
    host.run_analysis(candidate.candidate_id, session)

    assert host.investigation_for(candidate.candidate_id).claim_profile == "memory"
    assert '"claim_profile": "memory"' in captured[0]
    assert "input_or_index_controlled" in captured[0]
    assert "决定性" not in captured[0]  # schema 是中性名单,不带判定


def test_add_candidate_rejects_unknown_claim_profile(tmp_path: Path) -> None:
    host = HostAnalysisTracer(tmp_path, {})
    with pytest.raises(ValueError, match="未知 Claim Profile"):
        host.add_candidate({"target": "x", "claim_profile": "invented"})


def test_claim_updates_are_validated_before_tool_execution(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="must not run", raw="must not run"))
    read_tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": read_tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    proposal = _action(_claims_delta(
        {"root_cause": {"status": "supported", "evidence_ids": ["ev-999999"]}}))

    session = FakeSession([proposal, _action({}), _close()])
    investigation = host.run_analysis(candidate.candidate_id, session)

    # 引用不存在 Evidence 的 Claim 更新整份拒绝:坏动作的工具不执行,
    # 其 claims 不落状态;合法动作照常取得 ev-000001。
    assert "不存在" in (session.inputs[1] or "")
    assert investigation.state == {}
    assert len(investigation.evidence) == 1
    assert investigation.evidence[0].evidence_id == "ev-000001"


def test_submit_case_ready_freezes_case_and_advances_lifecycle(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/etc/device.conf"})
    replies = [
        {"decision_summary": "一次性判定全部必填 Claim",
         "state_delta": _claims_delta({name: _supported() for name in GENERIC_REQUIRED}),
         "next": {"kind": "tool_action", "tool": "read_file",
                  "arguments": {"path": "extracted/etc/device.conf"}}},
        {"decision_summary": "提交 ready 案卷",
         "state_delta": {"admission_reason": "ready"},
         "next": {"kind": "submit_case"}},
    ]
    session = FakeSession([
        parse_proposal(json.dumps(reply), "analysis") for reply in replies])

    investigation = host.run_analysis(candidate.candidate_id, session)

    assert investigation.lifecycle_status == "ready_for_verification"
    assert investigation.disposition is None
    assert investigation.stop_reason is None
    case_path = tmp_path / "verifications" / candidate.candidate_id / "case.json"
    case = json.loads(case_path.read_text(encoding="utf-8"))
    assert case["schema_version"] == 1
    assert case["admission_reason"] == "ready"
    assert case["claim_profile"] == "generic"
    assert list(case["claims"]) == list(GENERIC_REQUIRED)
    assert case["claims"]["root_cause"] == _supported()
    assert case["pending_claims"] == []
    assert case["blocking_gaps"] == []
    assert case["evidence_references"][0]["evidence_id"] == "ev-000001"
    events = [
        json.loads(line)["kind"]
        for line in (tmp_path / "investigations" / candidate.candidate_id
                     / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events[-2:] == ["proposal_accepted", "case_submitted"]


def test_submit_case_ready_rejected_until_gate_is_met(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([
        _action(_claims_delta({"target_exists": _supported()})),
        _submit("ready"),
        _action(_claims_delta({
            name: _supported("ev-000002")
            for name in GENERIC_REQUIRED if name != "target_exists"})),
        _submit("ready"),
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    # gate 未满足的 submit 整份拒绝并回喂;同一 Session 补判后成功提交,
    # 拒绝不留 pending 残留。
    assert "尚未评估" in (session.inputs[2] or "")
    assert investigation.lifecycle_status == "ready_for_verification"
    assert (tmp_path / "verifications" / candidate.candidate_id / "case.json").exists()


def test_submit_case_directs_decisive_refutation_to_rejected_closure(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([
        _action(_claims_delta({name: _supported() for name in GENERIC_REQUIRED})),
        _action(_claims_delta({"root_cause": {"status": "refuted"}})),
        _submit("ready"),
        _close(("ev-000001",), {"claims": {"root_cause": {"status": "refuted"}}}),
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    # 决定性反证存在时 submit 被拒并回喂指引 close_investigation;
    # 同一 Session 改提 close 后按 decisive_refutation 收束。
    assert "close_investigation" in (session.inputs[3] or "")
    assert not (tmp_path / "verifications").exists()
    assert investigation.lifecycle_status == "finished"
    assert investigation.disposition == "rejected"
    assert investigation.stop_reason == "decisive_refutation"


def test_close_without_decisive_refutation_stays_closed(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([
        _action(_claims_delta({"preconditions": {"status": "refuted"}})),
        _close(),
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    assert investigation.disposition == "closed"
    assert investigation.stop_reason == "agent_closed"


def test_submit_case_evidence_gap_freezes_pending_and_gaps(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({
        "target": "extracted/bin/upgrader", "claim_profile": "credentials"})
    session = FakeSession([
        _action({
            "claims": {"target_exists": _supported()},
            "gaps_opened": [{"id": "gap-1", "description": "缺材料有效性证据",
                             "blocking": True}],
        }),
        _submit("evidence_gap"),
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    assert investigation.lifecycle_status == "ready_for_verification"
    case = json.loads((tmp_path / "verifications" / candidate.candidate_id
                       / "case.json").read_text(encoding="utf-8"))
    assert case["admission_reason"] == "evidence_gap"
    assert case["claims"]["target_exists"] == _supported()
    assert case["claims"]["material_valid"] == {
        "status": "unassessed", "evidence_ids": []}
    assert "material_valid" in case["pending_claims"]
    assert case["blocking_gaps"] == [
        {"id": "gap-1", "description": "缺材料有效性证据"}]


def test_evidence_gap_submission_rejected_when_gate_passes(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([
        _action(_claims_delta({name: _supported() for name in GENERIC_REQUIRED})),
        _submit("evidence_gap"),
        _close(),
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    # gate 已满足时降级提交被拒并回喂;不改提 ready 就不产生案卷。
    assert "不要降级" in (session.inputs[2] or "")
    assert not (tmp_path / "verifications").exists()
    assert investigation.lifecycle_status == "finished"


def test_submit_case_requires_admission_reason(tmp_path: Path) -> None:
    host = HostAnalysisTracer(tmp_path, {"read_file": FakeTool(
        ToolResult(ok=True, text="same", raw="same"))})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([
        _action({}),
        FinalProposal(decision_summary="缺声明", state_delta={}, kind="submit_case"),
        _close(),
    ])
    investigation = host.run_analysis(candidate.candidate_id, session)

    # 缺 admission_reason 的 submit 整份拒绝并回喂,合法 close 收尾。
    assert "admission_reason" in (session.inputs[2] or "")
    assert investigation.lifecycle_status == "finished"


def test_five_stagnant_completed_actions_stop_investigation(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="identical", raw="identical"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    session = FakeSession([_action({}) for _ in range(8)])

    investigation = host.run_analysis(candidate.candidate_id, session)

    # 首次出现的 Observation 即新非重复证据,本身算进展;之后连续 5 个
    # 重复 digest 的空动作触发 no-progress,第七轮不再发起。
    assert investigation.lifecycle_status == "finished"
    assert investigation.disposition == "unresolved"
    assert investigation.stop_reason == "no_progress"
    assert investigation.no_progress_count == 5
    assert len(investigation.evidence) == 6
    assert len(tool.calls) == 6
    assert len(session.inputs) == 6
    events = [
        json.loads(line)["kind"]
        for line in (tmp_path / "investigations" / candidate.candidate_id
                     / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events[-1] == "no_progress_stop"
    with pytest.raises(ValueError, match="不可重新运行"):
        host.run_analysis(candidate.candidate_id, FakeSession([]))


def test_progress_resets_stagnant_streak(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="identical", raw="identical"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    # 首动(新 digest)进展 → 3 停滞 → 假设变化进展 → 4 停滞:连续计数
    # 被进展清零,远未到 5,调查以主动关闭收束。
    session = FakeSession(
        [_action({}) for _ in range(4)]
        + [_action({"hypothesis": {"statement": "新解释"}})]
        + [_action({}) for _ in range(4)]
        + [_close()])
    investigation = host.run_analysis(candidate.candidate_id, session)

    assert investigation.lifecycle_status == "finished"
    assert investigation.disposition == "closed"
    assert investigation.stop_reason == "agent_closed"
    assert investigation.no_progress_count == 4
    assert len(tool.calls) == 9


def test_claim_status_change_counts_as_progress(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    # 6 个动作逐步翻转全部必填 Claim:digest 重复但每个动作都有语义进展。
    assessed: dict[str, dict] = {}
    proposals = []
    for name in GENERIC_REQUIRED:
        assessed[name] = _supported()
        proposals.append(_action(_claims_delta(dict(assessed))))
    session = FakeSession(proposals + [_submit("ready")])

    investigation = host.run_analysis(candidate.candidate_id, session)

    assert investigation.lifecycle_status == "ready_for_verification"
    assert investigation.no_progress_count == 0


def test_no_progress_counter_survives_resume(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    with pytest.raises(StopIteration):
        host.run_analysis(candidate.candidate_id,
                          FakeSession([_action({}) for _ in range(4)]))
    assert host.investigation_for(candidate.candidate_id).no_progress_count == 3

    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    assert resumed.investigation_for(candidate.candidate_id).no_progress_count == 3
    investigation = resumed.run_analysis(
        candidate.candidate_id, FakeSession([_action({}) for _ in range(2)]))
    assert investigation.stop_reason == "no_progress"
    assert investigation.no_progress_count == 5


def test_submit_case_resume_from_persisted_proposal_is_idempotent(
    tmp_path: Path, monkeypatch,
) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    replace = os.replace

    def crash_after_submit_proposal(source, target):
        if target.name != "state.json":
            replace(source, target)  # 预算台账/配置快照等运行级工件照常落盘
            return
        events = target.parent / "events.jsonl"
        last = json.loads(events.read_text().splitlines()[-1])
        if last["kind"] == "proposal_accepted" and "submit_case" in last["state"]["runtime"]["pending"]["proposal"]["kind"]:
            raise OSError("power lost")
        replace(source, target)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", crash_after_submit_proposal)
        with pytest.raises(OSError, match="power lost"):
            host.run_analysis(candidate.candidate_id, FakeSession([
                _action(_claims_delta({name: _supported() for name in GENERIC_REQUIRED})),
                _submit("ready"),
            ]))

    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    result = resumed.run_analysis(candidate.candidate_id, FakeSession([]))
    assert result.lifecycle_status == "ready_for_verification"
    case = json.loads((tmp_path / "verifications" / candidate.candidate_id
                       / "case.json").read_text(encoding="utf-8"))
    assert case["admission_reason"] == "ready"


def test_restore_backfills_claim_profile_from_candidate_proposal(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({
        "target": "extracted/bin/router", "claim_profile": "config"})
    with pytest.raises(StopIteration):
        host.run_analysis(candidate.candidate_id, FakeSession([_action({})]))

    store = InvestigationStore(tmp_path, candidate.candidate_id)
    saved = store.load()
    del saved["investigation"]["claim_profile"]  # 票 08 之前的快照形态
    store.save("legacy_projection", saved)

    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    assert resumed.investigation_for(candidate.candidate_id).claim_profile == "config"


def test_protocol_failure_never_enters_no_progress_count(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    invalid = ProposalError((ValidationIssue(
        path="$.next.kind", expected="role-allowed next kind",
        actual='"invented"',
        allowed_values=("tool_action", "submit_case", "close_investigation"),
    ),), raw_reply='{"next":{"kind":"invented"}}')

    investigation = host.run_analysis(candidate.candidate_id, FakeSession(
        [invalid] + [_action({}) for _ in range(5)] + [_close()]))

    # 协议重生成不是已完成的语义动作:无效回复只触发反馈回喂,
    # 不进入 no-progress 计数(5 个合法动作后 4 停滞,close 收束)。
    assert investigation.stop_reason == "agent_closed"
    assert investigation.no_progress_count == 4
    assert len(investigation.evidence) == 5


def test_claim_statuses_vocabulary_is_the_adr_set() -> None:
    assert CLAIM_STATUSES == (
        "unassessed", "supported", "refuted", "not_applicable")

"""Host Analysis tracer tests: exercise the real Host seam with fakes only."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from firmware_audit.step5_agent.host import (
    ActionProposal,
    FinalProposal,
    HostAnalysisTracer,
    ProposalError,
    ProposalRejectedError,
    ValidationIssue,
)
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
        _action({"working_hypothesis": "配置可能暴露固定令牌"}, {"path": "extracted/etc/device.conf", "limit": 40}),
        _action({"checked_paths": ["extracted/etc/device.conf"]}, {"limit": 40, "path": "extracted/etc/device.conf"}),
        _close(("ev-000001", "ev-000002"), {"closure_note": "重复读取结果一致"}),
    ])

    investigation = host.run_analysis(candidate.candidate_id, session)

    assert candidate.candidate_id == "cand-0001"
    assert investigation.investigation_id == "inv-0001"
    assert investigation.lifecycle_status == "finished"
    assert investigation.disposition == "closed"
    assert investigation.stop_reason == "decisive_refutation"
    assert investigation.closure_reason == "工具 Evidence 构成决定性反证"
    assert investigation.closure_evidence == ("ev-000001", "ev-000002")
    assert investigation.state == {
        "working_hypothesis": "配置可能暴露固定令牌",
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
        _action({"working_hypothesis": "first-only"}),
        _close(),
    ])
    second_session = FakeSession([
        _action({"working_hypothesis": "second-only"}),
        _close(("ev-000002",)),
    ])
    first_result = host.run_analysis(first.candidate_id, first_session)
    second_result = host.run_analysis(second.candidate_id, second_session)

    assert (first.candidate_id, second.candidate_id) == ("cand-0001", "cand-0002")
    assert (first_result.investigation_id, second_result.investigation_id) == (
        "inv-0001", "inv-0002",
    )
    assert first_result.state == {"working_hypothesis": "first-only"}
    assert second_result.state == {"working_hypothesis": "second-only"}
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

    with pytest.raises(FileExistsError):
        host.run_analysis(candidate.candidate_id, FakeSession([_action({})]))

    assert existing.read_text(encoding="utf-8") == "original immutable evidence"
    investigation = host.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "queued"
    assert investigation.evidence == []
    assert tool.calls == []


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
    with pytest.raises(ProposalRejectedError, match=r"\$\.next\.kind"):
        host.run_analysis(candidate.candidate_id, session)

    assert host.investigation_for(candidate.candidate_id) == before
    assert tool.calls == []
    assert not (tmp_path / "investigations" / candidate.candidate_id / "evidence").exists()

    completed = host.run_analysis(candidate.candidate_id, session)
    assert completed.lifecycle_status == "finished"
    assert completed.evidence[0].evidence_id == "ev-000001"


def test_unauthorized_action_rejects_whole_proposal_before_state_delta(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="must not run", raw="must not run"))
    host = HostAnalysisTracer(tmp_path, {"web_search": tool})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    proposal = ActionProposal(
        decision_summary="尝试越权外部查询",
        state_delta={"working_hypothesis": "must-not-apply"},
        tool="web_search",
        arguments={"query": "known issue"},
    )

    with pytest.raises(ProposalRejectedError, match="无权调用"):
        host.run_analysis(candidate.candidate_id, FakeSession([proposal]))

    investigation = host.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "queued"
    assert investigation.state == {}
    assert investigation.evidence == []
    assert tool.calls == []


@pytest.mark.parametrize(
    "proposal",
    [
        ActionProposal(
            decision_summary="非法动作类型",
            state_delta={"working_hypothesis": "must-not-apply"},
            tool="read_file",
            arguments={"path": "extracted/bin/router"},
            kind="invented",
        ),
        ActionProposal(
            decision_summary="非法工具参数",
            state_delta={"working_hypothesis": "must-not-apply"},
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

    with pytest.raises(ProposalRejectedError):
        host.run_analysis(candidate.candidate_id, FakeSession([proposal, _close()]))

    investigation = host.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "queued"
    assert investigation.state == {}
    assert investigation.evidence == []
    assert tool.calls == []


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
    host = HostAnalysisTracer(tmp_path, {})
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    close = FinalProposal(
        decision_summary="主动关闭",
        state_delta=state_delta,
        kind="close_investigation",
    )

    with pytest.raises(ProposalRejectedError):
        host.run_analysis(candidate.candidate_id, FakeSession([close]))

    investigation = host.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "queued"
    assert investigation.disposition is None
    assert investigation.stop_reason is None

"""Interrupted logical calls through the real Host Action Loop seam."""
import json
import os

import pytest

from firmware_audit.step5_agent.host import ActionProposal, HostAnalysisTracer
from firmware_audit.step5_agent.providers.tools.base import ToolResult
from firmware_audit.step5_agent.host.store import InvestigationStore, StoreError
from firmware_audit.test.test_step5_host_analysis import FakeSession, FakeTool, _action, _close


class PowerLoss(BaseException):
    """Process interruption, not an ordinary tool failure."""


class InterruptedRead:
    def __init__(self):
        self.attempts = 0

    def execute(self, **arguments):
        self.attempts += 1
        if self.attempts == 1:
            raise PowerLoss()
        return ToolResult(ok=True, text="literal after recovery")


def _events(root, candidate):
    path = root / "investigations" / candidate / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_read_only_interruption_retries_same_logical_call(tmp_path):
    tool = InterruptedRead()
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/app"})
    with pytest.raises(PowerLoss):
        host.run_analysis(candidate.candidate_id, FakeSession([_action({"saved": True})]))

    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    session = FakeSession([_close()])
    result = resumed.run_analysis(candidate.candidate_id, session)

    assert tool.attempts == 2
    assert result.state == {"saved": True}
    assert [ref.evidence_id for ref in result.evidence] == ["ev-000001"]
    assert result.tool_attempts == 2
    assert result.logical_tool_calls == 1
    events = _events(tmp_path, candidate.candidate_id)
    started = [event for event in events if event["kind"] == "tool_started"]
    retried = [event for event in events if event["kind"] == "tool_attempt"]
    finished = [event for event in events if event["kind"] == "tool_finished"]
    assert len(started) == len(retried) == len(finished) == 1
    calls = [event["state"]["runtime"]["last_tool_call"] for event in started + retried + finished]
    assert {call["call_id"] for call in calls} == {"call-000001"}
    assert [call["attempt"] for call in calls] == [1, 2, 2]
    assert "literal after recovery" in session.inputs[0]


def test_never_replayed_interruption_feeds_failure_then_alternative(tmp_path):
    unsafe = InterruptedRead()
    reader = FakeTool(ToolResult(ok=True, text="alternative observation"))
    tools = {"sandbox_verify": unsafe, "read_file": reader}
    host = HostAnalysisTracer(tmp_path, tools)
    candidate = host.add_candidate({"target": "extracted/app"})
    action = ActionProposal("verify", {}, "sandbox_verify", {"code": "print('check')"})
    with pytest.raises(PowerLoss):
        host.run_analysis(candidate.candidate_id, FakeSession([action]))

    resumed = HostAnalysisTracer(tmp_path, tools)
    session = FakeSession([_action({}), _close(("ev-000002",))])
    result = resumed.run_analysis(candidate.candidate_id, session)
    assert unsafe.attempts == 1
    assert result.tool_attempts == result.logical_tool_calls == 2
    assert [ref.evidence_id for ref in result.evidence] == ["ev-000001", "ev-000002"]
    assert "interrupted" in session.inputs[0]
    assert "替代" in session.inputs[0]
    interrupted = [e for e in _events(tmp_path, candidate.candidate_id) if e["kind"] == "tool_interrupted"]
    assert len(interrupted) == 1
    assert interrupted[0]["state"]["runtime"]["last_tool_call"]["status"] == "interrupted"
    original = json.loads((tmp_path / result.evidence[0].location).read_text())
    assert original["tool_result"]["ok"] is False


@pytest.mark.parametrize("boundary", ["started", "observation", "finished"])
@pytest.mark.parametrize("tool_name", ["read_file", "sandbox_verify"])
def test_recovery_at_durable_tool_boundaries(tmp_path, monkeypatch, boundary, tool_name):
    tool = FakeTool(ToolResult(ok=True, text="durable literal"))
    host = HostAnalysisTracer(tmp_path, {tool_name: tool})
    candidate = host.add_candidate({"target": "extracted/app"})
    arguments = {"path": "extracted/app"} if tool_name == "read_file" else {"code": "print('test')"}
    action = ActionProposal("inspect", {"saved": 1}, tool_name, arguments)
    replace, fsync = os.replace, os.fsync

    def crash_before_snapshot(source, target):
        event = _events(tmp_path, candidate.candidate_id)[-1]
        if event["kind"] == "tool_" + boundary:
            if boundary == "finished":
                assert len(list(tmp_path.glob("investigations/*/evidence/ev-*.json"))) == 1
            raise PowerLoss()
        replace(source, target)

    def crash_after_observation(descriptor):
        fsync(descriptor)
        if list(tmp_path.glob("investigations/*/evidence/ev-*.json")):
            assert not any(e["kind"] == "tool_finished" for e in _events(tmp_path, candidate.candidate_id))
            raise PowerLoss()

    with monkeypatch.context() as patch:
        if boundary == "observation":
            patch.setattr(os, "fsync", crash_after_observation)
        else:
            patch.setattr(os, "replace", crash_before_snapshot)
        with pytest.raises(PowerLoss):
            host.run_analysis(candidate.candidate_id, FakeSession([action]))
    resumed = HostAnalysisTracer(tmp_path, {tool_name: tool})
    result = resumed.run_analysis(candidate.candidate_id, FakeSession([_close()]))
    assert result.state == {"saved": 1}
    assert len(result.evidence) == result.logical_tool_calls == 1
    assert len([e for e in _events(tmp_path, candidate.candidate_id) if e["kind"] == "tool_finished"]) == 1
    if boundary == "started":
        assert len(tool.calls) == (1 if tool_name == "read_file" else 0)
    else:
        assert len(tool.calls) == result.tool_attempts == 1


def test_repeated_interruptions_keep_identity_across_candidates(tmp_path):
    tool = InterruptedRead()
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    first = host.add_candidate({"target": "extracted/first"})
    second = host.add_candidate({"target": "extracted/second"})
    for _ in range(2):
        tool.attempts = 0
        with pytest.raises(PowerLoss):
            host.run_analysis(first.candidate_id, FakeSession([_action({})]))
        host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    result = host.run_analysis(first.candidate_id, FakeSession([_close()]))
    assert result.tool_attempts == 3
    assert result.logical_tool_calls == 1
    next_result = host.run_analysis(second.candidate_id, FakeSession([_action({}), _close(("ev-000002",))]))
    assert next_result.evidence[0].evidence_id == "ev-000002"
    assert next_result.logical_tool_calls == next_result.tool_attempts == 1


@pytest.mark.parametrize("damage", ["policy", "identity", "arguments", "attempt", "status",
                                    "finished", "counters", "missing_call"])
def test_corrupt_call_state_refuses_recovery_before_execution(tmp_path, damage):
    tool = InterruptedRead()
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/app"})
    with pytest.raises(PowerLoss):
        host.run_analysis(candidate.candidate_id, FakeSession([_action({})]))
    store = InvestigationStore(tmp_path, candidate.candidate_id)
    saved = store.load()
    call = saved["runtime"]["last_tool_call"]
    if damage == "policy":
        call["replay_policy"] = "never"
    elif damage == "identity":
        call["call_id"] = "call-999999"
    elif damage == "arguments":
        call["arguments"] = {"path": "extracted/other"}
    elif damage == "attempt":
        call["attempt"] = True
    elif damage == "status":
        call["status"] = "prepared"
    elif damage == "finished":
        call["finished"] = True
        call["status"] = "finished"
    elif damage == "counters":
        saved["investigation"]["tool_attempts"] = -1
    else:
        del saved["runtime"]["last_tool_call"]
    store.save("damaged_call", saved)
    with pytest.raises(StoreError, match="检查|新运行世代"):
        HostAnalysisTracer(tmp_path, {"read_file": tool})
    assert tool.attempts == 1

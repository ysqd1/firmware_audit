"""Host Action Loop recovery, with crashes injected at filesystem boundaries."""
import json
import os

import pytest

from firmware_audit.step5_agent.host import HostAnalysisTracer
from firmware_audit.step5_agent.host import AgentSession
from firmware_audit.step5_agent.host.store import InvestigationStore, StoreError
from firmware_audit.step5_agent.engine.context import ContextManager
from firmware_audit.step5_agent.providers.tools.base import ToolResult
from firmware_audit.test.test_step5_host_analysis import FakeSession, FakeTool, _action, _close


@pytest.mark.parametrize("damage", ["missing_candidate", "bad_runtime", "bad_identity"])
def test_damaged_projection_refuses_resume_with_recovery_guidance(tmp_path, damage):
    host = HostAnalysisTracer(tmp_path, {})
    candidate = host.add_candidate({"target": "extracted/app"})
    store = InvestigationStore(tmp_path, candidate.candidate_id)
    saved = store.load()
    if damage == "missing_candidate":
        del saved["candidate"]
    elif damage == "bad_runtime":
        saved["runtime"] = []
    else:
        saved["investigation"]["candidate_id"] = "cand-9999"
    store.save("damaged_projection", saved)
    with pytest.raises(StoreError, match="检查|新运行世代"):
        HostAnalysisTracer(tmp_path, {})


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="Linux fd fault injection")
def test_partial_observation_write_is_not_published(tmp_path, monkeypatch):
    tool = FakeTool(ToolResult(ok=True, text="literal"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/app"})
    original_fsync = os.fsync
    def crash_on_evidence(descriptor):
        # The file descriptor is the external filesystem fault boundary.
        opened = os.readlink(f"/proc/self/fd/{descriptor}")
        if "/evidence/" in opened:
            os.ftruncate(descriptor, 8)
            raise OSError("partial Observation")
        original_fsync(descriptor)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", crash_on_evidence)
        with pytest.raises(OSError, match="partial Observation"):
            host.run_analysis(candidate.candidate_id, FakeSession([_action({})]))
    assert not list(tmp_path.glob("investigations/*/evidence/ev-*.json"))
    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    assert resumed.investigation_for(candidate.candidate_id).evidence == []
    result = resumed.run_analysis(candidate.candidate_id, FakeSession([_close()]))
    assert [ref.evidence_id for ref in result.evidence] == ["ev-000001"]
    assert result.tool_attempts == 2
    assert result.logical_tool_calls == 1


def test_persisted_proposal_does_not_request_model_again(tmp_path, monkeypatch):
    tool = FakeTool(ToolResult(ok=True, text="literal"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/etc/device.conf"})
    replace = os.replace
    def crash_after_proposal(source, target):
        events = target.parent / "events.jsonl"
        if json.loads(events.read_text().splitlines()[-1])["kind"] == "proposal_accepted":
            raise OSError("power lost")
        replace(source, target)
    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", crash_after_proposal)
        with pytest.raises(OSError, match="power lost"):
            host.run_analysis(candidate.candidate_id, FakeSession([_action({"hypothesis": "saved"})]))
    assert tool.calls == []
    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    session = FakeSession([_close()])
    result = resumed.run_analysis(candidate.candidate_id, session)
    assert result.lifecycle_status == "finished"
    assert result.state == {"hypothesis": "saved"}
    assert len(tool.calls) == 1
    assert len(session.inputs) == 1
    assert "current_state" in session.inputs[0]
    assert "saved" in session.inputs[0]
    assert result.evidence[0].evidence_id == "ev-000001"


def test_unpersisted_reply_is_requested_again_from_current_state(tmp_path):
    tool = FakeTool(ToolResult(ok=True, text="literal"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/etc/device.conf"})
    with pytest.raises(StopIteration):
        host.run_analysis(candidate.candidate_id, FakeSession([_action({"hypothesis": "saved"})]))
    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    session = FakeSession([_close()])
    result = resumed.run_analysis(candidate.candidate_id, session)
    assert result.state == {"hypothesis": "saved"}
    assert "saved" in session.inputs[0]
    assert "Observation View" in session.inputs[0]
    assert "remaining_budget" in session.inputs[0]
    assert len(tool.calls) == 1
    assert resumed.add_candidate({"target": "extracted/other"}).candidate_id == "cand-0002"


@pytest.mark.parametrize("boundary", ["observation", "completed", "closed"])
def test_completed_evidence_and_close_survive_snapshot_failure(tmp_path, monkeypatch, boundary):
    tool = FakeTool(ToolResult(ok=True, text="literal"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    candidate = host.add_candidate({"target": "extracted/etc/device.conf"})
    replace = os.replace
    with monkeypatch.context() as patch:
        if boundary == "observation":
            original_sync = os.fsync
            def crash_after_observation(descriptor):
                original_sync(descriptor)
                if list(tmp_path.glob("investigations/*/evidence/*.json")):
                    raise OSError("power lost")
            patch.setattr(os, "fsync", crash_after_observation)
        else:
            kind = "action_completed" if boundary == "completed" else "analysis_closed"
            def crash_before_snapshot(source, target):
                event = json.loads((target.parent / "events.jsonl").read_text().splitlines()[-1])
                if event["kind"] == kind:
                    raise OSError("power lost")
                replace(source, target)
            patch.setattr(os, "replace", crash_before_snapshot)
        with pytest.raises(OSError, match="power lost"):
            host.run_analysis(candidate.candidate_id, FakeSession([_action({"value": "saved"}), _close()]))
    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    result = resumed.investigation_for(candidate.candidate_id)
    if boundary != "closed":
        result = resumed.run_analysis(candidate.candidate_id, FakeSession([_close()]))
    assert result.lifecycle_status == "finished"
    assert result.state == {"value": "saved"}
    assert len(result.evidence) == 1
    assert len(tool.calls) == 1


def test_real_session_resume_uses_fixed_prompt_and_state_not_old_history(tmp_path):
    tool = FakeTool(ToolResult(ok=True, text="literal"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool}, remaining_budget={"llm_calls": 9})
    candidate = host.add_candidate({"target": "extracted/etc/device.conf"})
    with pytest.raises(StopIteration):
        host.run_analysis(candidate.candidate_id, FakeSession([_action({"value": "saved"})]))
    context = ContextManager("fixed system", "stale task")
    context.append("assistant", "old private transcript")
    context.summaries.append("old summary")
    class InspectingLLM:
        def chat(self, messages):
            text = json.dumps(messages)
            assert "fixed system" in text
            assert "saved" in text and "remaining_budget" in text
            assert "stale task" not in text and "old private transcript" not in text
            assert "old summary" not in text
            return json.dumps({"decision_summary": "close", "state_delta": {
                "closure_reason": "refuted", "evidence_refs": ["ev-000001"]},
                "next": {"kind": "close_investigation"}}), {}
    session = AgentSession("analysis", InspectingLLM(), context)
    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool})
    assert resumed.run_analysis(candidate.candidate_id, session).lifecycle_status == "finished"

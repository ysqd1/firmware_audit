"""Durable Store seam: event history survives interrupted snapshot publication."""
import json
from pathlib import Path

import pytest

from firmware_audit.step5_agent.host.store import (
    InvestigationStore,
    StoreError,
    load_investigation_snapshot,
)


@pytest.mark.parametrize("reuse_instance", [False, True])
def test_event_survives_failed_snapshot_replace(tmp_path, monkeypatch, reuse_instance):
    store = InvestigationStore(tmp_path, "cand-0001")
    store.save("candidate_created", {"value": 1})
    with monkeypatch.context() as patch:
        def interrupted_replace(source, target):
            raise OSError("power lost before snapshot replace")
        patch.setattr("os.replace", interrupted_replace)
        with pytest.raises(OSError):
            store.save("proposal_accepted", {"value": 2})

    recovered = store if reuse_instance else InvestigationStore(tmp_path, "cand-0001")
    assert recovered.load() == {"value": 2}
    recovered.save("analysis_closed", {"value": 3})
    events = [json.loads(line) for line in recovered.events_path.read_text().splitlines()]
    assert [event["seq"] for event in events] == [1, 2, 3]
    assert json.loads(recovered.snapshot_path.read_text())["last_event_seq"] == 3


def test_truncated_tail_is_quarantined_but_middle_corruption_is_rejected(tmp_path):
    store = InvestigationStore(tmp_path, "cand-0001")
    store.save("candidate_created", {"value": 1})
    tail = b'{"event_version": 1, "seq": 2'
    with store.events_path.open("ab") as handle:
        handle.write(tail)
    with pytest.warns(RuntimeWarning, match="尾部"):
        recovered = InvestigationStore(tmp_path, "cand-0001")
    assert recovered.load() == {"value": 1}
    assert list(store.directory.glob("events.tail-*.bin"))[0].read_bytes() == tail
    recovered.save("continued", {"value": 2})
    assert InvestigationStore(tmp_path, "cand-0001").load() == {"value": 2}
    original = store.events_path.read_bytes()
    store.events_path.write_bytes(b"broken\n" + original)
    with pytest.raises(StoreError, match="事件"):
        InvestigationStore(tmp_path, "cand-0001")
    assert store.events_path.read_bytes() == b"broken\n" + original


@pytest.mark.parametrize("target,key", [("snapshot", "schema_version"), ("event", "event_version")])
def test_incompatible_versions_refuse_resume(tmp_path, target, key):
    store = InvestigationStore(tmp_path, "cand-0001")
    store.save("candidate_created", {"value": 1})
    path = store.snapshot_path if target == "snapshot" else store.events_path
    payload = json.loads(path.read_text())
    payload[key] = 99
    path.write_text(json.dumps(payload) + "\n")
    with pytest.raises(StoreError, match="新运行世代"):
        InvestigationStore(tmp_path, "cand-0001")


def test_history_gap_and_snapshot_without_history_refuse_resume(tmp_path):
    store = InvestigationStore(tmp_path, "cand-0001")
    store.save("candidate_created", {"value": 1})
    event = json.loads(store.events_path.read_text())
    event["seq"] = 2
    store.events_path.write_text(json.dumps(event) + "\n")
    with pytest.raises(StoreError, match="seq"):
        InvestigationStore(tmp_path, "cand-0001")
    store.events_path.unlink()
    with pytest.raises(StoreError, match="历史"):
        InvestigationStore(tmp_path, "cand-0001")


# ---- 票 22:Investigation 终态投影的共享解包(reporting/evaluation 共用)----


def _write_state_snapshot(path: Path, state: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"schema_version": 1, "last_event_seq": 1, "state": state},
                   ensure_ascii=False) + "\n",
        encoding="utf-8")
    return path


def test_load_investigation_snapshot_missing_state_returns_none(tmp_path):
    path = tmp_path / "investigations" / "cand-0001" / "state.json"
    assert load_investigation_snapshot(path) is None


def test_load_investigation_snapshot_returns_terminal_projection(tmp_path):
    path = _write_state_snapshot(
        tmp_path / "investigations" / "cand-0001" / "state.json",
        {"investigation": {"candidate_id": "cand-0001",
                           "lifecycle_status": "finished",
                           "disposition": "confirmed",
                           "stop_reason": "completed"},
         "runtime": {}})
    assert load_investigation_snapshot(path) == {
        "candidate_id": "cand-0001", "lifecycle_status": "finished",
        "disposition": "confirmed", "stop_reason": "completed"}


def test_load_investigation_snapshot_rejects_corrupt_json(tmp_path):
    path = tmp_path / "investigations" / "cand-0001" / "state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(StoreError, match="Investigation 快照损坏"):
        load_investigation_snapshot(path)


@pytest.mark.parametrize("state", [
    pytest.param({}, id="missing-investigation"),
    pytest.param({"investigation": "finished"}, id="non-object-investigation"),
])
def test_load_investigation_snapshot_rejects_broken_projection(
        tmp_path, state):
    path = _write_state_snapshot(
        tmp_path / "investigations" / "cand-0001" / "state.json", state)
    with pytest.raises(StoreError, match="cand-0001 快照损坏"):
        load_investigation_snapshot(path)

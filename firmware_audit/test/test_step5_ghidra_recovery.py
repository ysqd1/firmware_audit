"""Ghidra recovery contract with real files and Docker replaced at its seam."""
import json
import os

import pytest

from firmware_audit.step5_agent.providers.tools import ghidra_decompile as gd
from firmware_audit.step5_agent.host import ActionProposal, HostAnalysisTracer
from firmware_audit.test.test_step5_host_analysis import FakeSession, _close
from firmware_audit.test.test_step5_tool_recovery import PowerLoss, _events
from firmware_audit.test.test_step5_ghidra_tool import _FakeDocker, _make_ctx, _write_elf


def test_complete_digest_validated_cache_is_recoverable_without_execution(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path)
    _write_elf(tmp_path, "bin/app")
    docker = _FakeDocker()
    monkeypatch.setattr(gd, "run_docker", docker)
    assert gd.GhidraDecompileTool(ctx).execute(file_ref="bin/app").ok

    recovered = gd.GhidraDecompileTool(ctx).recover_cached_result(file_ref="extracted/bin/app")
    assert recovered is not None and recovered.ok
    assert recovered.data["cache"] == "validated"
    assert len(docker.calls) == 1
    artifacts = recovered.data["artifacts"]
    assert {artifact["path"] for artifact in artifacts} == {
        "analysis/bin/app.c", "analysis/bin/app.imports.json", "analysis/bin/app.strings.json",
    }
    assert all(artifact["size"] > 0 and len(artifact["digest"]) == 64 for artifact in artifacts)
    receipt = json.loads((tmp_path / "analysis/bin/app.cache.json").read_text())
    assert receipt["schema_version"] == 1


@pytest.mark.parametrize("damage", ["missing_c", "missing_imports", "missing_strings", "c_digest",
                                    "imports_digest", "strings_digest", "input_digest", "receipt",
                                    "schema", "invalid_json"])
def test_invalid_cache_is_not_accepted_and_retry_bypasses_weak_cache(tmp_path, monkeypatch, damage):
    ctx = _make_ctx(tmp_path)
    source = _write_elf(tmp_path, "bin/app")
    docker = _FakeDocker()
    monkeypatch.setattr(gd, "run_docker", docker)
    tool = gd.GhidraDecompileTool(ctx)
    assert tool.execute(file_ref="bin/app").ok
    paths = {"c": tmp_path / "analysis/bin/app.c",
             "imports": tmp_path / "analysis/bin/app.imports.json",
             "strings": tmp_path / "analysis/bin/app.strings.json"}
    receipt = tmp_path / "analysis/bin/app.cache.json"
    if damage.startswith("missing_"):
        paths[damage.removeprefix("missing_")].unlink()
    elif damage == "input_digest":
        source.write_bytes(source.read_bytes() + b"changed")
    elif damage.endswith("_digest"):
        path = paths[damage.removesuffix("_digest")]
        path.write_text(path.read_text() + " ")
    elif damage == "schema":
        data = json.loads(receipt.read_text())
        data["schema_version"] = 99
        receipt.write_text(json.dumps(data))
    elif damage == "invalid_json":
        paths["strings"].write_text("{")
    else:
        receipt.unlink()
    assert tool.recover_cached_result(file_ref="bin/app") is None
    result = tool.execute_after_interruption(file_ref="bin/app")
    assert result.ok
    assert len(docker.calls) == 2
    assert tool.recover_cached_result(file_ref="bin/app") is not None


def test_retry_replaces_deduplicated_artifacts_without_modifying_other_cache(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path)
    _write_elf(tmp_path, "bin/first")
    _write_elf(tmp_path, "bin/second")
    monkeypatch.setattr(gd, "run_docker", _FakeDocker())
    tool = gd.GhidraDecompileTool(ctx)
    assert tool.execute(file_ref="bin/first").ok
    assert tool.execute(file_ref="bin/second").ok
    before = (tmp_path / "analysis/bin/first.c").read_bytes()
    monkeypatch.setattr(gd, "run_docker", _FakeDocker(functions=7))
    assert tool.execute_after_interruption(file_ref="bin/second").ok
    assert (tmp_path / "analysis/bin/first.c").read_bytes() == before
    assert tool.recover_cached_result(file_ref="bin/first") is not None


@pytest.mark.parametrize("cache_valid", [True, False])
def test_host_recovers_ghidra_cache_or_retries_same_call(tmp_path, monkeypatch, cache_valid):
    ctx = _make_ctx(tmp_path)
    _write_elf(tmp_path, "bin/app")
    docker = _FakeDocker()
    monkeypatch.setattr(gd, "run_docker", docker)
    run_dir = tmp_path / "agent/run"
    host = HostAnalysisTracer(run_dir, {"ghidra_decompile": gd.GhidraDecompileTool(ctx)})
    candidate = host.add_candidate({"target": "extracted/bin/app"})
    action = ActionProposal("decompile", {}, "ghidra_decompile", {"file_ref": "bin/app"})
    link = os.link
    def interrupt_before_observation(source, target):
        if "evidence" in str(target):
            raise PowerLoss()
        return link(source, target)
    with monkeypatch.context() as patch:
        patch.setattr(os, "link", interrupt_before_observation)
        with pytest.raises(PowerLoss):
            host.run_analysis(candidate.candidate_id, FakeSession([action]))
    assert len(docker.calls) == 1
    if not cache_valid:
        (tmp_path / "analysis/bin/app.imports.json").write_text("[]")
    host = HostAnalysisTracer(run_dir, {"ghidra_decompile": gd.GhidraDecompileTool(ctx)})
    result = host.run_analysis(candidate.candidate_id, FakeSession([_close()]))
    assert result.logical_tool_calls == 1
    assert result.tool_attempts == len(docker.calls) == (1 if cache_valid else 2)
    assert [ref.evidence_id for ref in result.evidence] == ["ev-000001"]
    history = _events(run_dir, candidate.candidate_id)
    finished = [e for e in history if e["kind"] == "tool_finished"]
    assert len(finished) == 1
    assert finished[0]["state"]["runtime"]["last_tool_call"]["call_id"] == "call-000001"


def test_retry_cannot_certify_old_sidecar_left_by_incomplete_generation(tmp_path, monkeypatch):
    ctx = _make_ctx(tmp_path)
    _write_elf(tmp_path, "bin/app")
    docker = _FakeDocker()
    monkeypatch.setattr(gd, "run_docker", docker)
    tool = gd.GhidraDecompileTool(ctx)
    assert tool.execute(file_ref="bin/app").ok
    def incomplete(*args, **kwargs):
        result = docker(*args, **kwargs)
        output = next(m[0] for m in kwargs["mounts"] if m[1] == "/work/output")
        (output / "imports.json").unlink()
        return result
    monkeypatch.setattr(gd, "run_docker", incomplete)
    result = tool.execute_after_interruption(file_ref="bin/app")
    assert result.ok is False
    assert "r2" in result.error
    assert tool.recover_cached_result(file_ref="bin/app") is None

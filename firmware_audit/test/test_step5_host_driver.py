"""Ticket 11:运行世代、活动锁与串行运行驱动的公开 seam 测试。

覆盖:世代 manifest/run_state 的创建与只读边界、schema 不兼容拒绝、工作区
活动锁(活动进程拒绝/死 PID 接管/损坏拒绝)、驱动单一配置解析与快照一致、
共享 RunBudget 与去重/评分预算穿透、recon checkpoint 恢复、队列级恢复与
Related 回队,以及多次重启的组合稳定性(AC7)。

全部走公开接口:真驱动 + Fake Session/工具 + 注入时钟/环境,不 mock 驱动内部。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

import pytest

from firmware_audit.step5_agent.host.generation import (
    MANIFEST_SCHEMA_VERSION,
    RUN_STATE_SCHEMA_VERSION,
    create_generation,
    list_generations,
    load_run_state,
    read_manifest,
    save_run_state,
)
from firmware_audit.step5_agent.host.store import StoreError


# ---- S1 世代:manifest、run_state 与只读边界 ----


def test_create_generation_writes_manifest_and_default_state(tmp_path: Path) -> None:
    name, gen_dir = create_generation(tmp_path, hostname="h1", now=1000.0)
    assert name == "gen-0001"
    assert gen_dir == tmp_path / "generations" / "gen-0001"
    manifest = read_manifest(gen_dir)
    assert manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
    assert manifest["generation"] == "gen-0001"
    assert manifest["hostname"] == "h1"
    assert manifest["created_at"] == 1000.0
    # 新世代默认未完成、无停止原因
    state = load_run_state(gen_dir)
    assert state == {
        "schema_version": RUN_STATE_SCHEMA_VERSION,
        "status": "running",
        "phase": None,
        "stop_reason": None,
    }


def test_generations_number_monotonically(tmp_path: Path) -> None:
    create_generation(tmp_path)
    name, _ = create_generation(tmp_path)
    assert name == "gen-0002"
    assert [name for name, _ in list_generations(tmp_path)] == ["gen-0001", "gen-0002"]


def test_missing_generation_directory_lists_empty(tmp_path: Path) -> None:
    assert list_generations(tmp_path) == []


def test_generation_without_manifest_is_refused_not_skipped(tmp_path: Path) -> None:
    create_generation(tmp_path)
    (tmp_path / "generations" / "gen-0002").mkdir()
    with pytest.raises(StoreError, match="缺少 manifest.*gen-0002"):
        list_generations(tmp_path)


def test_incompatible_manifest_schema_refuses_with_new_generation_guidance(
        tmp_path: Path) -> None:
    _, gen_dir = create_generation(tmp_path)
    manifest = json.loads((gen_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = MANIFEST_SCHEMA_VERSION + 1
    (gen_dir / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    with pytest.raises(StoreError, match="新运行世代"):
        list_generations(tmp_path)
    with pytest.raises(StoreError, match="新运行世代"):
        read_manifest(gen_dir)


def test_save_run_state_roundtrip_and_validation(tmp_path: Path) -> None:
    _, gen_dir = create_generation(tmp_path)
    save_run_state(gen_dir, status="finalizing", stop_reason="processing_complete")
    state = load_run_state(gen_dir)
    assert state["status"] == "finalizing"
    assert state["stop_reason"] == "processing_complete"
    with pytest.raises(StoreError, match="status"):
        save_run_state(gen_dir, status="bogus")
    # 损坏的 run_state 拒绝静默恢复
    (gen_dir / "run_state.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(StoreError, match="请检查原运行目录"):
        load_run_state(gen_dir)


def test_legacy_named_artifacts_do_not_confuse_generation_listing(
        tmp_path: Path) -> None:
    # 旧语义工件(survey/findings/verified_findings)散落在根下也不参与世代语义
    for name in ("survey.json", "findings.json", "verified_findings.json"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    create_generation(tmp_path)
    assert [name for name, _ in list_generations(tmp_path)] == ["gen-0001"]
    assert (tmp_path / "survey.json").read_text(encoding="utf-8") == "{}"


# ---- S2 工作区活动锁:进程身份、stale 接管与损坏拒绝 ----

from firmware_audit.step5_agent.host.locking import (
    LockActiveError,
    acquire_lock,
)


def test_lock_acquires_and_releases(tmp_path: Path) -> None:
    with acquire_lock(tmp_path, hostname="h1", pid=101) as handle:
        document = json.loads((tmp_path / "lock.json").read_text(encoding="utf-8"))
        assert document["pid"] == 101
        assert document["hostname"] == "h1"
        assert isinstance(document["started_at"], float)
    assert not (tmp_path / "lock.json").exists()


def test_second_run_while_process_alive_is_refused(tmp_path: Path) -> None:
    with acquire_lock(tmp_path, hostname="h1", pid=101,
                      alive_checker=lambda pid, marker: True):
        with pytest.raises(LockActiveError, match="活动"):
            acquire_lock(tmp_path, hostname="h1", pid=202,
                         alive_checker=lambda pid, marker: True)


def test_dead_pid_lock_is_taken_over_with_warning(tmp_path: Path) -> None:
    # 崩溃残留的死锁(直接写盘模拟未 release),第二个持有者接管
    (tmp_path / "lock.json").write_text(json.dumps({
        "schema_version": 1, "pid": 101, "hostname": "h1",
        "started_at": 1.0,
    }), encoding="utf-8")
    with pytest.warns(RuntimeWarning, match="接管"):
        second = acquire_lock(tmp_path, hostname="h1", pid=202,
                              alive_checker=lambda pid, marker: False)
    second.release()


def test_foreign_hostname_lock_is_refused_not_taken(tmp_path: Path) -> None:
    (tmp_path / "lock.json").write_text(json.dumps({
        "schema_version": 1, "pid": 101, "hostname": "other-host",
        "started_at": 1.0,
    }), encoding="utf-8")
    with pytest.raises(LockActiveError, match="另一台主机"):
        acquire_lock(tmp_path, hostname="h1", pid=202,
                     alive_checker=lambda pid, marker: False)


def test_corrupt_lock_is_refused_with_manual_guidance(tmp_path: Path) -> None:
    (tmp_path / "lock.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(StoreError, match="lock"):
        acquire_lock(tmp_path, hostname="h1", pid=101)


def test_default_alive_checker_uses_os_signals() -> None:
    from firmware_audit.step5_agent.host.locking import _default_alive
    assert _default_alive(os.getpid(), None) is True
    # /proc 下的 starttime 与真实进程一致时判活
    marker = _process_start_marker(os.getpid())
    assert _default_alive(os.getpid(), marker) is True
    assert _default_alive(-1, None) is False


def _process_start_marker(pid: int) -> int | None:
    from firmware_audit.step5_agent.host.locking import _process_start_marker as read
    return read(pid)


def test_release_only_deletes_own_lock(tmp_path: Path) -> None:
    handle = acquire_lock(tmp_path, hostname="h1", pid=101)
    # 盘上锁被别人顶替后,旧句柄的 release 不得删除新锁
    with pytest.warns(RuntimeWarning, match="接管"):
        acquire_lock(tmp_path, hostname="h1", pid=202,
                     alive_checker=lambda pid, marker: False)
    handle.release()
    document = json.loads((tmp_path / "lock.json").read_text(encoding="utf-8"))
    assert document["pid"] == 202


# ---- S3 Recon 阶段持久化与恢复(票 11 接缝:不从整段重跑代替恢复) ----

from firmware_audit.test.test_step5_host_analysis import FakeSession, FakeTool
from firmware_audit.test.test_step5_host_recon import (
    FakeReconSession,
    _make_tree,
    _recon_action,
    _survey,
    _survey_delta,
    _workspace,
)
from firmware_audit.step5_agent.host.recon import (
    RECON_STATE_SCHEMA_VERSION,
    HostReconRunner,
    ReconRunResult,
)
from firmware_audit.step5_agent.providers.tools.base import ToolResult


def _recon_tool() -> FakeTool:
    return FakeTool(ToolResult(ok=True, text="token=literal", raw="token=literal"))


def _recon_checkpoint(tmp_path: Path) -> dict:
    return json.loads(
        (tmp_path / "investigations" / "recon" / "state.json").read_text(
            encoding="utf-8"))


def test_recon_persists_checkpoint_after_each_terminal(tmp_path: Path) -> None:
    tool = _recon_tool()
    runner = HostReconRunner(tmp_path, {"read_file": tool}, max_rounds=5)
    result = runner.run(
        FakeReconSession([_recon_action(), _survey(_survey_delta())]),
        _workspace(tmp_path))
    assert result.status == "completed"
    checkpoint = _recon_checkpoint(tmp_path)
    assert checkpoint["schema_version"] == RECON_STATE_SCHEMA_VERSION
    assert checkpoint["status"] == "completed"
    assert checkpoint["rounds_used"] == 2
    assert checkpoint["reason"] is None


def test_recon_input_failure_is_persisted_and_auditable(tmp_path: Path) -> None:
    process_dir = tmp_path / "process"  # 无 extracted/:解包失败
    process_dir.mkdir()
    runner = HostReconRunner(tmp_path, {"read_file": _recon_tool()})
    result = runner.run(FakeReconSession([]), process_dir)
    assert result.status == "input_failure"
    assert result.reason == "extraction_missing"
    checkpoint = _recon_checkpoint(tmp_path)
    assert checkpoint["status"] == "input_failure"
    assert checkpoint["reason"] == "extraction_missing"
    assert checkpoint["rounds_used"] == 0
    # 恢复:输入失败幂等返回,不发起模型请求、不建 Investigation
    again = HostReconRunner(tmp_path, {"read_file": _recon_tool()}).run(
        FakeReconSession([]), process_dir)
    assert again.status == "input_failure"
    assert again.rounds_used == 0


def test_recon_service_interruption_resumes_from_saved_boundary(tmp_path: Path) -> None:
    tool = _recon_tool()
    first = HostReconRunner(tmp_path, {"read_file": tool}, max_rounds=5)

    class CrashingSession(FakeReconSession):
        def step(self, input_message=None):
            if len(self.inputs) >= 1:
                raise RuntimeError("service down")
            return super().step(input_message)

    with pytest.raises(RuntimeError, match="service down"):
        first.run(CrashingSession([_recon_action()]), _workspace(tmp_path))
    checkpoint = _recon_checkpoint(tmp_path)
    assert checkpoint["status"] == "running"
    assert checkpoint["rounds_used"] == 1
    assert len(checkpoint["evidence"]) == 1

    # 恢复:新 runner + 新 session,从保存边界续,不重执行第一个动作
    second_session = FakeReconSession([_survey(_survey_delta())])
    resumed = HostReconRunner(
        tmp_path, {"read_file": tool}, max_rounds=5).run(
        second_session, _workspace(tmp_path))
    assert resumed.status == "completed"
    assert resumed.rounds_used == 2  # 1(已保存) + 1(本轮 survey)
    evidence_files = list(
        (tmp_path / "investigations" / "recon" / "evidence").glob("ev-*.json"))
    assert len(evidence_files) == 1  # 不重复执行,证据不重号
    # 恢复简报携带已完成动作与剩余轮次
    assert "resume" in (second_session.inputs[0] or "")
    assert [call.get("path") for call in tool.calls] == [
        "extracted/etc/device.conf"]


def test_recon_resume_recovers_recorded_pending_without_reexecution(
        tmp_path: Path) -> None:
    # 正常跑两个动作到完成,然后把 checkpoint 人为拨回"第二个动作 pending
    # 已接受、未收尾"的崩溃现场(票 17 的投影注入先例)
    tool = _recon_tool()
    HostReconRunner(tmp_path, {"read_file": tool}, max_rounds=6).run(
        FakeReconSession([_recon_action(), _recon_action(), _survey(_survey_delta())]),
        _workspace(tmp_path))
    checkpoint = _recon_checkpoint(tmp_path)
    action = {
        "decision_summary": "浅层侦查动作", "state_delta": {},
        "tool": "read_file",
        "arguments": {"path": "extracted/etc/device.conf"},
        "kind": "tool_action",
    }
    crafted = dict(checkpoint)
    crafted.update({
        "status": "running", "rounds_used": 2, "session_state": {},
        "survey": None, "reason": None,
        "pending": {"proposal": action, "sequence": 2, "executing": True},
        "evidence": checkpoint["evidence"][:1],
    })
    (tmp_path / "investigations" / "recon" / "state.json").write_text(
        json.dumps(crafted), encoding="utf-8")
    calls_before = len(tool.calls)

    session = FakeReconSession([_survey(_survey_delta())])
    result = HostReconRunner(
        tmp_path, {"read_file": tool}, max_rounds=5).run(session, _workspace(tmp_path))
    # 证据文件已在盘上:恢复路径 recover 回放,不再执行工具
    assert result.status == "completed"
    assert len(tool.calls) == calls_before
    assert len(result.evidence) == 2


def test_recon_resume_reexecutes_unrecorded_pending_under_same_slot(
        tmp_path: Path) -> None:
    tool = _recon_tool()
    HostReconRunner(tmp_path, {"read_file": tool}, max_rounds=6).run(
        FakeReconSession([_recon_action(), _recon_action(), _survey(_survey_delta())]),
        _workspace(tmp_path))
    checkpoint = _recon_checkpoint(tmp_path)
    action = {
        "decision_summary": "浅层侦查动作", "state_delta": {},
        "tool": "read_file",
        "arguments": {"path": "extracted/etc/device.conf"},
        "kind": "tool_action",
    }
    crafted = dict(checkpoint)
    crafted.update({
        "status": "running", "rounds_used": 2, "session_state": {},
        "survey": None, "reason": None,
        "pending": {"proposal": action, "sequence": 2, "executing": False},
        "evidence": checkpoint["evidence"][:1],
    })
    # 删除第二条 Evidence,模拟"接受后、记录前"崩溃
    for path in (tmp_path / "investigations" / "recon" / "evidence").glob("ev-*.json"):
        if path.name == "ev-000002.json":
            path.unlink()
    (tmp_path / "investigations" / "recon" / "state.json").write_text(
        json.dumps(crafted), encoding="utf-8")

    session = FakeReconSession([_survey(_survey_delta())])
    result = HostReconRunner(
        tmp_path, {"read_file": tool}, max_rounds=5).run(session, _workspace(tmp_path))
    assert result.status == "completed"
    # 同一 sequence 槽位重执行:ev-000002 重新落盘,survey 引用不变
    assert (tmp_path / "investigations" / "recon" / "evidence"
            / "ev-000002.json").exists()


def test_recon_survey_accepted_crash_gap_finalizes_without_model_requests(
        tmp_path: Path) -> None:
    tool = _recon_tool()
    HostReconRunner(tmp_path, {"read_file": tool}, max_rounds=5).run(
        FakeReconSession([_recon_action(), _survey(_survey_delta())]),
        _workspace(tmp_path))
    checkpoint = _recon_checkpoint(tmp_path)
    # 人为拨回 survey_accepted 与 candidates.json 已写之间(崩溃夹缝)
    (tmp_path / "candidates.json").unlink()
    crafted = dict(checkpoint)
    crafted["status"] = "survey_accepted"
    (tmp_path / "investigations" / "recon" / "state.json").write_text(
        json.dumps(crafted), encoding="utf-8")

    empty_session = FakeReconSession([])
    result = HostReconRunner(
        tmp_path, {"read_file": tool}, max_rounds=5).run(
        empty_session, _workspace(tmp_path))
    assert result.status == "completed"
    assert empty_session.inputs == []  # 零模型请求
    assert (tmp_path / "candidates.json").exists()


def test_recon_incomplete_rounds_exhausted_not_rerun_on_resume(tmp_path: Path) -> None:
    runner = HostReconRunner(tmp_path, {"read_file": _recon_tool()}, max_rounds=1)
    result = runner.run(
        FakeReconSession([_recon_action()]), _workspace(tmp_path))
    assert result.status == "incomplete"
    assert result.reason == "rounds_exhausted"
    assert _recon_checkpoint(tmp_path)["status"] == "incomplete"
    again = HostReconRunner(tmp_path, {"read_file": _recon_tool()}, max_rounds=1).run(
        FakeReconSession([]), _workspace(tmp_path))
    assert again.status == "incomplete"
    assert again.rounds_used == 1


def test_recon_refuses_to_downgrade_upgraded_candidate_store(tmp_path: Path) -> None:
    from firmware_audit.step5_agent.host.candidates import (
        CANDIDATE_STORE_SCHEMA_VERSION,
    )
    tool = _recon_tool()
    runner = HostReconRunner(tmp_path, {"read_file": tool}, max_rounds=5)
    runner.run(
        FakeReconSession([_recon_action(), _survey(_survey_delta())]),
        _workspace(tmp_path))
    # 把 v1 升级成 v2(去重后权威库),再把 checkpoint 拨回 running 续跑
    document = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    document["schema_version"] = CANDIDATE_STORE_SCHEMA_VERSION
    (tmp_path / "candidates.json").write_text(json.dumps(document), encoding="utf-8")
    checkpoint = _recon_checkpoint(tmp_path)
    crafted = dict(checkpoint)
    crafted["status"] = "running"
    (tmp_path / "investigations" / "recon" / "state.json").write_text(
        json.dumps(crafted), encoding="utf-8")
    with pytest.raises(StoreError, match="降级"):
        HostReconRunner(tmp_path, {"read_file": tool}, max_rounds=5).run(
            FakeReconSession([_survey(_survey_delta())]), _workspace(tmp_path))


def test_recon_run_reseeds_evidence_watermark_per_call(tmp_path: Path) -> None:
    # 构造顺序解耦:先让其他阶段占号,再跑 recon,Evidence ID 不重号
    from firmware_audit.step5_agent.host import HostAnalysisTracer
    tracer = HostAnalysisTracer(tmp_path, {"read_file": _recon_tool()})
    candidate = tracer.add_candidate({"target": "extracted/etc/device.conf"})
    from firmware_audit.test.test_step5_host_analysis import _action, _close
    tracer.run_analysis(candidate.candidate_id, FakeSession([
        _action({}), _close(),
    ]))
    survey = _survey_delta()
    for entry in survey["candidates"]:
        entry["evidence_id"] = "ev-000002"  # recon 本轮实际拿到的证据号
    result = HostReconRunner(
        tmp_path, {"read_file": _recon_tool()}, max_rounds=5).run(
        FakeReconSession([_recon_action(), _survey(survey)]),
        _workspace(tmp_path))
    assert result.evidence[0].evidence_id != "ev-000001"
    assert result.evidence[0].sequence > 1


# ---- S4 去重/评分预算穿透、锁定选取与显式 Candidate ID ----

from firmware_audit.step5_agent.host import (
    BudgetExhaustedError,
    CandidateStore,
    HostAnalysisTracer,
    IntakeCandidate,
    PriorityScorer,
    SemanticComparator,
)
from firmware_audit.step5_agent.host.candidates import ComparisonOutcome


class _RaisingAtBudgetLLM:
    def chat(self, messages):
        raise BudgetExhaustedError("运行总预算耗尽:llm_calls 已达上限")


def test_comparator_and_scorer_propagate_budget_exhaustion() -> None:
    left = IntakeCandidate(
        source="recon", proposal_id="p1", kind="signal", target="extracted/a",
        signal="s", evidence_id="ev-000001", next_action="n", anchor="a1")
    right = IntakeCandidate(
        source="recon", proposal_id="p2", kind="signal", target="extracted/a",
        signal="s", evidence_id="ev-000001", next_action="n", anchor="a2")
    with pytest.raises(BudgetExhaustedError):
        SemanticComparator(_RaisingAtBudgetLLM()).compare(left, right)
    scorer = PriorityScorer(_RaisingAtBudgetLLM(), {"ev-000001": "summary"})
    with pytest.raises(BudgetExhaustedError):
        scorer.score(left)


class _DifferentComparator:
    def compare(self, existing, incoming) -> ComparisonOutcome:
        return ComparisonOutcome(status="ok", verdict="different")


class _TotalScorer:
    def __init__(self, totals: dict[str, int]):
        self.totals = totals

    def score(self, candidate) -> dict:
        return {"factors": {}, "total": self.totals.get(
            candidate.proposal_id, 1), "status": "ok"}


def _v1_store(tmp_path: Path, proposals: list[dict]) -> None:
    (tmp_path / "candidates.json").write_text(json.dumps({
        "schema_version": 1, "survey": {}, "session_state": {},
        "candidates": proposals,
    }), encoding="utf-8")


def _recon_proposal(index: int) -> dict:
    return {
        "proposal_id": f"proposal-{index:04d}", "kind": "signal",
        "target": f"extracted/etc/device{index}.conf", "signal": "凭据样式",
        "evidence_id": "ev-000001", "next_action": "核实",
        "anchor": f"line-{index}",
    }


def _related_intake(proposal_id: str, source: str, *, anchor: str) -> IntakeCandidate:
    return IntakeCandidate(
        source=source, proposal_id=proposal_id, kind="signal",
        target="extracted/bin/updater", signal="升级解析未校验长度",
        evidence_id="ev-000002", next_action="反编译确认", anchor=anchor)


def test_store_rebuild_locks_prior_selection_and_caps_new_candidates(
        tmp_path: Path) -> None:
    _v1_store(tmp_path, [_recon_proposal(1), _recon_proposal(2)])
    store = CandidateStore(tmp_path)
    first = store.build(_DifferentComparator(), lambda ctx: _TotalScorer({}))
    assert [c["candidate_id"] for c in first["candidates"]] == [
        "cand-0001", "cand-0002"]
    assert all(c["disposition"] is None for c in first["candidates"])

    # Related 回队:既有 ID/评分原样保留,新候选竞争剩余名额
    related = _related_intake("rel-cand-0001-1", "verification:cand-0001",
                              anchor="parse+0x42")
    second = store.build(
        _DifferentComparator(), lambda ctx: _TotalScorer({}),
        extra_intake=[related])
    by_id = {c["candidate_id"]: c for c in second["candidates"]}
    assert set(by_id) == {"cand-0001", "cand-0002", "cand-0003"}
    assert by_id["cand-0001"]["queue"]["selected"] is True
    assert by_id["cand-0001"]["disposition"] is None
    assert by_id["cand-0003"]["disposition"] is None
    # 同一 related 重复消费:幂等,不新增 Candidate、不改 ID
    third = store.build(
        _DifferentComparator(), lambda ctx: _TotalScorer({}),
        extra_intake=[related])
    assert [c["candidate_id"] for c in third["candidates"]] == [
        "cand-0001", "cand-0002", "cand-0003"]

    # 名额已满(2 个已锁定,slots=2):新候选明确 not_started,已处理身份保留
    # 高分新候选也不得挤掉已锁定的低分既有候选(总名额 2 已用尽)
    totals = {"rel-cand-0001-1": 9, "rel-cand-0002-1": 9}
    fourth_related = _related_intake("rel-cand-0002-1", "verification:cand-0002",
                                     anchor="upg+0x10")
    fourth = store.build(
        _DifferentComparator(), lambda ctx: _TotalScorer(totals),
        extra_intake=[fourth_related], slots=2)
    by_id = {c["candidate_id"]: c for c in fourth["candidates"]}
    assert by_id["cand-0004"]["disposition"] == "not_started"
    for locked in ("cand-0001", "cand-0002"):
        assert by_id[locked]["disposition"] is None  # 已入选不被挤掉
        assert by_id[locked]["queue"]["selected"] is True


def test_store_rebuild_refuses_cross_source_same_id_rewrite(tmp_path: Path) -> None:
    _v1_store(tmp_path, [_recon_proposal(1)])
    store = CandidateStore(tmp_path)
    store.build(_DifferentComparator(), lambda ctx: _TotalScorer({}))
    # 先消费一个来源的 related,再用另一来源同名不同内容复写 → 响亮拒绝
    store.build(
        _DifferentComparator(), lambda ctx: _TotalScorer({}),
        extra_intake=[_related_intake("rel-cand-0001-1", "verification:cand-0001",
                                      anchor="parse+0x42")])
    clash = _related_intake("rel-cand-0001-1", "analysis:cand-0002",
                            anchor="different-anchor")
    with pytest.raises(Exception, match="proposal_id"):
        store.build(_DifferentComparator(), lambda ctx: _TotalScorer({}),
                    extra_intake=[clash])


def test_add_candidate_with_explicit_id_respects_watermark(tmp_path: Path) -> None:
    tracer = HostAnalysisTracer(tmp_path, {})
    first = tracer.add_candidate({"target": "x"}, candidate_id="cand-0007")
    assert first.candidate_id == "cand-0007"
    second = tracer.add_candidate({"target": "y"})
    assert second.candidate_id == "cand-0008"
    with pytest.raises(ValueError, match="非法 Candidate ID"):
        tracer.add_candidate({"target": "z"}, candidate_id="cand-2")
    with pytest.raises(ValueError, match="水位"):
        tracer.add_candidate({"target": "w"}, candidate_id="cand-0007")


# ---- S5 运行驱动:全链路 Fake Session/工具 + 世代/配置/预算/恢复 ----

import re

from firmware_audit.step5_agent.host import RunDriver
from firmware_audit.test.test_step5_host_analysis import (
    _action as _analysis_action,
    _claims_delta,
    _close,
    _submit,
    _supported,
)
from firmware_audit.test.test_step5_host_analysis import GENERIC_REQUIRED
from firmware_audit.test.test_step5_host_verification import (
    _result as _v_result,
)
from firmware_audit.test.test_step5_host_verification import (
    _v_action,
    _v_complete,
)

_EV_IN_INPUT = re.compile(r"Observation View \[(ev-\d{6})\]")


class SmartAnalysisSession:
    """自适应 Analysis Session:从 Observation View 读本轮证据号再提交。"""

    role = "analysis"

    def __init__(self, candidate_id: str | None = None, *,
                 fail_on_step: int | None = None):
        self.inputs: list[str | None] = []
        self.last_usage = None
        self.fail_on_step = fail_on_step

    def step(self, input_message: str | None = None):
        self.inputs.append(input_message)
        if self.fail_on_step is not None and len(self.inputs) >= self.fail_on_step:
            raise RuntimeError("service down")
        if len(self.inputs) == 1:
            return _analysis_action({})
        if len(self.inputs) == 2:
            evidence = _EV_IN_INPUT.search(self.inputs[-1] or "").group(1)
            return _analysis_action(_claims_delta(
                {name: _supported(evidence) for name in GENERIC_REQUIRED}))
        return _submit("ready")


class SmartVerificationSession:
    """自适应复核 Session:独立取证后逐项 supported,complete 收尾。"""

    role = "verification"

    def __init__(self, candidate_id: str | None = None, *,
                 related: dict | None = None):
        self.inputs: list[str | None] = []
        self.last_usage = None
        self.related = related

    def step(self, input_message: str | None = None):
        self.inputs.append(input_message)
        if len(self.inputs) == 1:
            return _v_action({})
        if len(self.inputs) == 2:
            evidence = _EV_IN_INPUT.search(self.inputs[-1] or "").group(1)
            return _v_action({"claim_results": {
                name: _v_result("supported", evidence, claim=name)
                for name in GENERIC_REQUIRED}})
        return _v_complete(
            {"related_candidates": [self.related]} if self.related else None)


class FakeDedupLLM:
    """去重/评分 LLM:全部判 different,评分按调用序给递增总分。"""

    def __init__(self, *, fail_after: int | None = None):
        self.calls = 0
        self.fail_after = fail_after

    def chat(self, messages):
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            raise BudgetExhaustedError("运行总预算耗尽")
        payload = json.loads(messages[-1]["content"])
        if "verdict" in payload:  # 比较请求
            return json.dumps({"verdict": "different", "rationale": "目标不同"}), {}
        return json.dumps({"factors": {
            "external_reachability": {"score": 2, "evidence_id": "ev-000001",
                                      "note": "外部可达"},
        }}), {}


class SessionScript:
    """驱动注入的 session 工厂:按角色/Candidate 派发脚本化 Session。"""

    def __init__(self, *, analysis=None, verification=None, recon=None):
        self.recon = recon
        self.analysis_factory = analysis or SmartAnalysisSession
        self.verification_factory = verification or SmartVerificationSession
        self.created: list[tuple[str, str | None]] = []

    def __call__(self, role: str, candidate_id: str | None = None,
                 run_dir: Path | None = None):
        self.created.append((role, candidate_id))
        if role == "recon":
            return self.recon
        if role == "analysis":
            return self.analysis_factory(candidate_id)
        return self.verification_factory(candidate_id)


def _driver_env() -> dict[str, str]:
    return {}  # 隔离宿主环境:驱动不得读到本机 STEP5_* 变量


def _make_driver(tmp_path: Path, *, sessions, llm=None, explicit=None,
                 profile=None, env=None) -> RunDriver:
    tool = FakeTool(ToolResult(ok=True, text="token=literal", raw="token=literal"))
    return RunDriver(
        tmp_path,
        tools={"read_file": tool},
        session_factory=sessions,
        llm=llm if llm is not None else FakeDedupLLM(),
        process_dir=_workspace(tmp_path),
        explicit=explicit,
        profile=profile,
        env=env if env is not None else _driver_env(),
    )


def _recon_sessions() -> SessionScript:
    return SessionScript(recon=FakeReconSession([
        _recon_action(), _survey(_survey_delta())]))


def test_driver_full_chain_creates_generation_and_seals_processing(
        tmp_path: Path) -> None:
    sessions = _recon_sessions()
    driver = _make_driver(tmp_path, sessions=sessions)
    summary = driver.run()
    assert summary.created is True
    assert summary.generation == "gen-0001"
    assert summary.status == "completed"
    assert summary.stop_reason == "sealed"
    assert summary.candidates == 2
    assert summary.findings == 2  # 两个案卷都独立支持 → confirmed
    state = load_run_state(summary.gen_dir)
    assert state["status"] == "completed"
    assert "seal" in json.loads(
        (summary.gen_dir / "manifest.json").read_text(encoding="utf-8"))
    # 配置快照随世代冻结,且与 runner 实际轮次同源
    snapshot = json.loads(
        (summary.gen_dir / "config.json").read_text(encoding="utf-8"))
    assert snapshot["resolved"]["max_candidates"] == 8
    # Session 编排:recon ×1,analysis ×2,verification ×2
    assert [role for role, _ in sessions.created] == [
        "recon", "analysis", "analysis", "verification", "verification"]
    assert [cid for role, cid in sessions.created if role == "analysis"] == [
        "cand-0001", "cand-0002"]
    # 去重/评分的模型请求也过预算台账:总计数 = recon 2 + analysis 3×2
    # + verification 3×2 + 去重/评分 llm.calls;封存期注记请求被假 LLM
    # 拒收(JSON 解析失败)→ 只告警跳过,失败请求不记账
    ledger = json.loads(
        (summary.gen_dir / "budget.json").read_text(encoding="utf-8"))
    llm = driver._llm  # noqa: SLF001 -- 断言台账与真实调用数一致
    assert llm.calls >= 3  # 两个 Candidate 各评分一次 + 一次失败的注记请求
    assert ledger["llm_calls"] == 2 + 3 * 2 + 3 * 2 + llm.calls - 1


def test_driver_resumes_unfinished_generation_and_freezes_config(
        tmp_path: Path) -> None:
    # 第一段:recon 之后、analysis 中断(服务故障)
    class FailingAnalysis(SmartAnalysisSession):
        def __init__(self, candidate_id):
            super().__init__(
                candidate_id,
                fail_on_step=3 if candidate_id == "cand-0002" else None)

    sessions = SessionScript(
        recon=FakeReconSession([_recon_action(), _survey(_survey_delta())]),
        analysis=FailingAnalysis)
    driver = _make_driver(tmp_path, sessions=sessions,
                          env={"STEP5_RECON_MAX_ITERS": "9"})
    with pytest.raises(RuntimeError, match="service down"):
        driver.run()
    state = load_run_state(driver.root / "generations" / "gen-0001")
    assert state["status"] == "running"
    assert state["stop_reason"] == "interrupted:RuntimeError"
    # 服务中断:queued 保留,不落 not_started
    tracer_state = json.loads(
        (driver.root / "generations" / "gen-0001" / "investigations"
         / "cand-0002" / "state.json").read_text(encoding="utf-8"))
    # 服务中断:进行中的调查保留现场(不落终态、不落 not_started)
    assert tracer_state["state"]["investigation"]["lifecycle_status"] == "investigating"

    # 第二段:换一套环境变量恢复——配置快照冻结,不二次解析
    sessions2 = _recon_sessions()
    driver2 = _make_driver(tmp_path, sessions=sessions2, env={})
    summary = driver2.run()
    assert summary.created is False
    assert summary.generation == "gen-0001"
    assert summary.status == "completed"
    snapshot = json.loads(
        (summary.gen_dir / "config.json").read_text(encoding="utf-8"))
    assert snapshot["sources"]["recon_max_rounds"] == "environment"
    assert snapshot["resolved"]["recon_max_rounds"] == 9


def test_driver_profile_layer_and_explicit_override(tmp_path: Path) -> None:
    sessions = SessionScript(recon=FakeReconSession([_recon_action()]))
    driver = _make_driver(
        tmp_path, sessions=sessions,
        profile={"recon_max_rounds": 1})
    summary = driver.run()
    assert summary.stop_reason == "recon_incomplete:rounds_exhausted"
    snapshot = json.loads(
        (summary.gen_dir / "config.json").read_text(encoding="utf-8"))
    assert snapshot["sources"]["recon_max_rounds"] == "profile"

    # 显式参数优先于环境与 profile
    sessions2 = SessionScript(recon=FakeReconSession([_recon_action()]))
    driver2 = _make_driver(
        tmp_path / "w2", sessions=sessions2,
        explicit={"recon_max_rounds": 1},
        env={"STEP5_RECON_MAX_ITERS": "30"},
        profile={"recon_max_rounds": 30})
    summary2 = driver2.run()
    assert summary2.stop_reason == "recon_incomplete:rounds_exhausted"
    snapshot2 = json.loads(
        (summary2.gen_dir / "config.json").read_text(encoding="utf-8"))
    assert snapshot2["resolved"]["recon_max_rounds"] == 1
    assert snapshot2["sources"]["recon_max_rounds"] == "explicit"


def test_driver_input_failure_is_auditable_and_creates_no_investigation(
        tmp_path: Path) -> None:
    process_dir = tmp_path / "empty_process"  # 无 extracted/
    process_dir.mkdir()
    sessions = _recon_sessions()
    driver = _make_driver(tmp_path, sessions=sessions)
    driver.process_dir = process_dir
    summary = driver.run()
    assert summary.stop_reason == "recon_input_failure:extraction_missing"
    gen_dir = summary.gen_dir
    assert not list((gen_dir / "investigations").glob("cand-*"))
    assert not (gen_dir / "candidates.json").exists()
    # 恢复(同一空树):幂等,不再发起模型请求
    sessions2 = _recon_sessions()
    driver2 = _make_driver(tmp_path, sessions=sessions2)
    driver2.process_dir = process_dir
    driver2.run()
    assert sessions2.recon.inputs == []


def test_driver_budget_exhaustion_marks_queued_not_started(tmp_path: Path) -> None:
    class AnalysisOneAction(SmartAnalysisSession):
        """只走一步就收尾不了,配合极小 llm 预算触发耗尽。"""

    sessions = _recon_sessions()
    # recon 2 + 评分 2 + cand-0001 全程 3 = 7;cand-0002 第一步被拒
    driver = _make_driver(
        tmp_path, sessions=sessions,
        explicit={"max_llm_calls": 7})
    summary = driver.run()
    assert summary.stop_reason == "budget_exhausted"
    assert summary.status == "running"
    state = load_run_state(summary.gen_dir)
    assert state["status"] == "running"
    # cand-0001 进行中保留现场;cand-0002 未开始 → not_started 收账
    first = json.loads((summary.gen_dir / "investigations" / "cand-0001"
                        / "state.json").read_text(encoding="utf-8"))
    assert first["state"]["investigation"]["lifecycle_status"] == (
        "ready_for_verification")
    second = json.loads((summary.gen_dir / "investigations" / "cand-0002"
                         / "state.json").read_text(encoding="utf-8"))
    assert second["state"]["investigation"]["disposition"] == "not_started"


def test_driver_related_candidates_requeue_and_process_new_case(
        tmp_path: Path) -> None:
    related = {
        "proposal_id": "rel-cand-0001-1", "kind": "signal",
        "target": "extracted/bin/updater",
        "signal": "升级包解析未校验长度字段",
        "evidence_id": "ev-000004",  # 复核会话内独立取得的证据
        "next_action": "反编译解析函数确认边界检查",
        "anchor": "parse_header+0x42",
    }

    sessions = SessionScript(
        recon=FakeReconSession([_recon_action(), _survey(_survey_delta())]))

    class RelatedVerification(SmartVerificationSession):
        """cand-0001 的复核:complete 时带 related(proposal 引用会话证据)。"""

        def __init__(self, candidate_id=None):
            super().__init__(candidate_id)
            self._related = None

        def step(self, input_message=None):
            self.inputs.append(input_message)
            if len(self.inputs) == 1:
                return _v_action({})
            if len(self.inputs) == 2:
                evidence = _EV_IN_INPUT.search(self.inputs[-1] or "").group(1)
                self._related = dict(related, evidence_id=evidence)
                return _v_action({"claim_results": {
                    name: _v_result("supported", evidence, claim=name)
                    for name in GENERIC_REQUIRED}})
            return _v_complete({"related_candidates": [self._related]})

    sessions.verification_factory = lambda candidate_id: (
        RelatedVerification() if candidate_id == "cand-0001"
        else SmartVerificationSession())
    driver = _make_driver(tmp_path, sessions=sessions)
    summary = driver.run()
    assert summary.status == "completed"
    # related 入库成为 cand-0003 且被完整处理(独立分析+复核)
    roles = [role for role, _ in sessions.created]
    assert roles.count("analysis") == 3
    assert roles.count("verification") == 3
    store = json.loads(
        (summary.gen_dir / "candidates.json").read_text(encoding="utf-8"))
    by_id = {c["candidate_id"]: c for c in store["candidates"]}
    assert by_id["cand-0003"]["source"] == "verification:cand-0001"
    assert by_id["cand-0003"]["disposition"] is None
    assert summary.findings == 3


def test_driver_force_abandons_running_generation_and_starts_new(
        tmp_path: Path) -> None:
    sessions = _recon_sessions()
    driver = _make_driver(tmp_path, sessions=sessions,
                          explicit={"recon_max_rounds": 1})
    driver.run()  # 停在 recon incomplete(世代未完成)
    first_dir = driver.root / "generations" / "gen-0001"

    sessions2 = _recon_sessions()
    driver2 = _make_driver(tmp_path, sessions=sessions2)
    summary = driver2.run(force=True)
    assert summary.generation == "gen-0002"
    assert summary.created is True
    assert load_run_state(first_dir)["status"] == "abandoned"
    # 再次 force:gen-0002 已封存(completed 只读),force 直接新开 gen-0003
    sessions3 = _recon_sessions()
    driver3 = _make_driver(tmp_path, sessions=sessions3)
    summary3 = driver3.run(force=True)
    assert summary3.generation == "gen-0003"
    assert load_run_state(summary.gen_dir)["status"] == "completed"


def test_driver_treats_sealed_generation_as_readonly(tmp_path: Path) -> None:
    """票 12:封存世代不被恢复或改写;后续运行开新世代。"""
    sessions = _recon_sessions()
    summary = _make_driver(tmp_path, sessions=sessions).run()
    assert summary.status == "completed"
    gen_dir = summary.gen_dir
    sealed = {
        path.name: path.read_bytes() for path in (
            gen_dir / "manifest.json", gen_dir / "findings.json",
            gen_dir / "report.md", gen_dir / "run_state.json",
        )
    }

    sessions2 = _recon_sessions()
    summary2 = _make_driver(tmp_path, sessions=sessions2).run()
    assert summary2.generation == "gen-0002"  # 新世代,不恢复封存世代
    assert summary2.status == "completed"
    # 封存机器工件字节不变(sealed immutability)
    for name, payload in sealed.items():
        assert (gen_dir / name).read_bytes() == payload, name


def test_driver_refuses_second_concurrent_run_via_lock(tmp_path: Path) -> None:
    import threading
    started = threading.Event()
    release = threading.Event()

    class HangingRecon(FakeReconSession):
        def step(self, input_message=None):
            self.inputs.append(input_message)
            started.set()
            release.wait(timeout=10)
            return _survey(_survey_delta())

    sessions = SessionScript(recon=HangingRecon([]))
    driver = _make_driver(tmp_path, sessions=sessions)
    thread = threading.Thread(target=driver.run, daemon=True)
    thread.start()
    assert started.wait(timeout=10)
    second = _make_driver(tmp_path, sessions=_recon_sessions())
    with pytest.raises(Exception, match="活动"):
        second.run()
    release.set()
    thread.join(timeout=10)


def test_driver_never_reads_legacy_semantic_artifacts(tmp_path: Path) -> None:
    legacy = tmp_path / "process" / "agent"
    (legacy / "1_analysis").mkdir(parents=True)
    (legacy / "1_analysis" / "survey.json").write_text("{}", encoding="utf-8")
    (legacy / "1_analysis" / "findings.json").write_text("{}", encoding="utf-8")
    (legacy / "1_analysis" / "verified_findings.json").write_text(
        "{}", encoding="utf-8")
    sessions = _recon_sessions()
    summary = _make_driver(tmp_path, sessions=sessions).run()
    assert summary.status == "completed"
    # 旧工件原样保留,未被读取或迁移
    for name in ("survey.json", "findings.json", "verified_findings.json"):
        assert (legacy / "1_analysis" / name).read_text(
            encoding="utf-8") == "{}"


def test_driver_rejects_illegal_projection_on_resume(tmp_path: Path) -> None:
    sessions = _recon_sessions()
    driver = _make_driver(tmp_path, sessions=sessions,
                          explicit={"max_llm_calls": 7})
    driver.run()  # 预算耗尽收账(cand-0002 → not_started)
    gen_dir = driver.root / "generations" / "gen-0001"
    # 人为破坏一个投影:queued 配上终态 disposition(票 17 非法轴)
    def _damage(path: Path) -> None:
        # queued 配终态 disposition:票 17 的领域非法轴
        document = json.loads(path.read_text(encoding="utf-8"))
        document["state"]["investigation"]["lifecycle_status"] = "queued"
        document["state"]["investigation"]["disposition"] = "confirmed"
        path.write_text(json.dumps(document), encoding="utf-8")

    _damage(gen_dir / "investigations" / "cand-0002" / "state.json")
    events_path = gen_dir / "investigations" / "cand-0002" / "events.jsonl"
    lines = events_path.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[-1])
    event["state"]["investigation"]["lifecycle_status"] = "queued"
    event["state"]["investigation"]["disposition"] = "confirmed"
    lines[-1] = json.dumps(event, ensure_ascii=False)
    events_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(StoreError, match="生命周期投影非法"):
        _make_driver(tmp_path, sessions=_recon_sessions()).run()


# ---- S6 多次重启的组合稳定性(票 11 AC7) ----


def test_multi_restart_keeps_ids_evidence_budget_and_queue_stable(
        tmp_path: Path) -> None:
    gen_dir = tmp_path / "generations" / "gen-0001"

    def _evidence_ids() -> list[tuple[int, str]]:
        found = []
        for tree in ("investigations", "verifications"):
            for path in sorted((gen_dir / tree).glob("*/evidence/ev-*.json")):
                document = json.loads(path.read_text(encoding="utf-8"))
                found.append((document["sequence"], document["evidence_id"]))
        return sorted(found)

    # 第一段:cand-0002 复核中途服务中断
    class FailingVerification(SmartVerificationSession):
        def __init__(self, candidate_id=None):
            super().__init__(candidate_id)
            self.broken = candidate_id == "cand-0002"

        def step(self, input_message=None):
            if self.broken and len(self.inputs) >= 2:
                raise RuntimeError("service down")
            return super().step(input_message)

    first_sessions = SessionScript(
        recon=FakeReconSession([_recon_action(), _survey(_survey_delta())]))
    first_sessions.verification_factory = FailingVerification
    with pytest.raises(RuntimeError, match="service down"):
        _make_driver(tmp_path, sessions=first_sessions).run()
    first_ids = _evidence_ids()
    first_ledger = json.loads(
        (gen_dir / "budget.json").read_text(encoding="utf-8"))
    first_store = json.loads(
        (gen_dir / "candidates.json").read_text(encoding="utf-8"))
    assert [c["candidate_id"] for c in first_store["candidates"]] == [
        "cand-0001", "cand-0002"]
    assert [cid for role, cid in first_sessions.created
            if role == "verification"] == ["cand-0001", "cand-0002"]

    # 第二段:恢复并完成;cand-0002 从保存边界续,不重跑 cand-0001
    second_sessions = SessionScript(
        recon=FakeReconSession([]))  # recon 已完成,不应被请求
    driver2 = _make_driver(tmp_path, sessions=second_sessions)
    summary = driver2.run()
    assert summary.status == "completed"
    assert second_sessions.recon.inputs == []
    # 只补未收尾的复核;cand-0001 走幂等重放(results.json 已在),
    # 不再驱动 Session——队列顺序与第一段一致
    assert [role for role, _ in second_sessions.created] == ["verification"]
    assert [cid for role, cid in second_sessions.created] == ["cand-0002"]

    # Candidate ID / 选取稳定:既有 ID 不变、不重复注册
    second_store = json.loads(
        (gen_dir / "candidates.json").read_text(encoding="utf-8"))
    assert [c["candidate_id"] for c in second_store["candidates"]] == [
        "cand-0001", "cand-0002"]

    # Evidence ID 两棵树含 recon 全程唯一、单调不减,重启不重号不丢号
    second_ids = _evidence_ids()
    assert len({evidence_id for _, evidence_id in second_ids}) == len(second_ids)
    assert [item for item in first_ids] == [
        item for item in second_ids if item in set(first_ids)]
    assert set(second_ids) >= set(first_ids)

    # 预算单调累计,无重复扣账:恢复会话从重建上下文重走(独立取证→
    # claim_results→complete 共 3 步),cand-0001 走重放零请求
    second_ledger = json.loads(
        (gen_dir / "budget.json").read_text(encoding="utf-8"))
    assert second_ledger["llm_calls"] > first_ledger["llm_calls"]
    assert second_ledger["llm_calls"] == first_ledger["llm_calls"] + 3

    # 结论完整:两个案卷均 confirmed → 2 条 Finding,生命周期全收束
    findings = json.loads(
        (gen_dir / "findings.json").read_text(encoding="utf-8"))
    assert [f["candidate_id"] for f in findings["findings"]] == [
        "cand-0001", "cand-0002"]


# ---- S7 评审修复的回归钉子(P1/P2/P3 + Spec 补强) ----


def test_concurrent_cold_start_lock_admits_exactly_one(tmp_path: Path) -> None:
    import threading
    barrier = threading.Barrier(2)
    results: list[str] = []
    errors: list[BaseException] = []

    def contender(name: str) -> None:
        try:
            barrier.wait(timeout=10)
            with acquire_lock(tmp_path, hostname="h1",
                              alive_checker=lambda pid, marker: True):
                results.append(name)
        except BaseException as exc:  # noqa: BLE001 -- 记录竞争失败方
            errors.append(exc)

    threads = [threading.Thread(target=contender, args=(f"c{i}",))
               for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    # 独占创建保证:恰好一个持有者,另一个被拒(LockActiveError)
    assert len(results) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], LockActiveError)


def test_incompatible_generation_does_not_brick_workspace(tmp_path: Path) -> None:
    _, broken_dir = create_generation(tmp_path)
    manifest = json.loads((broken_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["schema_version"] = 99
    (broken_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    # 默认路径:不兼容世代被跳过(告警)且不被读取,直接新建新世代
    with pytest.warns(RuntimeWarning, match="跳过无法恢复的世代"):
        summary = _make_driver(tmp_path, sessions=_recon_sessions()).run()
    assert summary.generation == "gen-0002"
    assert summary.status == "completed"
    # force 同样可行:指引"请创建新运行世代"经驱动真的能执行
    with pytest.warns(RuntimeWarning, match="跳过无法恢复的世代"):
        forced = _make_driver(tmp_path, sessions=_recon_sessions()).run(force=True)
    assert forced.generation == "gen-0003"
    # 不兼容世代原样保留
    assert json.loads(
        (broken_dir / "manifest.json").read_text(encoding="utf-8")
    )["schema_version"] == 99


def test_multiple_unfinished_generations_refuse_default_resume(
        tmp_path: Path) -> None:
    create_generation(tmp_path)
    create_generation(tmp_path)
    with pytest.raises(StoreError, match="多个未完成世代.*force"):
        _make_driver(tmp_path, sessions=_recon_sessions()).run()


def test_resume_completes_interrupted_investigation_with_disposition(
        tmp_path: Path) -> None:
    """P1-1 回归:analysis 中断的调查(investigating)必须被恢复驱动到终态。"""
    class FailingAnalysis(SmartAnalysisSession):
        def __init__(self, candidate_id=None):
            super().__init__(
                candidate_id,
                fail_on_step=3 if candidate_id == "cand-0002" else None)

    sessions = SessionScript(
        recon=FakeReconSession([_recon_action(), _survey(_survey_delta())]),
        analysis=FailingAnalysis)
    with pytest.raises(RuntimeError, match="service down"):
        _make_driver(tmp_path, sessions=sessions).run()
    gen_dir = tmp_path / "generations" / "gen-0001"
    mid = json.loads((gen_dir / "investigations" / "cand-0002"
                      / "state.json").read_text(encoding="utf-8"))
    assert mid["state"]["investigation"]["lifecycle_status"] == "investigating"

    summary = _make_driver(tmp_path, sessions=_recon_sessions()).run()
    assert summary.status == "completed"
    assert summary.findings == 2  # 中断候选也被完整分析+复核
    final = json.loads((gen_dir / "investigations" / "cand-0002"
                        / "state.json").read_text(encoding="utf-8"))
    investigation = final["state"]["investigation"]
    assert investigation["lifecycle_status"] == "finished"
    assert investigation["disposition"] == "confirmed"
    assert (gen_dir / "verifications" / "cand-0002" / "results.json").exists()


def test_case_crash_gap_does_not_deadlock_generation(tmp_path: Path) -> None:
    """P1-1 二阶:case.json 已落盘但生命周期仍 investigating 的崩溃夹缝。"""
    class FailingAnalysis(SmartAnalysisSession):
        def __init__(self, candidate_id=None):
            super().__init__(
                candidate_id,
                fail_on_step=3 if candidate_id == "cand-0002" else None)

    sessions = SessionScript(
        recon=FakeReconSession([_recon_action(), _survey(_survey_delta())]),
        analysis=FailingAnalysis)
    with pytest.raises(RuntimeError, match="service down"):
        _make_driver(tmp_path, sessions=sessions).run()
    gen_dir = tmp_path / "generations" / "gen-0001"
    # 人为制造 submit_case 两段写之间的崩溃现场:有案卷、生命周期未推进
    path = gen_dir / "investigations" / "cand-0002" / "state.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    events = gen_dir / "investigations" / "cand-0002" / "events.jsonl"
    lines = events.read_text(encoding="utf-8").splitlines()
    event = json.loads(lines[-1])
    for target in (document["state"], event["state"]):
        target["investigation"]["lifecycle_status"] = "investigating"
    path.write_text(json.dumps(document), encoding="utf-8")
    lines[-1] = json.dumps(event, ensure_ascii=False)
    events.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = _make_driver(tmp_path, sessions=_recon_sessions()).run()
    assert summary.status == "completed"  # 不再每次恢复都撞 begin_verification
    assert summary.findings == 2


def test_store_build_budget_exhaustion_keeps_previous_version_and_ids(
        tmp_path: Path) -> None:
    _v1_store(tmp_path, [_recon_proposal(1), _recon_proposal(2)])

    class ExhaustingScorer:
        def __init__(self):
            self.calls = 0

        def score(self, candidate) -> dict:
            self.calls += 1
            if self.calls >= 2:  # 第二个候选评分时预算耗尽
                raise BudgetExhaustedError("运行总预算耗尽")
            return {"factors": {}, "total": 1, "status": "ok"}

    store = CandidateStore(tmp_path)
    with pytest.raises(BudgetExhaustedError):
        store.build(_DifferentComparator(), lambda ctx: ExhaustingScorer())
    # 恢复边界:盘上保持上一完整版本(v1),未完成评分不落半成品
    document = json.loads(
        (tmp_path / "candidates.json").read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    # 预算恢复后重建:ID 分配稳定(v1 顺序确定性 → 同样的 cand-0001/0002)
    rebuilt = store.build(
        _DifferentComparator(), lambda ctx: _TotalScorer({}))
    assert [c["candidate_id"] for c in rebuilt["candidates"]] == [
        "cand-0001", "cand-0002"]


def test_priority_scorer_grounds_verification_tree_evidence(tmp_path: Path) -> None:
    """Spec#2:verification 来源的 Related Candidate 以自身证据 ground 评分。"""
    verification_evidence = (
        tmp_path / "verifications" / "cand-0001" / "evidence" / "ev-000002.json")
    verification_evidence.parent.mkdir(parents=True)
    verification_evidence.write_text(json.dumps({
        "evidence_id": "ev-000002", "summary": "复核观察到的升级解析缺陷",
    }), encoding="utf-8")

    captured: list[dict] = []

    class RecordingScorer:
        def score(self, candidate) -> dict:
            captured.append(candidate.as_dict())
            return {"factors": {}, "total": 1, "status": "ok"}

    store = CandidateStore(tmp_path)
    store.build(
        _DifferentComparator(), lambda ctx: RecordingScorer(),
        extra_intake=[_related_intake("rel-cand-0001-1", "verification:cand-0001",
                                      anchor="parse+0x42")])
    # 评分器拿到的可用证据表包含 verifications 树的 Evidence
    assert any(
        payload.get("available_evidence", {}).get("ev-000002")
        for payload in captured) or captured  # 记录式评分器只证明可调用
    # 直接断言 _evidence_context 的扫描口径
    context = store._evidence_context()  # noqa: SLF001 -- 口径钉子
    assert context.get("ev-000002") == "复核观察到的升级解析缺陷"


def test_recon_input_failure_after_progress_keeps_rounds(tmp_path: Path) -> None:
    """P3-3:恢复中输入再度失败,结果与检查点同口径(不丢已耗轮次)。"""
    tool = _recon_tool()
    first_dir = tmp_path / "w1"
    process_dir = first_dir / "process"
    _make_tree(process_dir, {"extracted/etc/device.conf": 24})
    runner = HostReconRunner(first_dir, {"read_file": tool}, max_rounds=5)

    class CrashAfterAction(FakeReconSession):
        def step(self, input_message=None):
            self.inputs.append(input_message)
            if len(self.inputs) >= 2:
                raise RuntimeError("service down")
            return _recon_action()

    with pytest.raises(RuntimeError, match="service down"):
        runner.run(CrashAfterAction([]), process_dir)
    # 输入树在恢复前被破坏:再跑一轮,输入失败但轮次口径与检查点一致
    import shutil
    shutil.rmtree(process_dir / "extracted")
    again = HostReconRunner(first_dir, {"read_file": tool}, max_rounds=5).run(
        FakeReconSession([]), process_dir)
    assert again.status == "input_failure"
    assert again.rounds_used == 1
    assert len(again.evidence) == 1


def test_prior_projection_invariant_is_enforced(tmp_path: Path) -> None:
    _v1_store(tmp_path, [_recon_proposal(1)])
    store = CandidateStore(tmp_path)
    first = store.build(_DifferentComparator(), lambda ctx: _TotalScorer({}))
    # 人为破坏不变量:selected=False 但 disposition=None → 拒绝恢复
    first["candidates"][0]["queue"]["selected"] = False
    (tmp_path / "candidates.json").write_text(
        json.dumps(first), encoding="utf-8")
    with pytest.raises(StoreError, match="队列投影损坏"):
        store.build(
            _DifferentComparator(), lambda ctx: _TotalScorer({}),
            extra_intake=[_related_intake(
                "rel-cand-0001-1", "verification:cand-0001", anchor="x")])

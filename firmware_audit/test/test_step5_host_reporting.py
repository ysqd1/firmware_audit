"""Ticket 12:事实报告、完成门与运行封存(Host Store 持久化 seam)。

覆盖 AC:固定顺序报告、敏感值只呈现类型/位置/长度/digest 前缀、完成门五条件、
manifest seal(report digest + 工件 digests)与 completed 状态、确定性快照
(相同结构化输入 → 相同事实与 digest)、故障注入的 finalizing 恢复、
Analyst Notes 可选且不进事实 digest。

fixture 直接构造封存前的 finalizing 世代工件,走公开 reporting 接口。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from firmware_audit.step5_agent.host import reporting
from firmware_audit.step5_agent.host.budget import (
    BUDGET_SCHEMA_VERSION,
    resolve_effective_config,
)
from firmware_audit.step5_agent.host.generation import (
    create_generation,
    load_run_state,
    read_manifest,
    save_run_state,
)
from firmware_audit.step5_agent.host.driver import RunDriver
from firmware_audit.step5_agent.host.reporting import (
    SealError,
    build_evidence_index,
    build_fact_report,
    completion_gate,
    seal_run,
)
from firmware_audit.step5_agent.host.review import (
    ReviewOverlay,
    load_review_projection,
)
from firmware_audit.step5_agent.host.store import StoreError

SECRET = "SUPERSECRET-api-key-0123456789"

_SECTIONS = [
    "## 1. 运行摘要与有效配置",
    "## 2. Confirmed Findings",
    "## 3. Rejected Verification Cases",
    "## 4. Inconclusive Cases",
    "## 5. 未开始 Candidates",
    "## 6. Coverage Gaps",
    "## 7. Evidence Index",
    "## 8. 资源使用与停止原因",
]


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def _evidence_payload(evidence_id: str, *, tool: str = "read_file",
                      candidate_id: str = "cand-0001",
                      location: str | None = None,
                      observation: str = SECRET) -> dict:
    digest = hashlib.sha256(observation.encode("utf-8")).hexdigest()
    return {
        "schema_version": 1,
        "evidence_id": evidence_id,
        "tool": tool,
        "arguments": {"path": "extracted/etc/shadow"},
        "summary": "敏感凭据命中: " + SECRET,
        "location": location or f"investigations/{candidate_id}/evidence"
                                f"/{evidence_id}.json",
        "digest": digest,
        "candidate_id": candidate_id,
        "investigation_id": "inv-0001",
        "sequence": 1,
        "observation": observation,
        "tool_result": {"ok": True, "text": observation, "raw": observation,
                        "data": None, "error": None, "elapsed": 0.1},
    }


def _build_gen(root: Path, *, name_suffix: str = "") -> Path:
    """构造一个处理责任已收束、等待封存的 finalizing 世代。"""
    _name, gen_dir = create_generation(root / f"ws{name_suffix}", now=1000.0)
    save_run_state(gen_dir, status="finalizing", phase="accounting",
                   stop_reason="processing_complete")

    config = resolve_effective_config(explicit=None, env={}, profile=None)
    _write_json(gen_dir / "config.json",
                {"schema_version": 1, **config})
    _write_json(gen_dir / "budget.json", {
        "schema_version": BUDGET_SCHEMA_VERSION,
        "llm_calls": 12, "prompt_tokens": 3400, "completion_tokens": 800,
        "validated_rounds": 10, "tool_attempts": 30,
        "logical_tool_calls": 26, "active_seconds": 120.5,
    })
    _write_json(gen_dir / "candidates.json", {
        "schema_version": 2,
        "survey": {
            "attack_surface": [{"area": "etc/ 配置"}],
            "checked_scope": ["extracted/etc/*"],
            "coverage_gaps": [
                {"area": "vendor SDK 动态库", "reason": "超出处理名额"},
            ],
        },
        "candidates": [
            {"candidate_id": "cand-0001", "kind": "signal",
             "target": "extracted/etc/shadow", "signal": "弱口令哈希",
             "claim_profile": "credentials", "source": "recon",
             "next_action": "核对哈希强度", "initial_evidence": "ev-000001",
             "queue": {"queue": "signal", "rank": 0, "selected": True},
             "disposition": None, "priority": {"total": 9}},
            {"candidate_id": "cand-0002", "kind": "coverage",
             "target": "extracted/usr/lib/vendor", "signal": "未检查面",
             "claim_profile": "generic", "source": "recon",
             "next_action": "覆盖扫描", "initial_evidence": "ev-000001",
             "queue": {"queue": "coverage", "rank": 0, "selected": False},
             "disposition": "not_started", "priority": {"total": 3}},
        ],
    })
    _write_json(gen_dir / "investigations" / "cand-0001" / "state.json", {
        "schema_version": 1, "last_event_seq": 1,
        "state": {
            "candidate": {"candidate_id": "cand-0001",
                          "proposal": {"target": "extracted/etc/shadow"}},
            "investigation": {"investigation_id": "inv-0001",
                              "candidate_id": "cand-0001",
                              "claim_profile": "credentials",
                              "lifecycle_status": "finished",
                              "disposition": "confirmed",
                              "stop_reason": "completed"},
            "runtime": {},
        },
    })
    _write_json(
        gen_dir / "investigations" / "cand-0001" / "evidence"
        / "ev-000001.json",
        _evidence_payload("ev-000001"))
    claim_results = {
        "target_exists": {"judgment": "supported", "observed": "文件存在",
                          "evidence_ids": ["ev-000002"], "method": "read_file"},
        "root_cause": {"judgment": "supported", "observed": "默认弱哈希",
                       "evidence_ids": ["ev-000002"], "method": "read_file"},
        "trigger_or_exposure": {"judgment": "supported",
                                "observed": "认证路径可达",
                                "evidence_ids": ["ev-000002"], "method": "grep"},
        "actual_impact": {"judgment": "supported", "observed": "本地提权",
                          "evidence_ids": ["ev-000002"], "method": "grep",
                          "impact_scope": "component"},
        "preconditions": {"judgment": "supported",
                          "observed": "需要本地 shell", "evidence_ids": ["ev-000002"],
                          "method": "grep", "trigger_condition": "limited"},
        "mitigations": {"judgment": "not_applicable", "observed": "无缓解",
                        "evidence_ids": [], "method": "grep"},
        "material_valid": {"judgment": "supported", "observed": "哈希可破解",
                           "evidence_ids": ["ev-000002"], "method": "john"},
        "access_boundary": {"judgment": "supported", "observed": "本地用户",
                            "evidence_ids": ["ev-000002"], "method": "grep"},
        "actual_usage": {"judgment": "supported", "observed": "登录校验使用",
                         "evidence_ids": ["ev-000002"], "method": "grep"},
    }
    _write_json(gen_dir / "verifications" / "cand-0001" / "case.json", {
        "schema_version": 1, "candidate_id": "cand-0001",
        "investigation_id": "inv-0001", "claim_profile": "credentials",
        "admission_reason": "ready",
        "claims": {name: {"status": "supported", "evidence_ids": ["ev-000001"]}
                   for name in claim_results},
        "evidence_references": [], "pending_claims": [], "blocking_gaps": [],
    })
    _write_json(gen_dir / "verifications" / "cand-0001" / "results.json", {
        "schema_version": 1, "candidate_id": "cand-0001",
        "investigation_id": "inv-0001", "claim_profile": "credentials",
        "admission_reason": "ready", "verdict": "confirmed",
        "stop_reason": "completed", "claim_results": claim_results,
        "decisive_refuted": [], "unsupported": [],
        "evidence_references": [], "related_candidates": [],
        "finding_id": "f-0001", "rounds_used": 5, "max_rounds": 15,
    })
    _write_json(
        gen_dir / "verifications" / "cand-0001" / "evidence"
        / "ev-000002.json",
        _evidence_payload(
            "ev-000002", tool="grep", candidate_id="cand-0001",
            location="verifications/cand-0001/evidence/ev-000002.json",
            observation="命中 " + SECRET))
    _write_json(gen_dir / "findings.json", {
        "schema_version": 1,
        "findings": [{
            "schema_version": 1, "finding_id": "f-0001",
            "candidate_id": "cand-0001", "investigation_id": "inv-0001",
            "claim_profile": "credentials", "admission_reason": "ready",
            "verdict": "confirmed", "severity": "high",
            "severity_basis": {"impact_scope": "component",
                               "trigger_condition": "limited",
                               "mitigation_effect": None, "incomplete": False},
            "claims": claim_results, "evidence_references": [],
            "related_candidates": [],
        }],
    })
    return gen_dir


# ---- S1 完成门 ----


def test_completion_gate_passes_on_converged_run(tmp_path: Path) -> None:
    assert completion_gate(_build_gen(tmp_path)) == []


@pytest.mark.parametrize("mutate", [
    "no_store", "no_investigation", "not_finished", "bad_not_started",
    "ready_unverified",
])
def test_completion_gate_failures(tmp_path: Path, mutate: str) -> None:
    gen_dir = _build_gen(tmp_path)
    if mutate == "no_store":
        (gen_dir / "candidates.json").unlink()
    elif mutate == "no_investigation":
        shutil.rmtree(gen_dir / "investigations" / "cand-0001")
    elif mutate == "not_finished":
        snapshot = json.loads(
            (gen_dir / "investigations" / "cand-0001" / "state.json")
            .read_text(encoding="utf-8"))
        snapshot["state"]["investigation"]["lifecycle_status"] = "verifying"
        _write_json(gen_dir / "investigations" / "cand-0001" / "state.json",
                    snapshot)
    elif mutate == "bad_not_started":
        store = json.loads((gen_dir / "candidates.json").read_text(
            encoding="utf-8"))
        store["candidates"][1]["disposition"] = None
        _write_json(gen_dir / "candidates.json", store)
    else:
        (gen_dir / "verifications" / "cand-0001" / "results.json").unlink()
    failures = completion_gate(gen_dir)
    assert len(failures) == 1
    assert all(isinstance(item, str) for item in failures)


def test_completion_gate_exempts_budget_exhausted_unreviewed_ready_case(
        tmp_path: Path) -> None:
    """票 21:所属调查已按 unresolved/budget_exhausted 收束的未复核 ready
    案卷,复核责任视为已了结;世代可正常封存为 completed。"""
    gen_dir = _build_gen(tmp_path, name_suffix="-exempt")
    state_path = gen_dir / "investigations" / "cand-0001" / "state.json"
    snapshot = json.loads(state_path.read_text(encoding="utf-8"))
    snapshot["state"]["investigation"].update(
        disposition="unresolved", stop_reason="budget_exhausted")
    _write_json(state_path, snapshot)
    (gen_dir / "verifications" / "cand-0001" / "results.json").unlink()

    assert completion_gate(gen_dir) == []
    seal_run(gen_dir, now=2000.0)
    assert load_run_state(gen_dir)["status"] == "completed"


def test_completion_gate_still_rejects_non_budget_unreviewed_ready_case(
        tmp_path: Path) -> None:
    """票 21:豁免必须精确——其余未复核 ready 案卷(含非 budget_exhausted
    原因收束的调查)照旧拒绝封存。"""
    gen_dir = _build_gen(tmp_path, name_suffix="-strict")
    state_path = gen_dir / "investigations" / "cand-0001" / "state.json"
    snapshot = json.loads(state_path.read_text(encoding="utf-8"))
    snapshot["state"]["investigation"].update(
        disposition="unresolved", stop_reason="no_progress")
    _write_json(state_path, snapshot)
    (gen_dir / "verifications" / "cand-0001" / "results.json").unlink()

    failures = completion_gate(gen_dir)
    assert any("cand-0001" in item and "尚未复核" in item for item in failures)
    with pytest.raises(SealError, match="尚未复核"):
        seal_run(gen_dir, now=2000.0)
    assert load_run_state(gen_dir)["status"] == "finalizing"


# ---- S2 报告:固定顺序、确定性、敏感值呈现纪律 ----


def test_report_sections_in_fixed_order(tmp_path: Path) -> None:
    report = build_fact_report(_build_gen(tmp_path))
    positions = [report.index(header) for header in _SECTIONS]
    assert positions == sorted(positions)
    # 关键内容落位:confirmed 在第 2 节,coverage gap 在第 6 节。
    assert "f-0001" in report
    assert "vendor SDK 动态库" in report
    assert "cand-0002" in report  # not started 可见


def test_report_is_deterministic_snapshot(tmp_path: Path) -> None:
    first = _build_gen(tmp_path, name_suffix="-a")
    second = _build_gen(tmp_path, name_suffix="-b")
    assert build_fact_report(first) == build_fact_report(second)
    assert build_fact_report(first) == build_fact_report(first)


def test_report_hides_raw_observation_values(tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)
    report = build_fact_report(gen_dir)
    assert SECRET not in report
    index = build_evidence_index(gen_dir)
    assert len(index) == 2
    entry = index[0]
    assert entry["evidence_id"] == "ev-000001"
    assert entry["tool"] == "read_file"
    assert entry["location"] == "investigations/cand-0001/evidence/ev-000001.json"
    assert entry["bytes"] == len(SECRET.encode("utf-8"))
    digest = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()
    assert entry["digest_prefix"] == digest[:12]
    assert digest not in report  # 全长 digest 也不出现,只给前缀


def test_evidence_index_rejects_corrupt_evidence(tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)
    (gen_dir / "investigations" / "cand-0001" / "evidence"
     / "ev-000001.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(StoreError):
        build_evidence_index(gen_dir)


# ---- S3 封存:manifest seal + completed + 幂等 ----


def test_seal_run_completes_generation(tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)
    seal = seal_run(gen_dir, now=2000.0)
    assert load_run_state(gen_dir)["status"] == "completed"
    manifest = read_manifest(gen_dir)
    assert manifest["seal"] == seal
    facts = build_fact_report(gen_dir)
    assert seal["report_sha256"] == hashlib.sha256(
        facts.encode("utf-8")).hexdigest()
    digests = seal["artifact_digests"]
    assert digests["findings.json"] == hashlib.sha256(
        (gen_dir / "findings.json").read_bytes()).hexdigest()
    assert ("investigations/cand-0001/evidence/ev-000001.json" in digests)
    assert ("verifications/cand-0001/results.json" in digests)
    assert (gen_dir / "report.md").exists()


def test_seal_run_digests_deterministic_across_identical_runs(
        tmp_path: Path) -> None:
    first = seal_run(_build_gen(tmp_path, name_suffix="-a"), now=2000.0)
    second = seal_run(_build_gen(tmp_path, name_suffix="-b"), now=3000.0)
    assert first["report_sha256"] == second["report_sha256"]
    assert first["artifact_digests"] == second["artifact_digests"]


def test_seal_run_requires_finalizing(tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)
    save_run_state(gen_dir, status="running", phase="analysis")
    with pytest.raises(SealError, match="finalizing"):
        seal_run(gen_dir)
    assert load_run_state(gen_dir)["status"] == "running"


def test_seal_run_rejects_unconverged_run(tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)
    (gen_dir / "verifications" / "cand-0001" / "results.json").unlink()
    with pytest.raises(SealError, match="未复核"):
        seal_run(gen_dir)
    assert load_run_state(gen_dir)["status"] == "finalizing"


def test_seal_run_idempotent_after_completed(tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)
    first = seal_run(gen_dir, now=2000.0)
    report_bytes = (gen_dir / "report.md").read_bytes()
    again = seal_run(gen_dir, now=3000.0)
    assert again == first  # 已封存世代不重写任何工件
    assert (gen_dir / "report.md").read_bytes() == report_bytes


# ---- S4 故障注入:报告/manifest 失败保持 finalizing,恢复后续跑 ----


def test_seal_failure_keeps_finalizing_and_recovers(tmp_path: Path,
                                                    monkeypatch) -> None:
    gen_dir = _build_gen(tmp_path)
    real_atomic = reporting.atomic_json

    def fail_on_manifest(path, payload, **kwargs):
        if Path(path).name == "manifest.json":
            raise OSError("disk full before manifest seal")
        return real_atomic(path, payload, **kwargs)

    monkeypatch.setattr(reporting, "atomic_json", fail_on_manifest)
    with pytest.raises(OSError):
        seal_run(gen_dir, now=2000.0)
    assert load_run_state(gen_dir)["status"] == "finalizing"
    assert not (gen_dir / "manifest.json").exists() or "seal" not in json.loads(
        (gen_dir / "manifest.json").read_text(encoding="utf-8"))

    monkeypatch.undo()
    seal = seal_run(gen_dir, now=2100.0)
    assert load_run_state(gen_dir)["status"] == "completed"
    assert seal["report_sha256"]


def test_report_write_failure_keeps_finalizing(tmp_path: Path,
                                               monkeypatch) -> None:
    gen_dir = _build_gen(tmp_path)
    real_atomic = reporting.atomic_text

    def fail_on_report(path, text, **kwargs):
        if Path(path).name == "report.md":
            raise OSError("disk full before report")
        return real_atomic(path, text, **kwargs)

    monkeypatch.setattr(reporting, "atomic_text", fail_on_report)
    with pytest.raises(OSError):
        seal_run(gen_dir)
    assert load_run_state(gen_dir)["status"] == "finalizing"
    assert load_run_state(gen_dir)["stop_reason"] == "processing_complete"
    monkeypatch.undo()
    seal_run(gen_dir)
    assert load_run_state(gen_dir)["status"] == "completed"


# ---- S5 Analyst Notes:最后的可选标注段,不进事实 digest ----


def test_analyst_notes_appended_after_facts_without_touching_digest(
        tmp_path: Path) -> None:
    plain = _build_gen(tmp_path, name_suffix="-a")
    noted = _build_gen(tmp_path, name_suffix="-b")
    plain_seal = seal_run(plain, now=2000.0)
    noted_seal = seal_run(noted, analyst_notes="该组件在历史版本已有修复公告。",
                          now=2000.0)
    assert plain_seal["report_sha256"] == noted_seal["report_sha256"]
    noted_report = (noted / "report.md").read_text(encoding="utf-8")
    assert "Analyst Notes" in noted_report
    assert "历史版本已有修复公告" in noted_report
    # 注记段在全部事实章节之后,且明确标注非机器事实。
    assert noted_report.index("## 8. 资源使用与停止原因") < noted_report.index(
        "Analyst Notes")
    assert "非机器事实" in noted_report
    assert "Analyst Notes" not in (plain / "report.md").read_text(
        encoding="utf-8")


# ---- S6 驱动集成:finalizing 恢复直达封存,失败保持 finalizing ----


class _ExplodingSessionFactory:
    """finalizing 恢复不得驱动任何 Session;一旦被调用即失败。"""

    def __call__(self, role, candidate_id=None, run_dir=None):  # pragma: no cover
        raise AssertionError(f"finalizing 恢复不得创建 {role} Session")


class _NotesLLM:
    """注记 LLM:固定回一段文本并记账 usage。"""

    def __init__(self) -> None:
        self.calls: list[list[dict]] = []

    def chat(self, messages):
        self.calls.append(messages)
        return "凭据类问题与默认配置弱口令同源,建议优先跟进 SDK 覆盖缺口。", {
            "prompt_tokens": 10, "completion_tokens": 20}


def _driver(root: Path, *, llm) -> RunDriver:
    return RunDriver(
        root, tools={}, session_factory=_ExplodingSessionFactory(), llm=llm,
        process_dir=root / "process")


def test_driver_resumes_finalizing_straight_to_seal(tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)  # root=tmp_path/"ws", gen-0001 finalizing
    driver = _driver(tmp_path / "ws", llm=None)
    summary = driver.run()
    assert summary.status == "completed"
    assert summary.stop_reason == "sealed"
    assert load_run_state(gen_dir)["status"] == "completed"
    assert "seal" in read_manifest(gen_dir)


def test_driver_seal_failure_keeps_finalizing_and_recovers(
        tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)
    results_path = gen_dir / "verifications" / "cand-0001" / "results.json"
    results = results_path.read_text(encoding="utf-8")
    results_path.unlink()  # ready 案卷未复核 → 封存门拒绝
    driver = _driver(tmp_path / "ws", llm=None)
    with pytest.raises(SealError):
        driver.run()
    state = load_run_state(gen_dir)
    assert state["status"] == "finalizing"
    assert state["stop_reason"].startswith("seal_failed")

    results_path.write_text(results, encoding="utf-8")  # 恢复工件后续跑
    assert driver.run().status == "completed"
    assert load_run_state(gen_dir)["status"] == "completed"


def test_driver_generates_analyst_notes_via_llm(tmp_path: Path) -> None:
    gen_dir = _build_gen(tmp_path)
    llm = _NotesLLM()
    summary = _driver(tmp_path / "ws", llm=llm).run()
    assert summary.status == "completed"
    assert len(llm.calls) == 1  # 只有一次注记请求,处理未重跑
    report = (gen_dir / "report.md").read_text(encoding="utf-8")
    assert "SDK 覆盖缺口" in report
    assert "Analyst Notes" in report
    # 注记请求计入台账(真实模型请求都进 llm_calls)。
    ledger = json.loads((gen_dir / "budget.json").read_text(encoding="utf-8"))
    assert ledger["llm_calls"] == 13


def test_driver_notes_failure_does_not_block_seal(tmp_path: Path) -> None:
    class _BrokenNotesLLM:
        def chat(self, messages):
            raise RuntimeError("模型服务不可用")

    gen_dir = _build_gen(tmp_path)
    with pytest.warns(RuntimeWarning, match="Analyst Notes"):
        summary = _driver(tmp_path / "ws", llm=_BrokenNotesLLM()).run()
    assert summary.status == "completed"
    assert "Analyst Notes" not in (gen_dir / "report.md").read_text(
        encoding="utf-8")



def test_sealed_run_accepts_review_overlay_without_touching_seal(
        tmp_path: Path) -> None:
    """跨票回归(票 12↔13):封存写入 completed 后 overlay 即生效。"""
    gen_dir = _build_gen(tmp_path)
    seal = seal_run(gen_dir, now=2000.0)
    manifest_before = (gen_dir / "manifest.json").read_bytes()

    record = ReviewOverlay(gen_dir).append(
        reviewer="human/dr", finding_id="f-0001", field="severity",
        old_value="high", new_value="medium",
        rationale="实测触发需要物理接触,影响范围收窄",
        evidence_ids=["ev-000001"])
    assert record["seq"] == 1
    # 覆盖层不是封存机器工件:manifest seal 与其字节都不因 review 改变。
    assert (gen_dir / "manifest.json").read_bytes() == manifest_before
    assert "reviews.json" not in seal["artifact_digests"]
    projection = load_review_projection(gen_dir)
    assert projection["findings"][0]["machine"]["severity"] == "high"
    assert projection["findings"][0]["reviewed"]["severity"] == "medium"

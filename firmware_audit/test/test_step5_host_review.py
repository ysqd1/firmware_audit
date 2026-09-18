"""Ticket 13:封存机器结果上的追加式 Review Overlay。

覆盖 AC:追加记录字段完备(reviewer/时间/目标字段/旧值/新值/理由/Evidence
Reference)、未封存/未知目标/错误旧值/不存在 Evidence 的明确拒绝、只追加与
重放、冲突 review、sealed immutability(机器工件字节不变)与 machine/reviewed
并列的报告投影(Benchmark 默认 machine result、reviewed result 单独统计)。

全部走公开接口:真世代目录 + 人工构造的封存工件,不 mock 模块内部。
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from firmware_audit.step5_agent.host import review as review_module
from firmware_audit.step5_agent.host.generation import (
    create_generation,
    save_run_state,
)
from firmware_audit.step5_agent.host.review import (
    REVIEW_PROJECTION_SCHEMA_VERSION,
    REVIEW_SCHEMA_VERSION,
    ReviewError,
    ReviewOverlay,
    load_review_projection,
    project_review_report,
)
from firmware_audit.step5_agent.host.store import StoreError
from firmware_audit.step5_agent.host.verification import FINDING_SCHEMA_VERSION


def _write_evidence(gen_dir: Path, evidence_id: str, *, tree: str = "investigations",
                    candidate_id: str = "cand-0001") -> Path:
    path = gen_dir / tree / candidate_id / "evidence" / f"{evidence_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, "evidence_id": evidence_id}),
                    encoding="utf-8")
    return path


def _seal_run(tmp_path: Path, *, severity: str | None = "high",
              status: str | None = "completed") -> Path:
    """构造一个已封存世代:manifest + findings(含机器 severity)+ run_state。"""
    _name, gen_dir = create_generation(tmp_path, now=1000.0)
    _write_findings(gen_dir, severity=severity)
    _write_evidence(gen_dir, "ev-000001")
    if status is not None:
        save_run_state(gen_dir, status=status)
    return gen_dir


def _write_findings(gen_dir: Path, *, severity: str | None) -> None:
    finding: dict = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "finding_id": "f-0001",
        "candidate_id": "cand-0001",
        "investigation_id": "cand-0001",
        "claim_profile": "data_propagation",
        "admission_reason": "ready",
        "verdict": "confirmed",
        "claims": {},
        "evidence_references": [],
        "related_candidates": [],
    }
    if severity is not None:
        finding["severity"] = severity
    (gen_dir / "findings.json").write_text(
        json.dumps({"schema_version": FINDING_SCHEMA_VERSION,
                    "findings": [finding]}, ensure_ascii=False) + "\n",
        encoding="utf-8")


def _append(overlay: ReviewOverlay, **overrides) -> dict:
    """默认一条合法的 severity 复核决定;单测按需覆盖参数。"""
    payload = dict(
        reviewer="human/dr",
        finding_id="f-0001",
        field="severity",
        old_value="high",
        new_value="medium",
        rationale="已证实出栈前长度校验阻断越界写入,影响范围收窄",
        evidence_ids=["ev-000001"],
    )
    payload.update(overrides)
    return overlay.append(**payload)


# ---- S1 追加记录:字段完备、只追加、重放 ----


def test_append_writes_complete_record_and_replays(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    first = _append(overlay, now=2000.0)
    second = _append(overlay, old_value="medium", new_value="low",
                     rationale="补充复核确认触发条件需要物理接触", now=3000.0)

    assert first == {
        "seq": 1,
        "reviewer": "human/dr",
        "recorded_at": 2000.0,
        "target": {"artifact": "finding", "finding_id": "f-0001",
                   "field": "severity"},
        "old_value": "high",
        "new_value": "medium",
        "rationale": "已证实出栈前长度校验阻断越界写入,影响范围收窄",
        "evidence_ids": ["ev-000001"],
    }
    assert second["seq"] == 2
    assert second["new_value"] == "low"

    # 只追加:reviews 数组只增不改,既有记录内容原样保留。
    document = json.loads((gen_dir / "reviews.json").read_text(encoding="utf-8"))
    assert document["schema_version"] == REVIEW_SCHEMA_VERSION
    assert document["reviews"] == [first, second]

    # 重放:新实例从盘上权威记录恢复同一历史。
    replayed = ReviewOverlay(gen_dir).records()
    assert replayed == [first, second]


def test_overlay_absent_when_no_reviews(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    assert ReviewOverlay(gen_dir).records() == []
    assert not (gen_dir / "reviews.json").exists()


# ---- S2 拒绝矩阵:未封存、未知目标、错误旧值、不存在 Evidence ----


@pytest.mark.parametrize("status", ["running", "finalizing", "abandoned"])
def test_unsealed_run_rejected_and_untouched(tmp_path: Path, status: str) -> None:
    gen_dir = _seal_run(tmp_path, status=status)
    with pytest.raises(ReviewError, match="封存"):
        _append(ReviewOverlay(gen_dir))
    assert not (gen_dir / "reviews.json").exists()


def test_missing_run_state_rejected(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path, status=None)
    with pytest.raises(ReviewError, match="封存"):
        _append(ReviewOverlay(gen_dir))


def test_unknown_target_field_rejected(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    with pytest.raises(ReviewError, match="字段"):
        _append(overlay, field="verdict", new_value="rejected")
    with pytest.raises(ReviewError, match="字段"):
        _append(overlay, field="title")
    assert overlay.records() == []


def test_unknown_finding_rejected(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    with pytest.raises(ReviewError, match="f-0099"):
        _append(overlay, finding_id="f-0099")
    assert overlay.records() == []


def test_machine_field_missing_rejected(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path, severity=None)
    overlay = ReviewOverlay(gen_dir)
    with pytest.raises(ReviewError, match="severity"):
        _append(overlay)
    assert overlay.records() == []


def test_conflicting_old_value_rejected(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    _append(overlay)
    # 旧值停留在机器值(与已追加决定冲突)→ 拒绝。
    with pytest.raises(ReviewError, match="旧值"):
        _append(overlay, rationale="另一位复核者基于过期现场调整")
    # 链式旧值(等于当前有效值)→ 追加成功,历史保留两次决定。
    chained = _append(overlay, old_value="medium", new_value="low",
                      rationale="二次复核补充材料")
    assert chained["seq"] == 2
    history = ReviewOverlay(gen_dir).records()
    assert [record["new_value"] for record in history] == ["medium", "low"]


def test_stale_instance_rejects_via_disk_reread(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    stale = ReviewOverlay(gen_dir)
    fresh = ReviewOverlay(gen_dir)
    _append(fresh)
    # stale 实例的内存视图落在 fresh 追加之后;append 必须按盘上权威状态校验。
    with pytest.raises(ReviewError, match="旧值"):
        _append(stale, rationale="过期视图的并发追加")


@pytest.mark.parametrize("evidence_ids", [["ev-000009"], ["ev-1"], ["not-evidence"],
                                          [], ["ev-000001", "ev-000009"]])
def test_nonexistent_evidence_rejected(tmp_path: Path, evidence_ids: list) -> None:
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    with pytest.raises(ReviewError, match="[Ee]vidence"):
        _append(overlay, evidence_ids=evidence_ids)
    assert overlay.records() == []


def test_verification_tree_evidence_accepted(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    _write_evidence(gen_dir, "ev-000004", tree="verifications",
                    candidate_id="cand-0001")
    record = _append(ReviewOverlay(gen_dir), evidence_ids=["ev-000004"])
    assert record["evidence_ids"] == ["ev-000004"]


# ---- S3 severity 人工调整:理由与取值纪律 ----


@pytest.mark.parametrize("payload", [
    {"rationale": "  "},
    {"new_value": "extreme"},
    {"new_value": "high"},  # 与旧值相同,不构成修改
    {"reviewer": ""},
    {"old_value": "low"},  # 旧值失真同时也会被取值校验拦下
])
def test_invalid_adjustment_rejected(tmp_path: Path, payload: dict) -> None:
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    with pytest.raises(ReviewError):
        _append(overlay, **payload)
    assert overlay.records() == []


def test_severity_change_keeps_rationale_in_history(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    record = _append(ReviewOverlay(gen_dir))
    assert "长度校验" in record["rationale"]
    assert ReviewOverlay(gen_dir).records()[0]["rationale"] == record["rationale"]


# ---- S4 sealed immutability:追加 review 不改任何机器工件 ----


def test_machine_artifacts_unchanged_after_reviews(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    results_path = gen_dir / "verifications" / "cand-0001" / "results.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text('{"schema_version": 1}', encoding="utf-8")
    machine_paths = (
        gen_dir / "manifest.json", gen_dir / "run_state.json",
        gen_dir / "findings.json", results_path,
        gen_dir / "investigations" / "cand-0001" / "evidence" / "ev-000001.json",
    )
    before = {path: path.read_bytes() for path in machine_paths}
    overlay = ReviewOverlay(gen_dir)
    _append(overlay)
    _append(overlay, old_value="medium", new_value="low", rationale="继续下调")
    for path, payload in before.items():
        assert path.read_bytes() == payload, path
    # findings 的机器值不受 overlay 影响:重新读取仍是 high。
    machine = json.loads((gen_dir / "findings.json").read_text(encoding="utf-8"))
    assert machine["findings"][0]["severity"] == "high"


# ---- S5 报告投影:machine/reviewed 并列 + 多次 review 历史 ----


def test_projection_shows_machine_and_reviewed_side_by_side(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    first = _append(overlay, now=2000.0)
    second = _append(overlay, old_value="medium", new_value="low",
                     rationale="二次复核", now=3000.0)
    projection = load_review_projection(gen_dir)

    assert projection["schema_version"] == REVIEW_PROJECTION_SCHEMA_VERSION
    entry = projection["findings"][0]
    assert entry["machine"]["severity"] == "high"
    assert entry["reviewed"]["severity"] == "low"
    assert entry["history"] == [first, second]
    # Benchmark 默认 machine result:机器侧统计不被 overlay 改写。
    assert projection["summary"]["machine_severities"] == {"high": 1}
    assert projection["summary"]["reviewed_severities"] == {"low": 1}
    assert projection["summary"]["review_count"] == 2
    # 深拷贝隔离:修改投影的 reviewed 不得反噬 machine 事实。
    entry["reviewed"]["severity"] = "critical"
    assert entry["machine"]["severity"] == "high"


def test_projection_without_reviews_keeps_machine_only(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    projection = load_review_projection(gen_dir)
    entry = projection["findings"][0]
    assert entry["reviewed"] is None
    assert entry["history"] == []
    assert projection["summary"]["machine_severities"] == {"high": 1}
    assert projection["summary"]["reviewed_severities"] is None
    assert projection["summary"]["review_count"] == 0


def test_projection_is_pure_over_documents(tmp_path: Path) -> None:
    gen_dir = _seal_run(tmp_path)
    record = _append(ReviewOverlay(gen_dir))
    findings_document = json.loads(
        (gen_dir / "findings.json").read_text(encoding="utf-8"))
    projection = project_review_report(findings_document, [record])
    assert projection["findings"][0]["reviewed"]["severity"] == "medium"
    # 纯函数:入参文档不被就地修改。
    assert findings_document["findings"][0]["severity"] == "high"
    assert findings_document["findings"][0].get("reviewed") is None


# ---- S6 覆盖层自身的损坏拒绝与并发追加(重放安全) ----


@pytest.mark.parametrize("mutation", ["broken_json", "version", "seq_gap",
                                      "missing_field"])
def test_corrupt_overlay_refused_on_load(tmp_path: Path, mutation: str) -> None:
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    _append(overlay)
    _append(overlay, old_value="medium", new_value="low", rationale="二调")
    path = gen_dir / "reviews.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    records = document["reviews"]
    if mutation == "broken_json":
        path.write_text('{"schema_version": 1, "reviews": [', encoding="utf-8")
        with pytest.raises(StoreError):
            ReviewOverlay(gen_dir).records()
        return
    if mutation == "version":
        document["schema_version"] = 99
    elif mutation == "seq_gap":
        records[1]["seq"] = 3
    else:
        del records[1]["rationale"]
    path.write_text(json.dumps(document, ensure_ascii=False) + "\n",
                    encoding="utf-8")
    with pytest.raises(StoreError):
        ReviewOverlay(gen_dir).records()


def test_concurrent_append_loser_rejected_without_poisoning(
        tmp_path: Path, monkeypatch) -> None:
    """同一校验窗口的并发写者:输家明确拒绝,覆盖层保持完整可读。"""
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    _append(overlay)
    real_atomic_json = review_module.atomic_json

    def racing_publish(path, payload, **kwargs):
        real_atomic_json(path, payload, **kwargs)
        # 模拟并发赢家的重发布:基于同一旧状态(只有第 1 条)写入自己的决定,
        # 顶替掉刚落盘的本记录。
        winner = deepcopy(payload["reviews"][-1])
        winner["reviewer"] = "codex/opponent"
        real_atomic_json(path, {
            "schema_version": payload["schema_version"],
            "reviews": payload["reviews"][:-1] + [winner],
        })
        return None

    monkeypatch.setattr(review_module, "atomic_json", racing_publish)
    with pytest.raises(ReviewError, match="并发"):
        _append(overlay, old_value="medium", new_value="low", rationale="输家")
    monkeypatch.undo()
    # 覆盖层没有被毒化:仍可完整重放,seq 连续,只剩赢家的记录。
    surviving = ReviewOverlay(gen_dir).records()
    assert [record["seq"] for record in surviving] == [1, 2]
    assert surviving[-1]["reviewer"] == "codex/opponent"
    assert surviving[-1]["new_value"] == "low"


def test_legitimate_successor_append_keeps_earlier_record(
        tmp_path: Path, monkeypatch) -> None:
    """本记录落盘后被后来者合法追加:写后复读不得误拒已成功的记录。"""
    gen_dir = _seal_run(tmp_path)
    overlay = ReviewOverlay(gen_dir)
    real_atomic_json = review_module.atomic_json

    def chained_publish(path, payload, **kwargs):
        real_atomic_json(path, payload, **kwargs)
        successor = deepcopy(payload["reviews"][-1])
        successor["seq"] = successor["seq"] + 1
        successor["reviewer"] = "codex/successor"
        real_atomic_json(path, {
            "schema_version": payload["schema_version"],
            "reviews": payload["reviews"] + [successor],
        })
        return None

    monkeypatch.setattr(review_module, "atomic_json", chained_publish)
    record = _append(overlay)
    monkeypatch.undo()
    surviving = ReviewOverlay(gen_dir).records()
    assert [item["seq"] for item in surviving] == [1, 2]
    assert surviving[0] == record
    assert surviving[1]["reviewer"] == "codex/successor"

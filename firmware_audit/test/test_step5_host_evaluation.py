"""Ticket 15:封存后的 Benchmark 对照评估。

覆盖 AC:GT 隔离(边界测试证明 Agent 运行输入与快照不含 Ground Truth 路径
或内容)、未封存运行拒绝、确定性阶段只生成候选映射(语义措辞不同仍可对应,
不输出 full/partial/miss)、Codex reviewer 材料全量、字段级量表与
full/partial/miss 由 Host 派生、每 GT 唯一 primary 与重复不重复计分、
unmatched 三分类与 uncertain 不进确定指标、评审工件审计字段与
machine/reviewed 指标并列、评审结果重放审计。

全部走公开接口:真世代目录 + 真 seal_run 封存 + 注入评审模型回复,
不 mock 模块内部。
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from firmware_audit.step5_agent.host.evaluation import (
    CANDIDATE_MAP_SCHEMA_VERSION,
    EVALUATION_REVIEW_SCHEMA_VERSION,
    EVALUATION_REVIEW_SYSTEM_PROMPT,
    EvaluationError,
    canonical_json,
    compute_metrics,
    evaluate_run,
    generate_candidate_map,
    load_evaluation_review,
    load_ground_truth,
    normalize_benchmark_address,
    normalize_benchmark_component,
    normalize_benchmark_path,
    normalize_benchmark_symbol,
)
from firmware_audit.step5_agent.host.generation import (
    create_generation,
    load_run_state,
    read_manifest,
    save_run_state,
)
from firmware_audit.step5_agent.host.reporting import seal_run
from firmware_audit.step5_agent.host.review import ReviewOverlay
from firmware_audit.step5_agent.host.severity import SEVERITY_LEVELS
from firmware_audit.step5_agent.host.budget import (
    BUDGET_SCHEMA_VERSION,
    resolve_effective_config,
)
from firmware_audit.step5_agent.host.candidates import (
    CANDIDATE_STORE_SCHEMA_VERSION,
)
from firmware_audit.step5_agent.host.claims import required_claims
from firmware_audit.step5_agent.host.verification import (
    CASE_SCHEMA_VERSION,
    FINDING_SCHEMA_VERSION,
    RESULTS_SCHEMA_VERSION,
)

# ---- 夹具:一个已封存的完整世代 + 独立 Ground Truth 根 ----

GENERIC_CLAIMS = tuple(required_claims("generic"))


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def _evidence_payload(evidence_id: str, *, candidate_id: str,
                      arguments: dict, summary: str) -> dict:
    observation = summary
    return {
        "schema_version": 1,
        "evidence_id": evidence_id,
        "tool": "read_file",
        "arguments": arguments,
        "summary": summary,
        "location": f"investigations/{candidate_id}/evidence/{evidence_id}.json",
        "digest": hashlib.sha256(observation.encode("utf-8")).hexdigest(),
        "candidate_id": candidate_id,
        "investigation_id": candidate_id,
        "sequence": 1,
        "observation": observation,
        "tool_result": {"ok": True, "text": observation, "raw": observation,
                        "data": None, "error": None, "elapsed": 0.1},
    }


def _claims_document(observed: str) -> dict:
    return {
        name: {"judgment": "supported", "observed": observed,
               "evidence_ids": ["ev-000001"], "method": "static_analysis"}
        for name in GENERIC_CLAIMS
    }


def _investigation_state(candidate_id: str, disposition: str) -> dict:
    return {
        "schema_version": 1, "last_event_seq": 1,
        "state": {
            "candidate": {"candidate_id": candidate_id},
            "investigation": {
                "investigation_id": candidate_id,
                "candidate_id": candidate_id,
                "claim_profile": "generic",
                "lifecycle_status": "finished",
                "disposition": disposition,
                "stop_reason": "completed",
            },
            "runtime": {},
        },
    }


def _case_document(candidate_id: str, admission: str) -> dict:
    return {
        "schema_version": CASE_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "investigation_id": candidate_id,
        "claim_profile": "generic",
        "admission_reason": admission,
        "claims": {name: {"status": "supported", "evidence_ids": ["ev-000001"]}
                   for name in GENERIC_CLAIMS},
        "evidence_references": [],
        "pending_claims": [],
        "blocking_gaps": [],
    }


def _results_document(candidate_id: str, verdict: str,
                      finding_id: str | None) -> dict:
    payload = {
        "schema_version": RESULTS_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "investigation_id": candidate_id,
        "claim_profile": "generic",
        "admission_reason": "ready",
        "verdict": verdict,
        "stop_reason": "completed",
        "claim_results": _claims_document(f"{candidate_id} 观测"),
        "decisive_refuted": [],
        "unsupported": [],
        "evidence_references": [],
        "related_candidates": [],
    }
    if finding_id is not None:
        payload["finding_id"] = finding_id
    return payload


def _finding_document(finding_id: str, candidate_id: str, severity: str) -> dict:
    return {
        "schema_version": FINDING_SCHEMA_VERSION,
        "finding_id": finding_id,
        "candidate_id": candidate_id,
        "investigation_id": candidate_id,
        "claim_profile": "generic",
        "admission_reason": "ready",
        "verdict": "confirmed",
        "severity": severity,
        "severity_basis": {"impact_scope": "component",
                           "trigger_condition": "limited",
                           "mitigation_effect": None, "incomplete": False},
        "claims": _claims_document(f"{candidate_id} 观测"),
        "evidence_references": [],
        "related_candidates": [],
    }


def _store_document() -> dict:
    def record(candidate_id: str, target: str, *, selected: bool,
               disposition: str | None, kind: str = "signal") -> dict:
        return {
            "candidate_id": candidate_id, "kind": kind, "target": target,
            "signal": "待查信号", "claim_profile": "generic",
            "source": "recon", "next_action": "继续取证",
            "initial_evidence": "ev-000001",
            "queue": {"queue": "signal" if kind == "signal" else "coverage",
                      "rank": 0, "selected": selected},
            "disposition": disposition, "priority": {"total": 5},
        }

    return {
        "schema_version": CANDIDATE_STORE_SCHEMA_VERSION,
        "survey": {"attack_surface": [{"area": "etc/ 配置"}],
                   "checked_scope": ["extracted/etc/*"],
                   "coverage_gaps": []},
        "candidates": [
            record("cand-0001", "extracted/etc/shadow", selected=True,
                   disposition="confirmed"),
            record("cand-0002", "extracted/unitree/bin/service",
                   selected=True, disposition="inconclusive"),
            record("cand-0003", "extracted/usr/lib/libhttpd.so",
                   selected=True, disposition="confirmed"),
            record("cand-0004", "extracted/etc/shadow", selected=True,
                   disposition="confirmed"),
            record("cand-0005", "extracted/opt/vendor", selected=False,
                   disposition="not_started", kind="coverage"),
        ],
    }


_EVIDENCE = (
    ("ev-000001", "cand-0001", {"path": "extracted/etc/shadow"},
     "弱哈希命中 extracted/etc/shadow"),
    ("ev-000002", "cand-0002", {"path": "extracted/unitree/bin/service"},
     "服务解析路径 extracted/unitree/bin/service"),
    ("ev-000003", "cand-0003",
     {"path": "extracted/usr/lib/libhttpd.so", "func_name": "do_overflow"},
     "溢出点 do_overflow"),
    ("ev-000004", "cand-0004", {"path": "extracted/etc/shadow"},
     "同目标复核 extracted/etc/shadow"),
)


def _build_sealed_gen(
    tmp_path: Path, *, closed_investigation: bool = False,
) -> Path:
    """构造处理责任收束并真正 seal_run 封存的世代。"""
    _name, gen_dir = create_generation(tmp_path / "ws", now=1000.0)
    save_run_state(gen_dir, status="finalizing", phase="accounting",
                   stop_reason="processing_complete")
    config = resolve_effective_config(explicit=None, env={}, profile=None)
    _write_json(gen_dir / "config.json", {"schema_version": 1, **config})
    _write_json(gen_dir / "budget.json", {
        "schema_version": BUDGET_SCHEMA_VERSION,
        "llm_calls": 12, "prompt_tokens": 3400, "completion_tokens": 800,
        "validated_rounds": 10, "tool_attempts": 30,
        "logical_tool_calls": 26, "active_seconds": 120.5,
    })
    _write_json(gen_dir / "candidates.json", _store_document())

    dispositions = {"cand-0001": "confirmed", "cand-0002": "inconclusive",
                    "cand-0003": "confirmed", "cand-0004": "confirmed"}
    if closed_investigation:
        dispositions["cand-0002"] = "closed"
    for candidate_id, disposition in dispositions.items():
        _write_json(gen_dir / "investigations" / candidate_id / "state.json",
                    _investigation_state(candidate_id, disposition))
    for evidence_id, candidate_id, arguments, summary in _EVIDENCE:
        _write_json(
            gen_dir / "investigations" / candidate_id / "evidence"
            / f"{evidence_id}.json",
            _evidence_payload(evidence_id, candidate_id=candidate_id,
                              arguments=arguments, summary=summary))

    for candidate_id, admission in (("cand-0001", "ready"),
                                    ("cand-0002", "evidence_gap"),
                                    ("cand-0003", "ready"),
                                    ("cand-0004", "ready")):
        _write_json(gen_dir / "verifications" / candidate_id / "case.json",
                    _case_document(candidate_id, admission))
    verdicts = {"cand-0001": "confirmed", "cand-0002": "inconclusive",
                "cand-0003": "confirmed", "cand-0004": "confirmed"}
    finding_ids = {"cand-0001": "f-0001", "cand-0003": "f-0002",
                   "cand-0004": "f-0003"}
    for candidate_id, verdict in verdicts.items():
        _write_json(
            gen_dir / "verifications" / candidate_id / "results.json",
            _results_document(candidate_id, verdict,
                              finding_ids.get(candidate_id)))
    if closed_investigation:
        (gen_dir / "verifications" / "cand-0002" / "results.json").unlink()

    findings = [
        _finding_document("f-0001", "cand-0001", "high"),
        _finding_document("f-0002", "cand-0003", "critical"),
        _finding_document("f-0003", "cand-0004", "medium"),
    ]
    _write_json(gen_dir / "findings.json",
                {"schema_version": FINDING_SCHEMA_VERSION,
                 "findings": findings})
    seal_run(gen_dir, now=2000.0)
    return gen_dir


def _gt_document() -> dict:
    return {
        "schema_version": 1,
        "case_id": "case-001",
        "items": [
            {"gt_id": "gt-0001", "title": "弱口令哈希",
             "root_cause": {"path": "etc/shadow",
                            "mechanism": "默认弱哈希算法存储口令"},
             "entry_point": "etc/shadow",
             "key_relations": ["登录认证", "crypt 比较"],
             "impact": "本地口令可离线破解"},
            {"gt_id": "gt-0002", "title": "服务请求解析溢出",
             "root_cause": {"path": "unitree/bin/service",
                            "symbol": "parse_request"},
             "entry_point": "tcp/9000",
             "key_relations": ["recv", "parse_request", "strcpy"],
             "impact": "远程代码执行"},
            {"gt_id": "gt-0003", "title": "HTTP 服务溢出",
             "root_cause": {"path": "/usr/lib/libhttpd.so",
                            "symbol": "DoOverflow"},
             "entry_point": "http/80",
             "key_relations": ["read_request", "DoOverflow", "memcpy"],
             "impact": "远程代码执行"},
        ],
    }


def _write_gt(tmp_path: Path, document: dict | None = None) -> Path:
    path = tmp_path / "gt-root" / "ground_truth.json"
    _write_json(path, document if document is not None else _gt_document())
    return path


# ---- 评审模型替身 ----


def _field(agreement: str = "consistent") -> dict:
    return {"agreement": agreement, "gt_quote": "GT 原文引用",
            "machine_quote": "机器材料原文引用", "rationale": "字段判断依据"}


def _fields(**overrides: str) -> dict:
    values = {"root_cause": "consistent", "trigger_or_entry": "consistent",
              "key_relations": "consistent", "impact": "consistent",
              "machine_disposition": "consistent"}
    values.update(overrides)
    return {name: _field(agreement) for name, agreement in values.items()}


def _review_reply() -> dict:
    return {
        "matches": [
            {"gt_id": "gt-0001", "primary": {"kind": "finding", "id": "f-0001"},
             "duplicates": [{"kind": "finding", "id": "f-0003"}],
             "fields": _fields(), "rationale": "同一弱哈希问题"},
            {"gt_id": "gt-0002",
             "primary": {"kind": "investigation", "id": "cand-0002"},
             "duplicates": [],
             "fields": _fields(key_relations="inconsistent",
                               impact="not_assessed"),
             "rationale": "调查同一问题但链路与影响有缺口"},
            {"gt_id": "gt-0003", "primary": {"kind": "finding", "id": "f-0002"},
             "duplicates": [], "fields": _fields(), "rationale": "同一溢出问题"},
        ],
        "unmatched": [],
    }


class ScriptedReviewer:
    """语义评审替身:固定回复 + 捕获材料;鸭子类型 .model 与 .chat。"""

    model = "codex-evaluator-x"

    def __init__(self, reply: dict | None = None, *, error: Exception | None = None):
        self.reply = json.dumps(
            reply if reply is not None else _review_reply(),
            ensure_ascii=False)
        self.error = error
        self.messages: list[dict] | None = None
        self.usage = {"prompt_tokens": 100, "completion_tokens": 40}

    def chat(self, messages: list[dict]):
        self.messages = messages
        if self.error is not None:
            raise self.error
        return self.reply, dict(self.usage)


class _ModellessReviewer(ScriptedReviewer):
    """无法确定模型版本的评审替身(getattr 得到 None)。"""

    model = None


# ---- S1 确定性规范化 ----


def test_normalize_benchmark_path_strips_tool_and_nesting_prefixes() -> None:
    assert normalize_benchmark_path(
        "foo.tar.xz.extracted/0/extracted/etc/Shadow") == "etc/shadow"
    assert normalize_benchmark_path("extracted/squashfs-root/etc/Passwd") == \
        "etc/passwd"
    assert normalize_benchmark_path("/etc//passwd/") == "etc/passwd"
    assert normalize_benchmark_path("analysis/unitree/x.c") == "unitree/x.c"


def test_normalize_benchmark_address_component_symbol_aliases() -> None:
    assert normalize_benchmark_address("0x0040_A1B2") == "40a1b2"
    assert normalize_benchmark_address("0x0") == "0"
    assert normalize_benchmark_component("/usr/lib/libssl.so.1.1") == "ssl"
    assert normalize_benchmark_component("OpenSSL-3.0.2") == "openssl"
    assert normalize_benchmark_symbol("int auth::do_Login(void*)") == "dologin"
    assert normalize_benchmark_symbol("do-login") == "dologin"
    assert normalize_benchmark_symbol("*DoOverflow") == "dooverflow"
    with pytest.raises(EvaluationError):
        normalize_benchmark_address("not-hex")


def test_load_ground_truth_accepts_valid_document(tmp_path: Path) -> None:
    path = _write_gt(tmp_path)
    document = load_ground_truth(path)
    assert document["case_id"] == "case-001"
    assert [item["gt_id"] for item in document["items"]] == [
        "gt-0001", "gt-0002", "gt-0003"]


def test_load_ground_truth_rejects_invalid_documents(
        tmp_path: Path) -> None:
    base = _gt_document()
    mutations = {
        "schema": {"schema_version": 2},
        "no_items": {"items": []},
        "dup_gt": {"items": [base["items"][0], dict(base["items"][0])]},
        "unknown_key": {"items": [{**base["items"][0], "answer": "泄露"}]},
        "bad_gt_id": {"items": [{**base["items"][0], "gt_id": "item-1"}]},
        "empty_entry": {"items": [{**base["items"][0], "entry_point": ""}]},
        "no_root_cause": {"items": [{**base["items"][0],
                                     "root_cause": {}}]},
        "bad_address": {"items": [{**base["items"][0], "root_cause": {
            "address": "zzz"}}]},
        "bad_relations": {"items": [{**base["items"][0],
                                     "key_relations": [""]}]},
    }
    for index, mutation in enumerate(mutations.values()):
        document = deepcopy(base)
        document.update(mutation)
        path = tmp_path / f"gt-{index}.json"
        _write_json(path, document)
        with pytest.raises(EvaluationError):
            load_ground_truth(path)
    with pytest.raises(EvaluationError):
        load_ground_truth(tmp_path / "missing.json")


# ---- S2 封存门(AC2) ----


def test_evaluation_rejects_unsealed_run(tmp_path: Path) -> None:
    _name, gen_dir = create_generation(tmp_path / "ws", now=1000.0)
    _write_json(gen_dir / "candidates.json", _store_document())
    for status in ("running", "finalizing"):
        save_run_state(gen_dir, status=status)
        with pytest.raises(EvaluationError, match="未封存"):
            generate_candidate_map(gen_dir, _gt_document())
    (gen_dir / "run_state.json").unlink()
    with pytest.raises(EvaluationError, match="未封存"):
        generate_candidate_map(gen_dir, _gt_document())
    sealed = _build_sealed_gen(tmp_path / "ws2")
    # 对照:封存后同一调用可用(完整性由其余测试覆盖)。
    assert generate_candidate_map(sealed, _gt_document())["generation"]


# ---- S3 确定性候选映射(AC3) ----


def test_candidate_map_builds_deterministic_mapping_without_semantic_labels(
        tmp_path: Path) -> None:
    gen_dir = _build_sealed_gen(tmp_path)
    mapping = generate_candidate_map(gen_dir, _gt_document())
    assert mapping["schema_version"] == CANDIDATE_MAP_SCHEMA_VERSION
    assert mapping["generation"] == "gen-0001"

    by_gt = {entry["gt_id"]: entry["matches"]
             for entry in mapping["candidates"]}
    # 路径信号:GT 等待 etc/shadow,机器工具路径 extracted/etc/shadow。
    assert any(match["id"] == "f-0001" and "path:etc/shadow" in match["signals"]
               for match in by_gt["gt-0001"])
    # 语义措辞不同仍可对应:GT /usr/lib/libhttpd.so + DoOverflow 与机器
    # extracted/usr/lib/libhttpd.so + do_overflow 在规范化后相交。
    f0002 = next(match for match in by_gt["gt-0003"]
                 if match["id"] == "f-0002")
    assert "symbol:dooverflow" in f0002["signals"]
    assert "path:usr/lib/libhttpd.so" in f0002["signals"]
    # inconclusive 调查按 candidate_id 进入候选。
    assert any(match["kind"] == "investigation"
               and match["id"] == "cand-0002"
               for match in by_gt["gt-0002"])

    # 确定性阶段不输出任何语义标签:match 结构只有 kind/id/signals。
    dumped = json.dumps(mapping, ensure_ascii=False)
    for label in ("full", "partial", "miss"):
        assert f'"{label}"' not in dumped
    for entry in mapping["candidates"]:
        for match in entry["matches"]:
            assert set(match) == {"kind", "id", "signals"}

    first = (gen_dir / "evaluation" / "candidates.json").read_bytes()
    generate_candidate_map(gen_dir, _gt_document())
    assert (gen_dir / "evaluation" / "candidates.json").read_bytes() == first


def test_candidate_map_lists_unmatched_ground_truth(tmp_path: Path) -> None:
    gen_dir = _build_sealed_gen(tmp_path)
    document = _gt_document()
    document["items"].append({
        "gt_id": "gt-0004", "title": "机器未触及的面",
        "root_cause": {"path": "nowhere/else.bin", "mechanism": "不相关"},
        "entry_point": "nowhere/else.bin",
        "key_relations": [], "impact": "无",
    })
    mapping = generate_candidate_map(gen_dir, document)
    assert mapping["unmatched_ground_truth"] == ["gt-0004"]


# ---- S4 语义裁定(AC4-AC8) ----


def test_evaluate_run_writes_auditable_review(tmp_path: Path) -> None:
    gen_dir = _build_sealed_gen(tmp_path)
    gt_path = _write_gt(tmp_path)
    reviewer = ScriptedReviewer()
    artifact = evaluate_run(gen_dir, gt_path, reviewer, now=3000.0)

    assert artifact["schema_version"] == EVALUATION_REVIEW_SCHEMA_VERSION
    assert artifact["generation"] == "gen-0001"
    assert artifact["created_at"] == 3000.0
    assert artifact["model"] == "codex-evaluator-x"
    # 固定提示与输入 digest(AC8)。
    assert artifact["reviewer_prompt"] == EVALUATION_REVIEW_SYSTEM_PROMPT
    assert artifact["reviewer_prompt_sha256"] == hashlib.sha256(
        EVALUATION_REVIEW_SYSTEM_PROMPT.encode("utf-8")).hexdigest()
    assert artifact["inputs"]["ground_truth"] == {
        "source": "ground_truth.json", "case_id": "case-001",
        "sha256": hashlib.sha256(gt_path.read_bytes()).hexdigest(),
    }
    seal = read_manifest(gen_dir)["seal"]
    assert artifact["inputs"]["machine"]["report_sha256"] == \
        seal["report_sha256"]
    assert artifact["inputs"]["machine"]["artifact_digests"] == \
        seal["artifact_digests"]
    assert artifact["inputs"]["candidate_map_sha256"] == hashlib.sha256(
        canonical_json(artifact["candidate_map"]).encode("utf-8")).hexdigest()
    assert artifact["usage"] == {"prompt_tokens": 100, "completion_tokens": 40}
    # 运行面统计(ADR-0012 L61:未决调查与资源消耗)。
    assert artifact["run"]["investigation_dispositions"] == {
        "confirmed": 3, "inconclusive": 1, "not_started": 1}
    assert artifact["run"]["resources"]["llm_calls"] == 12

    # 量表派生:full ⟺ confirmed Finding + 三决定字段一致;
    # inconclusive 调查 primary → partial。
    results = {match["gt_id"]: match["result"] for match in artifact["matches"]}
    assert results == {"gt-0001": "full", "gt-0002": "partial",
                       "gt-0003": "full"}
    gt1 = artifact["matches"][0]
    assert gt1["primary"] == {"kind": "finding", "id": "f-0001"}
    assert gt1["duplicates"] == [{"kind": "finding", "id": "f-0003"}]
    assert set(gt1["fields"]) == {"root_cause", "trigger_or_entry",
                                  "key_relations", "impact",
                                  "machine_disposition"}

    # machine/reviewed 指标并列(无覆盖层时 reviewed=None)。
    assert artifact["metrics"]["reviewed"] is None
    machine = artifact["metrics"]["machine"]
    assert machine["results"] == {"full": 2, "partial": 1, "miss": 0}
    assert machine["unmatched"] == {"novel_valid": 0, "unsupported": 0,
                                    "uncertain": 0}
    assert machine["definitive"] == {"full": 2, "partial": 1, "miss": 0,
                                     "unmatched_novel_valid": 0,
                                     "unmatched_unsupported": 0}
    assert machine["severity_distribution"] == {"high": 1, "critical": 1,
                                                "medium": 1}
    assert machine["confirmed_findings"] == 3

    # 落盘与材料包(AC4)。
    assert (gen_dir / "evaluation" / "evaluation_review.json").exists()
    system, user = reviewer.messages
    assert system["content"] == EVALUATION_REVIEW_SYSTEM_PROMPT
    materials = json.loads(user["content"])
    assert set(materials) == {"ground_truth", "candidates", "findings",
                              "investigations", "verification_cases",
                              "evidence", "candidate_map"}
    assert materials["ground_truth"]["case_id"] == "case-001"
    assert any(item["candidate_id"] == "cand-0002"
               and item["disposition"] == "inconclusive"
               for item in materials["investigations"])
    assert materials["verification_cases"]
    assert any(item["evidence_id"] == "ev-000001"
               for item in materials["evidence"])


def test_reviewed_projection_reported_separately(tmp_path: Path) -> None:
    gen_dir = _build_sealed_gen(tmp_path)
    ReviewOverlay(gen_dir).append(
        reviewer="human/dr", finding_id="f-0003", field="severity",
        old_value="medium", new_value="low", rationale="实际影响有限",
        evidence_ids=["ev-000004"])
    reviewer = ScriptedReviewer()
    artifact = evaluate_run(gen_dir, _write_gt(tmp_path), reviewer,
                            now=3000.0)
    assert artifact["metrics"]["machine"]["severity_distribution"] == {
        "high": 1, "critical": 1, "medium": 1}
    assert artifact["metrics"]["reviewed"]["severity_distribution"] == {
        "high": 1, "critical": 1, "low": 1}


def test_evaluate_run_rejects_unsealed_and_repeat_and_modelless(
        tmp_path: Path) -> None:
    _name, gen_dir = create_generation(tmp_path / "ws", now=1000.0)
    with pytest.raises(EvaluationError, match="未封存"):
        evaluate_run(gen_dir, _write_gt(tmp_path), ScriptedReviewer())

    sealed = _build_sealed_gen(tmp_path / "ws2")
    gt_path = _write_gt(tmp_path / "gt2")
    evaluate_run(sealed, gt_path, ScriptedReviewer(), now=3000.0)
    with pytest.raises(EvaluationError, match="已存在"):
        evaluate_run(sealed, gt_path, ScriptedReviewer())

    fresh = _build_sealed_gen(tmp_path / "ws3")
    with pytest.raises(EvaluationError, match="模型版本"):
        evaluate_run(fresh, gt_path, _ModellessReviewer())
    assert not (fresh / "evaluation" / "candidates.json").exists()


def test_service_failure_writes_no_review(tmp_path: Path) -> None:
    gen_dir = _build_sealed_gen(tmp_path)
    gt_path = _write_gt(tmp_path)
    reviewer = ScriptedReviewer(error=RuntimeError("service down"))
    with pytest.raises(EvaluationError, match="评审模型调用失败"):
        evaluate_run(gen_dir, gt_path, reviewer)
    assert not (gen_dir / "evaluation" / "evaluation_review.json").exists()
    # 确定性候选映射是有效产物,失败后保留供排查与重算。
    assert (gen_dir / "evaluation" / "candidates.json").exists()


def test_evaluate_run_rejects_invalid_review_replies(tmp_path: Path) -> None:
    def drop_match(reply: dict) -> dict:
        reply["matches"] = reply["matches"][:2]
        return reply

    def duplicate_gt(reply: dict) -> dict:
        reply["matches"].append(deepcopy(reply["matches"][0]))
        return reply

    def unknown_finding(reply: dict) -> dict:
        reply["matches"][0]["primary"] = {"kind": "finding", "id": "f-9999"}
        return reply

    # closed 调查不能作 primary 的用例见
    # test_closed_investigation_cannot_be_primary(需要 closed 夹具)。

    def miss_with_duplicates(reply: dict) -> dict:
        reply["matches"][2]["primary"] = None
        reply["matches"][2]["duplicates"] = [
            {"kind": "finding", "id": "f-0003"}]
        reply["matches"][0]["duplicates"] = []
        return reply

    def duplicate_of_primary(reply: dict) -> dict:
        reply["matches"][2]["duplicates"] = [
            {"kind": "finding", "id": "f-0001"}]
        return reply

    def unmatched_primary(reply: dict) -> dict:
        reply["matches"][0]["duplicates"] = []
        reply["unmatched"] = [{
            "kind": "finding", "id": "f-0001",
            "classification": "novel_valid", "machine_quote": "x",
            "rationale": "r"}]
        return reply

    def missing_classification(reply: dict) -> dict:
        reply["matches"][0]["duplicates"] = []
        return reply

    def bad_classification(reply: dict) -> dict:
        reply["unmatched"] = [{
            "kind": "finding", "id": "f-0003", "classification": "maybe",
            "machine_quote": "x", "rationale": "r"}]
        reply["matches"][0]["duplicates"] = []
        return reply

    def bad_agreement(reply: dict) -> dict:
        reply["matches"][0]["fields"]["root_cause"] = _field("maybe")
        return reply

    def empty_rationale(reply: dict) -> dict:
        reply["matches"][0]["fields"]["root_cause"] = _field("consistent")
        reply["matches"][0]["fields"]["root_cause"]["rationale"] = " "
        return reply

    def unknown_key(reply: dict) -> dict:
        reply["matches"][0]["verdict"] = "full"
        return reply

    def not_json(reply: dict) -> dict:
        return "抱歉,我无法输出 JSON"  # type: ignore[return-value]

    cases = {
        "drop_match": drop_match, "duplicate_gt": duplicate_gt,
        "unknown_finding": unknown_finding,
        "miss_with_duplicates": miss_with_duplicates,
        "duplicate_of_primary": duplicate_of_primary,
        "unmatched_primary": unmatched_primary,
        "missing_classification": missing_classification,
        "bad_classification": bad_classification, "bad_agreement": bad_agreement,
        "empty_rationale": empty_rationale, "unknown_key": unknown_key,
        "not_json": not_json,
    }
    for index, (name, mutate) in enumerate(cases.items()):
        ws = tmp_path / f"case-{index}"
        gen_dir = _build_sealed_gen(ws)
        gt_path = _write_gt(ws)
        mutated = mutate(deepcopy(_review_reply()))
        if name == "not_json":
            reviewer = ScriptedReviewer()
            reviewer.reply = mutated  # type: ignore[assignment]
        else:
            reviewer = ScriptedReviewer(mutated)
        with pytest.raises(EvaluationError) as excinfo:
            evaluate_run(gen_dir, gt_path, reviewer)
        assert not (gen_dir / "evaluation" / "evaluation_review.json").exists(), \
            name


def test_closed_investigation_cannot_be_primary(tmp_path: Path) -> None:
    gen_dir = _build_sealed_gen(tmp_path, closed_investigation=True)
    reply = _review_reply()
    with pytest.raises(EvaluationError, match="inconclusive"):
        evaluate_run(gen_dir, _write_gt(tmp_path), ScriptedReviewer(reply))


# ---- S5 指标纯函数(AC6/AC7) ----


def test_compute_metrics_primary_only_and_uncertain_excluded() -> None:
    matches = [
        {"gt_id": "gt-0001", "result": "full",
         "primary": {"kind": "finding", "id": "f-0001"}, "duplicates": [],
         "fields": {}, "rationale": "r"},
        {"gt_id": "gt-0002", "result": "miss", "primary": None,
         "duplicates": [], "fields": {}, "rationale": "r"},
    ]
    unmatched = [
        {"kind": "finding", "id": "f-0002", "classification": "uncertain",
         "machine_quote": None, "rationale": "r"},
        {"kind": "finding", "id": "f-0003", "classification": "novel_valid",
         "machine_quote": None, "rationale": "r"},
    ]
    metrics = compute_metrics(
        2, matches, unmatched,
        machine_severities={"high": 3}, reviewed_severities=None)
    assert metrics["machine"]["results"] == {"full": 1, "partial": 0,
                                             "miss": 1}
    assert metrics["machine"]["unmatched"]["uncertain"] == 1
    # uncertain 不进入确定指标。
    assert metrics["machine"]["definitive"] == {
        "full": 1, "partial": 0, "miss": 1,
        "unmatched_novel_valid": 1, "unmatched_unsupported": 0}


# ---- S6 重放审计(AC9) ----


def test_replay_audit_passes_and_verifies_ground_truth(
        tmp_path: Path) -> None:
    gen_dir = _build_sealed_gen(tmp_path)
    gt_path = _write_gt(tmp_path)
    evaluate_run(gen_dir, gt_path, ScriptedReviewer(), now=3000.0)
    artifact = load_evaluation_review(gen_dir)
    assert artifact["generation"] == "gen-0001"
    provided = load_evaluation_review(gen_dir, gt_path)
    assert provided["inputs"]["ground_truth"]["case_id"] == "case-001"


def test_replay_audit_detects_tampering(tmp_path: Path) -> None:
    def mutate_result(artifact: dict) -> None:
        artifact["matches"][0]["result"] = "miss"

    def mutate_prompt(artifact: dict) -> None:
        artifact["reviewer_prompt"] += "\n被篡改"

    def mutate_prompt_digest(artifact: dict) -> None:
        artifact["reviewer_prompt_sha256"] = "0" * 64

    def mutate_machine(artifact: dict) -> None:
        artifact["inputs"]["machine"]["artifact_digests"] = {"x": "0"}

    def mutate_map(artifact: dict) -> None:
        artifact["candidate_map"]["candidates"] = []

    def drop_match(artifact: dict) -> None:
        artifact["matches"] = artifact["matches"][:2]

    cases = (mutate_result, mutate_prompt, mutate_prompt_digest,
             mutate_machine, mutate_map, drop_match)
    for index, mutate in enumerate(cases):
        ws = tmp_path / f"case-{index}"
        gen_dir = _build_sealed_gen(ws)
        evaluate_run(gen_dir, _write_gt(ws), ScriptedReviewer(), now=3000.0)
        path = gen_dir / "evaluation" / "evaluation_review.json"
        artifact = json.loads(path.read_text(encoding="utf-8"))
        mutate(artifact)
        _write_json(path, artifact)
        with pytest.raises(EvaluationError, match="审计失败"):
            load_evaluation_review(gen_dir)


def test_replay_audit_survives_post_evaluation_overlay(tmp_path: Path) -> None:
    """覆盖层是追加式的:评审之后合法追加 severity review 不推翻审计。

    reviewed 指标的 severity 快照锚定评审时刻,审计只做内部一致性校验,
    不对"当前"投影复算(否则合法追加会被误判为篡改)。
    """
    gen_dir = _build_sealed_gen(tmp_path)
    gt_path = _write_gt(tmp_path)
    evaluate_run(gen_dir, gt_path, ScriptedReviewer(), now=3000.0)
    ReviewOverlay(gen_dir).append(
        reviewer="human/dr", finding_id="f-0003", field="severity",
        old_value="medium", new_value="low", rationale="评审后人工复核",
        evidence_ids=["ev-000004"])
    # 审计通过,且工件保住评审时刻的快照(当时还没有覆盖记录)。
    artifact = load_evaluation_review(gen_dir)
    assert artifact["metrics"]["reviewed"] is None


def test_replay_audit_detects_machine_and_gt_mismatch(
        tmp_path: Path) -> None:
    gen_dir = _build_sealed_gen(tmp_path)
    gt_path = _write_gt(tmp_path)
    evaluate_run(gen_dir, gt_path, ScriptedReviewer(), now=3000.0)
    # 封存机器工件被改动 → 机器 digest 与 manifest seal 不一致。
    findings_path = gen_dir / "findings.json"
    document = json.loads(findings_path.read_text(encoding="utf-8"))
    document["findings"][0]["severity"] = "low"
    _write_json(findings_path, document)
    with pytest.raises(EvaluationError, match="封存机器工件"):
        load_evaluation_review(gen_dir, gt_path)

    # 另一份 GT 文件 → digest/case_id 不一致。
    fresh = _build_sealed_gen(tmp_path / "ws2")
    evaluate_run(fresh, gt_path, ScriptedReviewer(), now=3000.0)
    other = _write_gt(tmp_path / "other", {
        "schema_version": 1, "case_id": "case-999",
        "items": _gt_document()["items"]})
    with pytest.raises(EvaluationError, match="Ground Truth"):
        load_evaluation_review(fresh, other)


# ---- S7 Ground Truth 隔离边界(AC1) ----


def test_ground_truth_never_enters_agent_run(tmp_path: Path) -> None:
    from firmware_audit.test.test_step5_host_driver import (
        _make_driver,
        _recon_sessions,
    )

    marker = "GT-CONFIDENTIAL-MARKER-7f3a"
    gt_document = {
        "schema_version": 1, "case_id": "case-iso",
        "items": [{
            "gt_id": "gt-0001", "title": marker,
            "root_cause": {"path": "nowhere/marker.bin", "mechanism": marker},
            "entry_point": "nowhere/marker.bin",
            "key_relations": [marker], "impact": marker,
        }],
    }
    gt_path = _write_gt(tmp_path, gt_document)

    driver = _make_driver(tmp_path, sessions=_recon_sessions())
    summary = driver.run()
    assert summary.status == "completed"
    generations = tmp_path / "generations"
    run_files = [path for path in generations.rglob("*") if path.is_file()]
    assert run_files
    for path in run_files:
        blob = path.read_bytes()
        assert marker.encode() not in blob, path
        assert b"gt-root" not in blob, path

    # 封存后评估:评审工件可含 GT 引用,但仍不得落 GT 宿主路径。
    finding_ids = [
        finding["finding_id"] for finding in json.loads(
            (summary.gen_dir / "findings.json").read_text(encoding="utf-8")
        )["findings"]]
    reply = {
        "matches": [{"gt_id": "gt-0001", "primary": None, "duplicates": [],
                     "fields": _fields(machine_disposition="inconsistent"),
                     "rationale": "没有对应调查"}],
        "unmatched": [
            {"kind": "finding", "id": finding_id,
             "classification": "novel_valid", "machine_quote": "x",
             "rationale": "新问题"}
            for finding_id in finding_ids],
    }
    artifact = evaluate_run(summary.gen_dir, gt_path,
                            ScriptedReviewer(reply), now=3000.0)
    assert artifact["metrics"]["machine"]["results"]["miss"] == 1
    for path in (p for p in generations.rglob("*") if p.is_file()):
        assert b"gt-root" not in path.read_bytes(), path

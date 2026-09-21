"""事实报告、完成门与运行封存(ADR-0012 L57/L81,票 12)。

报告前八节完全由盘上结构化工件确定生成:固定章节顺序、字节级确定性(相同
结构化输入 → 相同事实与 digest)。Evidence 默认只呈现工具、位置、长度与
digest 前缀——正文不展开 Observation/Summary 原文;权威 Evidence 与发给
Session 的 Observation View 原始字面值不被改写。

Analyst Notes 是最后的可选标注段,由调用方(驱动的 LLM 注记)提供文本;
digest 只覆盖事实部分,注记缺失或失败不影响封存。封存 = manifest 追加
``seal`` 块(report digest + 机器工件 digests)+ run_state 置 completed;
确定性报告或 manifest 失败时抛错且不触碰 run_state,世代保持 finalizing,
下次恢复继续。封存后机器工件不可修改——已 completed 的世代幂等返回既有
封存块,绝不重写。
"""
from __future__ import annotations

from collections import Counter
import hashlib
import time
from pathlib import Path
from typing import Any

from .budget import BUDGET_SCHEMA_VERSION, load_config_snapshot
from .candidates import CANDIDATE_STORE_SCHEMA_VERSION
from .generation import (
    load_run_state,
    read_manifest,
    save_run_state,
)
from .store import (
    StoreError,
    atomic_json,
    atomic_text,
    load_investigation_snapshot,
    read_json_object,
    store_error_boundary,
)
from .verification import (
    load_cases,
    load_findings_document,
    load_verification_results,
)

SEAL_SCHEMA_VERSION = 1
# 报告中呈现的 digest 前缀长度:可定位、不可还原。
DIGEST_PREFIX_CHARS = 12

# 进入 manifest seal 的顶层机器工件;investigations/ 与 verifications/ 两棵
# 树全量计入。run_state(驱动投影)与 reviews.json(票 13 覆盖层)不参与。
_SEALED_ROOT_FILES = ("candidates.json", "config.json", "budget.json",
                      "findings.json", "report.md")

ANALYST_NOTES_HEADING = "## Analyst Notes（可选，非机器事实）"

# 驱动封存期的可选注记生成提示词;固定文本,不随运行变化。
ANALYST_NOTES_SYSTEM_PROMPT = (
    "你是固件审计报告的分析员。基于给定事实报告写一段简短的 Analyst Notes"
    "(不超过 200 字,中文):指出跨问题的共性根因、最值得人工跟进的"
    " Coverage Gap 与结果解读注意点。你不得质疑、推翻或改写报告中的任何"
    "机器事实(Finding、verdict、severity、Evidence),只能补充解读;"
    "不要编造报告中不存在的路径、ID 或数据。直接输出注记正文,不要标题"
    "或任何前后缀。")


class SealError(ValueError):
    """封存前置条件不满足;世代保持 finalizing,不产生部分封存。"""


# ---- 完成门:五条件全部收束才允许置 completed ----


def completion_gate(gen_dir: Path) -> list[str]:
    """逐条检查封存前置条件;返回可读失败清单(空清单 = 可以封存)。

    "全部 ready 案卷已复核"带票 21(ADR-0012 2026-09-19)的精确豁免:所属
    Investigation 已按 unresolved/budget_exhausted 收束的未复核案卷,复核
    责任视为已了结;其余未复核 ready 案卷照旧拒绝。
    """
    gen_dir = Path(gen_dir)
    failures: list[str] = []
    store_path = gen_dir / "candidates.json"
    if not store_path.exists():
        return ["Candidate Store 缺失;全部 proposal 必须先入库"]
    store = read_json_object(store_path, "Candidate Store")
    if (store.get("schema_version") != CANDIDATE_STORE_SCHEMA_VERSION
            or not isinstance(store.get("candidates"), list)):
        raise StoreError("Candidate Store 结构或版本损坏；请检查原运行目录")
    for record in store["candidates"]:
        if not isinstance(record, dict):
            raise StoreError("Candidate 记录损坏；请检查原运行目录")
        candidate_id = str(record.get("candidate_id"))
        queue = record.get("queue")
        selected = isinstance(queue, dict) and queue.get("selected") is True
        if selected:
            failures.extend(_selected_candidate_failures(gen_dir, record))
        elif record.get("disposition") != "not_started":
            failures.append(
                f"未入选 Candidate {candidate_id} 必须标记 not_started"
                f"(实际 {record.get('disposition')!r})")
    for case in load_cases(gen_dir):
        candidate_id = case.get("candidate_id")
        if case.get("admission_reason") != "ready":
            continue
        if (gen_dir / "verifications" / str(candidate_id)
                / "results.json").exists():
            continue
        investigation = _investigation_snapshot(gen_dir, str(candidate_id))
        if (investigation.get("disposition") == "unresolved"
                and investigation.get("stop_reason") == "budget_exhausted"):
            continue  # 票 21:调查已按预算耗尽收束,复核责任随之了结
        failures.append(f"ready 案卷 {candidate_id} 尚未复核")
    return failures


def _investigation_snapshot(gen_dir: Path, candidate_id: str) -> dict[str, Any]:
    """单个 Investigation 的终态投影;目录缺失给空 dict,损坏按 Store 语义拒绝。

    解包与校验的单一出处见 ``store.load_investigation_snapshot``(票 22);
    这里适配按 ID 查找的缺失语义(容忍缺失 → 空 dict)。
    """
    snapshot = load_investigation_snapshot(
        gen_dir / "investigations" / candidate_id / "state.json")
    return {} if snapshot is None else snapshot


def _selected_candidate_failures(
        gen_dir: Path, record: dict[str, Any]) -> list[str]:
    candidate_id = str(record.get("candidate_id"))
    investigation = _investigation_snapshot(gen_dir, candidate_id)
    if not investigation:
        return [f"入选 Candidate {candidate_id} 缺少 Investigation"]
    if investigation.get("lifecycle_status") != "finished":
        return [f"入选 Investigation {candidate_id} 未结束"
                f"(lifecycle={investigation.get('lifecycle_status')!r})"]
    if not isinstance(investigation.get("disposition"), str):
        return [f"入选 Investigation {candidate_id} 缺少 disposition"]
    return []


# ---- Evidence Index:只呈现定位信息,不展开原文 ----


def build_evidence_index(gen_dir: Path) -> list[dict[str, Any]]:
    """运行内全部 Evidence 的定位索引;按 Evidence ID 升序,不含任何原文。"""
    gen_dir = Path(gen_dir)
    entries: list[dict[str, Any]] = []
    for tree in ("investigations", "verifications"):
        root = gen_dir / tree
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*/evidence/ev-*.json")):
            payload = read_json_object(path, "Evidence 工件")
            with store_error_boundary("Evidence 索引字段损坏"):
                observation = payload["observation"]
                if not isinstance(observation, str):
                    raise ValueError("observation 必须为字符串")
                entry = {
                    "evidence_id": _required_str(payload, "evidence_id"),
                    "candidate_id": _required_str(payload, "candidate_id"),
                    "tool": _required_str(payload, "tool"),
                    "location": _required_str(payload, "location"),
                    "bytes": len(observation.encode("utf-8")),
                    "digest_prefix": payload["digest"][:DIGEST_PREFIX_CHARS],
                }
            entries.append(entry)
    return sorted(entries, key=lambda entry: entry["evidence_id"])


def _required_str(payload: dict, field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} 必须为非空字符串")
    return value


# ---- 事实报告:固定八节,字节确定性 ----


def build_fact_report(gen_dir: Path) -> str:
    """从盘上结构化工件生成确定性事实报告(不含 Analyst Notes)。

    只读冻结工件(manifest/config/台账/Candidate Store/Investigation/
    Verification/Findings/Evidence);run_state 是驱动的可变投影,绝不进入
    报告——否则封存后复算的字节与封存时不一致,report digest 不可校验。
    """
    gen_dir = Path(gen_dir)
    manifest = read_manifest(gen_dir)
    config = load_config_snapshot(gen_dir)
    if config is None:
        raise StoreError("运行世代缺少配置快照;请检查原运行目录")
    store = read_json_object(gen_dir / "candidates.json", "Candidate Store")
    findings = _load_findings(gen_dir)
    investigation_states = _investigation_states(gen_dir)
    verification_results = load_verification_results(gen_dir)

    lines: list[str] = []
    lines.append(f"# 固件审计事实报告 — {manifest['generation']}")
    lines.append("")
    lines.append("> 前八节由 Host 从结构化工件确定性生成,不含模型措辞;"
                 "敏感值只呈现类型、位置、长度与 digest 前缀。")
    lines.append("")

    # 1. 运行摘要与有效配置
    lines.append("## 1. 运行摘要与有效配置")
    lines.append("")
    lines.append(f"- 世代: {manifest['generation']}")
    lines.append(f"- 创建时间: {manifest.get('created_at')}")
    lines.append(f"- 主机: {manifest.get('hostname')}")
    lines.append("- 有效配置:")
    for key in sorted(config["resolved"]):
        lines.append(f"  - {key}: {config['resolved'][key]}"
                     f"(来源: {config['sources'].get(key, 'unknown')})")
    lines.append("")

    # 2. Confirmed Findings
    confirmed = [finding for finding in findings
                 if finding.get("verdict") == "confirmed"]
    lines.append(f"## 2. Confirmed Findings({len(confirmed)})")
    lines.append("")
    if not confirmed:
        lines.append("(无)")
        lines.append("")
    for finding in confirmed:
        _render_finding(lines, finding)
    lines.append("")

    # 3. Rejected Verification Cases
    rejected = [(cid, result) for cid, result in verification_results.items()
                if result.get("verdict") == "rejected"]
    lines.append(f"## 3. Rejected Verification Cases({len(rejected)})")
    lines.append("")
    if not rejected:
        lines.append("(无)")
    for candidate_id, result in rejected:
        lines.append(
            f"- {candidate_id}: decisive_refuted="
            f"{result.get('decisive_refuted') or []};"
            f" stop_reason={result.get('stop_reason')}")
    lines.append("")

    # 4. Inconclusive Cases(含 closed/unresolved 调查)
    inconclusive = [(cid, result) for cid, result
                    in verification_results.items()
                    if result.get("verdict") == "inconclusive"]
    lines.append(f"## 4. Inconclusive Cases({len(inconclusive)})")
    lines.append("")
    if not inconclusive:
        lines.append("(无)")
    for candidate_id, result in inconclusive:
        lines.append(
            f"- {candidate_id}: unsupported={result.get('unsupported') or []};"
            f" stop_reason={result.get('stop_reason')}")
    unconverged = [(cid, state) for cid, state in investigation_states.items()
                   if state.get("disposition") in ("closed", "unresolved")]
    lines.append("")
    lines.append(f"### Closed / Unresolved Investigations({len(unconverged)})")
    lines.append("")
    if not unconverged:
        lines.append("(无)")
    for candidate_id, state in unconverged:
        lines.append(f"- {candidate_id}: disposition={state.get('disposition')};"
                     f" stop_reason={state.get('stop_reason')}")
        # 票 26:protocol_error 收束的调查附最终拒绝原因(落盘于权威投影)。
        detail = state.get("protocol_error_detail")
        if (state.get("stop_reason") == "protocol_error"
                and isinstance(detail, str) and detail.strip()):
            lines.append(f"  最终拒绝: {detail}")
    lines.append("")

    # 5. 未开始 Candidates
    records = [record for record in store.get("candidates", [])
               if isinstance(record, dict)]
    not_started = sorted(
        str(record.get("candidate_id")) for record in records
        if (record.get("queue") or {}).get("selected") is not True)
    lines.append(f"## 5. 未开始 Candidates({len(not_started)})")
    lines.append("")
    if not not_started:
        lines.append("(无)")
    else:
        lines.append(", ".join(not_started))
    lines.append("")

    # 6. Coverage Gaps
    survey = store.get("survey") if isinstance(store.get("survey"), dict) else {}
    gaps = [gap for gap in survey.get("coverage_gaps", [])
            if isinstance(gap, dict)]
    lines.append(f"## 6. Coverage Gaps({len(gaps)})")
    lines.append("")
    if not gaps:
        lines.append("(无)")
    for gap in gaps:
        reason = gap.get("reason")
        lines.append(f"- {gap.get('area')}"
                     + (f": {reason}" if reason else ""))
    lines.append("")

    # 7. Evidence Index
    index = build_evidence_index(gen_dir)
    lines.append(f"## 7. Evidence Index({len(index)})")
    lines.append("")
    if not index:
        lines.append("(无)")
    for entry in index:
        lines.append(
            f"- {entry['evidence_id']}: tool={entry['tool']};"
            f" location={entry['location']}; bytes={entry['bytes']};"
            f" digest={entry['digest_prefix']}")
    lines.append("")

    # 8. 资源使用与停止原因
    ledger = read_json_object(gen_dir / "budget.json", "预算台账")
    if ledger.get("schema_version") != BUDGET_SCHEMA_VERSION:
        raise StoreError("预算台账版本不兼容；请检查原运行目录")
    lines.append("## 8. 资源使用与停止原因")
    lines.append("")
    lines.append(
        f"- LLM 调用: {ledger.get('llm_calls')}"
        f"(prompt {ledger.get('prompt_tokens')} +"
        f" completion {ledger.get('completion_tokens')} tokens;"
        f" validated_rounds {ledger.get('validated_rounds')})")
    lines.append(
        f"- 工具执行: {ledger.get('tool_attempts')} attempts"
        f"(逻辑调用 {ledger.get('logical_tool_calls')})")
    lines.append(f"- 活动时长: {ledger.get('active_seconds')}s")
    dispositions = Counter(
        str(state.get("disposition")) for state in investigation_states.values())
    lines.append("- 调查 disposition 分布: "
                 + (", ".join(f"{name}×{count}" for name, count
                              in sorted(dispositions.items())) or "(无)"))
    stops = Counter(
        str(state.get("stop_reason")) for state in investigation_states.values()
        if state.get("stop_reason") is not None)
    lines.append("- 调查停止原因分布: "
                 + (", ".join(f"{name}×{count}" for name, count
                              in sorted(stops.items())) or "(无)"))
    lines.append("")
    return "\n".join(lines)


def _render_finding(lines: list[str], finding: dict[str, Any]) -> None:
    finding_id = finding.get("finding_id")
    lines.append(f"### {finding_id} · {finding.get('candidate_id')}"
                 f" · severity={finding.get('severity')}")
    lines.append("")
    basis = finding.get("severity_basis") or {}
    lines.append(
        f"- Profile: {finding.get('claim_profile')};"
        f" Admission: {finding.get('admission_reason')}")
    lines.append(
        f"- Severity 依据: impact_scope={basis.get('impact_scope')},"
        f" trigger_condition={basis.get('trigger_condition')},"
        f" mitigation_effect={basis.get('mitigation_effect')},"
        f" incomplete={basis.get('incomplete')}")
    claims = finding.get("claims") if isinstance(finding.get("claims"), dict) else {}
    claim_summary = ", ".join(
        f"{name}={record.get('judgment') if isinstance(record, dict) else '?'}"
        for name, record in claims.items())
    lines.append(f"- Claims: {claim_summary or '(无)'}")
    references = finding.get("evidence_references") or []
    evidence_ids = sorted({
        str(reference.get("evidence_id")) for reference in references
        if isinstance(reference, dict) and reference.get("evidence_id")})
    lines.append("- Evidence: " + (", ".join(evidence_ids) or "(无)"))
    lines.append("")


def _load_findings(gen_dir: Path) -> list[dict[str, Any]]:
    document = load_findings_document(gen_dir)
    return [finding for finding in document["findings"]
            if isinstance(finding, dict)]


def _investigation_states(gen_dir: Path) -> dict[str, dict[str, Any]]:
    """全部 Investigation 的终态投影,按 Candidate ID 升序。"""
    root = gen_dir / "investigations"
    if not root.is_dir():
        return {}
    return {directory.name: _investigation_snapshot(gen_dir, directory.name)
            for directory in sorted(root.glob("cand-*"))}


# ---- 封存:报告 digest + manifest seal + completed ----


def seal_run(
    gen_dir: Path, *, analyst_notes: str | None = None, now: float | None = None,
) -> dict[str, Any]:
    """封存 finalizing 世代;任何失败保持原状(可恢复),成功幂等。"""
    gen_dir = Path(gen_dir)
    state = load_run_state(gen_dir)
    status = state["status"] if state is not None else "running"
    if status == "completed":
        seal = read_manifest(gen_dir).get("seal")
        if not isinstance(seal, dict):
            raise StoreError("completed 世代缺少封存块;请检查原运行目录")
        return seal
    if status != "finalizing":
        raise SealError(
            f"只有 finalizing 世代可以封存(当前 {status});"
            "请先收束处理责任或显式 force 创建新世代")
    failures = completion_gate(gen_dir)
    if failures:
        raise SealError("封存前置条件不满足: " + "; ".join(failures))

    facts = build_fact_report(gen_dir)
    report_sha256 = hashlib.sha256(facts.encode("utf-8")).hexdigest()
    report = facts
    if analyst_notes is not None and analyst_notes.strip():
        report = (facts.rstrip("\n") + "\n\n---\n\n" + ANALYST_NOTES_HEADING
                  + "\n\n" + analyst_notes.strip() + "\n")
    atomic_text(gen_dir / "report.md", report)

    artifact_digests = _artifact_digests(gen_dir)
    manifest = read_manifest(gen_dir)
    manifest["seal"] = {
        "schema_version": SEAL_SCHEMA_VERSION,
        "sealed_at": float(now if now is not None else time.time()),
        "report_sha256": report_sha256,
        "artifact_digests": artifact_digests,
    }
    atomic_json(gen_dir / "manifest.json", manifest)
    save_run_state(gen_dir, status="completed", phase="sealed",
                   stop_reason="sealed")
    return manifest["seal"]


def _artifact_digests(gen_dir: Path) -> dict[str, str]:
    """封存时刻全部机器工件的 sha256;键按路径排序,字节可复算。"""
    digests: dict[str, str] = {}
    for name in _SEALED_ROOT_FILES:
        path = gen_dir / name
        if path.exists():
            digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    for tree in ("investigations", "verifications"):
        root = gen_dir / tree
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file():
                relative = path.relative_to(gen_dir).as_posix()
                digests[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {key: digests[key] for key in sorted(digests)}

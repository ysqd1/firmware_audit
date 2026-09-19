"""封存后的 Benchmark 对照评估(ADR-0012 L61-69,票 15)。

评估只发生在运行完全封存之后:确定性阶段把双方路径、地址、组件与函数别名
规范化并生成 Ground Truth → Finding/Investigation 的候选映射,不输出任何
full/partial/miss 语义标签;语义裁定由用户显式启动,评审模型读取完整结构化
材料(Ground Truth、Findings、inconclusive/closed Investigations、复核案卷、
Evidence Reference、Candidate Store 与候选映射)按固定量表输出字段级判断,
Host 按固定规则从字段判断与 primary 派生 full/partial/miss——与 severity
矩阵同款分工:LLM 交字段判断,Host 定最终标签,量表正确性是代码硬约束。

Ground Truth 隔离:Agent 运行阶段(参数、提示、快照、工作区)完全不接触
Ground Truth 根;评估工件只记录其文件名与 sha256,不落宿主路径。评审工件
``evaluation/evaluation_review.json`` 保存字段决定、双方引用、理由、模型
版本、固定提示与输入 digest;``load_evaluation_review`` 对盘上工件做重放
审计(提示 digest/机器 digest/决策合法性/指标复算)。
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import time
from typing import Any

from .candidates import CANDIDATE_ID_PATTERN, normalize_target_path
from .generation import load_run_state, read_manifest
from .review import load_review_projection
from .severity import SEVERITY_LEVELS
from .store import (
    StoreError,
    atomic_json,
    load_investigation_snapshot,
    read_json_object,
    unknown_keys,
)
from .verification import (
    load_cases,
    load_findings_document,
    load_verification_results,
)

GROUND_TRUTH_SCHEMA_VERSION = 1
CANDIDATE_MAP_SCHEMA_VERSION = 1
# v2:run 块 disposition 分布换源(Candidate Store 队列投影 → Investigation
# 终态投影,票 20);v1 工件的 run 块是错源统计,不兼容,重放审计按版本拒绝。
EVALUATION_REVIEW_SCHEMA_VERSION = 2

# 结果与 unmatched 分类的固定词汇(ADR-0012 L67/L69)。
MATCH_RESULTS = ("full", "partial", "miss")
UNMATCHED_CLASSIFICATIONS = ("novel_valid", "unsupported", "uncertain")
# 字段级量表:根因或机制、输入或触发、关键关系、实际影响、机器 disposition。
FIELD_RUBRIC = ("root_cause", "trigger_or_entry", "key_relations", "impact",
                "machine_disposition")
FIELD_AGREEMENTS = ("consistent", "inconsistent", "not_assessed")
# full 的决定性字段(ADR-0012 L67:根因和关键处理关系语义一致、影响对应且
# 有 confirmed Finding;触发/入口与 disposition 不参与 full 判定)。
FULL_DECISIVE_FIELDS = ("root_cause", "key_relations", "impact")

GT_ID_PATTERN = re.compile(r"gt-[0-9]{3,}")

_EVALUATION_DIR = "evaluation"
_CANDIDATE_MAP_NAME = "candidates.json"
_REVIEW_NAME = "evaluation_review.json"

# 机器侧信号抽取:prose 只回收路径与地址,符号只来自结构化字段,避免英文
# 文档词把候选映射泛洪成全连接。
_PATH_IN_TEXT = re.compile(r"[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+")
_HEX_IN_TEXT = re.compile(r"\b0x[0-9a-fA-F]{1,16}\b")
_ADDRESS_SHAPED = re.compile(r"0x[0-9a-fA-F]{1,16}")
_HEX_PLAIN = re.compile(r"[0-9a-f]{4,16}")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_SIGNAL_KINDS = ("path", "address", "symbol", "component")


class EvaluationError(ValueError):
    """对照评估被拒绝或评审不可用;封存机器工件与既有评估产物原样保留。"""


# ---- Ground Truth 加载与校验 ----


def load_ground_truth(path: Path) -> dict[str, Any]:
    """读取并严格校验 Ground Truth 文档;它位于 Agent 工具边界之外的独立根。"""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise EvaluationError(f"Ground Truth 文件不可读: {path} ({exc})") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"Ground Truth 不是合法 JSON: {path} ({exc})") from exc
    if not isinstance(payload, dict):
        raise EvaluationError("Ground Truth 顶层必须是 JSON object")
    _known_keys(payload, {"schema_version", "case_id", "items"}, "ground_truth")
    if (type(payload.get("schema_version")) is not int
            or payload["schema_version"] != GROUND_TRUTH_SCHEMA_VERSION):
        raise EvaluationError(
            f"Ground Truth schema_version 必须为 {GROUND_TRUTH_SCHEMA_VERSION}")
    case_id = payload.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        raise EvaluationError("ground_truth.case_id 必须为非空字符串")
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        raise EvaluationError("ground_truth.items 必须为非空数组")
    seen: set[str] = set()
    normalized_items = []
    for index, item in enumerate(items):
        normalized = _validate_gt_item(item, index)
        if normalized["gt_id"] in seen:
            raise EvaluationError(
                f"Ground Truth 条目 gt_id 重复: {normalized['gt_id']}")
        seen.add(normalized["gt_id"])
        normalized_items.append(normalized)
    return {"schema_version": GROUND_TRUTH_SCHEMA_VERSION,
            "case_id": case_id, "items": normalized_items}


def _validate_gt_item(item: Any, index: int) -> dict[str, Any]:
    label = f"ground_truth.items[{index}]"
    if not isinstance(item, dict):
        raise EvaluationError(f"{label} 必须为 object")
    _known_keys(item, {"gt_id", "title", "root_cause", "entry_point",
                       "key_relations", "impact", "preconditions", "component"},
                label)
    gt_id = item.get("gt_id")
    if not isinstance(gt_id, str) or not GT_ID_PATTERN.fullmatch(gt_id):
        raise EvaluationError(
            f"{label}.gt_id 必须形如 gt-0001,收到 {gt_id!r}")
    for key in ("title", "entry_point", "impact"):
        value = item.get(key)
        if not isinstance(value, str) or not value.strip():
            raise EvaluationError(f"{label}.{key} 必须为非空字符串")
    root_cause = item.get("root_cause")
    if not isinstance(root_cause, dict):
        raise EvaluationError(f"{label}.root_cause 必须为 object")
    _known_keys(root_cause, {"path", "symbol", "address", "mechanism"},
                f"{label}.root_cause")
    if not any(root_cause.get(key) for key in
               ("path", "symbol", "address", "mechanism")):
        raise EvaluationError(
            f"{label}.root_cause 至少包含 path/symbol/address/mechanism 之一")
    for key, value in root_cause.items():
        if not isinstance(value, str) or not value.strip():
            raise EvaluationError(f"{label}.root_cause.{key} 必须为非空字符串")
    if root_cause.get("address"):
        normalize_benchmark_address(root_cause["address"], label)
    relations = item.get("key_relations")
    if not isinstance(relations, list) or any(
            not isinstance(entry, str) or not entry.strip()
            for entry in relations):
        raise EvaluationError(
            f"{label}.key_relations 必须为非空字符串数组")
    return deepcopy(item)


def _known_keys(value: dict, allowed: set[str], label: str) -> None:
    unknown = sorted(unknown_keys(value, allowed))
    if unknown:
        raise EvaluationError(
            f"{label} 存在未知字段: {', '.join(unknown)};"
            f"允许字段: {', '.join(sorted(allowed))}")


# ---- 确定性规范化:路径 / 地址 / 组件 / 函数别名 ----


def normalize_benchmark_path(value: str) -> str:
    """Benchmark 匹配用的路径规范化键(两侧同构,只用于候选召回)。

    与 ``normalize_target_path`` 的差别:剥工具根(``extracted/``、
    ``analysis/``)与 binwalk 嵌套前缀(``<name>.extracted/<N>/``、
    ``<fstype>-root/``),并做小写折叠——这是跨标注者/跨机器的召回键,
    不是 ADR-0008 的工具路径口径。
    """
    if not isinstance(value, str):
        return ""
    segments = [segment for segment in
                normalize_target_path(value).split("/") if segment]
    # 工具根与嵌套前缀交错出现(如 <name>.extracted/0/extracted/...),
    # 两种剥离循环到稳定,避免前缀残留。
    while True:
        before = len(segments)
        while segments and segments[0].lower() in ("extracted", "analysis"):
            segments.pop(0)
        if segments:
            head = segments[0].lower()
            if (head.endswith(".extracted") and len(segments) >= 2
                    and segments[1].isdigit()):
                segments = segments[2:]
            elif head.endswith("-root"):
                segments = segments[1:]
        if len(segments) == before:
            break
    return "/".join(segments).lower()


def normalize_benchmark_address(value: str, label: str = "address") -> str:
    """地址规范化键:去 0x/分隔符,输出无前导零的小写十六进制。"""
    if not isinstance(value, str):
        raise EvaluationError(f"{label} 必须为字符串")
    text = value.strip().lower().replace("_", "").replace(" ", "")
    if text.startswith("0x"):
        text = text[2:]
    if not text or not re.fullmatch(r"[0-9a-f]+", text):
        raise EvaluationError(f"{label} 不是合法十六进制地址: {value!r}")
    return text.lstrip("0") or "0"


def normalize_benchmark_component(value: str) -> str:
    """组件规范化键:取末段、小写、剥 lib 前缀与 .so/版本后缀。"""
    if not isinstance(value, str):
        return ""
    name = value.strip().replace("\\", "/").split("/")[-1].lower()
    if name.startswith("lib"):
        name = name[3:]
    name = re.sub(r"\.so(\.[0-9.]+)*$", "", name)
    name = re.sub(r"-[0-9][0-9.]*$", "", name)
    return name


def normalize_benchmark_symbol(value: str) -> str:
    """函数别名规范化键:剥参数表/限定名/指针记号,折叠分隔符与下划线。

    ``do_Login``/``do-login``/``DoLogin`` 折叠为同一召回键;这只用于候选
    召回,语义裁定仍由评审模型判断。
    """
    if not isinstance(value, str):
        return ""
    text = value.strip().split("(")[0].strip()
    text = re.split(r"::|\.", text)[-1]
    text = re.sub(r"[^A-Za-z0-9]", "", text.lstrip("*").strip())
    return text.lower()


# ---- 封存门与机器视图 ----


def require_sealed_run(gen_dir: Path) -> None:
    """Evaluator 只接受 completed 世代(ADR-0012 L61:结果冻结后才读两侧)。"""
    state = load_run_state(Path(gen_dir))
    status = state["status"] if state is not None else "missing"
    if status != "completed":
        raise EvaluationError(
            f"运行未封存(run_state.status={status});"
            "对照评估只能在 completed 世代上进行")


def _machine_views(gen_dir: Path) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """(confirmed Findings, candidate_id → Investigation disposition) 视图。

    封存不变量的校验点:findings.json 只允许 confirmed Finding,违反即拒绝
    评估(机器不变量被破坏时不产出任何评估结论)。
    """
    findings = [finding for finding in
                load_findings_document(gen_dir)["findings"]
                if isinstance(finding, dict)]
    for finding in findings:
        if finding.get("verdict") != "confirmed":
            raise EvaluationError(
                f"Finding {finding.get('finding_id')} 不是 confirmed;"
                "封存运行的 findings.json 只允许 confirmed Finding")
    dispositions: dict[str, str] = {}
    root = Path(gen_dir) / "investigations"
    for path in sorted(root.glob("cand-*/state.json")) if root.is_dir() else []:
        candidate_id = path.parent.name
        investigation = load_investigation_snapshot(path)
        if investigation is None:
            # glob 只命中已存在的 state.json,None 只能是读取前被删的竞态;
            # 沿用改动前 read_json_object 对该场景的"快照损坏"口径拒绝。
            raise StoreError(
                f"Investigation {candidate_id} 快照损坏；请检查原运行目录")
        disposition = investigation.get("disposition")
        dispositions[candidate_id] = disposition if isinstance(disposition, str) \
            else ""
    return findings, dispositions


def _evidence_records(gen_dir: Path) -> list[dict[str, Any]]:
    """两棵 Evidence 树的 Reference 记录(id/工具/参数/摘要/位置/digest)。"""
    records: list[dict[str, Any]] = []
    for tree in ("investigations", "verifications"):
        root = Path(gen_dir) / tree
        for path in sorted(root.glob("*/evidence/ev-*.json")) \
                if root.is_dir() else []:
            payload = read_json_object(path, "Evidence 工件")
            records.append({
                "evidence_id": payload.get("evidence_id"),
                "candidate_id": payload.get("candidate_id"),
                "tool": payload.get("tool"),
                "arguments": payload.get("arguments"),
                "summary": payload.get("summary"),
                "location": payload.get("location"),
                "digest": payload.get("digest"),
            })
    return records


# ---- 确定性阶段:规范化 + 候选映射(不输出语义标签) ----


def _object_texts(record: dict[str, Any] | None, finding: dict[str, Any] | None,
                  results: dict[str, Any] | None,
                  evidence: list[dict[str, Any]]) -> dict[str, list[str]]:
    """单台机器对象的结构化字段与 prose 文本池(信号抽取的输入)。"""
    structured: list[str] = []
    prose: list[str] = []

    def take(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            structured.append(value)

    if record:
        for key in ("target", "anchor", "component_or_entry",
                    "possible_source", "possible_sink"):
            take(record.get(key))
        mechanism = record.get("mechanism")
        if isinstance(mechanism, str) and mechanism.strip():
            prose.append(mechanism)
    for claims in (finding.get("claims") if finding else None,
                   results.get("claim_results") if results else None):
        if isinstance(claims, dict):
            for claim in claims.values():
                if isinstance(claim, dict):
                    observed = claim.get("observed")
                    if isinstance(observed, str) and observed.strip():
                        prose.append(observed)
    for item in evidence:
        arguments = item.get("arguments")
        if isinstance(arguments, dict):
            for value in arguments.values():
                if isinstance(value, str):
                    take(value)
        summary = item.get("summary")
        if isinstance(summary, str) and summary.strip():
            prose.append(summary)
    return {"structured": structured, "prose": prose}


def _looks_like_address(value: str) -> bool:
    if _ADDRESS_SHAPED.fullmatch(value):
        return True
    return bool(_HEX_PLAIN.fullmatch(value) and re.search(r"[a-f]", value))


def _signal_sets(texts: dict[str, list[str]]) -> dict[str, set[str]]:
    """把文本池规范化成四类信号键;prose 只回收路径与地址。"""
    paths: set[str] = set()
    addresses: set[str] = set()
    symbols: set[str] = set()
    components: set[str] = set()
    for value in texts["structured"]:
        if "/" in value:
            paths.add(normalize_benchmark_path(value))
            components.add(normalize_benchmark_component(value))
        elif _looks_like_address(value):
            addresses.add(normalize_benchmark_address(value))
        elif _IDENT.fullmatch(value):
            symbols.add(normalize_benchmark_symbol(value))
            components.add(normalize_benchmark_component(value))
    for value in texts["prose"]:
        paths.update(normalize_benchmark_path(match)
                     for match in _PATH_IN_TEXT.findall(value))
        addresses.update(normalize_benchmark_address(match)
                         for match in _HEX_IN_TEXT.findall(value))
    return {"path": {item for item in paths if item and item != "."},
            "address": addresses, "symbol": symbols, "component": components}


def _gt_signal_sets(ground_truth: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    per_item: dict[str, dict[str, set[str]]] = {}
    for item in ground_truth["items"]:
        root_cause = item["root_cause"]
        paths = {normalize_benchmark_path(root_cause["path"])} \
            if root_cause.get("path") else set()
        paths.add(normalize_benchmark_path(item["entry_point"]))
        symbols = {normalize_benchmark_symbol(root_cause["symbol"])} \
            if root_cause.get("symbol") else set()
        addresses = {normalize_benchmark_address(root_cause["address"])} \
            if root_cause.get("address") else set()
        components = {normalize_benchmark_component(value) for value in
                      (item.get("component"), root_cause.get("path"))
                      if value}
        per_item[item["gt_id"]] = {
            "path": {value for value in paths if value and value != "."},
            "address": addresses, "symbol": symbols,
            "component": {value for value in components if value},
        }
    return per_item


def generate_candidate_map(
    gen_dir: Path, ground_truth: dict[str, Any],
) -> dict[str, Any]:
    """确定性候选映射:规范化四类键并求交,不输出 full/partial/miss。

    输入是封存机器工件与已装载的 Ground Truth(``evaluate_run`` 会先补上
    ``source_name``/``source_sha256`` 溯源字段);输出落盘
    ``evaluation/candidates.json``,字节确定(相同输入 → 相同字节),可反复
    重算比对。
    """
    gen_dir = Path(gen_dir)
    require_sealed_run(gen_dir)
    manifest = read_manifest(gen_dir)
    store = read_json_object(gen_dir / "candidates.json", "Candidate Store")
    records = {record.get("candidate_id"): record
               for record in store.get("candidates", [])
               if isinstance(record, dict) and record.get("candidate_id")}
    findings, dispositions = _machine_views(gen_dir)
    results_by_candidate = load_verification_results(gen_dir)
    evidence_by_candidate: dict[str, list[dict[str, Any]]] = {}
    for item in _evidence_records(gen_dir):
        evidence_by_candidate.setdefault(item.get("candidate_id") or "",
                                         []).append(item)

    objects: list[dict[str, Any]] = []
    signals_by_object: dict[tuple[str, str], dict[str, set[str]]] = {}
    for finding in findings:
        object_id = str(finding.get("finding_id"))
        candidate_id = str(finding.get("candidate_id") or "")
        texts = _object_texts(records.get(candidate_id), finding,
                              results_by_candidate.get(candidate_id),
                              evidence_by_candidate.get(candidate_id, []))
        signals_by_object[("finding", object_id)] = _signal_sets(texts)
        objects.append({"kind": "finding", "id": object_id,
                        "candidate_id": candidate_id})
    for candidate_id in sorted(dispositions):
        texts = _object_texts(records.get(candidate_id), None,
                              results_by_candidate.get(candidate_id),
                              evidence_by_candidate.get(candidate_id, []))
        signals_by_object[("investigation", candidate_id)] = \
            _signal_sets(texts)
        objects.append({"kind": "investigation", "id": candidate_id,
                        "disposition": dispositions[candidate_id]})
    objects.sort(key=lambda obj: (obj["kind"], obj["id"]))

    gt_signals = _gt_signal_sets(ground_truth)
    candidates: list[dict[str, Any]] = []
    unmatched_gt: list[str] = []
    for item in ground_truth["items"]:
        gt_id = item["gt_id"]
        expected = gt_signals[gt_id]
        matches: list[dict[str, Any]] = []
        for key in sorted(signals_by_object):
            fired = [f"{kind}:{value}" for kind in _SIGNAL_KINDS
                     for value in sorted(expected[kind]
                                         & signals_by_object[key][kind])]
            if fired:
                matches.append({"kind": key[0], "id": key[1],
                                "signals": sorted(fired)})
        if matches:
            candidates.append({"gt_id": gt_id, "matches": matches})
        else:
            unmatched_gt.append(gt_id)

    mapping = {
        "schema_version": CANDIDATE_MAP_SCHEMA_VERSION,
        "generation": manifest["generation"],
        "ground_truth": {
            "source": ground_truth.get("source_name", ""),
            "case_id": ground_truth["case_id"],
            "sha256": ground_truth.get("source_sha256", ""),
        },
        "note": "确定性候选映射;本阶段不做任何语义判定,"
                "语义标签由封存后的语义评审给出",
        "machine_objects": objects,
        "candidates": candidates,
        "unmatched_ground_truth": unmatched_gt,
    }
    atomic_json(gen_dir / _EVALUATION_DIR / _CANDIDATE_MAP_NAME, mapping)
    return mapping


def canonical_json(value: Any) -> str:
    """评估工件内嵌结构的规范序列化(digest 复算的唯一口径)。

    与 ``clone_json_value`` 分工:那个是"校验并深拷贝"的入参闸门,这个只做
    已校验 JSON 值的字节规范化;allow_nan=False 保证 digest 输入无 NaN。
    """
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


# ---- 语义裁定材料与固定提示 ----


def build_review_materials(
    gen_dir: Path, ground_truth: dict[str, Any],
    candidate_map: dict[str, Any],
) -> dict[str, Any]:
    """Codex reviewer 的完整结构化材料包(ADR-0012 L65 全量清单)。"""
    gen_dir = Path(gen_dir)
    findings, dispositions = _machine_views(gen_dir)
    investigations: list[dict[str, Any]] = []
    root = gen_dir / "investigations"
    for candidate_id in sorted(dispositions):
        if dispositions[candidate_id] == "confirmed":
            continue  # confirmed 调查已由 Finding 表达,避免材料重复
        # 材料要的是整份 state(含 runtime 等外层),不是 investigation
        # 终态投影——不走 store.load_investigation_snapshot,形状不同。
        snapshot = read_json_object(
            root / candidate_id / "state.json", "Investigation 快照")
        investigations.append({
            "candidate_id": candidate_id,
            "disposition": dispositions[candidate_id],
            "state": snapshot.get("state", {}),
        })
    cases = load_cases(gen_dir)
    results = load_verification_results(gen_dir)
    verification_cases = [
        {"case": case, "results": results.get(str(case.get("candidate_id")))}
        for case in cases
    ]
    return {
        "ground_truth": ground_truth,
        "candidates": read_json_object(
            gen_dir / "candidates.json", "Candidate Store"),
        "findings": load_findings_document(gen_dir),
        "investigations": investigations,
        "verification_cases": verification_cases,
        "evidence": _evidence_records(gen_dir),
        "candidate_map": candidate_map,
    }


EVALUATION_REVIEW_SYSTEM_PROMPT = """## 角色
你是 Benchmark 对照评估的语义评审。Benchmark 运行已完全封存,你的任务是
把参考答案(Ground Truth)与机器结果做字段级语义裁定,产出可审计的结构化
结论。语义匹配不要求路径、函数名或描述文本完全一致;你要按问题机制、触发
条件、关键处理关系和实际影响做判断,并为每项决定引用双方材料原文。

## 输入
用户消息是一份 JSON 材料,包含:ground_truth(参考答案)、candidates
(Candidate Store 记录)、findings(机器 confirmed Finding)、investigations
(inconclusive/closed/rejected/unresolved 调查的终态快照,按
candidate_id 寻址;confirmed 调查已由 findings 表达,不再重复)、
verification_cases(复核案卷与结果)、evidence(Evidence Reference 清单,
只含引用与摘要,可按 evidence_id 引用)与 candidate_map(确定性候选映射)。
candidate_map 只是召回线索:你可以依据材料建立映射之外的对应,也可以否决
映射中的对应;但 primary/duplicates/unmatched 引用的对象必须真实存在于
材料中。

## 字段级量表
对每个 Ground Truth 条目,分别就以下五个字段给出判断;每个字段包含
agreement(consistent / inconsistent / not_assessed)、gt_quote(参考答案
原文引用,可为 null)、machine_quote(机器材料原文引用,可为 null)与
rationale(一句话依据,不得为空):
- root_cause:根因或问题机制是否语义一致;
- trigger_or_entry:输入入口或触发条件是否对应;
- key_relations:关键处理关系是否对应;
- impact:实际影响是否对应;
- machine_disposition:机器结论(confirmed Finding / inconclusive /
  rejected 等)与参考答案的成立性是否对应。

## 结果规则(由 Host 按字段判断确定性推导,你不输出结果标签)
- full:primary 是 confirmed Finding,且 root_cause、key_relations、impact
  三项 agreement 均为 consistent;
- partial:存在 primary 但不满足 full 条件——能确认机器调查过同一问题,
  但链路、影响或最终确认仍有缺口;inconclusive Investigation 可以作为
  primary 进入该类;
- miss:没有任何可信对应(primary 必须为 null)。

## 对应与计分
- 每个 Ground Truth 条目最多一个 primary;同一问题的重复 Finding 放进
  duplicates,不重复计分;
- primary.kind="finding" 时必须是 findings 中的 confirmed Finding;
  primary.kind="investigation" 时必须是 disposition=inconclusive 的调查;
  rejected/closed/unresolved 的调查不能作为 primary;
- 所有没有被任何 primary 引用的 confirmed Finding 必须各出现一次:或作为
  某 Ground Truth 的 duplicates,或进入 unmatched;unmatched 分类为:
  - novel_valid:机器发现的有效新问题(Ground Truth 未覆盖);
  - unsupported:引用或推理不足以支持该结论的错误结果;
  - uncertain:无法判断;uncertain 不进入确定指标,不要强行猜测。

## 回复协议
只输出一份纯 JSON,不要 Markdown 或额外文字:
{"matches": [{"gt_id": "gt-0001", "primary": {"kind": "finding",
  "id": "f-0001"}, "duplicates": [], "fields": {"root_cause":
  {"agreement": "consistent", "gt_quote": "...", "machine_quote": "...",
  "rationale": "..."}, "trigger_or_entry": {...}, "key_relations": {...},
  "impact": {...}, "machine_disposition": {...}}, "rationale": "..."}],
 "unmatched": [{"kind": "finding", "id": "f-0002", "classification":
  "novel_valid", "machine_quote": "...", "rationale": "..."}]}
primary 为 null 时写作 "primary": null。"""


# ---- 评审回复解析与确定性校验 ----


def _finding_index(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(finding.get("finding_id")): finding for finding in findings}


def _parse_reply(reply: str) -> dict[str, Any]:
    try:
        payload = json.loads(reply)
    except json.JSONDecodeError as exc:
        raise EvaluationError(f"评审回复不是合法 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EvaluationError("评审回复必须是 JSON object")
    _known_keys(payload, {"matches", "unmatched"}, "评审回复")
    if not isinstance(payload.get("matches"), list) \
            or not isinstance(payload.get("unmatched"), list):
        raise EvaluationError("评审回复的 matches/unmatched 必须为数组")
    return payload


def _validate_field_entry(entry: Any, label: str) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise EvaluationError(f"{label} 必须为 object")
    _known_keys(entry, {"agreement", "gt_quote", "machine_quote", "rationale"},
                label)
    agreement = entry.get("agreement")
    if agreement not in FIELD_AGREEMENTS:
        raise EvaluationError(
            f"{label}.agreement 必须为 {'/'.join(FIELD_AGREEMENTS)},"
            f"收到 {agreement!r}")
    for key in ("gt_quote", "machine_quote"):
        value = entry.get(key)
        if value is not None and not isinstance(value, str):
            raise EvaluationError(f"{label}.{key} 必须为字符串或 null")
    rationale = entry.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        raise EvaluationError(f"{label}.rationale 必须为非空字符串")
    return deepcopy(entry)


def _validate_reference(
    ref: Any, *, kinds: tuple[str, ...],
    findings_index: dict[str, dict[str, Any]],
    dispositions: dict[str, str],
    label: str,
) -> tuple[str, str]:
    if not isinstance(ref, dict):
        raise EvaluationError(f"{label} 必须为 object")
    _known_keys(ref, {"kind", "id"}, label)
    kind = ref.get("kind")
    object_id = ref.get("id")
    if kind not in kinds:
        raise EvaluationError(f"{label}.kind 必须为 {'/'.join(kinds)}")
    if not isinstance(object_id, str) or not object_id:
        raise EvaluationError(f"{label}.id 必须为非空字符串")
    if kind == "finding":
        if object_id not in findings_index:
            raise EvaluationError(f"{label} 引用未知 Finding {object_id}")
    else:
        if not CANDIDATE_ID_PATTERN.fullmatch(object_id):
            raise EvaluationError(
                f"{label} 的 Investigation 必须按 candidate_id 寻址:"
                f"{object_id!r}")
        if object_id not in dispositions:
            raise EvaluationError(
                f"{label} 引用未知 Investigation {object_id}")
    return kind, object_id


def _validate_review_reply(
    payload: dict[str, Any],
    *,
    gt_ids: list[str],
    findings: list[dict[str, Any]],
    dispositions: dict[str, str],
) -> dict[str, Any]:
    """确定性校验评审回复;同时按固定量表派生每项 GT 的结果标签。

    ``gt_ids`` 是全部 Ground Truth 条目标识:评估入口来自已装载的 GT,
    重放审计来自盘上工件(配合映射覆盖校验)。
    """
    findings_index = _finding_index(findings)
    matches = payload["matches"]
    seen_gt: set[str] = set()
    primary_findings: set[str] = set()
    normalized_matches: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        label = f"matches[{index}]"
        if not isinstance(match, dict):
            raise EvaluationError(f"{label} 必须为 object")
        _known_keys(match, {"gt_id", "primary", "duplicates", "fields",
                            "rationale", "result"}, label)
        gt_id = match.get("gt_id")
        if not isinstance(gt_id, str) or gt_id not in gt_ids:
            raise EvaluationError(
                f"{label}.gt_id 必须是 Ground Truth 条目之一,收到 {gt_id!r}")
        if gt_id in seen_gt:
            raise EvaluationError(
                f"Ground Truth {gt_id} 出现多次;每项只评审一次")
        seen_gt.add(gt_id)
        primary = match.get("primary")
        if primary is not None:
            kind, object_id = _validate_reference(
                primary, kinds=("finding", "investigation"),
                findings_index=findings_index, dispositions=dispositions,
                label=f"{label}.primary")
            if kind == "finding" \
                    and findings_index[object_id].get("verdict") != "confirmed":
                raise EvaluationError(
                    f"{label}.primary 引用的 Finding {object_id} 不是 confirmed")
            if kind == "investigation" \
                    and dispositions[object_id] != "inconclusive":
                raise EvaluationError(
                    f"{label}.primary 调查 {object_id} disposition="
                    f"{dispositions[object_id]!r};只有 inconclusive 调查"
                    "可以作为 primary")
            if kind == "finding":
                primary_findings.add(object_id)
        duplicates: list[dict[str, Any]] = []
        raw_duplicates = match.get("duplicates")
        if not isinstance(raw_duplicates, list):
            raise EvaluationError(f"{label}.duplicates 必须为数组")
        if primary is None and raw_duplicates:
            raise EvaluationError(
                f"{label} 判 miss(无 primary)时不得携带 duplicates;"
                "重复对应只对存在 primary 的 Ground Truth 有意义")
        for dup_index, dup in enumerate(raw_duplicates):
            kind, object_id = _validate_reference(
                dup, kinds=("finding",), findings_index=findings_index,
                dispositions=dispositions, label=f"{label}.duplicates[{dup_index}]")
            if findings_index[object_id].get("verdict") != "confirmed":
                raise EvaluationError(
                    f"{label}.duplicates[{dup_index}] 引用的 Finding "
                    f"{object_id} 不是 confirmed")
            duplicates.append({"kind": kind, "id": object_id})
        fields = match.get("fields")
        if not isinstance(fields, dict):
            raise EvaluationError(f"{label}.fields 必须为 object")
        _known_keys(fields, set(FIELD_RUBRIC), f"{label}.fields")
        normalized_fields = {
            name: _validate_field_entry(
                fields.get(name), f"{label}.fields.{name}")
            for name in FIELD_RUBRIC
        }
        rationale = match.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise EvaluationError(f"{label}.rationale 必须为非空字符串")
        normalized_matches.append({
            "gt_id": gt_id,
            "primary": deepcopy(primary) if primary is not None else None,
            "duplicates": duplicates,
            "fields": normalized_fields,
            "rationale": rationale,
            "result": _derive_result(primary, normalized_fields),
        })
    if len(seen_gt) != len(gt_ids):
        missing = [gt_id for gt_id in gt_ids if gt_id not in seen_gt]
        raise EvaluationError(
            f"Ground Truth 条目缺少评审: {', '.join(missing)}")

    normalized_unmatched: list[dict[str, Any]] = []
    classified: set[str] = set()
    for index, entry in enumerate(payload["unmatched"]):
        label = f"unmatched[{index}]"
        if not isinstance(entry, dict):
            raise EvaluationError(f"{label} 必须为 object")
        _known_keys(entry, {"kind", "id", "classification", "machine_quote",
                            "rationale"}, label)
        kind, object_id = _validate_reference(
            {"kind": entry.get("kind"), "id": entry.get("id")},
            kinds=("finding",), findings_index=findings_index,
            dispositions=dispositions, label=label)
        if findings_index[object_id].get("verdict") != "confirmed":
            raise EvaluationError(
                f"{label} 引用的 Finding {object_id} 不是 confirmed")
        classification = entry.get("classification")
        if classification not in UNMATCHED_CLASSIFICATIONS:
            raise EvaluationError(
                f"{label}.classification 必须为 "
                f"{'/'.join(UNMATCHED_CLASSIFICATIONS)},收到 {classification!r}")
        if object_id in classified:
            raise EvaluationError(
                f"Finding {object_id} 在 unmatched 中出现多次")
        classified.add(object_id)
        machine_quote = entry.get("machine_quote")
        if machine_quote is not None and not isinstance(machine_quote, str):
            raise EvaluationError(f"{label}.machine_quote 必须为字符串或 null")
        rationale = entry.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise EvaluationError(f"{label}.rationale 必须为非空字符串")
        normalized_unmatched.append({
            "kind": kind, "id": object_id,
            "classification": classification,
            "machine_quote": machine_quote, "rationale": rationale,
        })

    # 完整性:未被任何 primary 引用的 confirmed Finding 必须各出现一次
    # (duplicates 或 unmatched);担任过 primary 的 Finding 已计分,不得再
    # 出现在 duplicates/unmatched 中重复计分。
    accounted: set[str] = set()
    for match in normalized_matches:
        for dup in match["duplicates"]:
            object_id = dup["id"]
            if object_id in primary_findings:
                raise EvaluationError(
                    f"Finding {object_id} 已是某 Ground Truth 的 primary,"
                    f"不得同时作为 {match['gt_id']} 的重复对应")
            if object_id in accounted:
                raise EvaluationError(
                    f"Finding {object_id} 被引用多次;重复对应只计一次")
            accounted.add(object_id)
    for entry in normalized_unmatched:
        object_id = entry["id"]
        if object_id in primary_findings:
            raise EvaluationError(
                f"Finding {object_id} 已是某 Ground Truth 的 primary,"
                "不得同时进入 unmatched")
        if object_id in accounted:
            raise EvaluationError(
                f"Finding {object_id} 被引用多次;duplicates 与 unmatched"
                "不得重叠")
        accounted.add(object_id)
    expected = set(findings_index) - primary_findings
    if accounted != expected:
        problems = []
        missing = sorted(expected - accounted)
        extra = sorted(accounted - expected)
        if missing:
            problems.append("缺少分类: " + ", ".join(missing))
        if extra:
            problems.append("多出引用: " + ", ".join(extra))
        raise EvaluationError(
            "duplicates/unmatched 未与未匹配 confirmed Finding 一一对应: "
            + "; ".join(problems))
    return {"matches": normalized_matches, "unmatched": normalized_unmatched}


def _derive_result(primary: dict[str, Any] | None,
                   fields: dict[str, Any]) -> str:
    """固定量表规则:full/partial/miss 由字段判断 + primary 派生(Host 硬约束)。

    miss ⟺ 无 primary;full ⟺ primary 是 confirmed Finding 且
    root_cause/key_relations/impact 三项一致;其余(含 inconclusive 调查
    作 primary、决定性字段有缺口)为 partial。
    """
    if primary is None:
        return "miss"
    if primary["kind"] != "finding":
        return "partial"
    if all(fields[name]["agreement"] == "consistent"
           for name in FULL_DECISIVE_FIELDS):
        return "full"
    return "partial"


# ---- 指标:machine/reviewed 并列,uncertain 不进确定指标 ----


def compute_metrics(
    ground_truth_items: int,
    matches: list[dict[str, Any]],
    unmatched: list[dict[str, Any]],
    *,
    machine_severities: dict[str, int],
    reviewed_severities: dict[str, int] | None,
) -> dict[str, Any]:
    """指标纯函数:每项 GT 只按 primary 计一次,重复对应不重复得分。

    ``definitive`` 是确定指标——uncertain(match 与 unmatched 两侧)都
    不进入;``results``/``unmatched`` 计数保留完整分布供审计。severity
    分布在 machine 与 reviewed 两个投影下分别给出(票 13:覆盖层只能调整
    severity,因此两投影当前仅在 severity 分布上可能不同)。
    """
    results = {name: 0 for name in MATCH_RESULTS}
    for match in matches:
        results[match["result"]] += 1
    classifications = {name: 0 for name in UNMATCHED_CLASSIFICATIONS}
    for entry in unmatched:
        classifications[entry["classification"]] += 1
    definitive = {
        "full": results["full"],
        "partial": results["partial"],
        "miss": results["miss"],
        "unmatched_novel_valid": classifications["novel_valid"],
        "unmatched_unsupported": classifications["unsupported"],
    }

    def block(severity_distribution: dict[str, int]) -> dict[str, Any]:
        return {
            "ground_truth_items": ground_truth_items,
            "results": dict(results),
            "unmatched": dict(classifications),
            "definitive": dict(definitive),
            "confirmed_findings": sum(machine_severities.values()),
            "severity_distribution": dict(severity_distribution),
        }

    return {
        "machine": block(machine_severities),
        "reviewed": (block(reviewed_severities)
                     if reviewed_severities is not None else None),
    }


def _run_context(gen_dir: Path) -> dict[str, Any]:
    """ADR-0012 L61 运行面统计:调查 disposition 分布与运行资源消耗。

    分布读各 Investigation 的终态投影(``investigations/<cand>/state.json``
    的 disposition,经 ``_machine_views``),与事实报告第 8 节同一盘上数据源
    但装载各自独立(报告走 reporting 的 ``_investigation_states``;缺失
    disposition 第 8 节计作 "None" 桶、此处滤非字符串——completed 世代有
    完成门兜底,两读法不会分叉)。该源能表达 confirmed/rejected/inconclusive
    /closed/unresolved/not_started 全部词汇。Candidate Store 是错源:其队列
    投影受票 11 不变量约束只有 None/not_started 两态,当数据源时生产世代上
    分布永远退化为 not_started×N 或空(票 20)。
    """
    _findings, dispositions = _machine_views(gen_dir)
    counts = Counter(value for value in dispositions.values() if value)
    budget_path = gen_dir / "budget.json"
    resources: dict[str, Any] | None = None
    if budget_path.exists():
        ledger = read_json_object(budget_path, "预算台账")
        resources = {key: ledger.get(key) for key in
                     ("llm_calls", "prompt_tokens", "completion_tokens",
                      "tool_attempts", "logical_tool_calls", "active_seconds")}
    return {
        "investigation_dispositions": dict(sorted(counts.items())),
        "resources": resources,
    }


def _severity_distributions(
    gen_dir: Path,
) -> tuple[dict[str, int], dict[str, int] | None]:
    """machine/reviewed severity 分布(票 13 投影;无覆盖记录时 reviewed=None)。"""
    summary = load_review_projection(gen_dir)["summary"]
    return summary["machine_severities"], summary["reviewed_severities"]


# ---- 评审入口:用户显式启动 ----


def evaluate_run(
    gen_dir: Path,
    ground_truth_path: Path,
    llm,
    *,
    model: str | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """用户显式启动的封存后对照评估:候选映射 → 语义裁定 → 指标落盘。

    ``llm`` 为鸭子类型 ``.chat(messages) -> (reply, usage)``(SemanticComparator
    同款);模型版本取 ``model`` 参数或 ``llm.model``。评审失败(服务失败/
    回复非法)不写任何评审工件;``evaluation/candidates.json`` 是确定性产物,
    失败后保留供排查与重算。已存在评审工件时拒绝重复评审——覆盖会摧毁
    审计链,如需重新评审请先显式归档旧工件。
    """
    gen_dir = Path(gen_dir)
    require_sealed_run(gen_dir)
    review_path = gen_dir / _EVALUATION_DIR / _REVIEW_NAME
    if review_path.exists():
        raise EvaluationError(
            f"评审工件已存在: {review_path};重跑评审会摧毁审计链,"
            "如需重新评审请显式归档旧工件")
    ground_truth = load_ground_truth(ground_truth_path)
    ground_truth = {
        **ground_truth,
        "source_name": Path(ground_truth_path).name,
        "source_sha256": hashlib.sha256(
            Path(ground_truth_path).read_bytes()).hexdigest(),
    }
    model_name = model or getattr(llm, "model", None)
    if not isinstance(model_name, str) or not model_name:
        raise EvaluationError(
            "无法确定评审模型版本;请显式传入 model 参数")
    candidate_map = generate_candidate_map(gen_dir, ground_truth)

    materials = build_review_materials(gen_dir, ground_truth, candidate_map)
    messages = [
        {"role": "system", "content": EVALUATION_REVIEW_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(materials, ensure_ascii=False)},
    ]
    try:
        reply, usage = llm.chat(messages)
    except Exception as exc:
        raise EvaluationError(f"评审模型调用失败: {exc}") from exc

    findings, dispositions = _machine_views(gen_dir)
    review = _validate_review_reply(
        _parse_reply(reply),
        gt_ids=[item["gt_id"] for item in ground_truth["items"]],
        findings=findings, dispositions=dispositions)
    machine_severities, reviewed_severities = _severity_distributions(gen_dir)
    metrics = compute_metrics(
        len(ground_truth["items"]), review["matches"], review["unmatched"],
        machine_severities=machine_severities,
        reviewed_severities=reviewed_severities)

    manifest = read_manifest(gen_dir)
    seal = manifest.get("seal")
    if not isinstance(seal, dict):
        raise StoreError("completed 世代缺少封存块;请检查原运行目录")
    artifact = {
        "schema_version": EVALUATION_REVIEW_SCHEMA_VERSION,
        "generation": manifest["generation"],
        "created_at": float(now if now is not None else time.time()),
        "model": model_name,
        "reviewer_prompt": EVALUATION_REVIEW_SYSTEM_PROMPT,
        "reviewer_prompt_sha256": hashlib.sha256(
            EVALUATION_REVIEW_SYSTEM_PROMPT.encode("utf-8")).hexdigest(),
        "inputs": {
            "ground_truth": {
                "source": ground_truth["source_name"],
                "case_id": ground_truth["case_id"],
                "sha256": ground_truth["source_sha256"],
            },
            "machine": {
                "report_sha256": seal.get("report_sha256"),
                "artifact_digests": deepcopy(seal.get("artifact_digests")),
            },
            "candidate_map_sha256": hashlib.sha256(
                canonical_json(candidate_map).encode("utf-8")).hexdigest(),
        },
        "candidate_map": candidate_map,
        "matches": review["matches"],
        "unmatched": review["unmatched"],
        "metrics": metrics,
        "run": _run_context(gen_dir),
        "usage": deepcopy(usage) if isinstance(usage, dict) else {},
    }
    atomic_json(review_path, artifact)
    return artifact


def _verify_sealed_files(gen_dir: Path, seal: dict[str, Any]) -> None:
    """逐文件复算封存 digest;封存机器工件被改动即审计失败。

    manifest seal 的 artifact_digests 在封存时刻固定,是"封存后机器工件
    不可修改"的完整性凭据;审计必须对着盘上现文件复算,而不是只比对
    工件与 manifest 两份记录(它们可以一起被篡改)。
    """
    digests = seal.get("artifact_digests")
    if not isinstance(digests, dict) or not digests:
        raise StoreError("manifest seal 缺少工件 digest;请检查原运行目录")
    for relative, expected in sorted(digests.items()):
        path = gen_dir / relative
        actual = hashlib.sha256(path.read_bytes()).hexdigest() \
            if path.is_file() else None
        if actual != expected:
            raise EvaluationError(
                f"评审工件审计失败: 封存机器工件 {relative} 与封存 digest "
                "不符(封存后被改动或缺失)")


# ---- 重放审计 ----


def load_evaluation_review(
    gen_dir: Path, ground_truth_path: Path | None = None,
) -> dict[str, Any]:
    """重放审计:校验盘上评审工件与封存机器工件、固定提示与指标的一致性。

    校验链:固定提示与当前代码一致(prompt 漂移即告警)且自 digest 相符、
    机器 digest 与 manifest seal 一致并逐文件复算封存 digest、候选映射
    digest 可复算且世代一致、决策引用与完整性可对当前机器工件重放、
    result 标签与字段派生一致、machine 指标与运行面统计可复算、reviewed
    指标做内部一致性校验(其 severity 快照锚定评审时刻,覆盖层合法追加
    不影响审计)。提供 ``ground_truth_path`` 时额外校验 Ground Truth 文件
    digest 与 case_id。任何一项不符都说明工件被篡改或由不兼容版本产出。
    """
    gen_dir = Path(gen_dir)
    path = gen_dir / _EVALUATION_DIR / _REVIEW_NAME
    if not path.exists():
        raise EvaluationError(f"评审工件不存在: {path}")
    artifact = read_json_object(path, "评审工件")
    if (type(artifact.get("schema_version")) is not int
            or artifact["schema_version"] != EVALUATION_REVIEW_SCHEMA_VERSION):
        raise EvaluationError("评审工件 schema_version 不兼容")

    def audit_failure(reason: str) -> EvaluationError:
        return EvaluationError(f"评审工件审计失败: {reason}")

    prompt = artifact.get("reviewer_prompt")
    if not isinstance(prompt, str):
        raise audit_failure("reviewer_prompt 缺失")
    if prompt != EVALUATION_REVIEW_SYSTEM_PROMPT:
        raise audit_failure(
            "固定评审提示与当前代码不一致(提示漂移);该工件由其它版本提示产出")
    if (hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            != artifact.get("reviewer_prompt_sha256")):
        raise audit_failure("reviewer_prompt_sha256 与提示原文不符")

    manifest = read_manifest(gen_dir)
    seal = manifest.get("seal")
    if not isinstance(seal, dict):
        raise StoreError("completed 世代缺少封存块;请检查原运行目录")
    inputs = artifact.get("inputs")
    if not isinstance(inputs, dict):
        raise audit_failure("inputs 缺失")
    machine = inputs.get("machine")
    if (not isinstance(machine, dict)
            or machine.get("report_sha256") != seal.get("report_sha256")
            or machine.get("artifact_digests") != seal.get("artifact_digests")):
        raise audit_failure("机器工件 digest 与 manifest seal 不一致")
    _verify_sealed_files(gen_dir, seal)

    candidate_map = artifact.get("candidate_map")
    if not isinstance(candidate_map, dict):
        raise audit_failure("candidate_map 缺失")
    if (hashlib.sha256(canonical_json(candidate_map).encode("utf-8")).hexdigest()
            != inputs.get("candidate_map_sha256")):
        raise audit_failure("候选映射 digest 与内嵌映射不符")
    if candidate_map.get("generation") != artifact.get("generation"):
        raise audit_failure("候选映射世代与评审工件不一致")

    matches = artifact.get("matches")
    unmatched = artifact.get("unmatched")
    if not isinstance(matches, list) or not isinstance(unmatched, list):
        raise audit_failure("matches/unmatched 缺失或不是数组")
    gt_ids = [match.get("gt_id") for match in matches]
    if any(not isinstance(gt_id, str) or not GT_ID_PATTERN.fullmatch(gt_id)
           for gt_id in gt_ids):
        raise audit_failure("matches 中的 gt_id 非法")
    if len(set(gt_ids)) != len(gt_ids):
        raise audit_failure("matches 中 gt_id 重复")
    mapped_ids = {entry.get("gt_id") for entry in
                  candidate_map.get("candidates", []) if isinstance(entry, dict)}
    mapped_ids |= set(candidate_map.get("unmatched_ground_truth") or [])
    if set(gt_ids) != mapped_ids:
        raise audit_failure("matches 覆盖的 Ground Truth 与候选映射不一致")

    if ground_truth_path is not None:
        ground_truth = load_ground_truth(Path(ground_truth_path))
        digest = hashlib.sha256(
            Path(ground_truth_path).read_bytes()).hexdigest()
        recorded = inputs.get("ground_truth")
        if (not isinstance(recorded, dict)
                or recorded.get("sha256") != digest
                or recorded.get("case_id") != ground_truth["case_id"]):
            raise audit_failure(
                "Ground Truth 文件与评审工件记录的 digest/case_id 不一致")

    findings, dispositions = _machine_views(gen_dir)
    review = _validate_review_reply(
        {"matches": deepcopy(matches), "unmatched": deepcopy(unmatched)},
        gt_ids=gt_ids, findings=findings, dispositions=dispositions)
    # 存储的 result 标签必须与"字段判断 + primary"的确定性复算一致;单改
    # 标签(不动字段)在这里暴露,而不是被复算静默覆盖。
    derived = {match["gt_id"]: match["result"] for match in review["matches"]}
    stored = {match.get("gt_id"): match.get("result")
              for match in matches if isinstance(match, dict)}
    if derived != stored:
        raise audit_failure("结果标签与字段判断的确定性复算不符")
    # machine 侧由封存锚定,可严格复算;reviewed 侧的 severity 快照锚定
    # 评审时刻——覆盖层是追加式的,评审之后合法追加 review 会改变"当前"
    # 投影,因此 reviewed 块只做内部一致性校验,不对当前状态复算。
    machine_severities, _ = _severity_distributions(gen_dir)
    recomputed = compute_metrics(
        len(gt_ids), review["matches"], review["unmatched"],
        machine_severities=machine_severities,
        reviewed_severities=None)["machine"]
    metrics = artifact.get("metrics")
    if not isinstance(metrics, dict) or recomputed != metrics.get("machine"):
        raise audit_failure("machine 指标与决策复算结果不一致")
    reviewed = metrics.get("reviewed")
    if reviewed is not None:
        for key in ("ground_truth_items", "results", "unmatched",
                    "definitive", "confirmed_findings"):
            if reviewed.get(key) != recomputed.get(key):
                raise audit_failure(
                    f"reviewed 指标 {key} 与 machine 块不一致(覆盖层不可及"
                    "字段必须同值)")
        distribution = reviewed.get("severity_distribution")
        if (not isinstance(distribution, dict)
                or any(name not in SEVERITY_LEVELS for name in distribution)
                or sum(distribution.values())
                != recomputed["confirmed_findings"]):
            raise audit_failure("reviewed severity 分布形状非法")
    if _run_context(gen_dir) != artifact.get("run"):
        raise audit_failure("运行面统计与盘上工件不符")
    return artifact

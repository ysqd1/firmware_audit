"""封存机器结果上的追加式 Review Overlay(ADR-0012,票 13)。

人工或 Codex 复核不得编辑封存机器工件;所有复核决定写入世代目录下独立的
``reviews.json``,其 ``reviews`` 数组只增不改(逻辑只追加),经 ``atomic_json``
原子重发布——崩溃只会留下旧版或新版完整文件,不存在撕裂现场。并发追加按
"写后复读"检测:本记录不是文件最后一条时,说明另一复核者赢得了同一次重发布,
明确拒绝并引导重读重提,绝不留下重复序号毒化整份覆盖层。

机器侧事实(findings/verifications/manifest/run_state)的字节不受任何影响;
报告投影把 machine result 与 reviewed result 并列展示并保留完整 review 历史,
Benchmark 默认消费 machine result。

封存判据是 ``run_state.status == "completed"``(票 12 负责写入;在此之前
本 overlay 对真实运行一律拒绝追加,测试可直接构造 completed 世代)。
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
import re
import time
from typing import Any

from .generation import load_run_state
from .severity import SEVERITY_LEVELS
from .store import StoreError, atomic_json, read_json_object
from .verification import load_findings_document as _load_findings_document

REVIEW_SCHEMA_VERSION = 1
REVIEW_PROJECTION_SCHEMA_VERSION = 1

# 可复核目标字段注册表:机器工件可被 overlay 调整的字段白名单,未知字段一律
# 拒绝。v1 只开放 Finding.severity(ADR-0012 故事 129);扩展字段是 schema
# 演进决策,不在追加路径上自由发挥。
REVIEWABLE_FINDING_FIELDS = ("severity",)

_EVIDENCE_ID_PATTERN = re.compile(r"ev-[0-9]{6}")


class ReviewError(ValueError):
    """复核决定被明确拒绝;机器工件与既有 overlay 原样保留。"""


def _evidence_exists(gen_dir: Path, evidence_id: str) -> bool:
    filename = f"{evidence_id}.json"
    for tree in ("investigations", "verifications"):
        if list((gen_dir / tree).glob(f"*/evidence/{filename}")):
            return True
    return False


def _valid_evidence_ids(value: Any) -> bool:
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, str) for item in value))


class ReviewOverlay:
    """一个封存世代的追加式复核覆盖层;只写 ``reviews.json`` 一个文件。"""

    def __init__(self, gen_dir: Path):
        self.gen_dir = Path(gen_dir)
        self.path = self.gen_dir / "reviews.json"

    # ---- 读取与重放 ----

    def records(self) -> list[dict[str, Any]]:
        """按盘上权威记录返回全部 review;覆盖层损坏按 Store 语义拒绝。"""
        if not self.path.exists():
            return []
        document = read_json_object(self.path, "复核覆盖层")
        if (document.get("schema_version") != REVIEW_SCHEMA_VERSION
                or not isinstance(document.get("reviews"), list)):
            raise StoreError("覆盖层结构或版本损坏；请检查 reviews.json")
        records: list[dict[str, Any]] = []
        for index, record in enumerate(document["reviews"]):
            records.append(self._validate_record(record, index))
        return records

    @staticmethod
    def _validate_record(record: Any, index: int) -> dict[str, Any]:
        problems: list[str] = []
        if not isinstance(record, dict):
            problems.append("必须为 object")
        else:
            if type(record.get("seq")) is not int or record["seq"] != index + 1:
                problems.append("seq 不连续")
            target = record.get("target")
            if (not isinstance(target, dict)
                    or target.get("artifact") != "finding"
                    or not isinstance(target.get("finding_id"), str)
                    or not isinstance(target.get("field"), str)):
                problems.append("target 结构非法")
            for key in ("reviewer", "rationale", "old_value", "new_value"):
                if not isinstance(record.get(key), str) or not record[key]:
                    problems.append(f"{key} 非法")
            if not _valid_evidence_ids(record.get("evidence_ids")):
                problems.append("evidence_ids 非法")
            recorded_at = record.get("recorded_at")
            if (not isinstance(recorded_at, (int, float))
                    or isinstance(recorded_at, bool)):
                problems.append("recorded_at 非法")
        if problems:
            raise StoreError(
                f"覆盖层记录 {index + 1} 结构损坏({'；'.join(problems)})；"
                "请检查 reviews.json")
        return record

    # ---- 追加 ----

    def append(
        self,
        *,
        reviewer: str,
        finding_id: str,
        field: str,
        old_value: str,
        new_value: str,
        rationale: str,
        evidence_ids: list[str],
        now: float | None = None,
    ) -> dict[str, Any]:
        """校验并追加一条复核决定;任一校验失败即拒绝,不留部分状态。"""
        self._require_sealed()
        for key, value in (("reviewer", reviewer), ("rationale", rationale)):
            if not isinstance(value, str) or not value.strip():
                raise ReviewError(f"{key} 必须为非空字符串")
        if field not in REVIEWABLE_FINDING_FIELDS:
            raise ReviewError(
                f"未知目标字段 {field!r};可复核字段: "
                f"{', '.join(REVIEWABLE_FINDING_FIELDS)}")
        finding = self._machine_finding(finding_id)
        if field not in finding:
            raise ReviewError(
                f"机器 Finding {finding_id} 没有 {field} 字段;"
                "复核只能调整机器结果已产出的字段")
        records = self.records()
        effective = self._effective_value(records, finding_id, field,
                                          finding[field])
        if old_value != effective:
            raise ReviewError(
                f"旧值失真:目标 {finding_id}.{field} 当前有效值为 "
                f"{effective!r},收到 {old_value!r};请基于最新复核状态重提")
        if field == "severity":
            if new_value not in SEVERITY_LEVELS:
                raise ReviewError(
                    f"severity 新值 {new_value!r} 非法;合法档位: "
                    f"{', '.join(SEVERITY_LEVELS)}")
            if new_value == old_value:
                raise ReviewError("新值与旧值相同,不构成复核修改")
        if not _valid_evidence_ids(evidence_ids):
            raise ReviewError("复核决定必须引用至少一个 Evidence Reference")
        for evidence_id in evidence_ids:
            if not _EVIDENCE_ID_PATTERN.fullmatch(evidence_id):
                raise ReviewError(f"Evidence Reference 格式非法: {evidence_id!r}")
            if not _evidence_exists(self.gen_dir, evidence_id):
                raise ReviewError(
                    f"Evidence {evidence_id} 在运行中不存在;"
                    "复核依据必须指向封存运行内的真实 Evidence")

        record = {
            "seq": len(records) + 1,
            "reviewer": reviewer,
            "recorded_at": float(now if now is not None else time.time()),
            "target": {"artifact": "finding", "finding_id": finding_id,
                       "field": field},
            "old_value": old_value,
            "new_value": new_value,
            "rationale": rationale,
            "evidence_ids": list(evidence_ids),
        }
        published = {"schema_version": REVIEW_SCHEMA_VERSION,
                     "reviews": records + [record]}
        atomic_json(self.path, published)
        # 写后复读:本记录必须仍占据自己的 seq 槽位。同窗并发的输家会被赢家的
        # 重发布顶替(槽位易主或整份变短),明确拒绝且不毒化覆盖层;而基于本
        # 记录之后的合法追加(槽位保留)不受影响。
        republished = self.records()
        if (len(republished) < record["seq"]
                or republished[record["seq"] - 1] != record):
            raise ReviewError(
                "并发追加冲突:另一复核决定已先行落盘;请重读覆盖层后重提")
        return deepcopy(record)

    # ---- 校验辅助 ----

    def _require_sealed(self) -> None:
        state = load_run_state(self.gen_dir)
        status = state["status"] if state is not None else "missing"
        if status != "completed":
            raise ReviewError(
                f"运行未封存(run_state.status={status});"
                "review overlay 只能追加在 completed 世代上")

    def _machine_finding(self, finding_id: str) -> dict[str, Any]:
        for finding in _load_findings_document(self.gen_dir)["findings"]:
            if (isinstance(finding, dict)
                    and finding.get("finding_id") == finding_id):
                return finding
        raise ReviewError(f"未知 Finding {finding_id};目标必须指向机器 Finding")

    @staticmethod
    def _effective_value(records: list[dict[str, Any]], finding_id: str,
                         field: str, machine_value: Any) -> Any:
        """当前有效值 = 机器值经既有 review 依序覆盖;追加前盘上重读。"""
        value = machine_value
        for record in records:
            target = record["target"]
            if target["finding_id"] == finding_id and target["field"] == field:
                value = record["new_value"]
        return value


# ---- 报告投影:machine/reviewed 并列 + 完整历史 ----


def project_review_report(
    findings_document: dict[str, Any], reviews: list[dict[str, Any]],
) -> dict[str, Any]:
    """纯投影:同一 Finding 的 machine result 与 reviewed result 并列。

    reviewed 只在该 Finding 存在覆盖记录时给出(机器字段按 overlay 依序应用);
    summary 分别统计 machine/reviewed severity 分布(reviewed 侧为全部 Finding
    应用 overlay 后的完整分布,未调整者沿用机器值;无任何 review 时为 None)。
    Benchmark 默认消费 machine 侧,reviewed 侧供单独统计。
    """
    findings = [finding for finding in findings_document.get("findings", [])
                if isinstance(finding, dict)]
    machine_severities = Counter(
        finding["severity"] for finding in findings if "severity" in finding)
    by_finding: dict[Any, list[dict[str, Any]]] = {}
    for record in reviews:
        target = record["target"]
        if target["artifact"] == "finding":
            by_finding.setdefault(target["finding_id"], []).append(record)
    entries: list[dict[str, Any]] = []
    reviewed_severities: Counter | None = None
    for finding in findings:
        history = deepcopy(by_finding.get(finding.get("finding_id"), []))
        reviewed = deepcopy(finding)
        for record in history:
            reviewed[record["target"]["field"]] = record["new_value"]
        adjusted = bool(history)
        if adjusted and reviewed_severities is None:
            reviewed_severities = Counter()
        if reviewed_severities is not None:
            # reviewed 侧是完整分布:未调整 Finding 沿用机器 severity。
            effective = reviewed if adjusted else finding
            if "severity" in effective:
                reviewed_severities[effective["severity"]] += 1
        entries.append({
            "finding_id": finding.get("finding_id"),
            "machine": deepcopy(finding),
            "reviewed": reviewed if adjusted else None,
            "history": history,
        })
    return {
        "schema_version": REVIEW_PROJECTION_SCHEMA_VERSION,
        "findings": entries,
        "summary": {
            "machine_severities": dict(machine_severities),
            "reviewed_severities": (dict(reviewed_severities)
                                    if reviewed_severities is not None else None),
            "review_count": len(reviews),
        },
    }


def load_review_projection(gen_dir: Path) -> dict[str, Any]:
    """读取封存世代并产出报告投影;机器工件只读,覆盖层按权威记录重放。

    投影是纯读取:未封存世代没有可追加的覆盖层,投影退化为 machine-only,
    因此不校验封存状态。
    """
    overlay = ReviewOverlay(gen_dir)
    return project_review_report(_load_findings_document(Path(gen_dir)),
                                 overlay.records())

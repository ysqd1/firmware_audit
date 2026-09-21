"""Candidate 接收、去重、评分与双队列选取的 Host 内聚模块。

另承载 Related Candidate 的共享契约:分析/复核两角色提出线索时用同一份字段
规格与校验(``related_candidate_records``/``related_candidate_contract``),运行
结束后由 ``stored_related_proposals``/``related_intake`` 把已校验线索交回 Candidate
Store 消费。

ADR-0012 把"Candidate 接收与去重、队列与优先级"收进 Host:本模块先把 Recon
survey 与 Related Candidate proposals 归一为 ``IntakeCandidate``,按
signal/coverage 两类确定性 fingerprint 合并精确重复,仅对"目标与 Claim
Profile 相同但 fingerprint 不同"的候选发起一次 same/different/uncertain 语义
比较(只有 same 合并);去重完成后才分配运行内递增 ``cand-xxxx``;评分由 LLM
提交 0/1/2 分项与 Evidence 依据、Host 按 signal/coverage 公式计算总分;最后
以 signal/coverage 双队列选取处理名额(默认 8,为最高分 coverage 保留 1)。

语义比较与评分是一次性纯 JSON 请求,不是 Agent Session:请求与结果进
dedup_log 并计入 llm_calls 记账(完整预算语义归后续工单);两者失败都保留
独立 Candidate / 回落 0 分,绝不阻塞流水。
"""
from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .budget import BudgetExhaustedError
from .json_values import JsonValueError, clone_json_value
from .store import (
    CANDIDATE_ID_PATTERN,
    InvestigationStore,
    StoreError,
    atomic_json,
    read_json_object,
)

# Claim Profile 枚举(ADR-0012):Profile 内容与 Claim 门槛由后续工单实现,
# 此处只作为 fingerprint 输入与语义比较门控维度。
CLAIM_PROFILES: tuple[str, ...] = (
    "data_propagation", "config", "credentials", "memory", "generic",
)
DEFAULT_CLAIM_PROFILE = "generic"

_CANDIDATE_KINDS = ("signal", "coverage")

# intake 记录的必填/可选字段。全部已知字段都允许出现在顶层或 extras
# (recon v1 工件把 fingerprint 输入字段收进 extras 透传),归一时顶层优先。
# recon survey 门按同一字段清单做上游类型把关(见 recon._gate 字段常量)。
_INTAKE_REQUIRED_TEXT = ("kind", "target", "signal", "evidence_id", "next_action")
# fingerprint 输入字段的单一来源;recon survey 门复用同一清单做上游类型把关。
FINGERPRINT_INPUT_FIELDS = ("anchor", "mechanism", "component_or_entry", "check_goal")
_INTAKE_OPTIONAL_NULLABLE = ("possible_source", "possible_sink")
_KNOWN_KEYS = frozenset({
    "proposal_id", *_INTAKE_REQUIRED_TEXT, "claim_profile",
    *FINGERPRINT_INPUT_FIELDS, *_INTAKE_OPTIONAL_NULLABLE, "extras",
})

# 已知错误位置(票 25):模型把领域字段包进一个名为 fingerprint 的嵌套对象。
# 真实两例 15 个 proposal 实测 extras.fingerprint.claim_profile 携带非 generic
# 意图却被缺省值静默掩盖。fingerprint 是 Host 派生值,不是可提交字段;嵌套里
# 出现任意已知 intake 字段即整份拒绝,未知嵌套元数据不受影响(不一刀切禁止)。
_MISPLACEMENT_NESTING_KEY = "fingerprint"
_MISPLACEMENT_FIELD_KEYS = _KNOWN_KEYS - {"proposal_id", "extras"}
# 拒绝文案与契约提示共用的平铺字段清单,由常量拼装防漂移。
FLAT_INPUT_FIELDS_HINT = "/".join((
    "claim_profile", *FINGERPRINT_INPUT_FIELDS, *_INTAKE_OPTIONAL_NULLABLE))


class CandidateIntakeError(ValueError):
    """Candidate proposal 未通过归一化契约。

    模型回复方向由调用边界翻译成模型可见的拒绝(ProposalRejectedError),盘上
    记录方向翻译成 StoreError(见 ``_intake_from_stored_record``);错误类型本身
    不表达"给谁看"。
    """


def normalize_target_path(value: str) -> str:
    """fingerprint 用的规范化目标路径:分隔符统一、折叠冗余段、剥尾斜杠。

    不做小写折叠:审计对象是大小写敏感文件系统里的工具路径(ADR-0008)。
    """
    normalized = value.replace("\\", "/")
    collapsed = re.sub(r"/{2,}", "/", normalized)
    while "/./" in collapsed:
        collapsed = collapsed.replace("/./", "/")
    return collapsed.strip().rstrip("/") or "."


def signal_fingerprint(target: str, anchor: str, claim_profile: str, mechanism: str) -> str:
    """signal 精确 fingerprint:目标路径 + 位置锚点 + Claim Profile + 问题机制。

    明文拼接不哈希:CONTEXT.md 把四元组本身定义为身份,明文可读、可 diff、
    可在 dedup_log 里直接解释。
    """
    return "|".join((
        "signal",
        normalize_target_path(target),
        anchor.strip(),
        claim_profile,
        mechanism.strip(),
    ))


def coverage_fingerprint(target: str, component_or_entry: str, check_goal: str) -> str:
    """coverage 精确 fingerprint:目标路径 + 组件或入口 + 检查目标。"""
    return "|".join((
        "coverage",
        normalize_target_path(target),
        component_or_entry.strip(),
        check_goal.strip(),
    ))


@dataclass(frozen=True)
class IntakeCandidate:
    """归一后的 Candidate proposal,等待去重与 ID 分配。

    fingerprint 输入字段(anchor/mechanism 或 component_or_entry/check_goal)
    允许为空字符串——缺失输入按空串参与 fingerprint,即"同 target 同机制缺
    锚点"的两个 proposal 视为精确重复,由提示词引导模型尽量补齐锚点。
    """

    source: str
    proposal_id: str
    kind: str
    target: str
    signal: str
    evidence_id: str
    next_action: str
    claim_profile: str = DEFAULT_CLAIM_PROFILE
    anchor: str = ""
    mechanism: str = ""
    component_or_entry: str = ""
    check_goal: str = ""
    possible_source: str | None = None
    possible_sink: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        if self.kind == "signal":
            return signal_fingerprint(
                self.target, self.anchor, self.claim_profile, self.mechanism,
            )
        return coverage_fingerprint(self.target, self.component_or_entry, self.check_goal)

    def comparison_gate_key(self) -> tuple[str, str]:
        """语义比较门控键:规范化 target + Claim Profile。"""
        return (normalize_target_path(self.target), self.claim_profile)

    def as_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "kind": self.kind,
            "target": self.target,
            "signal": self.signal,
            "evidence_id": self.evidence_id,
            "next_action": self.next_action,
            "claim_profile": self.claim_profile,
            "anchor": self.anchor,
            "mechanism": self.mechanism,
            "component_or_entry": self.component_or_entry,
            "check_goal": self.check_goal,
            "possible_source": self.possible_source,
            "possible_sink": self.possible_sink,
            "extras": dict(self.extras),
        }


def _field_from(record: dict[str, Any], name: str) -> Any:
    """顶层优先,extras 兜底(recon extras 透传链保持 v1 兼容)。"""
    if name in record:
        return record[name]
    extras = record.get("extras")
    if isinstance(extras, dict):
        return extras.get(name)
    return None


def find_misplaced_intake_fields(record: dict[str, Any]) -> tuple[str, ...]:
    """已知领域字段落在已知错误位置(嵌套 ``fingerprint`` 对象)的路径清单。

    只认两种已知错误位置:顶层 ``fingerprint`` 与 extras 直接 ``fingerprint``
    (真实两例实测形态);其余未知嵌套结构按未知 extras 原样保留。返回相对
    proposal 根的路径(如 ``extras.fingerprint.claim_profile``),供
    ``normalize_intake`` 的拒绝文案与 recon survey 门的问题清单共用。
    """
    if not isinstance(record, dict):
        return ()
    extras = record.get("extras")
    locations = (
        ("", record.get(_MISPLACEMENT_NESTING_KEY)),
        ("extras.", extras.get(_MISPLACEMENT_NESTING_KEY)
         if isinstance(extras, dict) else None),
    )
    findings: list[str] = []
    for prefix, nested in locations:
        if isinstance(nested, dict):
            findings.extend(
                f"{prefix}{_MISPLACEMENT_NESTING_KEY}.{key}"
                for key in nested if key in _MISPLACEMENT_FIELD_KEYS)
    return tuple(findings)


def _intake_from_stored_record(record: dict[str, Any], *, source: str) -> IntakeCandidate:
    """归一盘上已入册的 Candidate 记录。

    同一份 intake 契约有两种来源:模型新输入(Recon proposal / Related
    Candidate)失败是 ``CandidateIntakeError``,由调用方翻译成模型可见的拒绝;
    盘上记录损坏则是 Store 语义,必须按 StoreError 停下并引导检查原目录,
    不得让模型契约错误类型冒充磁盘损坏。盘上读取走 ``stored=True``:记录按
    已接受时刻的归一原样复现,不按新契约重新审判(票 25 旧恢复兼容——修复前
    入册的错放历史保持 generic + extras 透传,续跑与重放等幂;已封存世代不
    重算、不改写)。
    """
    try:
        return normalize_intake(record, source=source, stored=True)
    except (CandidateIntakeError, JsonValueError) as exc:
        raise StoreError(
            f"既有 Candidate 记录未通过 intake 契约；请检查原运行目录: {exc}") from exc


def _text(value: Any, *, nullable: bool = False) -> str | None:
    if value is None:
        if nullable:
            return None
        return ""
    if not isinstance(value, str):
        raise CandidateIntakeError(f"必须是非空字符串或缺失: {value!r}")
    return value.strip()


def normalize_intake(
    record: dict[str, Any],
    *,
    source: str,
    proposal_id: str | None = None,
    stored: bool = False,
) -> IntakeCandidate:
    """把 recon survey proposal 或 Related Candidate 记录归一为 IntakeCandidate。

    必填 kind/target/signal/evidence_id/next_action;claim_profile 缺省
    generic 且必须属于枚举;fingerprint 输入与 possible_source/sink 为可选
    字符串;未知键保留进 extras(顶层已知键除外),不丢信息。

    模型新输入(默认)把已知领域字段嵌进 ``fingerprint`` 对象的整份拒绝并
    告知正确字段位置(票 25);``stored=True`` 供盘上已入册记录复现已接受
    形态,不做错放拒绝(见 ``_intake_from_stored_record``)。
    """
    if not isinstance(record, dict):
        raise CandidateIntakeError("Candidate proposal 必须是 JSON object")
    if not isinstance(source, str) or not source.strip():
        raise CandidateIntakeError("source 必须是非空字符串")
    resolved_id = proposal_id if proposal_id is not None else record.get("proposal_id")
    if not isinstance(resolved_id, str) or not resolved_id.strip():
        raise CandidateIntakeError("proposal_id 必须是非空字符串")

    misplaced = find_misplaced_intake_fields(record)
    if misplaced and not stored:
        raise CandidateIntakeError(
            "proposal 把已知字段嵌进了 "
            f"{_MISPLACEMENT_NESTING_KEY} 对象({', '.join(misplaced)});"
            f"{_MISPLACEMENT_NESTING_KEY} 由 Host 派生,不是可提交字段。请把这些字段"
            f"平铺在 proposal 顶层({FLAT_INPUT_FIELDS_HINT},extras "
            "直接字段亦可),并完整重新生成整份 proposal,不要只改动嵌套结构")

    values: dict[str, Any] = {}
    for name in _INTAKE_REQUIRED_TEXT:
        raw = _field_from(record, name)
        if raw is None:
            raise CandidateIntakeError(f"缺少必填字段: {name}")
        text = _text(raw)
        if not text:
            raise CandidateIntakeError(f"必填字段不能为空白: {name}")
        values[name] = text
    if values["kind"] not in _CANDIDATE_KINDS:
        raise CandidateIntakeError(
            f"kind 只允许 {_CANDIDATE_KINDS}: {values['kind']!r}")

    profile = _field_from(record, "claim_profile")
    if profile is None:
        profile = DEFAULT_CLAIM_PROFILE
    profile = _text(profile)
    if profile not in CLAIM_PROFILES:
        raise CandidateIntakeError(f"claim_profile 只允许 {CLAIM_PROFILES}: {profile!r}")

    for name in FINGERPRINT_INPUT_FIELDS:
        raw = _field_from(record, name)
        values[name] = "" if raw is None else _text(raw)
    for name in _INTAKE_OPTIONAL_NULLABLE:
        raw = _field_from(record, name)
        values[name] = None if raw is None else _text(raw, nullable=True)

    known = _KNOWN_KEYS | {"proposal_id"}
    extras = {
        key: value for key, value in record.items() if key not in known
    }
    raw_extras = record.get("extras")
    if isinstance(raw_extras, dict):
        extras.update({
            key: value for key, value in raw_extras.items()
            if key not in FINGERPRINT_INPUT_FIELDS and key != "claim_profile"
        })
    extras = clone_json_value(extras, "Candidate proposal extras")

    return IntakeCandidate(
        source=source.strip(),
        proposal_id=resolved_id.strip(),
        kind=values["kind"],
        target=values["target"],
        signal=values["signal"],
        evidence_id=values["evidence_id"],
        next_action=values["next_action"],
        claim_profile=profile,
        anchor=values["anchor"],
        mechanism=values["mechanism"],
        component_or_entry=values["component_or_entry"],
        check_goal=values["check_goal"],
        possible_source=values["possible_source"],
        possible_sink=values["possible_sink"],
        extras=extras,
    )


# ---- Related Candidate:两角色共用的校验与提示契约 ----

# 模型回复里必须自带的字段:proposal_id 加上 intake 自身的必填文本字段清单,
# 与 normalize_intake 同源,不另抄一份(claim_profile/possible_*/extras 仍按
# intake 缺省规则处理)。
RELATED_CANDIDATE_FIELDS = ("proposal_id", *_INTAKE_REQUIRED_TEXT)
_RELATED_ROLES = ("analysis", "verification")
# relation 字符串 → 角色,登记在案而非靠后缀解析。
_RELATION_ROLES = {f"{role}_related": role for role in _RELATED_ROLES}
# 独立入口/位置/机制门槛:两角色一致,按 kind 取对应字段,至少一项非空。
RELATED_INDEPENDENCE_FIELDS: dict[str, tuple[str, ...]] = {
    "signal": ("anchor", "mechanism"),
    "coverage": ("component_or_entry", "check_goal"),
}
# 引用纪律的角色措辞:证据集合由调用方给出,这里只决定报错怎么说。
_EVIDENCE_DISCIPLINE = {
    "analysis": "本 Investigation 的 Evidence",
    "verification": "本次复核会话独立取得的 Evidence",
}
# 分支观察该写回哪里:analysis 写 Claim,verification 写 Claim Result。
_OBSERVATION_TARGET = {"analysis": "Claim", "verification": "Claim Result"}


@dataclass(frozen=True)
class RelatedOrigin:
    """Related Candidate 的来源身份:提出角色 + 提出时的 Candidate/Investigation。"""

    role: str
    candidate_id: str
    investigation_id: str

    def __post_init__(self) -> None:
        if self.role not in _RELATED_ROLES:
            raise CandidateIntakeError(
                f"未知 Related Candidate 提出角色 {self.role!r};允许值: "
                + ", ".join(_RELATED_ROLES))
        for name in ("candidate_id", "investigation_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise CandidateIntakeError(f"Related Candidate 来源缺少 {name}")

    @property
    def source(self) -> str:
        """proposal 的稳定来源标签(来源角色 + 提出方 Candidate)。"""
        return f"{self.role}:{self.candidate_id}"

    def record(self) -> dict[str, Any]:
        """落盘用的来源关系块;由 Host 盖章,模型提供的同名字段一律被覆盖。"""
        return {
            "relation": f"{self.role}_related",
            "from_candidate": self.candidate_id,
            "from_investigation": self.investigation_id,
        }


def related_candidate_records(
    entries: Any,
    *,
    evidence_ids: frozenset[str],
    origin: RelatedOrigin,
    label: str = "state_delta.related_candidates",
) -> tuple[dict[str, Any], ...]:
    """校验并固化 Related Candidate proposal(analysis 与 verification 单一出处)。

    契约 = Candidate intake 契约(必填/类型/Profile/fingerprint 输入)+ 独立入口
    门槛 + 引用纪律(只能指向调用方给出的证据集合)。返回的记录带 Host 盖章的
    ``origin``,``source`` 由来源身份派生,模型无法冒充来源。违规抛
    ``CandidateIntakeError``,由调用边界翻译成模型可见的拒绝。
    """
    if not isinstance(entries, list) or not entries:
        raise CandidateIntakeError(f"{label} 必须为非空数组")
    records: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        item_label = f"{label}[{index}]"
        if not isinstance(entry, dict):
            raise CandidateIntakeError(f"{item_label} 必须为 JSON object")
        try:
            intake = normalize_intake(entry, source=origin.source)
        except CandidateIntakeError as exc:
            raise CandidateIntakeError(f"{item_label} 未通过 Candidate 契约: {exc}") from exc
        if intake.evidence_id not in evidence_ids:
            raise CandidateIntakeError(
                f"{item_label}.evidence_id 必须引用{_EVIDENCE_DISCIPLINE[origin.role]};"
                f"实际引用 {intake.evidence_id!r}")
        independent = RELATED_INDEPENDENCE_FIELDS[intake.kind]
        if not any(getattr(intake, name).strip() for name in independent):
            raise CandidateIntakeError(
                f"{item_label} 缺少独立入口、位置或机制字段"
                f"({'/'.join(independent)} 至少其一);"
                f"同一案卷内的分支观察应写入 {_OBSERVATION_TARGET[origin.role]},"
                "不构成 Related Candidate")
        records.append({"origin": origin.record(), **intake.as_dict()})
    return tuple(records)


# 提示里可直接照抄的完整 state_delta 片段(两段覆盖 signal/coverage 两类线索)。
_RELATED_EXAMPLES: tuple[dict[str, Any], ...] = (
    {"related_candidates": [{
        "proposal_id": "rel-cand-0001-1", "kind": "signal",
        "target": "extracted/bin/updater", "signal": "升级包解析未校验长度字段",
        "evidence_id": "ev-000123", "next_action": "反编译解析函数确认边界检查",
        "anchor": "parse_header+0x42", "mechanism": "integer overflow",
    }]},
    {"related_candidates": [{
        "proposal_id": "rel-cand-0001-2", "kind": "coverage",
        "target": "extracted/usr/bin/mqtt_client", "signal": "MQTT 客户端未见入站报文校验",
        "evidence_id": "ev-000123", "next_action": "审计入站解析与主题授权",
        "component_or_entry": "mqtt_client 订阅回调", "check_goal": "入站主题与载荷校验覆盖",
    }]},
)


def related_candidate_contract() -> str:
    """Related Candidate 的 LLM 可读契约(analysis 与 verification 单一出处)。

    字段清单与 ``normalize_intake`` 同源;示例是完整 state_delta 片段,由测试
    钉住"提示里写的样例真的能过解析与领域校验"。
    """
    lines = [
        "在 state_delta.related_candidates 里提交线索,每项必须自带:",
        "- proposal_id:本角色内唯一的线索 ID(同来源重复提交同 ID 视为同一项,内容必须一致)",
        "- kind:signal 或 coverage",
        "- target:工具路径(如 extracted/etc/device.conf)",
        "- signal:触发该线索的具体信号",
        "- evidence_id:你本次已取得的 Evidence ID,作为该线索的初始证据",
        "- next_action:下一步调查动作",
        "signal 线索还需 anchor(位置锚点)或 mechanism(问题机制)至少其一;coverage",
        "线索需 component_or_entry(组件或入口)或 check_goal(检查目标)至少其一。两者",
        "都为空说明它只是同一案卷内的分支观察,请写进 Claim,不要新开线索。可选字段",
        "claim_profile(缺省 generic)、possible_source/possible_sink。这些输入字段一律",
        "平铺在每项顶层(extras 直接字段亦可);fingerprint 由 Host 派生,不是可提交",
        "字段,包成嵌套的 fingerprint 对象会被整份拒绝。",
    ]
    for example, kind in zip(_RELATED_EXAMPLES, ("signal", "coverage")):
        lines += [
            f"示例(state_delta 片段,{kind}):",
            "```json",
            json.dumps(example, ensure_ascii=False),
            "```",
        ]
    return "\n".join(lines) + "\n"


def related_candidate_conflicts(
    records: tuple[dict[str, Any], ...],
    existing: list[dict[str, Any]],
) -> tuple[str, ...]:
    """同来源同一 proposal_id 但内容不同的线索 ID(两角色共用的幂等判据)。

    什么都不返回表示这次提交要么是新线索、要么是同一内容的恢复重放,可以幂等
    跳过;返回的 ID 说明模型想改写已入册线索,必须整份拒绝而非静默覆盖。
    """
    prior = {
        item["proposal_id"]: item for item in existing
        if isinstance(item, dict) and isinstance(item.get("proposal_id"), str)
    }
    return tuple(
        record["proposal_id"] for record in records
        if record["proposal_id"] in prior
        and prior[record["proposal_id"]] != record
    )


def related_intake(record: dict[str, Any]) -> IntakeCandidate:
    """已校验记录 → Candidate Store 可消费的 intake(票 11 幂等回队入口)。

    ``source`` 由记录里的 Host 盖章 origin 还原,不由调用方另传,避免跨来源
    同名 proposal 混源;记录损坏按 Store 语义拒绝。
    """
    origin = record.get("origin") if isinstance(record, dict) else None
    if not isinstance(origin, dict):
        raise StoreError("Related Candidate 记录缺少来源关系;请检查原运行目录")
    role = _RELATION_ROLES.get(origin.get("relation"))
    candidate_id = origin.get("from_candidate")
    if role is None:
        raise StoreError("Related Candidate 来源关系损坏;请检查原运行目录")
    try:
        source = RelatedOrigin(role, candidate_id, origin.get("from_investigation")).source
    except CandidateIntakeError as exc:
        raise StoreError(
            f"Related Candidate 来源身份损坏;请检查原运行目录: {exc}") from exc
    return _intake_from_stored_record(record, source=source)


def stored_related_proposals(run_dir: Path) -> tuple[dict[str, Any], ...]:
    """运行目录内两角色已校验的 Related Candidate(票 11 幂等回队入口)。

    只读权威工件,不解析 Transcript,也不依赖是否生成 Finding:分析侧取
    ``investigations/<cand>/state.json`` 的 ``state.related_candidates``,复核侧取
    ``verifications/<cand>/results.json``(中断未收尾的会话取同目录 state.json 的
    ``session.related_candidates``)。同一来源(relation + from_candidate +
    proposal_id)重复出现只保留一条;此处不合并候选、不分配 Candidate ID。
    """
    collected: dict[tuple[str, str, str], dict[str, Any]] = {}

    def collect(entries: Any) -> None:
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                raise StoreError("Related Candidate 记录结构损坏;请检查原运行目录")
            origin = entry.get("origin")
            proposal_id = entry.get("proposal_id")
            if not isinstance(origin, dict) or not isinstance(proposal_id, str):
                raise StoreError("Related Candidate 记录缺少来源或身份;请检查原运行目录")
            abstract_intake = (origin.get("relation"), origin.get("from_candidate"))
            if not all(isinstance(item, str) and item for item in abstract_intake):
                raise StoreError("Related Candidate 来源关系损坏;请检查原运行目录")
            collected.setdefault((*abstract_intake, proposal_id), entry)

    run_dir = Path(run_dir)
    for directory in sorted((run_dir / "investigations").glob("cand-*")):
        snapshot = InvestigationStore(run_dir, directory.name).load()
        investigation = snapshot.get("investigation") if isinstance(snapshot, dict) else None
        state = investigation.get("state") if isinstance(investigation, dict) else None
        collect(state.get("related_candidates") if isinstance(state, dict) else None)
    for directory in sorted((run_dir / "verifications").glob("cand-*")):
        results_path = directory / "results.json"
        if results_path.exists():
            try:
                payload = json.loads(results_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise StoreError(f"复核结果损坏;请检查原运行目录: {exc}") from exc
            collect(payload.get("related_candidates") if isinstance(payload, dict) else None)
            continue
        if not ((directory / "state.json").exists() or (directory / "events.jsonl").exists()):
            continue
        snapshot = InvestigationStore(run_dir, directory.name, root="verifications").load()
        session = snapshot.get("session") if isinstance(snapshot, dict) else None
        collect(session.get("related_candidates") if isinstance(session, dict) else None)
    return tuple(collected.values())


# ---- 语义去重 ----

COMPARISON_VERDICTS: tuple[str, ...] = ("same", "different", "uncertain")


@dataclass(frozen=True)
class ComparisonOutcome:
    """一次语义比较的结果;失败形态也是一等结果,不抛出打断去重。

    status: ok(合法 verdict)/ invalid_reply(协议无效)/ service_error(模型
    服务失败,含重试耗尽)。三种失败与 different/uncertain 一样保留独立
    Candidate——宁可不合并不吞线索。
    """

    status: Literal["ok", "invalid_reply", "service_error"]
    verdict: str | None
    rationale: str | None = None
    raw_reply: str | None = None


DEDUP_COMPARATOR_SYSTEM = """## 角色
你是固件审计 Candidate 去重判定器。给你两个 Candidate proposal,判断它们是否
指向同一个需要独立调查的问题(或同一个需要覆盖检查的目标)。

## 判定口径
- same: 两者指向同一目标上的同一问题机制/同一覆盖检查目标,合并后只值得
  一次 Investigation。
- different: 两者明显是不同问题(不同机制、不同入口或不同覆盖目标)。
- uncertain: 证据不足以判断。不确定时必须判 uncertain,不得猜测;uncertain
  保留独立 Candidate,不会丢失线索。

## 回复协议
只输出一份纯 JSON,不要 Markdown 或额外文字:
{"verdict": "same" | "different" | "uncertain", "rationale": "一句话依据"}"""


class SemanticComparator:
    """语义比较的一次性纯 JSON LLM 请求(非 Agent Session,无工具循环)。

    ``llm`` 为鸭子类型 ``.chat(messages) -> (reply, usage)``;任何抛出(含
    LLMError 重试耗尽)都归为 service_error,由调用方保留独立 Candidate。
    """

    def __init__(self, llm):
        self.llm = llm

    def compare(
        self,
        existing: IntakeCandidate,
        incoming: IntakeCandidate,
    ) -> ComparisonOutcome:
        request = comparison_request_payload(existing, incoming)
        messages = [
            {"role": "system", "content": DEDUP_COMPARATOR_SYSTEM},
            {"role": "user", "content": json.dumps(request, ensure_ascii=False)},
        ]
        try:
            reply, _usage = self.llm.chat(messages)
        except BudgetExhaustedError:
            # 预算拒绝不是语义比较失败:耗尽必须中止流水,不得被误判为
            # uncertain 而保留独立 Candidate 后继续发请求(票 11 AC16)。
            raise
        except Exception:
            return ComparisonOutcome(status="service_error", verdict=None)
        try:
            payload = json.loads(reply)
            if not isinstance(payload, dict):
                raise ValueError("回复必须是 JSON object")
            verdict = payload.get("verdict")
            rationale = payload.get("rationale")
            if verdict not in COMPARISON_VERDICTS or (
                    rationale is not None and not isinstance(rationale, str)):
                raise ValueError("verdict 非法")
        except Exception:
            return ComparisonOutcome(
                status="invalid_reply", verdict=None, raw_reply=str(reply))
        return ComparisonOutcome(
            status="ok", verdict=verdict,
            rationale=rationale if isinstance(rationale, str) else None,
            raw_reply=str(reply),
        )


def comparison_request_payload(
    existing: IntakeCandidate,
    incoming: IntakeCandidate,
) -> dict[str, Any]:
    return {
        "existing_candidate": existing.as_dict(),
        "incoming_proposal": incoming.as_dict(),
        "question": "两者是否指向同一需要独立调查的问题或同一覆盖检查目标?",
    }


@dataclass(frozen=True)
class DedupResult:
    """去重终态:幸存 Candidate 记录(带已分配 ID)、按 ID 索引的归一 intake
    (供评分等后续阶段直接消费,不必从记录再归一一次)、决策日志与 LLM 计数。"""

    candidates: list[dict[str, Any]]
    intakes: dict[str, IntakeCandidate]
    dedup_log: list[dict[str, Any]]
    llm_calls: int


@dataclass
class _Survivor:
    """去重过程中的幸存者:主 proposal 不变,后来者只进 alias 与合并记录。"""

    intake: IntakeCandidate
    candidate_id: str | None
    aliases: list[str]
    merged: list[dict[str, Any]]
    # 既有记录的评分结果随幸存者往返:ID 不改号,评分也不因增量重入队而丢失。
    carried_priority: dict[str, Any] | None = None

    def to_record(self) -> dict[str, Any]:
        record = dict(self.intake.as_dict())
        record.pop("proposal_id", None)
        payload = {
            "candidate_id": self.candidate_id,
            "source": self.intake.source,
            "proposal_id": self.intake.proposal_id,
            **record,
            "fingerprint": self.intake.fingerprint(),
            "aliases": list(self.aliases),
            "merged_proposals": [dict(item) for item in self.merged],
        }
        if self.carried_priority is not None:
            payload["priority"] = dict(self.carried_priority)
        return payload

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> _Survivor:
        # 先做结构把关,再归一内容:盘上记录损坏一律 StoreError,不落进
        # normalize_intake 的模型契约错误通道(票 17/S6)。
        if not isinstance(record, dict):
            raise StoreError("既有 Candidate 记录结构损坏;请检查原运行目录")
        candidate_id = record.get("candidate_id")
        aliases = record.get("aliases", [])
        merged = record.get("merged_proposals", [])
        priority = record.get("priority")
        if (not isinstance(candidate_id, str)
                or not CANDIDATE_ID_PATTERN.fullmatch(candidate_id)
                or not isinstance(aliases, list)
                or not all(isinstance(item, str) for item in aliases)
                or not isinstance(merged, list)
                or not all(isinstance(item, dict) for item in merged)
                or (priority is not None and not isinstance(priority, dict))):
            # 盘上既有记录损坏属 Store 语义:停止并引导检查,不混入 intake 契约错误。
            raise StoreError("既有 Candidate 记录结构损坏;请检查原运行目录")
        # 记账键(candidate_id/source/fingerprint/aliases/merged_proposals/priority)
        # 与派生字段(queue/disposition,每次 build 重算)不参与 intake 归一,否则
        # 会漏进 extras 导致重放比对误判"内容不同"。
        bookkeeping = {"candidate_id", "source", "fingerprint", "aliases",
                       "merged_proposals", "queue", "disposition", "priority"}
        intake = _intake_from_stored_record(
            {key: value for key, value in record.items() if key not in bookkeeping},
            source=record.get("source", "recon"),
        )
        return cls(intake, candidate_id, list(aliases),
                   [dict(item) for item in merged],
                   dict(priority) if priority is not None else None)


def _merge_into(
    survivor: _Survivor,
    incoming: IntakeCandidate,
    merged_via: str,
    comparison: dict[str, Any] | None,
) -> None:
    survivor.aliases.append(incoming.proposal_id)
    survivor.merged.append({
        "source": incoming.source,
        **incoming.as_dict(),
        "merged_via": merged_via,
        "comparison": comparison,
    })


def deduplicate(
    intakes: list[IntakeCandidate],
    *,
    comparator,
    existing: list[dict[str, Any]] | None = None,
) -> DedupResult:
    """把 intake 序列去重为幸存 Candidate,去重完成后才分配递增 ID。

    精确 fingerprint 重复确定性合并(零 LLM);仅对"规范化 target 与 Claim
    Profile 相同但 fingerprint 不同"的候选,与其中最早创建的幸存者做一次
    语义比较;只有 same 合并,different/uncertain/协议无效/服务失败保留
    独立。既有 Candidate(增量再入队)保持原 ID 且信息补充不改号。
    """
    survivors: list[_Survivor] = [
        _Survivor.from_record(record) for record in (existing or [])
    ]
    # 已入册 proposal 的权威内容:主 proposal 与被合并 proposal 各自记 own 内容,
    # 幂等重入按"同 ID 同内容跳过、同 ID 异内容拒绝"逐条比对。
    processed: dict[str, dict[str, Any]] = {
        survivor.intake.proposal_id: survivor.intake.as_dict()
        for survivor in survivors
    }
    for item in survivors:
        for merged_item in item.merged:
            merged_id = merged_item.get("proposal_id")
            if isinstance(merged_id, str) and merged_id not in processed:
                processed[merged_id] = {
                    key: value for key, value in merged_item.items()
                    if key not in ("source", "merged_via", "comparison")
                }

    dedup_log: list[dict[str, Any]] = []
    llm_calls = 0
    for incoming in intakes:
        known = processed.get(incoming.proposal_id)
        if known is not None:
            if known != incoming.as_dict():
                raise CandidateIntakeError(
                    f"proposal_id {incoming.proposal_id!r} 已按不同内容入册,拒绝复用")
            dedup_log.append({
                "type": "skipped_known_proposal",
                "proposal_id": incoming.proposal_id,
            })
            continue

        exact = next(
            (s for s in survivors if s.intake.fingerprint() == incoming.fingerprint()),
            None,
        )
        if exact is not None:
            _merge_into(exact, incoming, "exact_fingerprint", None)
            dedup_log.append({
                "type": "exact_merge",
                "survivor": exact.candidate_id,
                "incoming": incoming.proposal_id,
                "fingerprint": incoming.fingerprint(),
            })
            processed[incoming.proposal_id] = incoming.as_dict()
            continue

        gated = next(
            (s for s in survivors
             if s.intake.comparison_gate_key() == incoming.comparison_gate_key()),
            None,
        )
        if gated is None:
            survivors.append(_Survivor(incoming, None, [], []))
            dedup_log.append({
                "type": "created",
                "incoming": incoming.proposal_id,
            })
            processed[incoming.proposal_id] = incoming.as_dict()
            continue

        llm_calls += 1
        outcome = comparator.compare(gated.intake, incoming)
        request = comparison_request_payload(gated.intake, incoming)
        comparison = {
            "request": request,
            "verdict": outcome.verdict,
            "rationale": outcome.rationale,
        }
        if outcome.status == "ok" and outcome.verdict == "same":
            _merge_into(gated, incoming, "semantic_same", comparison)
            dedup_log.append({
                "type": "semantic_merge",
                "survivor": gated.candidate_id,
                "incoming": incoming.proposal_id,
                "verdict": "same",
                "rationale": outcome.rationale,
                "request": request,
            })
        else:
            survivors.append(_Survivor(incoming, None, [], []))
            # ADR-0012:比较请求与结果进决策日志——不同/不确定/失败也要留痕。
            entry = {
                "type": "kept_independent",
                "incoming": incoming.proposal_id,
                "compared_with": gated.candidate_id,
                "verdict": outcome.verdict,
                "reason": outcome.status if outcome.status != "ok" else outcome.verdict,
                "request": request,
                "rationale": outcome.rationale,
            }
            if outcome.raw_reply is not None:
                entry["raw_reply"] = outcome.raw_reply
            dedup_log.append(entry)
        processed[incoming.proposal_id] = incoming.as_dict()

    next_seq = max(
        (int(s.candidate_id.split("-")[1]) for s in survivors
         if isinstance(s.candidate_id, str) and s.candidate_id.startswith("cand-")),
        default=0,
    ) + 1
    for survivor in survivors:
        if survivor.candidate_id is None:
            survivor.candidate_id = f"cand-{next_seq:04d}"
            next_seq += 1
    return DedupResult(
        candidates=[survivor.to_record() for survivor in survivors],
        intakes={
            survivor.candidate_id: survivor.intake for survivor in survivors
        },
        dedup_log=dedup_log,
        llm_calls=llm_calls,
    )


# ---- 优先级评分:LLM 只交 0/1/2 分项与依据,Host 计算总分 ----

SIGNAL_FACTORS: tuple[str, ...] = (
    "external_reachability", "input_control", "high_impact_operation",
    "path_progress", "material_strength", "estimated_cost",
)
COVERAGE_FACTORS: tuple[str, ...] = (
    "component_value", "external_exposure", "unchecked_extent", "estimated_cost",
)
# 各分项中文释义进评分提示词;Host 侧只认枚举名与 0/1/2 数值。
_FACTOR_LABELS: dict[str, str] = {
    "external_reachability": "外部可达性",
    "input_control": "输入可控性",
    "high_impact_operation": "高影响操作",
    "path_progress": "路径进展",
    "material_strength": "材料强度",
    "component_value": "组件价值",
    "external_exposure": "外部暴露程度",
    "unchecked_extent": "尚未检查程度",
    "estimated_cost": "预计成本(越高越贵,从总分中扣减)",
}


def factors_for_kind(kind: str) -> tuple[str, ...]:
    if kind == "signal":
        return SIGNAL_FACTORS
    if kind == "coverage":
        return COVERAGE_FACTORS
    raise CandidateIntakeError(f"未知 Candidate kind: {kind!r}")


def grounded_factor(item: Any, evidence_ids) -> tuple[int, bool, str | None, str | None]:
    """单分项判定:"缺少依据时取 0" 的确定性兜底。

    计入条件 = score 是 {0,1,2} 中的 int(布尔显式排除)且 evidence_id 非空
    并指向真实 Evidence;返回 (有效值, 是否计入, evidence_id, note)。
    """
    if not isinstance(item, dict):
        return 0, False, None, None
    score = item.get("score")
    evidence_id = item.get("evidence_id")
    note = item.get("note")
    grounded = (
        type(score) is int and score in (0, 1, 2)
        and isinstance(evidence_id, str) and evidence_id.strip() in evidence_ids
    )
    return (
        score if grounded else 0,
        grounded,
        evidence_id if isinstance(evidence_id, str) and evidence_id.strip() else None,
        note if isinstance(note, str) else None,
    )


def compute_total(kind: str, values: dict[str, int]) -> int:
    """Host 公式:正项之和减预计成本;缺项按 0。"""
    factors = factors_for_kind(kind)
    positives = factors[:-1]
    cost = factors[-1]
    return sum(int(values.get(name, 0)) for name in positives) \
        - int(values.get(cost, 0))


PRIORITY_SCORER_SYSTEM_TEMPLATE = """## 角色
你是固件审计 Candidate 优先级评分器。对给定 Candidate 的 {kind} 队列
优先级分项逐项给出 0/1/2 分与 Evidence 依据;Host 按公式计算总分,不采纳
你直接给出的任何总分。

## 分项(只允许这些,0=低/无,1=中,2=高)
{factor_lines}

## 依据纪律
- 每个分项必须给出 evidence_id(来自用户消息中列出的 Evidence);没有依据
  的分项给 0 分,不要凭印象打分。
- estimated_cost 是预计调查成本,分数越高成本越高,会从总分中扣减。

## 回复协议
只输出一份纯 JSON,不要 Markdown 或额外文字:
{{"factors": {{"<分项名>": {{"score": 0|1|2, "evidence_id": "ev-xxxxxx" 或 null, "note": "一句话"}}}}}}"""

class PriorityScorer:
    """优先级评分的一次性纯 JSON LLM 请求;无效/失败确定性回落全 0 分。"""

    def __init__(self, llm, evidence_context: dict[str, str]):
        self.llm = llm
        self.evidence_context = dict(evidence_context)

    def score(self, candidate: IntakeCandidate) -> dict[str, Any]:
        factors = factors_for_kind(candidate.kind)
        messages = [
            {"role": "system", "content": self._system_prompt(candidate.kind)},
            {"role": "user", "content": json.dumps({
                "candidate": candidate.as_dict(),
                "available_evidence": self.evidence_context,
                "task": f"对该 {candidate.kind} Candidate 逐项打分",
            }, ensure_ascii=False)},
        ]
        try:
            reply, _usage = self.llm.chat(messages)
        except BudgetExhaustedError:
            # 预算拒绝不是评分失败:不得回落全 0 分并继续为后续候选发请求。
            raise
        except Exception:
            return self._result(candidate.kind, {}, "service_error")
        try:
            payload = json.loads(reply)
            if not isinstance(payload, dict) or not isinstance(payload.get("factors"), dict):
                raise ValueError("factors 非法")
        except Exception:
            return self._result(
                candidate.kind, {}, "invalid_reply", raw_reply=str(reply))
        evidence_ids = frozenset(self.evidence_context)
        values: dict[str, int] = {}
        factor_results: dict[str, dict[str, Any]] = {}
        for name in factors:
            value, grounded, evidence_id, note = grounded_factor(
                payload["factors"].get(name), evidence_ids)
            values[name] = value
            factor_results[name] = {
                "score": value,
                "evidence_id": evidence_id,
                "note": note,
                "used": grounded,
            }
        return self._result(
            candidate.kind, factor_results, "ok", values=values,
            raw_submission=payload,
        )

    def _system_prompt(self, kind: str) -> str:
        factor_lines = "\n".join(
            f"- {name}: {_FACTOR_LABELS[name]}" for name in factors_for_kind(kind)
        )
        return PRIORITY_SCORER_SYSTEM_TEMPLATE.format(
            kind=kind, factor_lines=factor_lines,
        )

    @staticmethod
    def _result(
        kind: str,
        factor_results: dict[str, Any],
        status: str,
        *,
        values: dict[str, int] | None = None,
        raw_submission: dict[str, Any] | None = None,
        raw_reply: str | None = None,
    ) -> dict[str, Any]:
        factors = factors_for_kind(kind)
        if not factor_results:
            factor_results = {
                name: {"score": 0, "evidence_id": None, "note": None, "used": False}
                for name in factors
            }
            values = {name: 0 for name in factors}
        return {
            "factors": {name: factor_results[name] for name in factors},
            "total": compute_total(kind, values or {}),
            "status": status,
            "raw": raw_submission if raw_submission is not None else raw_reply,
        }


def make_priority_scorer(llm):
    """``CandidateStore.build`` 的 scorer_factory 生产实现。"""
    return lambda evidence_context: PriorityScorer(llm, evidence_context)


# ---- signal/coverage 双队列选取 ----

DEFAULT_PROCESSING_SLOTS = 8


def resolve_processing_slots() -> int:
    """STEP5_CANDIDATE_SLOTS 覆盖处理名额(缺失/非法回落默认,下限 1)。"""
    raw = os.environ.get("STEP5_CANDIDATE_SLOTS", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_PROCESSING_SLOTS
    except ValueError:
        return DEFAULT_PROCESSING_SLOTS
    return max(1, value)


@dataclass(frozen=True)
class Selection:
    """选取终态:入选 ID(处理顺序)、各队列归属与队内名次。

    处理顺序 = signal 入选在前、coverage 入选在后(ADR 未指定跨队交错,
    运行世代工单可视需要调整;队内顺序永远是 分数降序 + 创建顺序)。
    """

    selected: tuple[str, ...]
    queue_of: dict[str, str]
    rank_of: dict[str, int]
    slots: int
    coverage_reserved: bool


def select_for_processing(records: list[dict[str, Any]], *, slots: int) -> Selection:
    """默认名额为最高分 coverage 保留一个;无 coverage 时名额归还 signal。

    signal 队不满时余量按分数续取 coverage,不闲置名额——保留名额的目的是
    防止密集 signal 挤掉覆盖责任,而不是让名额空转。队内排序 (−total,
    candidate_id 升序),同分按创建顺序(Candidate ID 即创建顺序)。
    """
    if type(slots) is not int or slots < 1:
        raise ValueError("slots 必须是 >=1 的整数")
    queues: dict[str, list[dict[str, Any]]] = {"signal": [], "coverage": []}
    for record in records:
        kind = record.get("kind")
        priority = record.get("priority")
        if kind not in queues:
            raise ValueError(f"候选记录缺少合法 kind: {record.get('candidate_id')!r}")
        if not isinstance(priority, dict) or type(priority.get("total")) is not int:
            raise ValueError(f"候选记录缺少 priority.total: {record.get('candidate_id')!r}")
        queues[kind].append(record)

    queue_of: dict[str, str] = {}
    rank_of: dict[str, int] = {}
    ordered: dict[str, list[str]] = {}
    for kind, queue in queues.items():
        queue.sort(key=lambda item: (-item["priority"]["total"], item["candidate_id"]))
        ordered[kind] = [item["candidate_id"] for item in queue]
        for rank, candidate_id in enumerate(ordered[kind], start=1):
            queue_of[candidate_id] = kind
            rank_of[candidate_id] = rank

    coverage_reserved = bool(ordered["coverage"])
    signal_capacity = slots - 1 if coverage_reserved else slots
    selected_signal = ordered["signal"][:signal_capacity]
    selected_coverage = ordered["coverage"][:1]
    if coverage_reserved and len(selected_signal) < signal_capacity:
        selected_coverage += ordered["coverage"][1:1 + signal_capacity - len(selected_signal)]
    return Selection(
        selected=tuple(selected_signal + selected_coverage),
        queue_of=queue_of,
        rank_of=rank_of,
        slots=slots,
        coverage_reserved=coverage_reserved,
    )


# ---- Candidate Store 门面:去重 → ID → 评分 → 选取 → 落盘 ----

CANDIDATE_STORE_SCHEMA_VERSION = 2
_V1_STORE_SCHEMA_VERSION = 1


class CandidateStore:
    """``run_dir/candidates.json`` 的唯一升级者与读取者。

    recon 落盘的 v1(原始 proposals)在此升级为 v2(去重后的权威 Candidate
    Store):归一 intake → fingerprint 去重 → 分配 ``cand-xxxx`` → 评分 →
    双队列选取 → not_started 标记 → 原子落盘。v2 再入队只处理新增 proposal,
    既有 Candidate 的 ID 与评分原样保留;queue/disposition 是选取投影,每次
    build 依当前名额重算。文件版本同时是断点语义:v1=去重未做,v2=已完成。
    """

    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        self.store_path = self.run_dir / "candidates.json"

    def _load(self) -> dict[str, Any] | None:
        if not self.store_path.exists():
            return None
        payload = read_json_object(self.store_path, "Candidate Store")
        if not isinstance(payload.get("candidates"), list):
            raise StoreError("Candidate Store 结构损坏;请检查原运行目录")
        version = payload.get("schema_version")
        if version not in (_V1_STORE_SCHEMA_VERSION, CANDIDATE_STORE_SCHEMA_VERSION):
            raise StoreError(
                f"Candidate Store schema_version={version!r} 不兼容;请创建新运行世代,保留原目录供检查")
        return payload

    def build(
        self,
        comparator,
        scorer_factory,
        *,
        extra_intake: list[IntakeCandidate] | None = None,
        slots: int | None = None,
    ) -> dict[str, Any]:
        """执行完整去重-评分-选取流水并原子落盘,返回最终 payload。

        ``scorer_factory(evidence_context)`` 在 build 内以盘上 Evidence 摘要表
        调用一次,生产接线用 ``make_priority_scorer(llm)``,测试注入假评分器。
        """
        payload = self._load()
        survey: dict[str, Any] = {}
        session_state: dict[str, Any] = {}
        existing: list[dict[str, Any]] | None = None
        dedup_log: list[dict[str, Any]] = []
        llm_calls = {"dedup": 0, "scoring": 0}
        intakes: list[IntakeCandidate] = list(extra_intake or [])
        if payload is not None:
            survey = payload.get("survey") if isinstance(payload.get("survey"), dict) else {}
            session_state = (payload.get("session_state")
                             if isinstance(payload.get("session_state"), dict) else {})
            if payload["schema_version"] == _V1_STORE_SCHEMA_VERSION:
                intakes = [
                    _intake_from_stored_record(record, source="recon")
                    for record in payload["candidates"]
                ] + intakes
            else:
                existing = payload["candidates"]
                dedup_log = list(payload.get("dedup_log", []))
                carried = payload.get("llm_calls")
                if isinstance(carried, dict):
                    llm_calls = {
                        "dedup": int(carried.get("dedup", 0)),
                        "scoring": int(carried.get("scoring", 0)),
                    }

        result = deduplicate(intakes, comparator=comparator, existing=existing)
        records = result.candidates
        llm_calls["dedup"] += result.llm_calls
        dedup_log.extend(result.dedup_log)

        evidence_context = self._evidence_context()
        scorer = scorer_factory(evidence_context)
        for record in records:
            if "priority" not in record:
                record["priority"] = scorer.score(result.intakes[record["candidate_id"]])
                llm_calls["scoring"] += 1

        resolved_slots = resolve_processing_slots() if slots is None else slots
        self._apply_queue_projection(records, previous=existing, slots=resolved_slots)

        final = clone_json_value({
            "schema_version": CANDIDATE_STORE_SCHEMA_VERSION,
            "survey": survey,
            "session_state": session_state,
            "candidates": records,
            "dedup_log": dedup_log,
            "llm_calls": llm_calls,
        }, "Candidate Store")
        atomic_json(self.store_path, final)
        return final

    def _apply_queue_projection(
        self,
        records: list[dict[str, Any]],
        *,
        previous: list[dict[str, Any]] | None,
        slots: int,
    ) -> None:
        """写入选取投影;增量重建时既有选取被锁定,新候选只竞争剩余名额。

        既有记录的 ``disposition is None`` 表示已入选(结局在 Investigation,
        票 11 的锁定选取):队列更新不得把已开始/已完成的调查挤成
        ``not_started``。新增记录按 ``slots - 已锁定数`` 的剩余名额重新走
        signal/coverage 双队列选取;名额用尽则明确 ``not_started``。
        """
        prior: dict[str, dict[str, Any]] = {}
        if previous:
            for record in previous:
                if not isinstance(record, dict):
                    raise StoreError("既有 Candidate 记录结构损坏;请检查原运行目录")
                candidate_id = record.get("candidate_id")
                queue = record.get("queue")
                disposition = record.get("disposition")
                if (not isinstance(candidate_id, str)
                        or not isinstance(queue, dict)
                        or disposition not in (None, "not_started")
                        or not isinstance(queue.get("selected"), bool)
                        or queue["selected"] != (disposition is None)):
                    raise StoreError(
                        "既有 Candidate 队列投影损坏;请检查原运行目录")
                prior[candidate_id] = record

        locked = [
            candidate_id for candidate_id, record in prior.items()
            if record["disposition"] is None
        ]
        fresh = [record for record in records
                 if record["candidate_id"] not in prior]
        if fresh:
            remaining = slots - len(locked)
            if remaining >= 1:
                selection = select_for_processing(fresh, slots=remaining)
                selected = set(selection.selected)
            else:
                selection = None
                selected = set()
        else:
            selection = None
            selected = set()
        for record in records:
            candidate_id = record["candidate_id"]
            if candidate_id in prior:
                # 既有记录:保留上次选取投影(ID/评分/别名已由 dedup 往返携带)
                record["queue"] = deepcopy(prior[candidate_id]["queue"])
                record["disposition"] = prior[candidate_id]["disposition"]
                continue
            if selection is not None:
                record["queue"] = {
                    "queue": selection.queue_of[candidate_id],
                    "rank": selection.rank_of[candidate_id],
                    "selected": candidate_id in selected,
                }
            else:
                record["queue"] = {
                    "queue": record.get("kind", "signal"),
                    "rank": 0,
                    "selected": False,
                }
            record["disposition"] = None if candidate_id in selected else "not_started"

    def _evidence_context(self) -> dict[str, str]:
        """评分依据的 Evidence 摘要表:盘上全部 Evidence ID → summary。

        评分依据只认这份全集(与 EvidenceRecorder.seed_sequence_from_files 同
        扫描口径,覆盖 investigations 与 verifications 两棵树——verification
        提出的 Related Candidate 初始证据在 verifications 树,漏扫会让它的
        分项永远无法以自身证据 ground);损坏文件跳过——对应分项会因
        evidence_id 不在全集而取 0。
        """
        context: dict[str, str] = {}
        paths = sorted(
            self.run_dir.glob("investigations/*/evidence/ev-*.json"))
        paths += sorted(
            self.run_dir.glob("verifications/*/evidence/ev-*.json"))
        for path in paths:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                evidence_id = payload["evidence_id"]
                summary = payload["summary"]
                if isinstance(evidence_id, str) and isinstance(summary, str):
                    context[evidence_id] = summary
            except (json.JSONDecodeError, UnicodeError, KeyError, TypeError):
                continue
        return context

    def not_started_ids(self) -> list[str]:
        """超出处理名额、明确标记 not_started 的 Candidate(要求已完成去重)。"""
        payload = self._load()
        if payload is None or payload["schema_version"] != CANDIDATE_STORE_SCHEMA_VERSION:
            raise StoreError("Candidate Store 尚未完成去重评分;先运行 build")
        return [
            record["candidate_id"] for record in payload["candidates"]
            if record.get("disposition") == "not_started"
        ]

"""Host 驱动的单实例 Recon:增强现场概览、浅层工具循环与 Candidate Store 入库。

这是 ADR-0012 Recon 阶段的 Host 控制循环,与 Analysis tracer 对称:Host 在
发起任何模型请求前先从解包树确定性构建增强现场概览并做输入分类(解包失败/
空树/无有效目标 → input failure);运行中逐轮完整校验 Proposal,按
``authorize_tool("recon", ...)`` 只执行浅层工具并留存 Evidence;complete_survey
四段齐备且每个 Candidate 带齐 target/信号/初始 Evidence/下一动作才被接受,
接受后把 survey 与合法 proposal 原子落盘为 ``candidates.json``(ADR-0012 运行
工件布局的 Candidate Store 入口;去重与 cand-ID 分配完成后,才构成
CONTEXT.md 定义的"校验、去重并分配稳定身份"的完整 Candidate Store)。

角色越权(r2/Ghidra)与 survey 不完整的结构化反馈、协议形状失败的重生成
提示统一进入同一 episode(票 10):无效回复整份重生成,连续三次按
input_failure/protocol_error 收束;轮次与运行总预算经 ``budget.RunBudget``
守卫。Candidate ID 分配与去重在去重完成后进行(后续工单),本票以运行内
proposal 序号保序。
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from ...file_rules import is_search_excluded
from ..providers.tools import (
    ToolAuthorizationError, authorize_tool, tool_names_for_role,
    role_tool_contract,
)
from ..providers.tools.base import MAX_TEXT_CHARS, validate_params
from .budget import RunBudget
from .candidates import (
    CANDIDATE_STORE_SCHEMA_VERSION,
    CLAIM_PROFILES,
    FINGERPRINT_INPUT_FIELDS,
    find_misplaced_intake_fields,
)
from .evidence import (
    DEFAULT_TOOL_RESULT_LIMIT_BYTES,
    EvidenceRecorder,
    EvidenceReference,
)
from .json_values import clone_json_value
from .session import (
    MAX_PROTOCOL_ATTEMPTS,
    ActionProposal,
    ProposalRejectedError,
    ValidationIssue,
    revalidate_proposal,
)
from .store import StoreError, atomic_json, read_json_object
from .tooling import (
    compact_session_context,
    execute_tool,
    normalize_tool_arguments,
    regeneration_feedback,
)

DEFAULT_RECON_MAX_ROUNDS = 30

# Recon Evidence 的命名空间:落在 investigations/recon/evidence/ 下,与
# cand-* 调查目录互不冲突(tracer 只恢复 cand-*)。
RECON_CANDIDATE_ID = "recon"
RECON_INVESTIGATION_ID = "recon-survey"

_MAX_TOP_DIRS = 20
_MAX_EXTENSIONS = 10
_MAX_LARGEST_FILES = 10


def build_site_overview(process_dir: Path) -> dict[str, Any]:
    """Host 侧确定性增强现场概览,替代 recon 自行逐轮枚举目录铺面。

    口径与 list_files 一致:SEARCH_EXCLUDE 命中目录不计入"可审"统计,但仍
    计入原始总数(供输入分类)。路径一律为 extracted/ 工具路径(ADR-0008)。

    与 legacy data/prompts.build_filtered_overview 的 rglob+排除名单统计
    同形属迁移期刻意平行:legacy 随公开入口切换删除,host 不向下耦合一个
    将死的消费者;口径分叉风险由本函数的固定名单测试钉住。
    """
    extracted = Path(process_dir) / "extracted"
    overview: dict[str, Any] = {
        "extracted_present": extracted.is_dir(),
        "total_file_count": 0,
        "auditable_file_count": 0,
        "top_level_dirs": [],
        "extension_distribution": {},
        "largest_files": [],
        "analysis_sidecars": _analysis_sidecar_counts(process_dir),
    }
    if not overview["extracted_present"]:
        return overview

    dir_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"files": 0, "bytes": 0})
    ext_counts: dict[str, int] = defaultdict(int)
    largest: list[tuple[str, int]] = []
    for path in extracted.rglob("*"):
        if not path.is_file():
            continue
        overview["total_file_count"] += 1
        rel = path.relative_to(extracted).as_posix()
        parts = rel.split("/")
        if any(is_search_excluded("/".join(parts[:i])) for i in range(1, len(parts) + 1)):
            continue
        overview["auditable_file_count"] += 1
        size = path.stat().st_size
        top = parts[0] + "/" if len(parts) > 1 else "(root)"
        dir_stats[top]["files"] += 1
        dir_stats[top]["bytes"] += size
        ext_counts[path.suffix.lower() or "(无扩展名)"] += 1
        largest.append((f"extracted/{rel}", size))

    overview["top_level_dirs"] = [
        {"name": name, **stats}
        for name, stats in sorted(
            dir_stats.items(), key=lambda kv: (-kv[1]["files"], kv[0]),
        )[:_MAX_TOP_DIRS]
    ]
    overview["extension_distribution"] = dict(
        sorted(ext_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:_MAX_EXTENSIONS],
    )
    overview["largest_files"] = [
        {"path": rel, "bytes": size}
        for rel, size in sorted(largest, key=lambda item: (-item[1], item[0]))[:_MAX_LARGEST_FILES]
    ]
    return overview


def _analysis_sidecar_counts(process_dir: Path) -> dict[str, int]:
    analysis = Path(process_dir) / "analysis"
    counts = {"c": 0, "strings_json": 0, "imports_json": 0}
    if not analysis.is_dir():
        return counts
    for path in analysis.rglob("*"):
        if not path.is_file():
            continue
        if path.name.endswith(".strings.json"):
            counts["strings_json"] += 1
        elif path.name.endswith(".imports.json"):
            counts["imports_json"] += 1
        elif path.suffix == ".c":
            counts["c"] += 1
    return counts


def input_failure_reason(overview: dict[str, Any]) -> str | None:
    """解包失败/空树/无有效目标的确定性判定;有效输入返回 None。"""
    if not overview.get("extracted_present"):
        return "extraction_missing"
    if not overview.get("total_file_count"):
        return "empty_tree"
    if not overview.get("auditable_file_count"):
        return "no_valid_targets"
    return None

# ---- Host Recon 运行结果与 Candidate Store ----

# Recon 写下的原始 proposal 工件版本;去重评分后的 Candidate Store 权威版本
# 见 candidates.CANDIDATE_STORE_SCHEMA_VERSION(工单 07 起为 2)。
RECON_STORE_SCHEMA_VERSION = 1
# 阶段检查点(票 11)的工件版本:阶段进度/终态与已引用 Evidence 的持久化。
RECON_STATE_SCHEMA_VERSION = 1
SURVEY_SECTIONS = ("attack_surface", "candidates", "checked_scope", "coverage_gaps")
_CANDIDATE_KINDS = ("signal", "coverage")
_CANDIDATE_REQUIRED_TEXT_FIELDS = ("target", "signal", "next_action")
_CANDIDATE_OPTIONAL_TEXT_FIELDS = ("possible_source", "possible_sink")
# 去重 fingerprint 的输入字段(工单 07)复用 candidates 的单一来源清单:
# survey 门只做类型/枚举把关,内容归一由 host.candidates.normalize_intake 负责。


@dataclass(frozen=True)
class CandidateProposal:
    """通过完整校验、等待去重与 ID 分配的合法 Candidate proposal。

    ``cand-xxxx`` 身份在去重完成后才分配(后续工单);此处以运行内
    proposal 序号保序,source/sink 允许为空,extras 原样保留供追溯。
    """

    proposal_id: str
    kind: Literal["signal", "coverage"]
    target: str
    signal: str
    evidence_id: str
    next_action: str
    possible_source: str | None = None
    possible_sink: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "kind": self.kind,
            "target": self.target,
            "signal": self.signal,
            "evidence_id": self.evidence_id,
            "next_action": self.next_action,
            "possible_source": self.possible_source,
            "possible_sink": self.possible_sink,
            "extras": dict(self.extras),
        }


@dataclass(frozen=True)
class ReconRunResult:
    """一次 Host 驱动 Recon 的终态。

    status 是本票的 Recon 阶段结果分类:completed(survey 已接受并入库)/
    input_failure(解包失败、空树或无有效目标,未发起模型请求)/ incomplete
    (轮次耗尽未获合法 survey)。它不是 Investigation 的 stop_reason 字段:
    工单 10/11 落地预算停止规则与运行世代时,input_failure 等值才按
    CONTEXT.md 的 stop reason 语义落账,reason 此处只是诊断明细。
    """

    status: Literal["completed", "input_failure", "incomplete"]
    reason: str | None = None
    overview: dict[str, Any] | None = None
    survey: dict[str, Any] | None = None
    session_state: dict[str, Any] = field(default_factory=dict)
    candidates: tuple[CandidateProposal, ...] = ()
    evidence: tuple[EvidenceReference, ...] = ()
    rounds_used: int = 0
    store_path: Path | None = None


def resolve_recon_max_rounds() -> int:
    """STEP5_RECON_MAX_ITERS 覆盖轮次上限(缺失/非法回落默认,下限 1)。

    消费点解析,模块常量不随环境变化。与 legacy runner.resolve_max_iters
    同形但默认值不同(Host 按 ADR-0012 为 30,legacy 20 随切换退役),
    刻意不 import legacy 模块:host 不依赖待删除代码。
    """
    raw = os.environ.get("STEP5_RECON_MAX_ITERS", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_RECON_MAX_ROUNDS
    except ValueError:
        return DEFAULT_RECON_MAX_ROUNDS
    return max(1, value)


def _feedback(error: str, issues, instruction: str) -> str:
    return json.dumps({
        "error": error,
        "issues": [issue.as_dict() for issue in issues],
        "instruction": instruction,
    }, ensure_ascii=False)


def _section_issues(state_delta: dict[str, Any]) -> list[ValidationIssue]:
    """四段齐备性:attack_surface/candidates/checked_scope 非空且都是数组。

    checked_scope 非空的理由是结构性的:被接受的 survey 至少有一个
    Candidate,而 Candidate 必须引用本轮 Evidence——工具确实跑过,"什么都没
    检查"与证据存在自相矛盾。coverage_gaps 允许为空:小树可能确实查完,
    强制非空会诱使模型编造缺口(防幻觉红线优先)。
    """
    issues: list[ValidationIssue] = []
    expectations = {
        "attack_surface": "non-empty array of objects with non-empty string target",
        "candidates": "non-empty array of candidate proposal objects",
        "checked_scope": "non-empty array of non-empty strings",
        "coverage_gaps": "array of objects with non-empty string area",
    }
    for section, expected in expectations.items():
        if section not in state_delta:
            issues.append(ValidationIssue(
                path=f"$.state_delta.{section}", expected=expected, actual="missing"))
        elif not isinstance(state_delta[section], list):
            issues.append(ValidationIssue(
                path=f"$.state_delta.{section}", expected=expected,
                actual=_json_type(state_delta[section])))
    for section in ("attack_surface", "candidates", "checked_scope"):
        value = state_delta.get(section)
        if isinstance(value, list) and not value:
            issues.append(ValidationIssue(
                path=f"$.state_delta.{section}",
                expected=expectations[section], actual="empty array"))
    return issues


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


def _item_issues(path: str, value: Any, expected: str) -> list[ValidationIssue]:
    if isinstance(value, dict):
        return []
    return [ValidationIssue(path=path, expected=expected, actual=_json_type(value))]


def _string_entry_issues(path: str, value: Any) -> list[ValidationIssue]:
    if isinstance(value, str) and value.strip():
        return []
    actual = "empty string" if isinstance(value, str) else _json_type(value)
    return [ValidationIssue(path=path, expected="non-empty string", actual=actual)]


def _attack_surface_issues(attack_surface: list) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for index, entry in enumerate(attack_surface):
        issues.extend(_item_issues(
            f"$.state_delta.attack_surface[{index}]", entry, "object"))
        if isinstance(entry, dict):
            issues.extend(_string_entry_issues(
                f"$.state_delta.attack_surface[{index}].target", entry.get("target")))
    return issues


def _coverage_gap_issues(gaps: list) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for index, entry in enumerate(gaps):
        issues.extend(_item_issues(
            f"$.state_delta.coverage_gaps[{index}]", entry, "object"))
        if isinstance(entry, dict):
            issues.extend(_string_entry_issues(
                f"$.state_delta.coverage_gaps[{index}].area", entry.get("area")))
    return issues


def _candidate_issues(
    candidates: list,
    evidence_ids: frozenset[str],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for index, entry in enumerate(candidates):
        base = f"$.state_delta.candidates[{index}]"
        issues.extend(_item_issues(base, entry, "candidate proposal object"))
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        if kind not in _CANDIDATE_KINDS:
            issues.append(ValidationIssue(
                path=f"{base}.kind", expected="candidate kind",
                actual=json.dumps(kind, ensure_ascii=False) if kind is not None else "missing",
                allowed_values=_CANDIDATE_KINDS))
        for name in _CANDIDATE_REQUIRED_TEXT_FIELDS:
            issues.extend(_string_entry_issues(f"{base}.{name}", entry.get(name)))
        for name in _CANDIDATE_OPTIONAL_TEXT_FIELDS:
            if name in entry and not isinstance(entry[name], str):
                issues.append(ValidationIssue(
                    path=f"{base}.{name}", expected="string or absent",
                    actual=_json_type(entry[name])))
        for name in FINGERPRINT_INPUT_FIELDS:
            if name in entry and not isinstance(entry[name], str):
                issues.append(ValidationIssue(
                    path=f"{base}.{name}", expected="string or absent",
                    actual=_json_type(entry[name])))
        profile = entry.get("claim_profile")
        if profile is not None and (
            not isinstance(profile, str) or profile not in CLAIM_PROFILES
        ):
            issues.append(ValidationIssue(
                path=f"{base}.claim_profile",
                expected="Claim Profile 枚举值或缺失(默认 generic)",
                actual=json.dumps(profile, ensure_ascii=False),
                allowed_values=CLAIM_PROFILES,
            ))
        # 票 25:领域字段错放进嵌套 fingerprint 对象时整份拒绝并指路平铺,
        # 不让非 generic 意图被缺省值静默掩盖(与 normalize_intake 同一检测出处)。
        for misplaced_path in find_misplaced_intake_fields(entry):
            issues.append(ValidationIssue(
                path=f"{base}.{misplaced_path}",
                expected=(
                    "平铺在 candidate 顶层的输入字段"
                    "(fingerprint 由 Host 派生,不接受嵌套对象)"),
                actual="嵌套在 fingerprint 对象内",
            ))
        evidence_id = entry.get("evidence_id")
        issues.extend(_string_entry_issues(f"{base}.evidence_id", evidence_id))
        if isinstance(evidence_id, str) and evidence_id.strip() \
                and evidence_id not in evidence_ids:
            issues.append(ValidationIssue(
                path=f"{base}.evidence_id",
                expected="Evidence ID from this recon run's tool observations",
                actual=json.dumps(evidence_id, ensure_ascii=False)))
    return issues


def _survey_issues(
    state_delta: dict[str, Any],
    evidence_ids: frozenset[str],
) -> list[ValidationIssue]:
    """complete_survey 的 Host 门:四段齐备 + 逐段/逐候选结构校验。

    signal/coverage 形成规则的语义判定靠提示词,但保留一条结构代理:
    coverage_gaps 非空而没有任何 coverage Candidate 时拒绝——ADR-0012 规定
    高价值未检查面必须形成 coverage Candidate,否则缺口既不入队也无人深查。
    """
    issues = _section_issues(state_delta)
    for section_validator, section in (
        (_attack_surface_issues, "attack_surface"),
        (_coverage_gap_issues, "coverage_gaps"),
    ):
        value = state_delta.get(section)
        if isinstance(value, list):
            issues.extend(section_validator(value))
    checked_scope = state_delta.get("checked_scope")
    if isinstance(checked_scope, list):
        for index, item in enumerate(checked_scope):
            issues.extend(_string_entry_issues(
                f"$.state_delta.checked_scope[{index}]", item))
    candidates = state_delta.get("candidates")
    if isinstance(candidates, list):
        issues.extend(_candidate_issues(candidates, evidence_ids))
    gaps = state_delta.get("coverage_gaps")
    if isinstance(gaps, list) and gaps and isinstance(candidates, list) and all(
        not isinstance(entry, dict) or entry.get("kind") != "coverage"
        for entry in candidates
    ):
        issues.append(ValidationIssue(
            path="$.state_delta.candidates",
            expected="coverage_gaps 非空时至少一个 kind=coverage 的 Candidate",
            actual="没有任何 coverage Candidate",
        ))
    return issues


def _build_candidate_proposals(candidates: list) -> list[CandidateProposal]:
    """把已通过校验的 proposal 转成保序的 CandidateProposal。"""
    proposals = []
    for index, entry in enumerate(candidates):
        known = {"kind", *_CANDIDATE_REQUIRED_TEXT_FIELDS, "evidence_id",
                 *_CANDIDATE_OPTIONAL_TEXT_FIELDS}
        proposals.append(CandidateProposal(
            proposal_id=f"proposal-{index + 1:04d}",
            kind=entry["kind"],
            target=entry["target"].strip(),
            signal=entry["signal"].strip(),
            evidence_id=entry["evidence_id"].strip(),
            next_action=entry["next_action"].strip(),
            possible_source=entry.get("possible_source"),
            possible_sink=entry.get("possible_sink"),
            extras={key: value for key, value in entry.items() if key not in known},
        ))
    return proposals


@dataclass(frozen=True)
class _GuardedAction:
    """单个 tool_action 通过完整守卫后的结果:要么可执行,要么只有反馈。"""

    feedback: str | None = None
    state_delta: dict[str, Any] | None = None
    arguments: dict[str, Any] | None = None
    tool: object | None = None

    @property
    def rejected(self) -> bool:
        return self.feedback is not None


class HostReconRunner:
    """Recon 阶段的唯一真实循环:概览注入、浅层工具、survey 门与入库。

    阶段进度持久化为 ``investigations/recon/state.json`` 检查点(票 11):每个
    动作接受/执行/收尾与全部终态都原子落盘,服务中断后从保存边界继续,不以
    重新执行整段 Recon 代替恢复;已记录 Evidence 按 ID 恢复回放,已接受未
    记录的动作在同一槽位重执行。Recon 没有 Investigation 事件投影,输入失败
    也绝不伪造 Investigation。
    """

    # 检查点状态机:running(进行中)→ survey_accepted(survey 已过门,待入库)
    # → completed;input_failure(输入/协议)/ incomplete(轮次耗尽)为终态。
    _CHECKPOINT_STATUSES = (
        "running", "survey_accepted", "completed", "input_failure", "incomplete",
    )

    def __init__(
        self,
        run_dir: Path,
        tools: dict[str, object],
        *,
        max_rounds: int | None = None,
        observation_view_limit: int = MAX_TEXT_CHARS,
        tool_result_limit_bytes: int = DEFAULT_TOOL_RESULT_LIMIT_BYTES,
        budget: RunBudget | None = None,
    ):
        self.tools = dict(tools)
        self._run_dir = Path(run_dir)
        # 运行级预算 seam:与 Analysis/Verification 共享 run_dir/budget.json 台账。
        self._budget = budget if budget is not None else RunBudget.load(run_dir)
        self._evidence_store = EvidenceRecorder(
            run_dir,
            observation_view_limit=observation_view_limit,
            tool_result_limit_bytes=tool_result_limit_bytes,
        )
        # Recon 无事件投影,序列水位来自盘上既有不可变 Evidence 文件,
        # 保证与前次运行或后续 Investigation 的 Evidence ID 互不重号。
        self._evidence_store.seed_sequence_from_files()
        if max_rounds is None:
            self.max_rounds = resolve_recon_max_rounds()
        else:
            self.max_rounds = max(1, int(max_rounds))
        self._checkpoint = self._load_checkpoint()

    # ---- 检查点 ----

    def _checkpoint_path(self) -> Path:
        return self._run_dir / "investigations" / RECON_CANDIDATE_ID / "state.json"

    def _load_checkpoint(self) -> dict[str, Any] | None:
        path = self._checkpoint_path()
        if not path.exists():
            return None
        payload = read_json_object(path, "Recon 检查点")
        if (type(payload.get("schema_version")) is not int
                or payload["schema_version"] != RECON_STATE_SCHEMA_VERSION
                or payload.get("status") not in self._CHECKPOINT_STATUSES
                or type(payload.get("rounds_used")) is not int
                or payload["rounds_used"] < 0
                or not isinstance(payload.get("session_state"), dict)
                or not isinstance(payload.get("evidence"), list)
                or not all(isinstance(item, dict) for item in payload["evidence"])
                or not all(isinstance(item, dict)
                           for item in payload.get("proposals", []))
                or not (payload.get("pending") is None
                        or isinstance(payload.get("pending"), dict))
                or not (payload.get("survey") is None
                        or isinstance(payload.get("survey"), dict))
                or not isinstance(payload.get("proposals"), list)
                or not (payload.get("store_path") is None
                        or isinstance(payload.get("store_path"), str))
                or not (payload.get("reason") is None
                        or isinstance(payload.get("reason"), str))
                or not (payload.get("overview") is None
                        or isinstance(payload.get("overview"), dict))):
            raise StoreError("Recon 检查点结构或版本损坏；请检查原运行目录")
        return payload

    def _save_checkpoint(
        self,
        status: str,
        ctx: dict[str, Any],
        *,
        reason: str | None = None,
        survey: dict[str, Any] | None = None,
        store_path: Path | None = None,
    ) -> None:
        payload = {
            "schema_version": RECON_STATE_SCHEMA_VERSION,
            "status": status,
            "reason": reason,
            "rounds_used": ctx["rounds"],
            "max_rounds": self.max_rounds,
            "session_state": clone_json_value(ctx["session_state"], "session_state"),
            "evidence": [asdict(reference) for reference in ctx["evidence"]],
            "pending": ctx["pending"],
            "survey": survey,
            "proposals": ctx["proposals"],
            "store_path": str(store_path) if store_path is not None else None,
            "overview": ctx["overview"],
        }
        atomic_json(self._checkpoint_path(), payload)

    def _recorded_result(self, saved: dict[str, Any]) -> ReconRunResult:
        """从检查点忠实重建终态结果,不再发起模型请求或工具执行。"""
        proposals = self._recorded_proposals(saved)
        return ReconRunResult(
            status=saved["status"],
            reason=saved.get("reason"),
            overview=saved.get("overview"),
            survey=saved.get("survey"),
            session_state=saved.get("session_state") or {},
            candidates=tuple(proposals),
            evidence=tuple(EvidenceReference(**item) for item in saved["evidence"]),
            rounds_used=saved["rounds_used"],
            store_path=Path(saved["store_path"]) if saved.get("store_path") else None,
        )

    @staticmethod
    def _recorded_proposals(saved: dict[str, Any]) -> list[CandidateProposal]:
        try:
            return [CandidateProposal(**dict(item))
                    for item in saved.get("proposals", [])]
        except TypeError as exc:
            raise StoreError(
                f"Recon 检查点 proposal 损坏；请检查原运行目录: {exc}") from exc

    def _recovered_evidence(
        self, saved: dict[str, Any],
    ) -> list[EvidenceReference]:
        """按权威文件恢复检查点引用的 Evidence;缺件或失约按 Store 语义拒绝。"""
        evidence: list[EvidenceReference] = []
        for item in saved["evidence"]:
            try:
                reference = EvidenceReference(**item)
            except TypeError as exc:
                raise StoreError(
                    f"Recon Evidence 引用损坏；请检查原运行目录: {exc}") from exc
            if type(reference.sequence) is not int or reference.sequence < 1:
                raise StoreError("Recon Evidence sequence 非法；请检查原运行目录")
            slot = self._evidence_store.restore_slot(
                RECON_CANDIDATE_ID, reference.sequence)
            recovered = self._evidence_store.recover(slot)
            if recovered is None or recovered[0] != reference:
                raise StoreError(
                    "Recon 已引用 Evidence 缺失或与事件不一致；请检查原运行目录")
            evidence.append(reference)
        return evidence

    @staticmethod
    def _validated_pending(pending: dict[str, Any]) -> ActionProposal:
        if (not isinstance(pending, dict)
                or not isinstance(pending.get("proposal"), dict)
                or pending["proposal"].get("kind") != "tool_action"
                or type(pending.get("sequence")) is not int
                or pending["sequence"] < 1
                or type(pending.get("executing")) is not bool):
            raise StoreError("Recon 待执行动作结构或身份损坏；请检查原运行目录")
        try:
            proposal = ActionProposal(**pending["proposal"])
        except TypeError as exc:
            raise StoreError(
                f"Recon 待执行动作字段损坏；请检查原运行目录: {exc}") from exc
        return revalidate_proposal(proposal, "recon")

    # ---- 主循环 ----

    def run(self, session, process_dir: Path) -> ReconRunResult:
        """驱动单实例 Recon Session,直到 survey 被接受或轮次耗尽。"""
        if getattr(session, "role", None) != "recon":
            raise ValueError("HostReconRunner 只接受 role='recon' 的 Agent Session")
        overview = build_site_overview(process_dir)
        failure = input_failure_reason(overview)
        saved = self._checkpoint

        # 幂等与终态短路:已完成/输入仍失败的检查点直接按记录返回,
        # 轮次已耗尽的 incomplete 不重跑;输入已修复的 input_failure 继续。
        if saved is not None:
            if saved["status"] == "completed":
                return self._recorded_result(saved)
            if (saved["status"] == "input_failure"
                    and failure == saved.get("reason")):
                return self._recorded_result(saved)
            if (saved["status"] == "incomplete"
                    and saved["rounds_used"] >= self.max_rounds):
                return self._recorded_result(saved)

        # 每次运行前从两棵 Evidence 树抬水位:与 runner 构造顺序解耦,
        # 其他阶段占号后本阶段 Evidence ID 依然全运行唯一。
        self._evidence_store.seed_sequence_from_files()

        ctx: dict[str, Any] = {
            "rounds": 0,
            "session_state": {},
            "evidence": [],
            "pending": None,
            "proposals": [],
            "overview": overview,
        }
        resuming = False
        if saved is not None:
            ctx["rounds"] = saved["rounds_used"]
            ctx["session_state"] = dict(saved["session_state"])
            ctx["evidence"] = self._recovered_evidence(saved)
            ctx["proposals"] = list(saved.get("proposals", []))
            ctx["overview"] = saved.get("overview") or overview
            resuming = bool(saved["rounds_used"] or ctx["evidence"])
            if saved["status"] == "survey_accepted":
                # survey 已过门:确定性收尾入库,零模型请求(崩溃夹缝恢复)。
                proposals = self._recorded_proposals(saved)
                store_path = self._persist_store(
                    saved["survey"], ctx["session_state"], proposals,
                )
                self._save_checkpoint(
                    "completed", ctx, survey=saved["survey"], store_path=store_path)
                return ReconRunResult(
                    status="completed",
                    overview=ctx["overview"],
                    survey=saved["survey"],
                    session_state=clone_json_value(ctx["session_state"], "session_state"),
                    candidates=tuple(proposals),
                    evidence=tuple(ctx["evidence"]),
                    rounds_used=ctx["rounds"],
                    store_path=store_path,
                )

        if failure is not None:
            self._save_checkpoint("input_failure", ctx, reason=failure)
            return ReconRunResult(
                status="input_failure", reason=failure,
                overview=overview,
                session_state=clone_json_value(
                    ctx["session_state"], "session_state"),
                evidence=tuple(ctx["evidence"]),
                rounds_used=ctx["rounds"],
            )

        pending: dict[str, Any] | None = None
        if saved is not None and saved.get("pending") is not None:
            self._validated_pending(saved["pending"])
            pending = saved["pending"]
            self._evidence_store.restore_sequence(pending["sequence"])

        input_message = (
            self._resume_message(ctx) if resuming and pending is None
            else self._overview_message(overview)
        )
        rounds = ctx["rounds"]
        session_state = ctx["session_state"]
        evidence = ctx["evidence"]
        # 无效回复(协议形状或守卫拒绝)整份重生成,连续 MAX_PROTOCOL_ATTEMPTS
        # 次按 input_failure/protocol_error 收束;轮次口径不变——每次模型请求
        # (含重生成)计一轮;重生成不计工具调用,活动时段离开 run 即封段。
        strikes = 0
        self._budget.start_active()
        try:
            while rounds < self.max_rounds:
                try:
                    if pending is None:
                        # Host 显式上下文压缩(ADR-0012 D3):与 analysis 同款,
                        # 过预算闸、计入台账与 Transcript,不占语义轮次。
                        compact_session_context(session, self._budget)
                        self._budget.require_llm()
                        rounds += 1
                        ctx["rounds"] = rounds
                        raw = session.step(input_message)
                        self._budget.record_llm_call(
                            getattr(session, "last_usage", None))
                        proposal = revalidate_proposal(raw, "recon")
                    else:
                        proposal = self._validated_pending(pending)
                    if isinstance(proposal, ActionProposal):
                        guarded = self._guard_action(proposal)
                        if guarded.rejected:
                            raise ProposalRejectedError(guarded.feedback or "")
                        assert guarded.state_delta is not None
                        if pending is None:
                            slot = self._evidence_store.reserve(RECON_CANDIDATE_ID)
                            pending = {
                                "proposal": asdict(proposal),
                                "sequence": slot.sequence,
                                "executing": False,
                            }
                            ctx["pending"] = pending
                            self._budget.record_logical_tool_call()
                            self._save_checkpoint("running", ctx)
                        else:
                            slot = self._evidence_store.restore_slot(
                                RECON_CANDIDATE_ID, pending["sequence"])
                        recovered = self._evidence_store.recover(slot)
                        if recovered is None:
                            # 先计 attempt 再执行(与 analysis/verification 的
                            # 崩溃口径一致:执行中断崩掉,这次真实尝试也已入账)。
                            self._budget.require_tool()
                            pending["executing"] = True
                            self._budget.record_tool_execution()
                            self._save_checkpoint("running", ctx)
                            result = execute_tool(guarded.tool, guarded.arguments)
                            recovered = self._evidence_store.record(
                                slot,
                                candidate_id=RECON_CANDIDATE_ID,
                                investigation_id=RECON_INVESTIGATION_ID,
                                tool_name=proposal.tool,
                                arguments=guarded.arguments,
                                result=result,
                            )
                        reference, input_message = recovered
                        if (reference.tool != proposal.tool
                                or reference.arguments != guarded.arguments
                                or reference.investigation_id != RECON_INVESTIGATION_ID):
                            raise StoreError(
                                "Recon Evidence 与待执行动作不匹配；请检查原运行目录")
                        evidence.append(reference)
                        session_state.update(guarded.state_delta)
                        pending = None
                        ctx["pending"] = None
                        self._save_checkpoint("running", ctx)
                        self._budget.record_validated_round()
                        strikes = 0
                        continue

                    issues = _survey_issues(
                        proposal.state_delta,
                        frozenset(reference.evidence_id for reference in evidence),
                    )
                    if issues:
                        raise ProposalRejectedError(_feedback(
                            "survey_rejected", issues,
                            "complete_survey 未通过 Host 校验;请修正以下问题,"
                            "从头重新提交整份 complete_survey。",
                        ))
                    proposals = _build_candidate_proposals(proposal.state_delta["candidates"])
                    ctx["proposals"] = [item.as_dict() for item in proposals]
                    self._save_checkpoint(
                        "survey_accepted", ctx, survey=clone_json_value(
                            proposal.state_delta, "survey"),
                    )
                    store_path = self._persist_store(
                        proposal.state_delta, session_state, proposals,
                    )
                    self._save_checkpoint(
                        "completed", ctx,
                        survey=clone_json_value(proposal.state_delta, "survey"),
                        store_path=store_path,
                    )
                    self._budget.record_validated_round()
                    return ReconRunResult(
                        status="completed",
                        overview=overview,
                        survey=clone_json_value(proposal.state_delta, "survey"),
                        session_state=clone_json_value(session_state, "session_state"),
                        candidates=tuple(proposals),
                        evidence=tuple(evidence),
                        rounds_used=rounds,
                        store_path=store_path,
                    )
                except ProposalRejectedError as exc:
                    strikes += 1
                    if strikes >= MAX_PROTOCOL_ATTEMPTS:
                        self._save_checkpoint(
                            "input_failure", ctx, reason="protocol_error")
                        return ReconRunResult(
                            status="input_failure", reason="protocol_error",
                            overview=overview,
                            session_state=clone_json_value(session_state, "session_state"),
                            evidence=tuple(evidence), rounds_used=rounds,
                        )
                    input_message = regeneration_feedback(str(exc))
            self._save_checkpoint("incomplete", ctx, reason="rounds_exhausted")
            return ReconRunResult(
                status="incomplete", reason="rounds_exhausted",
                overview=overview, session_state=clone_json_value(session_state, "session_state"),
                evidence=tuple(evidence), rounds_used=rounds,
            )
        finally:
            self._budget.stop_active()

    def _guard_action(self, proposal: ActionProposal) -> _GuardedAction:
        """整份校验通过才执行;角色越权与参数失约回喂反馈,接线错误致命。"""
        state_delta = clone_json_value(proposal.state_delta, "state_delta")
        arguments = clone_json_value(proposal.arguments, "tool arguments")
        try:
            contract = authorize_tool("recon", proposal.tool)
        except ToolAuthorizationError as exc:
            return _GuardedAction(feedback=_feedback(
                "proposal_rejected",
                [ValidationIssue(
                    path="$.next.tool",
                    expected="recon 已授权的浅层工具",
                    actual=json.dumps(proposal.tool, ensure_ascii=False),
                    allowed_values=tool_names_for_role("recon"),
                )],
                str(exc),
            ))
        checked, argument_error = validate_params(contract.tool_type.params, arguments)
        if argument_error is not None:
            return _GuardedAction(feedback=_feedback(
                "proposal_rejected",
                [ValidationIssue(
                    path="$.next.arguments",
                    expected="符合工具接口契约的参数",
                    actual=argument_error,
                )],
                f"工具 {proposal.tool} 参数未通过接口契约;请修正参数重新发起,"
                "或换用其他浅层工具。",
            ))
        assert checked is not None
        arguments = normalize_tool_arguments(contract.tool_type.params, checked)
        tool = self.tools.get(proposal.tool)
        if tool is None:
            raise ProposalRejectedError(
                f"Recon 工具 {proposal.tool!r} 已授权但未由 Host 配置"
            )
        if not callable(getattr(tool, "execute", None)):
            raise TypeError(f"工具 adapter {proposal.tool!r} 缺少 execute")
        return _GuardedAction(
            state_delta=state_delta, arguments=arguments, tool=tool,
        )

    def _overview_message(self, overview: dict[str, Any]) -> str:
        payload = {
            "phase": "recon",
            "site_overview": overview,
            "task": (
                "对解包树做广度攻击面调查:以浅层工具核实攻击面,完成时以 "
                "complete_survey 提交 attack_surface、candidates、"
                "checked_scope、coverage_gaps 四段;每个 candidate 引用本轮"
                "工具 Observation 的 Evidence ID,并给出 target、攻击面信号"
                "与下一步调查动作。"
            ),
        }
        return (
            "Recon 现场概览与任务(Host 注入):\n"
            + json.dumps(payload, ensure_ascii=False, sort_keys=True)
        )

    def _resume_message(self, ctx: dict[str, Any]) -> str:
        """恢复简报:概览 + 已完成动作 + 阶段状态 + 剩余轮次。"""
        payload = {
            "phase": "recon",
            "site_overview": ctx["overview"],
            "resume": {
                "completed_actions": [
                    {"evidence_id": reference.evidence_id,
                     "tool": reference.tool,
                     "summary": reference.summary}
                    for reference in ctx["evidence"]
                ],
                "session_state": ctx["session_state"],
                "rounds_used": ctx["rounds"],
                "remaining_rounds": self.max_rounds - ctx["rounds"],
            },
            "task": (
                "本次运行从保存边界恢复:已完成动作的 Evidence 如上,不要重复"
                "执行;继续广度攻击面调查,完成时以 complete_survey 提交四段。"
            ),
        }
        return (
            "Recon 恢复简报(Host 注入):\n"
            + json.dumps(payload, ensure_ascii=False, sort_keys=True)
        )

    def _persist_store(
        self,
        survey: dict[str, Any],
        session_state: dict[str, Any],
        proposals: list[CandidateProposal],
    ) -> Path:
        store_path = self._run_dir / "candidates.json"
        if store_path.exists():
            # 已升级的权威 Candidate Store(v2)绝不被 recon 的原始 proposal
            # 工件(v1)降级覆盖(票 11 接缝:恢复不得丢去重/评分/映射)。
            existing = read_json_object(store_path, "Candidate Store")
            if existing.get("schema_version") == CANDIDATE_STORE_SCHEMA_VERSION:
                raise StoreError(
                    "Candidate Store 已完成去重升级;拒绝把已升级的库降级写回,"
                    "请检查原运行目录或创建新运行世代")
        payload = clone_json_value({
            "schema_version": RECON_STORE_SCHEMA_VERSION,
            "survey": survey,
            "session_state": session_state,
            "candidates": [proposal.as_dict() for proposal in proposals],
        }, "Candidate Store")
        atomic_json(store_path, payload)
        return store_path


_RECON_SESSION_SYSTEM = """## 1 角色与使命
你是固件安全审计的侦查 Agent(recon)。使命:对解包树做一次广度攻击面调查,
产出 Candidate proposals、已检查范围与 coverage gaps,为逐条深度调查圈定
入口。只铺面、不深挖、不判级——判级与证据链是下游 analysis 的职责。

## 2 现场概览
Host 会在首轮消息注入确定性现场概览(顶层目录×文件数×大小、扩展名分布、
最大文件、反编译边车计数)。先用它定向,再按需用浅层工具核实,不要从零
逐层枚举目录浪费轮次。

## 3 工具纪律(角色契约强制)
- 只能使用 Host 授权的浅层工具:list_files / read_file / search_code /
  strings_query / imports_query / checksec / semgrep_scan / gitleaks_scan /
  binwalk_rescan。
- r2 工具族、ghidra_decompile、sandbox_verify、qemu_precheck、qemu_execute
  对 recon 不可见;
  直接请求会被 Host 拒绝并回喂错误 Observation。需要反编译或动态验证时,
  把它写进 candidate 的 next_action 交给 analysis。
- 观察到具体信号(可疑配置/硬编码/注入模式/危险导入)→ 形成 signal
  Candidate;高价值面尚未发现具体信号(网络解析器、升级处理器、管理接口
  等)→ 形成 coverage Candidate,只要求深度覆盖,不声称缺陷成立。
- Blind Discovery 证据纪律:版本号、配置开关、服务启动字符串只是攻击面
  信号;禁止把它们与公开已知问题做版本映射推断(如按版本区间认定存在
  公开漏洞),也不得当作缺陷成立的证据。信号只负责如实列出,是否成立由
  analysis 取证、verification 独立复核决定。

{{TOOL_CONTRACT}}

## 4 complete_survey 规范
完成时提交 complete_survey,内容全部放在 state_delta,四段缺一不可:
- attack_surface: 非空数组,每项 object 且含非空 target(工具路径,
  extracted/ 前缀)。
- candidates: 非空数组;有效解包树至少一个 Candidate。每项必须含:
  kind(signal|coverage)、target、signal(攻击面信号/入口角色)、
  evidence_id(本轮工具 Observation 的 Evidence ID)、next_action(下一步
  调查动作);possible_source/possible_sink 可为空。禁止引用不存在的
  Evidence ID。
- fingerprint 输入字段(可选但强烈建议,Host 用其去重):signal 候选带
  anchor(函数/行号等位置锚点)与 mechanism(问题机制,如 command
  injection/hardcoded credentials);coverage 候选带 component_or_entry
  (组件或入口)与 check_goal(检查目标);两者都可带 claim_profile
  (data_propagation/config/credentials/memory/generic,缺省 generic)。
  同一问题的重复 proposal 靠这些字段精确合并,缺失会增加一次语义比较。
  这些输入字段必须平铺在 candidate 顶层(extras 直接字段亦可);fingerprint
  是 Host 派生值,不是可提交字段,把输入字段包进嵌套的 fingerprint 对象会
  被整份拒绝。完整 candidate 示例(字段全部平铺):
```json
{"kind": "signal", "target": "extracted/www/cgi-bin/cgi-exec", "signal": "CGI 处理器导入 execl/system,命令组装参数未见校验", "evidence_id": "ev-000012", "next_action": "反编译命令组装点确认数据流与边界", "claim_profile": "data_propagation", "anchor": "handle_cgi_request", "mechanism": "command injection", "possible_source": "QUERY_STRING", "possible_sink": "execl 调用"}
```
- checked_scope: 非空字符串数组,记录已检查范围(目录/扫描/抽查);
  跑过工具却报空范围会被整份拒绝。
- coverage_gaps: object 数组,每项含非空 area(未检查的高价值面)。
缺段、空 attack_surface/candidates、字段缺失、字段错放或引用未知 Evidence
都会被 Host 整份拒绝并回喂问题清单,请修正后从头重新提交。

## 5 红线
- evidence_id 只能来自本轮 Observation View 中出现的 Evidence ID,禁止编造。
- 目录里没有的东西不要写;版本、行号、组件名只在工具返回中出现时才引用。
- coverage Candidate 不得写成问题结论;signal Candidate 不得判级或下结论。
- 同一文件最多 1-2 轮工具调用;可疑点只负责"列出来",深挖留给 analysis。"""

# 提示正文含 JSON 花括号,不能用 str.format;用占位符替换嵌入共享契约。
# 工具参数契约由注册表生成(票 27,ADR-0004 声明侧 A 送达),与执行校验
# 同源;拼入常量即被 prompt_version_document 指纹覆盖。
RECON_SESSION_SYSTEM = _RECON_SESSION_SYSTEM.replace(
    "{{TOOL_CONTRACT}}", role_tool_contract("recon"))

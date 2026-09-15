"""独立 Verification 的 Claim Result、verdict 聚合与 Finding 生成。

ADR-0012 把复核结论的接受权收进 Host:Verifier 只通过独立 Agent Session 逐项
提交 Claim Result(判断/实际观察/新 Evidence/验证方法/限制)与 Related Candidate
proposal;本模块以纯函数表达"引用必须来自本次复核 Evidence、决定性反驳即
rejected、全部必填被独立支持才 confirmed"的聚合规则,以及 ready 优先、
evidence-gap 按优先级补位的案卷队列。冻结案卷(claims.build_case_payload)
是只读输入:复核简报只把它作为重定位材料与缺口清单,不向 Verifier 透出
analysis 的判定或说服性说明。

``HostVerificationRunner`` 是本模块的动作循环:独立上下文、默认 15 轮预算、
本次会话 Evidence 留存与断点续跑,复核终态经 tracer 落回 Investigation
lifecycle,confirmed 案卷由 Host 追加为唯一 Finding 来源。无效回复整份
重生成(票 10):连续三次按 inconclusive/protocol_error 收束且不生成
Finding;局部轮次与运行总预算经 ``budget.RunBudget`` 守卫,运行级耗尽
保存现场不落终态。
"""
from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..providers.tools import ReplayPolicy, ToolAuthorizationError, authorize_tool
from ..providers.tools.base import MAX_TEXT_CHARS, ToolResult, validate_params
from .budget import RunBudget
from .candidates import CLAIM_PROFILES, normalize_intake
from .claims import (
    ADMISSION_REASONS,
    CASE_SCHEMA_VERSION,
    STOP_REASONS,
    is_decisive,
    profile_claim_document,
    required_claims,
)
from .evidence import (
    DEFAULT_TOOL_RESULT_LIMIT_BYTES,
    EvidenceRecorder,
    EvidenceReference,
)
from .json_values import JsonValueError, clone_json_value
from .session import (
    MAX_PROTOCOL_ATTEMPTS,
    ActionProposal,
    FinalProposal,
    ProposalRejectedError,
    revalidate_proposal,
)
from .store import InvestigationStore, StoreError, atomic_json
from .tooling import (
    execute_tool,
    json_clone_or_reject,
    normalize_tool_arguments,
    recover_cached_tool,
    regeneration_feedback,
    validate_saved_tool_call,
)

# ---- Claim Result 协议与 verdict 枚举(ADR-0012)----

# unresolved 仅由工具不可用等环境限制产生:阻断 confirmed,不构成反证。
CLAIM_RESULT_JUDGMENTS = ("supported", "refuted", "not_applicable", "unresolved")
VERDICTS = ("confirmed", "rejected", "inconclusive")
RESULTS_SCHEMA_VERSION = 1
FINDING_SCHEMA_VERSION = 1

DEFAULT_VERIFICATION_MAX_ROUNDS = 15


def resolve_verification_max_rounds() -> int:
    """STEP5_VERIFICATION_MAX_ITERS 覆盖轮次上限(缺失/非法回落默认,下限 1)。

    变量名沿用 ADR-0012 L39 指定的旋钮;迁移期 legacy 编排层
    (runner.resolve_max_iters,默认 8)与新 Host(默认 15)同名双消费,
    legacy 随公开切换退役后恢复单语义。
    """
    raw = os.environ.get("STEP5_VERIFICATION_MAX_ITERS", "").strip()
    try:
        value = int(raw) if raw else DEFAULT_VERIFICATION_MAX_ROUNDS
    except ValueError:
        return DEFAULT_VERIFICATION_MAX_ROUNDS
    return max(1, value)


# ---- state_delta 两阶段:整份校验成计划,再免校验幂等应用 ----


def _reject(message: str) -> None:
    raise ProposalRejectedError(message)


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _reject(f"{label} 必须为非空字符串")
    return value


def _optional_string(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        _reject(f"{label} 必须为非空字符串或省略")
    return value


def _known_keys(value: dict, allowed: frozenset[str] | set[str], label: str) -> None:
    unknown = [key for key in value if key not in allowed]
    if unknown:
        _reject(f"{label} 含未知字段: {', '.join(map(str, unknown))};"
                f"允许字段: {', '.join(sorted(allowed))}")


def _claim_results_state(state: dict[str, Any]) -> dict[str, Any]:
    results = state.get("claim_results")
    if not isinstance(results, dict):
        return {}
    return {name: record for name, record in results.items()
            if isinstance(name, str) and isinstance(record, dict)}


def _related_state(state: dict[str, Any]) -> list[dict[str, Any]]:
    related = state.get("related_candidates")
    if not isinstance(related, list):
        return []
    return [item for item in related if isinstance(item, dict)]


def _validate_claim_result_updates(
    updates: Any,
    *,
    evidence_ids: frozenset[str],
    profile: str,
) -> tuple[tuple[tuple[str, dict[str, Any]], ...], ...]:
    if not isinstance(updates, dict):
        _reject("state_delta.claim_results 必须为 JSON object")
    allowed_claims = required_claims(profile)
    planned: list[tuple[str, dict[str, Any]]] = []
    for name, value in updates.items():
        if name not in allowed_claims:
            _reject(
                f"state_delta.claim_results 含未知 Claim {name!r}"
                f"(Profile {profile!r} 必填项之外不允许自由扩张 schema)")
        if not isinstance(value, dict):
            _reject(f"state_delta.claim_results.{name} 必须为 JSON object")
        _known_keys(
            value, {"judgment", "observed", "evidence_ids", "method", "limitations"},
            f"state_delta.claim_results.{name}")
        judgment = value.get("judgment")
        if judgment not in CLAIM_RESULT_JUDGMENTS:
            _reject(
                f"state_delta.claim_results.{name}.judgment 只允许 "
                + ", ".join(CLAIM_RESULT_JUDGMENTS))
        if judgment == "not_applicable" and is_decisive(profile, name):
            _reject(
                f"决定性 Claim {name!r} 不允许 not_applicable;"
                "复核中无法适用应判 unresolved 并说明限制")
        observed = _nonempty_string(
            value.get("observed"), f"state_delta.claim_results.{name}.observed")
        method = _nonempty_string(
            value.get("method"), f"state_delta.claim_results.{name}.method")
        raw_refs = value.get("evidence_ids", [])
        if not isinstance(raw_refs, list) or any(
                not isinstance(item, str) or not item for item in raw_refs):
            _reject(
                f"state_delta.claim_results.{name}.evidence_ids 必须为 Evidence ID 字符串数组")
        if judgment in ("supported", "refuted") and not raw_refs:
            _reject(
                f"{judgment} Claim Result {name!r} 必须引用至少一个本次复核"
                "独立取得的 Evidence ID;原案卷 Evidence 只能用于重定位,不能作为支持")
        missing = [item for item in raw_refs if item not in evidence_ids]
        if missing:
            _reject(
                f"state_delta.claim_results.{name}.evidence_ids 引用了不属于本次"
                "复核会话的 Evidence: " + ", ".join(missing))
        record: dict[str, Any] = {
            "judgment": judgment,
            "observed": observed,
            "evidence_ids": list(raw_refs),
            "method": method,
        }
        limitations = _optional_string(
            value.get("limitations"), f"state_delta.claim_results.{name}.limitations")
        if limitations is not None:
            record["limitations"] = limitations
        planned.append((name, record))
    return tuple(planned)


def _validate_related_candidates(
    entries: Any,
    *,
    evidence_ids: frozenset[str],
    case_candidate_id: str,
    case_investigation_id: str,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(entries, list) or not entries:
        _reject("state_delta.related_candidates 必须为非空数组")
    validated: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        label = f"state_delta.related_candidates[{index}]"
        if not isinstance(entry, dict):
            _reject(f"{label} 必须为 JSON object")
        try:
            intake = normalize_intake(entry, source=f"verification:{case_candidate_id}")
        except ValueError as exc:
            raise ProposalRejectedError(f"{label} 未通过 Candidate 契约: {exc}") from exc
        if intake.evidence_id not in evidence_ids:
            _reject(
                f"{label}.evidence_id 必须引用本次复核会话独立取得的 Evidence;"
                f"实际引用 {intake.evidence_id!r}")
        independent = (
            intake.anchor.strip() or intake.mechanism.strip()
            if intake.kind == "signal"
            else intake.component_or_entry.strip() or intake.check_goal.strip()
        )
        if not independent:
            required = ("anchor", "mechanism") if intake.kind == "signal" \
                else ("component_or_entry", "check_goal")
            _reject(
                f"{label} 缺少独立入口、位置或机制字段({'/'.join(required)} 至少其一);"
                "同一案卷内的分支观察应写入 Claim Result,不构成 Related Candidate")
        validated.append({
            "origin": {
                "relation": "verification_related",
                "from_candidate": case_candidate_id,
                "from_investigation": case_investigation_id,
            },
            **intake.as_dict(),
        })
    return tuple(validated)


@dataclass(frozen=True)
class VerificationDeltaPlan:
    """已整份校验的复核状态增量计划;应用阶段免校验且幂等(供恢复重放)。"""

    passthrough: tuple[tuple[str, Any], ...] = ()
    claim_results: tuple[tuple[str, dict[str, Any]], ...] = ()
    related_candidates: tuple[dict[str, Any], ...] = ()


def validate_verification_delta(
    state: dict[str, Any],
    delta: dict[str, Any],
    *,
    evidence_ids: frozenset[str],
    profile: str,
    case_candidate_id: str,
    case_investigation_id: str,
) -> VerificationDeltaPlan:
    """整份校验 verification state_delta;任何字段失约即拒绝,不做局部应用。

    ``evidence_ids`` 是允许被引用的全部 Evidence(本次复核已拥有的加上本次
    动作将要产生的预留 ID);冻结案卷自带的 analysis Evidence 不在其中。
    """
    if not isinstance(delta, dict):
        _reject("state_delta 必须为 JSON object")
    passthrough: list[tuple[str, Any]] = []
    claim_results: tuple[tuple[str, dict[str, Any]], ...] = ()
    related: tuple[dict[str, Any], ...] = ()
    for key, value in delta.items():
        if key == "claim_results":
            claim_results = _validate_claim_result_updates(
                value, evidence_ids=evidence_ids, profile=profile)
        elif key == "related_candidates":
            related = _validate_related_candidates(
                value, evidence_ids=evidence_ids,
                case_candidate_id=case_candidate_id,
                case_investigation_id=case_investigation_id,
            )
        elif key in ("hypothesis", "claims", "path_nodes", "evidence_gaps",
                     "gaps_opened", "gaps_resolved", "hypothesis_outcome"):
            _reject(
                f"state_delta.{key} 是 Analysis Investigation 的结构化状态,"
                "复核不可改写;复核只提交 claim_results 与 related_candidates")
        else:
            passthrough.append((key, deepcopy(value)))
    try:
        cloned = [(key, clone_json_value(value, f"state_delta.{key}"))
                  for key, value in passthrough]
    except JsonValueError as exc:
        raise ProposalRejectedError(str(exc)) from exc
    return VerificationDeltaPlan(
        passthrough=tuple(cloned),
        claim_results=claim_results,
        related_candidates=related,
    )


def apply_verification_delta_plan(
    state: dict[str, Any],
    plan: VerificationDeltaPlan,
) -> None:
    """把已校验计划应用到复核会话 state;免校验,重复应用幂等。"""
    for key, value in plan.passthrough:
        state[key] = deepcopy(value)
    if plan.claim_results:
        results = _claim_results_state(state)
        state["claim_results"] = results
        for name, record in plan.claim_results:
            results[name] = deepcopy(record)
    if plan.related_candidates:
        related = _related_state(state)
        state["related_candidates"] = related
        for item in plan.related_candidates:
            if not any(existing.get("proposal_id") == item["proposal_id"]
                       for existing in related):
                related.append(deepcopy(item))


# ---- verdict 聚合:ready 与 evidence_gap 同一规则 ----


@dataclass(frozen=True)
class VerdictResult:
    """Host 重算的复核终态;unsupported 是阻断 confirmed 的逐项清单。"""

    verdict: str
    decisive_refuted: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()


def aggregate_verdict(
    profile: str,
    claim_results: Any,
) -> VerdictResult:
    """全部必填被独立支持才 confirmed;任一决定性 refuted 即 rejected;其余 inconclusive。

    输入是已通过提交校验的记录;这里仍按容错口径分桶(恢复出的脏记录归
    unsupported),保证聚合永不因损坏状态崩溃。非决定性 not_applicable 视为
    已收束(与 analysis 侧"前置条件/缓解允许不适用"同一语义)。
    """
    if not isinstance(claim_results, dict):
        claim_results = {}
    decisive_refuted: list[str] = []
    unsupported: list[str] = []
    for name in required_claims(profile):
        record = claim_results.get(name)
        if not isinstance(record, dict):
            unsupported.append(name)
            continue
        judgment = record.get("judgment")
        # 决定性反驳的分流不依赖引用是否完好:正确出路都是 rejected。
        if judgment == "refuted":
            if is_decisive(profile, name):
                decisive_refuted.append(name)
            else:
                unsupported.append(name)
            continue
        if judgment == "not_applicable":
            if is_decisive(profile, name):
                unsupported.append(name)
            continue
        if judgment == "unresolved":
            unsupported.append(name)
            continue
        if judgment == "supported":
            refs = record.get("evidence_ids")
            if isinstance(refs, list) and refs:
                continue
        unsupported.append(name)
    if decisive_refuted:
        return VerdictResult(
            verdict="rejected",
            decisive_refuted=tuple(decisive_refuted),
            unsupported=tuple(unsupported),
        )
    if not unsupported:
        return VerdictResult(verdict="confirmed")
    return VerdictResult(verdict="inconclusive", unsupported=tuple(unsupported))


# ---- 案卷队列:ready 全量优先,evidence-gap 按优先级补位 ----


def _read_case_file(path: Path, expected_candidate_id: str) -> dict[str, Any]:
    """读取并校验单个冻结案卷;身份与结构失约按 Store 语义拒绝恢复。"""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise StoreError(f"冻结案卷损坏；请检查原运行目录: {path} ({exc})") from exc
    profile = payload.get("claim_profile") if isinstance(payload, dict) else None
    if (not isinstance(payload, dict)
            or payload.get("schema_version") != CASE_SCHEMA_VERSION
            or payload.get("candidate_id") != expected_candidate_id
            or payload.get("admission_reason") not in ADMISSION_REASONS
            or profile not in CLAIM_PROFILES
            or not isinstance(payload.get("claims"), dict)
            or not isinstance(payload.get("evidence_references"), list)):
        raise StoreError(
            f"冻结案卷结构或身份损坏；请检查原运行目录: {path}")
    missing_claims = [name for name in required_claims(profile)
                      if name not in payload["claims"]]
    if missing_claims:
        raise StoreError(
            f"冻结案卷缺少必填 Claim 快照 {', '.join(missing_claims)};请检查 {path}")
    return clone_json_value(payload, "冻结案卷")


def load_cases(run_dir: Path) -> list[dict[str, Any]]:
    """扫描并校验 ``verifications/<cand>/case.json``,按 Candidate ID 升序返回。"""
    directory = Path(run_dir) / "verifications"
    if not directory.is_dir():
        return []
    return [
        _read_case_file(path, path.parent.name)
        for path in sorted(directory.glob("cand-*/case.json"))
    ]


def plan_verification_queue(
    cases: list[dict[str, Any]],
    *,
    priority_of: dict[str, int],
    max_gap_cases: int | None = None,
) -> tuple[str, ...]:
    """所有 ready 案卷在前(按提交序);evidence-gap 按优先级补位且可被预算截断。

    ready 案卷永不因 gap 预算截断(ADR-0012:所有 ready 案卷均复核,不再
    top-K 丢弃);``max_gap_cases=None`` 表示不设限。同分按 Candidate ID
    (创建顺序)稳定排序。
    """
    if max_gap_cases is not None and (type(max_gap_cases) is not int or max_gap_cases < 0):
        raise ValueError("max_gap_cases 必须是 >=0 的整数或省略")
    ready: list[str] = []
    gaps: list[str] = []
    seen: set[str] = set()
    for case in cases:
        candidate_id = case.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id:
            raise ValueError("案卷缺少 candidate_id")
        if candidate_id in seen:
            raise ValueError(f"案卷 {candidate_id} 重复出现在队列输入中")
        seen.add(candidate_id)
        admission = case.get("admission_reason")
        if admission == "ready":
            ready.append(candidate_id)
        elif admission == "evidence_gap":
            gaps.append(candidate_id)
        else:
            raise ValueError(f"案卷 {candidate_id} 带未知 admission_reason {admission!r}")
    ready.sort()
    gaps.sort(key=lambda cid: (-int(priority_of.get(cid, 0) or 0), cid))
    if max_gap_cases is not None:
        gaps = gaps[:max_gap_cases]
    return tuple(ready + gaps)


# ---- 复核简报与 Finding 载荷 ----


def build_case_brief(
    case_payload: dict[str, Any],
    candidate_proposal: dict[str, Any],
    *,
    claim_results_so_far: dict[str, Any] | None = None,
    verification_evidence_ids: list[str] | None = None,
    last_action: dict[str, Any] | None = None,
    observation_view: str | None = None,
    remaining_rounds: int | None = None,
) -> dict[str, Any]:
    """构建 Verifier 独立上下文:不含 analysis 判定/说明,案卷引用只作重定位。

    冻结案卷 ``claims`` 的 status/note 是 analysis 的逐项判定与说明,一律不进
    简报(ADR-0012:复核不接收 verdict/说服性 rationale);evidence_references
    只保留重定位所需字段并附明示用途。
    """
    profile = case_payload["claim_profile"]
    proposal_fields = (
        "kind", "target", "signal", "next_action",
        "possible_source", "possible_sink", "anchor", "mechanism",
        "component_or_entry", "check_goal",
    )
    proposal = {
        key: candidate_proposal[key] for key in proposal_fields
        if key in candidate_proposal
    }
    references = [
        {key: deepcopy(reference[key]) for key in
         ("evidence_id", "tool", "arguments", "location", "summary", "digest")
         if isinstance(reference, dict) and key in reference}
        for reference in case_payload.get("evidence_references", [])
        if isinstance(reference, dict)
    ]
    brief: dict[str, Any] = {
        "candidate_id": case_payload["candidate_id"],
        "investigation_id": case_payload["investigation_id"],
        "claim_profile": profile,
        "admission_reason": case_payload["admission_reason"],
        "candidate": proposal,
        "claim_schema": profile_claim_document(profile),
        "evidence_references": references,
        "evidence_references_note": (
            "以上引用只用于重新定位原始材料;不可作为 Verification 的支持证据"),
        "pending_claims": list(case_payload.get("pending_claims", [])),
        "blocking_gaps": deepcopy(case_payload.get("blocking_gaps", [])),
        "claim_results_so_far": deepcopy(claim_results_so_far or {}),
        "verification_evidence_ids": list(verification_evidence_ids or []),
        "last_action": deepcopy(last_action),
        "observation_view": observation_view,
        "remaining_rounds": remaining_rounds,
    }
    return clone_json_value(brief, "复核简报")


def build_finding_payload(
    *,
    finding_id: str,
    case_payload: dict[str, Any],
    claim_results: dict[str, Any],
    evidence_references: list[dict[str, Any]],
    related_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """confirmed 案卷的唯一 Finding 载荷;Claim 按必填顺序确定性排列。"""
    profile = case_payload["claim_profile"]
    claims = {
        name: deepcopy(claim_results[name])
        for name in required_claims(profile) if name in claim_results
    }
    return clone_json_value({
        "schema_version": FINDING_SCHEMA_VERSION,
        "finding_id": finding_id,
        "candidate_id": case_payload["candidate_id"],
        "investigation_id": case_payload["investigation_id"],
        "claim_profile": profile,
        "admission_reason": case_payload["admission_reason"],
        "verdict": "confirmed",
        "claims": claims,
        "evidence_references": deepcopy(evidence_references),
        "related_candidates": deepcopy(related_candidates),
    }, "Finding 载荷")


# ---- Host 动作循环:独立复核会话、Evidence 留存与断点续跑 ----


@dataclass(frozen=True)
class CaseOutcome:
    """一个案卷的复核终态;verdict 与停止原因由 Host 聚合,不采纳模型自评。"""

    candidate_id: str
    verdict: str
    stop_reason: str
    claim_results: dict[str, Any]
    decisive_refuted: tuple[str, ...]
    unsupported: tuple[str, ...]
    evidence: tuple[EvidenceReference, ...]
    related_candidates: tuple[dict[str, Any], ...]
    finding_id: str | None
    rounds_used: int
    max_rounds: int
    results_path: Path


class HostVerificationRunner:
    """Verification 阶段的唯一真实循环:独立上下文、本次 Evidence 与聚合终态。"""

    def __init__(
        self,
        run_dir: Path,
        tools: dict[str, object],
        tracer,
        *,
        max_rounds: int | None = None,
        observation_view_limit: int = MAX_TEXT_CHARS,
        tool_result_limit_bytes: int = DEFAULT_TOOL_RESULT_LIMIT_BYTES,
        budget: RunBudget | None = None,
    ):
        self.tools = dict(tools)
        self.tracer = tracer
        self._run_dir = Path(run_dir)
        # 运行级预算 seam:与 Analysis tracer 共享 run_dir/budget.json 台账。
        self._budget = budget if budget is not None else RunBudget.load(run_dir)
        self._evidence_store = EvidenceRecorder(
            run_dir,
            observation_view_limit=observation_view_limit,
            tool_result_limit_bytes=tool_result_limit_bytes,
            namespace="verifications",
        )
        # 复核 Evidence 的序列水位来自两棵 Evidence 树的最高编号文件,
        # 与 Analysis/前次复核的 Evidence ID 互不重号。
        self._evidence_store.seed_sequence_from_files()
        self.max_rounds = (resolve_verification_max_rounds() if max_rounds is None
                           else max(1, int(max_rounds)))
        self._cases: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._stores: dict[str, InvestigationStore] = {}
        self._runtime: dict[str, dict[str, Any]] = {}
        self._evidence: dict[str, list[EvidenceReference]] = {}
        self._claimed_sessions: list[tuple[object, str]] = []
        self._resumed: set[str] = set()
        for directory in sorted((self._run_dir / "verifications").glob("cand-*")):
            if not ((directory / "events.jsonl").exists()
                    or (directory / "state.json").exists()):
                continue  # 只有冻结案卷、尚未开过复核会话
            store = InvestigationStore(self._run_dir, directory.name, root="verifications")
            try:
                self._restore_case_session(store, directory.name)
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise StoreError(
                    f"复核会话恢复失败；请检查原运行目录或创建新运行世代: {exc}"
                ) from exc

    # ---- 恢复 ----

    def _restore_case_session(self, store: InvestigationStore, candidate_id: str) -> None:
        """只接纳身份一致、Evidence 完整、工具调用契约完好的复核投影。"""
        saved = store.load()
        if saved is None:
            raise StoreError("复核会话缺少权威历史")
        case, session, runtime = saved["case"], saved["session"], saved["runtime"]
        evidence = saved["evidence"]
        if (not isinstance(case, dict) or case.get("candidate_id") != candidate_id
                or not isinstance(session, dict)
                or not isinstance(runtime, dict)
                or not isinstance(evidence, list)
                or not isinstance(runtime.get("pending"), (dict, type(None)))
                or not isinstance(runtime.get("last_action"), (dict, type(None)))
                or not isinstance(runtime.get("observation_view"), (str, type(None)))
                or not isinstance(runtime.get("last_tool_call"), (dict, type(None)))
                or type(runtime.get("logical_tool_calls")) is not int
                or runtime["logical_tool_calls"] < 0
                or type(runtime.get("tool_attempts")) is not int
                or runtime["tool_attempts"] < 0
                or type(runtime.get("max_rounds")) is not int
                or runtime["max_rounds"] < 1
                or type(runtime.get("rounds_used")) is not int
                or not 0 <= runtime["rounds_used"] <= runtime["max_rounds"]):
            raise StoreError("复核会话状态结构或身份损坏")
        # 复核快照必须与盘上冻结案卷逐字节一致,防止案卷被换内容后旧会话续跑。
        if case != _read_case_file(
                self._run_dir / "verifications" / candidate_id / "case.json",
                candidate_id):
            raise StoreError("复核快照与冻结案卷不一致；请检查原运行目录")
        lifecycle = self.tracer.investigation_for(candidate_id).lifecycle_status
        if lifecycle not in ("verifying", "finished"):
            raise StoreError(
                f"Investigation 处于 {lifecycle},与已存在的复核会话不一致")
        pending = runtime["pending"]
        if pending is not None:
            if not isinstance(pending["proposal"], dict):
                raise StoreError("待执行 Proposal 结构损坏")
            proposal_type = (ActionProposal
                             if pending["proposal"]["kind"] == "tool_action"
                             else FinalProposal)
            self._validated_proposal(proposal_type(**pending["proposal"]))
            if proposal_type is ActionProposal:
                if (type(pending["sequence"]) is not int or pending["sequence"] < 1
                        or type(pending["executing"]) is not bool):
                    raise StoreError("待执行工具身份损坏")
                self._evidence_store.restore_sequence(pending["sequence"])
        references = [EvidenceReference(**item) for item in evidence]
        for reference in references:
            if type(reference.sequence) is not int or reference.sequence < 1:
                raise StoreError("Evidence sequence 非法")
            slot = self._evidence_store.restore_slot(candidate_id, reference.sequence)
            recovered = self._evidence_store.recover(slot)
            if recovered is None or recovered[0] != reference:
                raise StoreError("已引用复核 Evidence 缺失或与事件不一致")
        validate_saved_tool_call(
            self._evidence_store, candidate_id,
            call=runtime["last_tool_call"], pending=runtime["pending"],
            logical_tool_calls=runtime["logical_tool_calls"],
            tool_attempts=runtime["tool_attempts"],
            evidence=references, role="verification",
        )
        self._cases[candidate_id] = case
        self._sessions[candidate_id] = session
        self._stores[candidate_id] = store
        self._runtime[candidate_id] = runtime
        self._evidence[candidate_id] = references
        self._resumed.add(candidate_id)

    # ---- 主循环 ----

    def run_case(self, candidate_id: str, session) -> CaseOutcome:
        """驱动一个独立复核 Session,直到 complete_verification 或轮次耗尽。"""
        case = self._case_for(candidate_id)
        if getattr(session, "role", None) != "verification":
            raise ValueError("HostVerificationRunner 只接受 role='verification' 的 Agent Session")
        bound = next(
            (bound for claimed, bound in self._claimed_sessions if claimed is session),
            None,
        )
        if bound is not None and bound != candidate_id:
            raise ValueError("每个复核案卷必须使用独立 Agent Session，不得跨案卷复用")
        if bound is None:
            self._claimed_sessions.append((session, candidate_id))

        results_path = self._results_path(candidate_id)
        if results_path.exists():
            # 已收尾案卷的幂等重放:只补齐生命周期落账,不重新驱动 Session。
            return self._replay_finished_case(candidate_id, results_path)

        # 会话开始前从两棵 Evidence 树抬水位:Analysis/前次复核可能已占号,
        # 保证本次复核的 Evidence ID 全运行唯一(ADR-0012)。
        self._evidence_store.seed_sequence_from_files()

        session_state = self._sessions.setdefault(
            candidate_id, {"claim_results": {}, "related_candidates": []})
        runtime = self._runtime.setdefault(candidate_id, self._fresh_runtime())
        evidence_list = self._evidence.setdefault(candidate_id, [])
        if candidate_id not in self._stores:
            self._stores[candidate_id] = InvestigationStore(
                self._run_dir, candidate_id, root="verifications")
        self.tracer.begin_verification(candidate_id)

        verification_id = f"verify-{case['investigation_id']}"
        input_message: str | None = self._case_context_message(candidate_id)
        needs_recovery_context = candidate_id in self._resumed
        if candidate_id in self._resumed:
            reset = getattr(session, "reset_for_resume", None)
            if callable(reset):
                reset()
            self._resumed.remove(candidate_id)
        # 运行总预算的活动时段与无效回复重生成语义与 analysis.run_analysis
        # 刻意同款(票 10);三连协议失败按 inconclusive/protocol_error 收束,
        # 不生成 Finding、不阻断后续案卷。
        self._budget.start_active()
        strikes = 0
        try:
            while True:
                try:
                    pending = runtime["pending"]
                    if pending:
                        cls = ActionProposal if pending["proposal"]["kind"] == "tool_action" else FinalProposal
                        proposal = self._validated_proposal(cls(**pending["proposal"]))
                    else:
                        # 局部轮次上限计本单元模型请求(含重生成);耗尽按既有
                        # budget_exhausted 收束,聚合已有结果(缺项→inconclusive)。
                        if runtime["rounds_used"] >= runtime["max_rounds"]:
                            return self._finalize(candidate_id, stop_reason="budget_exhausted")
                        self._budget.require_llm()
                        if needs_recovery_context:
                            input_message = self._case_context_message(candidate_id)
                            needs_recovery_context = False
                        runtime["rounds_used"] += 1
                        raw = session.step(input_message)
                        self._budget.record_llm_call(getattr(session, "last_usage", None))
                        proposal = self._validated_proposal(raw)
                    if isinstance(proposal, ActionProposal):
                        # 以下 pending 准备/恢复、replay 分流、attempt 推进与 Evidence
                        # 匹配校验与 analysis.py run_analysis 的动作块刻意逐行平行
                        # (票 05 恢复语义的安全关键路径);任何一侧修改必须同步另一侧,
                        # 进一步收敛属后续工单(带计数回调的 tooling 执行函数)。
                        upcoming_evidence_id = (
                            f"ev-{pending['sequence']:06d}" if pending
                            else self._evidence_store.peek_next_evidence_id()
                        )
                        plan, arguments, tool = self._validate_action(
                            proposal, candidate_id, upcoming_evidence_id)
                        if not pending:
                            slot = self._evidence_store.reserve(candidate_id)
                            pending = {"proposal": asdict(proposal), "sequence": slot.sequence, "executing": False}
                            runtime["pending"] = pending
                            runtime["last_tool_call"] = {
                                "call_id": f"call-{slot.sequence:06d}",
                                "evidence_id": slot.evidence_id,
                                "tool": proposal.tool, "arguments": arguments,
                                "replay_policy": authorize_tool(
                                    "verification", proposal.tool).replay_policy.value,
                                "attempt": 0, "status": "prepared", "finished": False,
                            }
                            runtime["logical_tool_calls"] += 1
                            self._budget.record_logical_tool_call()
                            self._checkpoint(candidate_id, "proposal_accepted")
                        else:
                            slot = self._evidence_store.restore_slot(candidate_id, pending["sequence"])
                        recovered = self._evidence_store.recover(slot)
                        call = runtime["last_tool_call"]
                        if recovered is None:
                            result = None
                            execute_method = "execute"
                            if pending["executing"] and call["replay_policy"] == ReplayPolicy.NEVER.value:
                                if call["status"] != "interrupted":
                                    call["status"] = "interrupted"
                                    self._checkpoint(candidate_id, "tool_interrupted")
                                result = ToolResult(
                                    ok=False, text="", data={"status": "interrupted", "call_id": call["call_id"]},
                                    error="interrupted：工具执行已中断，结果未知；禁止自动重放，请选择替代取证动作。",
                                )
                            elif pending["executing"] and call["replay_policy"] == ReplayPolicy.CACHE_VALIDATED.value:
                                execute_method = "execute_after_interruption"
                                result = recover_cached_tool(tool, arguments)
                            if result is None:
                                kind = "tool_attempt" if pending["executing"] else "tool_started"
                                self._budget.require_tool()
                                pending["executing"] = True
                                call["attempt"] += 1
                                call["status"] = "started"
                                runtime["tool_attempts"] += 1
                                self._budget.record_tool_execution()
                                self._checkpoint(candidate_id, kind)
                                result = execute_tool(tool, arguments, method=execute_method)
                            recovered = self._evidence_store.record(
                                slot, candidate_id=candidate_id,
                                investigation_id=verification_id,
                                tool_name=proposal.tool, arguments=arguments, result=result,
                            )
                        evidence, input_message = recovered
                        if (evidence.tool != proposal.tool or evidence.arguments != arguments
                                or evidence.investigation_id != verification_id):
                            raise StoreError("复核 Evidence 与待执行动作不匹配；请检查工件")
                        if not call["finished"]:
                            if call["status"] != "interrupted":
                                call["status"] = "finished"
                            call["finished"] = True
                            self._checkpoint(candidate_id, "tool_finished")
                        evidence_list.append(evidence)
                        apply_verification_delta_plan(session_state, plan)
                        runtime.update(pending=None, last_action=asdict(proposal), observation_view=input_message)
                        self._checkpoint(candidate_id, "action_completed")
                        self._budget.record_validated_round()
                        strikes = 0
                        continue

                    if proposal.kind != "complete_verification":
                        raise ProposalRejectedError(
                            "复核 Session 只接受 tool_action 或 complete_verification")
                    plan = self._validate_final(proposal, candidate_id)
                    # 先在 trial 上过"全部必填已有结果"门,拒绝路径零副作用。
                    trial = deepcopy(session_state)
                    apply_verification_delta_plan(trial, plan)
                    missing = [
                        name for name in required_claims(case["claim_profile"])
                        if name not in trial.get("claim_results", {})
                    ]
                    if missing:
                        raise ProposalRejectedError(
                            "complete_verification 被拒:必填 Claim 尚无复核结果: "
                            + ", ".join(missing))
                    if not pending:
                        runtime["pending"] = {"proposal": asdict(proposal)}
                        self._checkpoint(candidate_id, "proposal_accepted")
                    apply_verification_delta_plan(session_state, plan)
                    runtime.update(pending=None, last_action=asdict(proposal))
                    self._budget.record_validated_round()
                    return self._finalize(candidate_id, stop_reason="completed")
                except ProposalRejectedError as exc:
                    strikes += 1
                    if strikes >= MAX_PROTOCOL_ATTEMPTS:
                        return self._finalize(candidate_id, stop_reason="protocol_error")
                    input_message = regeneration_feedback(str(exc))
        finally:
            self._budget.stop_active()

    # ---- 终态与 Finding ----

    def _finalize(self, candidate_id: str, *, stop_reason: str) -> CaseOutcome:
        case = self._cases[candidate_id]
        session_state = self._sessions[candidate_id]
        runtime = self._runtime[candidate_id]
        evidence_list = self._evidence[candidate_id]
        if stop_reason == "protocol_error":
            # 三连协议失败按 ADR-0012 收束为 inconclusive,不聚合出 confirmed:
            # 复核未以合法 complete_verification 收尾,已录结果不足以确认;
            # unsupported 逐项列出尚无结果的必填 Claim。
            verdict = VerdictResult(
                "inconclusive",
                unsupported=tuple(
                    name for name in required_claims(case["claim_profile"])
                    if name not in _claim_results_state(session_state)
                ),
            )
        else:
            verdict = aggregate_verdict(
                case["claim_profile"], session_state.get("claim_results", {}))
        related = list(session_state.get("related_candidates", []))
        finding_id = None
        if verdict.verdict == "confirmed":
            finding_id = self._append_finding(
                candidate_id, case, session_state, evidence_list, related)
        atomic_json(self._results_path(candidate_id), {
            "schema_version": RESULTS_SCHEMA_VERSION,
            "candidate_id": candidate_id,
            "investigation_id": case["investigation_id"],
            "claim_profile": case["claim_profile"],
            "admission_reason": case["admission_reason"],
            "verdict": verdict.verdict,
            "stop_reason": stop_reason,
            "claim_results": deepcopy(session_state.get("claim_results", {})),
            "decisive_refuted": list(verdict.decisive_refuted),
            "unsupported": list(verdict.unsupported),
            "evidence_references": [asdict(reference) for reference in evidence_list],
            "related_candidates": deepcopy(related),
            "finding_id": finding_id,
            "rounds_used": runtime["rounds_used"],
            "max_rounds": runtime["max_rounds"],
        })
        self.tracer.finish_verification(
            candidate_id, disposition=verdict.verdict, stop_reason=stop_reason)
        self._checkpoint(candidate_id, "case_finished")
        return CaseOutcome(
            candidate_id=candidate_id,
            verdict=verdict.verdict,
            stop_reason=stop_reason,
            claim_results=deepcopy(session_state.get("claim_results", {})),
            decisive_refuted=verdict.decisive_refuted,
            unsupported=verdict.unsupported,
            evidence=tuple(evidence_list),
            related_candidates=tuple(related),
            finding_id=finding_id,
            rounds_used=runtime["rounds_used"],
            max_rounds=runtime["max_rounds"],
            results_path=self._results_path(candidate_id),
        )

    def _replay_finished_case(
        self, candidate_id: str, results_path: Path,
    ) -> CaseOutcome:
        """results.json 已存在的恢复路径:校验后幂等落账,不重跑 Session。"""
        try:
            payload = json.loads(results_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise StoreError(f"复核结果损坏；请检查原运行目录: {exc}") from exc
        if (not isinstance(payload, dict)
                or payload.get("schema_version") != RESULTS_SCHEMA_VERSION
                or payload.get("candidate_id") != candidate_id
                or payload.get("verdict") not in VERDICTS
                or payload.get("stop_reason") not in STOP_REASONS
                or not isinstance(payload.get("claim_results"), dict)
                or not isinstance(payload.get("evidence_references"), list)
                or not all(isinstance(item, dict) for item in payload["evidence_references"])
                or not isinstance(payload.get("related_candidates"), list)
                or not isinstance(payload.get("decisive_refuted", []), list)
                or not isinstance(payload.get("unsupported", []), list)
                or type(payload.get("finding_id")) not in (str, type(None))
                or type(payload.get("rounds_used")) is not int
                or type(payload.get("max_rounds")) is not int):
            raise StoreError("复核结果结构或身份损坏；请检查原运行目录")
        try:
            evidence = tuple(
                EvidenceReference(**item) for item in payload["evidence_references"])
        except (TypeError, KeyError) as exc:
            raise StoreError(
                f"复核结果 Evidence 引用损坏；请检查原运行目录: {exc}") from exc
        self.tracer.finish_verification(
            candidate_id,
            disposition=payload["verdict"],
            stop_reason=payload["stop_reason"],
        )
        return CaseOutcome(
            candidate_id=candidate_id,
            verdict=payload["verdict"],
            stop_reason=payload["stop_reason"],
            claim_results=payload["claim_results"],
            decisive_refuted=tuple(payload.get("decisive_refuted", ())),
            unsupported=tuple(payload.get("unsupported", ())),
            evidence=evidence,
            related_candidates=tuple(payload["related_candidates"]),
            finding_id=payload["finding_id"],
            rounds_used=payload["rounds_used"],
            max_rounds=payload["max_rounds"],
            results_path=results_path,
        )

    def _append_finding(
        self,
        candidate_id: str,
        case: dict[str, Any],
        session_state: dict[str, Any],
        evidence_list: list[EvidenceReference],
        related: list[dict[str, Any]],
    ) -> str:
        """confirmed 追加为运行内递增 Finding;按 Candidate 幂等防崩溃重放重复。"""
        findings_path = self._run_dir / "findings.json"
        document: dict[str, Any] = {
            "schema_version": FINDING_SCHEMA_VERSION, "findings": []}
        if findings_path.exists():
            try:
                loaded = json.loads(findings_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise StoreError(
                    f"Findings 损坏；请检查原运行目录: {exc}") from exc
            if (not isinstance(loaded, dict)
                    or loaded.get("schema_version") != FINDING_SCHEMA_VERSION
                    or not isinstance(loaded.get("findings"), list)):
                raise StoreError("Findings 结构损坏；请检查原运行目录")
            document = loaded
        for item in document["findings"]:
            if isinstance(item, dict) and item.get("candidate_id") == candidate_id:
                if not isinstance(item.get("finding_id"), str):
                    raise StoreError("既有 Finding 条目损坏；请检查原运行目录")
                return item["finding_id"]
        finding_id = f"f-{len(document['findings']) + 1:04d}"
        document["findings"].append(build_finding_payload(
            finding_id=finding_id,
            case_payload=case,
            claim_results=session_state.get("claim_results", {}),
            evidence_references=[asdict(reference) for reference in evidence_list],
            related_candidates=related,
        ))
        atomic_json(findings_path, document)
        return finding_id

    # ---- 校验与上下文 ----

    def _case_for(self, candidate_id: str) -> dict[str, Any]:
        if candidate_id not in self._cases:
            path = (self._run_dir / "verifications" / candidate_id / "case.json")
            if not path.exists():
                raise ValueError(
                    f"Candidate {candidate_id!r} 没有冻结案卷,无法进入复核")
            self._cases[candidate_id] = _read_case_file(path, candidate_id)
        return self._cases[candidate_id]

    def _results_path(self, candidate_id: str) -> Path:
        return (self._run_dir / "verifications" / candidate_id / "results.json")

    def _fresh_runtime(self) -> dict[str, Any]:
        return {
            "pending": None, "last_action": None, "observation_view": None,
            "last_tool_call": None,
            "logical_tool_calls": 0, "tool_attempts": 0,
            "rounds_used": 0, "max_rounds": self.max_rounds,
        }

    def _checkpoint(self, candidate_id: str, kind: str) -> None:
        self._stores[candidate_id].save(kind, {
            "case": self._cases[candidate_id],
            "session": self._sessions[candidate_id],
            "evidence": [asdict(reference) for reference in self._evidence[candidate_id]],
            "runtime": self._runtime[candidate_id],
        })

    def _case_context_message(self, candidate_id: str) -> str:
        case = self._cases[candidate_id]
        candidate = self.tracer.candidate_for(candidate_id)
        runtime = self._runtime[candidate_id]
        brief = build_case_brief(
            case, candidate.proposal,
            claim_results_so_far=self._sessions[candidate_id].get("claim_results", {}),
            verification_evidence_ids=[
                reference.evidence_id for reference in self._evidence[candidate_id]],
            last_action=runtime["last_action"],
            observation_view=runtime["observation_view"],
            remaining_rounds=runtime["max_rounds"] - runtime["rounds_used"],
        )
        return (
            "Verification Case（本 Session 只复核此案卷；独立重新取证,"
            "不依赖 analysis 结论）:\n"
            + json.dumps(brief, ensure_ascii=False, sort_keys=True)
        )

    def _validate_action(
        self,
        proposal: ActionProposal,
        candidate_id: str,
        upcoming_evidence_id: str,
    ) -> tuple[VerificationDeltaPlan, dict[str, Any], object]:
        """整份 action 通过 Host 守卫后才把任何 delta 交给循环应用。"""
        plan = validate_verification_delta(
            self._sessions[candidate_id],
            json_clone_or_reject(proposal.state_delta, "state_delta"),
            evidence_ids=frozenset(
                reference.evidence_id
                for reference in self._evidence[candidate_id]
            ) | {upcoming_evidence_id},
            profile=self._cases[candidate_id]["claim_profile"],
            case_candidate_id=self._cases[candidate_id]["candidate_id"],
            case_investigation_id=self._cases[candidate_id]["investigation_id"],
        )
        arguments = json_clone_or_reject(proposal.arguments, "tool arguments")
        try:
            contract = authorize_tool("verification", proposal.tool)
        except ToolAuthorizationError as exc:
            raise ProposalRejectedError(str(exc)) from exc
        checked_arguments, argument_error = validate_params(
            contract.tool_type.params,
            arguments,
        )
        if argument_error is not None:
            raise ProposalRejectedError(
                f"工具 {proposal.tool} 参数未通过接口契约: {argument_error}"
            )
        assert checked_arguments is not None
        arguments = normalize_tool_arguments(
            contract.tool_type.params,
            checked_arguments,
        )
        tool = self.tools.get(proposal.tool)
        if tool is None:
            raise ProposalRejectedError(
                f"Verification 工具 {proposal.tool!r} 已授权但未由 Host 配置"
            )
        if not callable(getattr(tool, "execute", None)):
            raise TypeError(f"工具 adapter {proposal.tool!r} 缺少 execute")
        return plan, arguments, tool

    def _validate_final(
        self,
        proposal: FinalProposal,
        candidate_id: str,
    ) -> VerificationDeltaPlan:
        """complete_verification 不执行工具,只允许引用已有本次 Evidence。"""
        case = self._cases[candidate_id]
        return validate_verification_delta(
            self._sessions[candidate_id],
            json_clone_or_reject(proposal.state_delta, "state_delta"),
            evidence_ids=frozenset(
                reference.evidence_id
                for reference in self._evidence[candidate_id]
            ),
            profile=case["claim_profile"],
            case_candidate_id=case["candidate_id"],
            case_investigation_id=case["investigation_id"],
        )

    @staticmethod
    def _validated_proposal(proposal: object) -> ActionProposal | FinalProposal:
        """不信任 Session adapter:按纯 JSON 协议重新校验整份 Proposal。"""
        return revalidate_proposal(proposal, "verification")



VERIFICATION_SESSION_SYSTEM = """## 1 角色与使命
你是固件安全审计的独立复核 Agent(verification)。给你一份冻结的 Verification
Case:对其中每条必填 Claim 独立重新取证并逐项提交 Claim Result。你不接收也不
猜测 analysis 的判定、severity、confidence 或结论性说明;案卷中的 Evidence
Reference 只用于重新定位原始材料,不能作为你的支持证据。最终 verdict 由 Host
按固定规则聚合,不接受你直接给出的任何总结论。

## 2 工具纪律
- 可用与 analysis 同类的取证工具:读盘、搜索、字符串、导入、r2 工具族、
  按需 Ghidra 与受控沙箱验证;每次工具调用都会形成本次复核的独立 Evidence
  (Observation View 中的 ev-xxxxxx)。
- 只有这些本次 Evidence 能支撑 Claim Result;引用其他 ID 会被整份拒绝。
- 单个工具失败是正常 Observation;判 unresolved 要写明限制,不要编造结果。

## 3 Claim Result 协议
随动作或 complete_verification 在 state_delta.claim_results 提交,逐项:
{"judgment": "supported|refuted|not_applicable|unresolved",
 "observed": "实际观察(必填)", "evidence_ids": ["ev-xxxxxx"],
 "method": "验证方法(必填)", "limitations": "限制说明(可选)"}
- supported 与 refuted 必须引用本次复核 Evidence;决定性 Claim(见
  claim_schema.decisive)不允许 not_applicable;工具不可用判 unresolved,
  它不是反证。
- 每轮可只提交部分 Claim Result;重复提交以最后一次为准。

## 4 complete_verification 规范
全部必填 Claim 都有 Claim Result 后才能提交 complete_verification(收尾内容
同样放入 state_delta);缺项会被整份拒绝。轮次预算有限,优先覆盖决定性 Claim。

## 5 Related Candidate 纪律
只有出现独立入口、处理位置或问题机制(signal 带 anchor/mechanism,coverage 带
component_or_entry/check_goal)时才在 state_delta.related_candidates 提出,且必须
引用本次复核 Evidence;同一案卷内的分支观察写进 Claim Result,不要开新
Candidate。"""

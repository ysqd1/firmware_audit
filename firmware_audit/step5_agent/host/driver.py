"""串行运行驱动:世代选择、活动锁、单一配置、共享预算与阶段编排。

ADR-0012 的运行级控制面(票 11):一个工作区同一时刻只允许一个活动运行
(locking);审计运行拥有递增世代与 manifest(generation),默认恢复唯一
未完成世代、完成世代只读、显式 force 只写新世代;有效配置只解析一次并
随世代冻结(budget.resolve_effective_config + config.json 快照),三个
runner 与 Candidate 名额全部由该快照下发;单一 ``RunBudget`` 实例注入三
runner,去重/评分的模型请求经同一预算闸计账。

阶段编排:Recon(checkpoint 恢复)→ Candidate Store 去重评分 → 注册入选
Candidate → 循环 {Analysis 队列 → Verification 案卷队列(ready 优先、
evidence-gap 按优先级)→ Related Candidate 幂等回队} 至不动点 → 收尾
(处理责任收束,status=finalizing)→ 封存(票 12:可选 LLM 注记 →
确定性事实报告 → manifest seal → completed)。finalizing 世代的恢复只续
封存、不重跑处理;封存失败保持 finalizing 可恢复。案例总预算耗尽按票 21
(ADR-0012 2026-09-19)即收束:剩余 queued 标 not_started,进行中调查统一
unresolved/budget_exhausted 终结,同一执行内走正常封存产出 completed 世代,
不冻结世代;模型服务中断保存现场并原样上抛(该路径仍可续跑)。
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import time
import warnings
from typing import Any, Callable, Mapping

from .analysis import HostAnalysisTracer
from .budget import (
    BudgetExhaustedError,
    RunBudget,
    load_config_snapshot,
    persist_config_snapshot,
    resolve_effective_config,
)
from .candidates import (
    CandidateStore,
    SemanticComparator,
    make_priority_scorer,
    related_intake,
    stored_related_proposals,
)
from .generation import (
    GENERATION_PATTERN,
    create_generation,
    generations_root,
    load_run_state,
    read_manifest,
    save_run_state,
)
from .locking import acquire_lock
from .recon import HostReconRunner
from .reporting import (
    ANALYST_NOTES_SYSTEM_PROMPT,
    build_fact_report,
    seal_run,
)
from .store import StoreError, read_json_object
from .verification import (
    HostVerificationRunner,
    load_cases,
    plan_verification_queue,
)

# 注册进 tracer 前剥掉的 Store 记账键;其余字段(含 source/origin 溯源块)
# 作为 Candidate proposal 保真传递。
_BOOKKEEPING_KEYS = (
    "candidate_id", "fingerprint", "aliases", "merged_proposals",
    "queue", "disposition", "priority",
)


class _ReplayOnlySession:
    """已收尾案卷的占位 Session:重放路径不得驱动任何模型请求。"""

    role = "verification"

    def step(self, input_message: str | None = None):  # pragma: no cover
        raise AssertionError("已收尾案卷的幂等重放不得驱动 Session")


class _BudgetedLLM:
    """去重/评分的一次性模型请求过运行预算闸;失败请求不记账。

    与三角色 runner 的守卫同源:发请求前 ``require_llm``,完成的请求计
    ``llm_calls`` 与 token;请求失败(异常上抛)不记账。请求自身占用独立
    活动段——runner 循环外没有开放段,停机间隔不进 active time。
    """

    def __init__(self, llm, budget: RunBudget):
        self.llm = llm
        self.budget = budget

    def chat(self, messages):
        self.budget.require_llm()
        own_segment = not self.budget.ledger.is_active
        if own_segment:
            self.budget.start_active()
        try:
            reply, usage = self.llm.chat(messages)
        finally:
            if own_segment:
                self.budget.stop_active()
        self.budget.record_llm_call(usage)
        return reply, usage


@dataclass(frozen=True)
class RunSummary:
    """一次驱动执行的终态摘要;判读细节以盘上工件为准。"""

    generation: str
    gen_dir: Path
    created: bool
    status: str
    stop_reason: str | None
    phase: str | None
    candidates: int = 0
    findings: int = 0
    registered: tuple[str, ...] = ()


class RunDriver:
    """Host 运行驱动:单写者、世代化、可恢复的串行编排。"""

    def __init__(
        self,
        root: Path,
        *,
        tools: dict[str, object],
        session_factory: Callable[..., object],
        llm: object,
        process_dir: Path,
        explicit: Mapping[str, Any] | None = None,
        profile: Mapping[str, Any] | None = None,
        env: Mapping[str, str] | None = None,
        clock: Callable[[], float] | None = None,
    ):
        self.root = Path(root)
        self.tools = dict(tools)
        # session_factory(role, candidate_id=None, run_dir=None) -> 全新
        # Session;每个 Candidate/案卷一个独立 Session(上下文隔离铁律),
        # run_dir 为当前世代目录(公开入口按它放置 transcript)。
        self._session_factory = session_factory
        self._llm = llm
        self.process_dir = Path(process_dir)
        self._explicit = dict(explicit) if explicit is not None else None
        self._profile = dict(profile) if profile is not None else None
        self._env = os.environ if env is None else dict(env)
        self._clock = clock or time.monotonic
        self._phase: str | None = None
        self._finalizing = False
        # 当前运行世代目录;session_factory 按它放置各 Session 的 transcript。
        self._run_dir: Path | None = None

    # ---- 公开入口 ----

    def run(self, *, force: bool = False) -> RunSummary:
        """执行(或恢复)一次审计运行;锁保证工作区单写者。"""
        with acquire_lock(self.root):
            return self._run_locked(force)

    # ---- 世代与配置 ----

    def _select_generation(self, force: bool) -> tuple[str, Path, bool]:
        generations = self._scan_generations()
        # 未完成 = running(工作未收束)或 finalizing(等票 12 报告封存);
        # completed/abandoned 是终局,不参与默认恢复。
        unfinished = [item for item in generations
                      if item[2] in ("running", "finalizing")]
        if force:
            # 显式 force 只写新世代:仅顶替仍在工作中的 running 世代;
            # finalizing 的工作已收束(等票 12 报告),机器工件一律不动。
            for _name, directory, status in unfinished:
                if status == "running":
                    save_run_state(directory, status="abandoned",
                                   stop_reason="superseded")
            name, directory = create_generation(self.root)
            return name, directory, True
        if not unfinished:
            name, directory = create_generation(self.root)
            return name, directory, True
        if len(unfinished) > 1:
            names = ", ".join(item[0] for item in unfinished)
            raise StoreError(
                f"存在多个未完成世代({names});请检查原运行目录或显式 force"
                " 创建新世代")
        name, directory, _status = unfinished[0]
        return name, directory, False

    def _scan_generations(self) -> list[tuple[str, Path, str]]:
        """容错扫描世代目录,返回 (名字, 目录, run_state 状态)。

        manifest 不兼容或损坏的世代不参与恢复(拒绝静默恢复,AC5),但也不
        阻断新建世代——"请创建新运行世代"的指引必须经 force 真的可行;
        此类世代原样保留并告警,供人工检查。结构损坏的 run_state 属盘上
        损坏,按 Store 语义停下而非跳过。
        """
        scanned: list[tuple[str, Path, str]] = []
        root = generations_root(self.root)
        if not root.is_dir():
            return []
        for directory in sorted(root.iterdir()):
            if not directory.is_dir() or not GENERATION_PATTERN.fullmatch(
                    directory.name):
                continue
            try:
                read_manifest(directory)
            except StoreError as exc:
                warnings.warn(
                    f"跳过无法恢复的世代 {directory.name}({exc});"
                    "该目录不会被读取或修改,请人工检查", RuntimeWarning)
                continue
            state = load_run_state(directory)
            scanned.append((directory.name, directory,
                            state["status"] if state else "running"))
        return scanned

    def _config(
        self, gen_dir: Path, created: bool, fresh: dict[str, Any],
    ) -> dict[str, Any]:
        """有效配置只解析一次:新建落盘快照,恢复读取冻结快照。"""
        snapshot = load_config_snapshot(gen_dir)
        if created:
            if snapshot is not None:
                raise StoreError(
                    "新世代已存在配置快照;请检查原运行目录或显式 force")
            persist_config_snapshot(gen_dir, fresh)
            return fresh
        if snapshot is None:
            raise StoreError(
                "运行世代缺少配置快照;请检查原运行目录或显式 force 创建新世代")
        return snapshot

    # ---- 主执行 ----

    def _run_locked(self, force: bool) -> RunSummary:
        # 配置先于世代解析:显式/profile 非法值(ConfigError)在建世代前
        # 失败,不留一个缺配置快照的空 running 世代(P3-6)。
        fresh_config = resolve_effective_config(
            explicit=self._explicit, env=self._env, profile=self._profile)
        name, gen_dir, created = self._select_generation(force)
        self._run_dir = gen_dir
        state = load_run_state(gen_dir)
        if state is not None and state["status"] not in ("running", "finalizing"):
            raise StoreError(
                f"世代 {name} 处于 {state['status']},机器工件只读;"
                "请显式 force 创建新世代")
        config = self._config(gen_dir, created, fresh_config)
        resolved = config["resolved"]
        # 单一 RunBudget:三 runner 与去重/评分共享同一台账,初始化顺序
        # 不再决定谁能看到谁的计数(票 10 遗留债务在本票收敛)。
        budget = RunBudget.load(
            gen_dir, clock=self._clock, config=resolved, persist=False)
        self._phase = None
        # 恢复 finalizing 世代时处理责任早已收束,异常回写必须保持 finalizing。
        self._finalizing = state is not None and state["status"] == "finalizing"
        if self._finalizing:
            # 票 12:finalizing 的恢复只续封存(报告/manifest/completed),
            # 绝不重跑 Recon/Analysis/Verification。
            try:
                return self._seal(name, gen_dir, created, budget)
            except Exception as exc:
                self._record_failure(gen_dir, exc)
                raise
        tracer = HostAnalysisTracer(
            gen_dir, self.tools,
            max_rounds=int(resolved["analysis_max_rounds"]), budget=budget)
        try:
            return self._execute(name, gen_dir, created, budget, resolved, tracer)
        except BudgetExhaustedError:
            # 票 21(ADR-0012 2026-09-19):预算耗尽即收束,不再冻结世代。
            # 剩余 queued 收账 not_started,进行中的调查(轮次中途、案卷已
            # 冻结未复核、复核中途)统一 unresolved/budget_exhausted 收束,
            # 随后同一执行内走正常 accounting → finalizing → 封存,产出
            # completed 世代;run 级停止原因与正常完成同词汇,预算耗尽由
            # 调查级 stop_reason 分布承载。
            return self._settle_budget_exhaustion(
                name, gen_dir, created, budget, tracer)
        except Exception as exc:
            # 模型服务中断等异常:现场已由既有 checkpoint 保存,这里只补一个
            # 可解释的停止原因并原样上抛(StoreError 即票 17 的拒绝路径)。
            self._record_failure(gen_dir, exc)
            raise

    def _settle_budget_exhaustion(
        self, name: str, gen_dir: Path, created: bool, budget: RunBudget,
        tracer: HostAnalysisTracer,
    ) -> RunSummary:
        """预算耗尽的收账与收束(票 21),随后与正常完成共用封存路径。

        收账/收束失败保持 running 现场可恢复;进入封存后的失败与正常路径
        同语义(保持 finalizing)。耗尽发生在 Candidate Store 建立之前
        (recon/去重阶段)时,完成门会以"Candidate Store 缺失"拒绝封存——
        世代停在 finalizing 并留响亮失败原因,force 新世代是唯一出路;
        该现场说明配置连 recon 都跑不完,属退化配置。
        """
        try:
            for candidate_id in tracer.queued_ids():
                tracer.mark_not_started(candidate_id)
            for candidate_id in tracer.in_flight_ids():
                tracer.close_budget_exhausted(candidate_id)
            return self._begin_finalizing(name, gen_dir, created, budget)
        except Exception as exc:
            self._record_failure(gen_dir, exc)
            raise

    def _begin_finalizing(
        self, name: str, gen_dir: Path, created: bool, budget: RunBudget,
    ) -> RunSummary:
        """处理责任全部收束后的唯一收尾路径:accounting → finalizing → 封存。"""
        self._set_phase(gen_dir, "accounting")
        save_run_state(gen_dir, status="finalizing", phase="accounting",
                       stop_reason="processing_complete")
        self._finalizing = True
        return self._seal(name, gen_dir, created, budget)

    def _execute(
        self, name: str, gen_dir: Path, created: bool, budget: RunBudget,
        resolved: Mapping[str, Any], tracer: HostAnalysisTracer,
    ) -> RunSummary:
        slots = int(resolved["max_candidates"])
        llm = _BudgetedLLM(self._llm, budget)
        comparator = SemanticComparator(llm)
        scorer_factory = make_priority_scorer(llm)
        store = CandidateStore(gen_dir)

        # ---- Recon:候选库已存在则跳过(升级后的 Store 绝不被降级重写) ----
        if not (gen_dir / "candidates.json").exists():
            self._set_phase(gen_dir, "recon")
            recon = HostReconRunner(
                gen_dir, self.tools,
                max_rounds=int(resolved["recon_max_rounds"]), budget=budget,
            ).run(self._session("recon"), self.process_dir)
            if recon.status != "completed":
                stop = f"recon_{recon.status}:{recon.reason}"
                save_run_state(gen_dir, status="running", phase="recon",
                               stop_reason=stop)
                return self._summary(name, gen_dir, created, "running",
                                     stop)

        # ---- Candidate Store:去重 → 评分 → 选取(锁定语义在 build 内) ----
        self._set_phase(gen_dir, "dedup")
        payload = store.build(comparator, scorer_factory, slots=slots)
        self._register_selected(tracer, payload)

        # ---- 处理循环:Analysis 队列 → Verification 案卷 → Related 回队 ----
        while True:
            self._set_phase(gen_dir, "analysis")
            # queued + investigating:服务中断的"当前 Investigation"从保存
            # 边界继续,未完成责任不得被静默跳过(P1-1)。
            for candidate_id in tracer.runnable_ids():
                tracer.run_analysis(
                    candidate_id, self._session("analysis", candidate_id))

            self._set_phase(gen_dir, "verification")
            verifier = HostVerificationRunner(
                gen_dir, self.tools, tracer,
                max_rounds=int(resolved["verification_max_rounds"]),
                budget=budget)
            priority_of = {
                record["candidate_id"]: int(
                    (record.get("priority") or {}).get("total", 0))
                for record in payload["candidates"]
            }
            order = plan_verification_queue(
                load_cases(gen_dir), priority_of=priority_of)
            for candidate_id in order:
                lifecycle = tracer.investigation_for(
                    candidate_id).lifecycle_status
                if lifecycle not in (
                        "ready_for_verification", "verifying", "finished"):
                    # 崩溃夹缝:case.json 已落盘但生命周期还停在 investigating
                    # (submit_case 的两段写之间)。此时案卷由上面的 analysis
                    # 轮重新驱动,不能提前派发复核。
                    continue
                if (gen_dir / "verifications" / candidate_id
                        / "results.json").exists():
                    # 已收尾案卷:幂等重放只补齐生命周期落账,不驱动 Session。
                    verifier.run_case(candidate_id, _ReplayOnlySession())
                    continue
                if lifecycle == "finished":
                    # 票 21:预算耗尽收束的调查,案卷复核责任已随之了结
                    # (无 results.json 也不是待办);恢复路径不得再派发复核。
                    continue
                verifier.run_case(
                    candidate_id, self._session("verification", candidate_id))

            self._set_phase(gen_dir, "related")
            related = stored_related_proposals(gen_dir)
            if not related:
                break
            payload = store.build(
                comparator, scorer_factory,
                extra_intake=[related_intake(record) for record in related],
                slots=slots)
            if not self._register_selected(tracer, payload):
                break  # 幂等不动点:没有新增入选 Candidate

        # ---- 收尾:处理责任全部收束 → 事实报告与封存(票 12) ----
        return self._begin_finalizing(name, gen_dir, created, budget)

    # ---- 封存(票 12) ----

    def _record_failure(self, gen_dir: Path, exc: Exception) -> None:
        """异常停止的状态回写:封存阶段保持 finalizing,其余保持 running。"""
        if self._finalizing:
            save_run_state(
                gen_dir, status="finalizing", phase=self._phase,
                stop_reason=f"seal_failed:{type(exc).__name__}")
        else:
            save_run_state(
                gen_dir, status="running", phase=self._phase,
                stop_reason=f"interrupted:{type(exc).__name__}")

    def _seal(
        self, name: str, gen_dir: Path, created: bool, budget: RunBudget,
    ) -> RunSummary:
        """封存阶段:可选 LLM 注记 → 确定性报告 → manifest seal → completed。"""
        self._phase = "sealing"
        notes = self._analyst_notes(gen_dir, budget)
        seal_run(gen_dir, analyst_notes=notes)
        return self._summary(name, gen_dir, created, "completed", "sealed")

    def _analyst_notes(self, gen_dir: Path, budget: RunBudget) -> str | None:
        """可选 LLM 注记:任何失败只告警跳过,绝不阻塞封存(ADR-0012 L81)。

        注记请求只记账不过预算闸——它是封存期的可选说明段,预算耗尽不应
        阻止一个处理责任已收束的运行完成封存。
        """
        if self._llm is None:
            return None
        try:
            reply, usage = self._llm.chat([
                {"role": "system", "content": ANALYST_NOTES_SYSTEM_PROMPT},
                {"role": "user", "content": build_fact_report(gen_dir)},
            ])
            budget.record_llm_call(usage)
            notes = reply.strip() if isinstance(reply, str) else ""
            return notes or None
        except Exception as exc:  # 可选段:任何失败都不阻塞封存(ADR-0012 L81)
            warnings.warn(
                f"Analyst Notes 生成失败,封存继续: {exc}", RuntimeWarning)
            return None

    # ---- 辅助 ----

    def _set_phase(self, gen_dir: Path, phase: str) -> None:
        self._phase = phase
        save_run_state(gen_dir, status="running", phase=phase)

    def _session(self, role: str, candidate_id: str | None = None):
        # run_dir 一并下发:生产 factory 按世代目录放置 transcript(公开
        # 切换,票 14);测试替身按需忽略。
        return self._session_factory(
            role, candidate_id, run_dir=self._run_dir)

    def _register_selected(
        self, tracer: HostAnalysisTracer, payload: dict[str, Any],
    ) -> list[str]:
        """把入选且尚未注册的 Candidate 按 Store 分配的显式 ID 注册进 tracer。"""
        registered: list[str] = []
        # 升序注册是下方 ID 对齐校验的前提:tracer 的数值水位只增不减,
        # 乱序注册会让低号候选撞上已抬高的水位,报"Candidate ID 对齐失败"。
        for record in sorted(payload["candidates"],
                             key=lambda item: item["candidate_id"]):
            queue = record.get("queue") or {}
            if not queue.get("selected"):
                continue
            candidate_id = record["candidate_id"]
            try:
                tracer.investigation_for(candidate_id)
                continue
            except KeyError:
                pass
            proposal = {key: value for key, value in record.items()
                        if key not in _BOOKKEEPING_KEYS}
            added = tracer.add_candidate(proposal, candidate_id=candidate_id)
            if added.candidate_id != candidate_id:  # pragma: no cover
                raise StoreError(
                    f"Candidate ID 对齐失败:期望 {candidate_id},"
                    f"实际 {added.candidate_id};请检查原运行目录")
            registered.append(candidate_id)
        return registered

    def _summary(
        self, name: str, gen_dir: Path, created: bool, status: str,
        stop_reason: str | None,
    ) -> RunSummary:
        candidates = 0
        store_path = gen_dir / "candidates.json"
        if store_path.exists():
            document = read_json_object(store_path, "Candidate Store")
            candidates = len(document.get("candidates", []))
        findings = 0
        findings_path = gen_dir / "findings.json"
        if findings_path.exists():
            document = read_json_object(findings_path, "Findings 工件")
            findings = len(document.get("findings", []))
        return RunSummary(
            generation=name, gen_dir=gen_dir, created=created, status=status,
            stop_reason=stop_reason, phase=self._phase, candidates=candidates,
            findings=findings,
            registered=tuple(sorted(_investigation_ids(gen_dir))),
        )


def _investigation_ids(gen_dir: Path) -> list[str]:
    """盘上已注册(有 Investigation 目录)的 Candidate ID;摘要展示用。"""
    return [directory.name for directory
            in sorted((gen_dir / "investigations").glob("cand-*"))]

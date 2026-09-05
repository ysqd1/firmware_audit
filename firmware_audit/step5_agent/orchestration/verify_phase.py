"""verify_phase——verification 每疑点一实例引擎(ADR-0009 T5;ADR-0003)。

severity+confidence 排序取前 K、单实例断点续跑身份校验、复核结论锚点回填
聚合、阶段终态判定与阶段级留痕,从编排主体迁出成独立模块:编排主体
(orchestrator)只剩一处调用与结果登记,测一段复核逻辑不再必须构造整个
Orchestrator——三块核心逻辑(rank_findings / resume_identity_matches /
merge_verdicts)是纯函数,可零依赖聚焦单测。

依赖显式收参(run_verify_phase,不读 host 状态):cfg(子 Agent 配置)/
agent_dir+process_dir(工作区)/base_llm/upstream(上游工件)/findings
(analysis 聚合全量候选)/agg(聚合器,归一化与去重键来源)/force;
留痕回调:dispatch_log(四动词对象,阶段级留痕)/next_seq(实例 seq 分配)/
budget_state(留痕附注)。返回 VerifyPhaseOutcome(Observation + 待登记
阶段结果 + 逐实例明细),登记进调度史/防重复标记仍归编排主体。

包内依赖:只 import state(共享词汇)与叶子层(data/engine/providers/
runner),不 import actions/orchestrator(单向 orchestrator → actions/
verify_phase → …,环由 state 切断,守护测试 test_step5_layer_guard)。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from .state import DispatchStatus, SubAgentResult
from ..data.artifacts import (CONFIDENCE_RANK, SEVERITY_RANK, load_artifact,
                              save_aggregate, stamp_provenance)
from ..data.prompts import build_verify_single_brief
from ..engine.display import make_display
from ..providers.llm_client import LLMError
from ..providers.tools.base import ToolResult
from ..runner import post_run_status, run_agent

# ADR-0003:verification 每疑点一实例——K 上限(env STEP5_VERIFY_K,默认 10)。
# 排序 rank 表(severity 主排序 + confidence 次排序)自 T6 起以 data 层
# SEVERITY_RANK/CONFIDENCE_RANK 为单一出处(原 T4 暂驻 actions、T5 随复核
# 引擎迁入的本模块定义收编到 data 层派生表)。
DEFAULT_VERIFY_K = 10


def verify_k() -> int:
    """verification 每疑点一实例的调度预算(analysis findings 取前 K 条复核)。

    env STEP5_VERIFY_K 可配置(默认 10);非法值/缺失回落默认。K 即调度上限——
    同类型 3 次上限(MAX_DISPATCH_PER_AGENT,见 actions)不适用于 verification:
    调度语义已改为按 finding 计数(K 上限),补跑逻辑整体取消(ADR-0003)。
    """
    raw = os.environ.get("STEP5_VERIFY_K", "").strip()
    try:
        k = int(raw) if raw else DEFAULT_VERIFY_K
    except ValueError:
        return DEFAULT_VERIFY_K
    return max(1, k)


# ---- 三块核心纯逻辑(零 IO 零 LLM,聚焦单测见 test_step5_verify_phase.py) ----

def rank_findings(findings: list) -> list[dict]:
    """候选 findings 排序:severity 主排序 + confidence 次排序(从高到低)。

    输入为 analysis 已聚合 findings(跨多次调度去重合并后的全部候选 N 条),
    非 dict 条目过滤;返回排序后的完整列表,K 切片由调用方做(top = 前 K)。
    """
    return sorted(
        [f for f in findings if isinstance(f, dict)],
        key=lambda f: (SEVERITY_RANK.get(
            str(f.get("severity", "info")).lower(), 9),
            CONFIDENCE_RANK.get(
                str(f.get("confidence", "")).lower(), 9)))


def resume_identity_matches(vfs: list, anchor: dict, agg) -> bool:
    """单实例断点续跑身份校验:工件 finding 与当前锚点按 file+title 归一化比对。

    目录名是全局 seq 位置而非 finding 身份,续跑时编排路径变化(如 analysis
    补跑次数不同)会让 seq 前移,本条 finding 可能命中**前一条** finding 的旧
    工件——只判文件存在就加载会把别人的复核结论错配进来(target/1 实测 9/10
    条整体错位,新[N].rationale==旧[N-1],无任何告警)。故加载后必须比对身份,
    不一致 → 弃用工件真实重跑(调用方据 False 分支处理)。

    匹配键=file+title 归一化(2026-09-03 review 修复):实例工件常缺 func/addr,
    完整 dedup_key 四元组全等会把合法工件误拒 → 每次续跑全部真跑、静默烧预算;
    file+title 是必填身份字段,区分度足够(错位场景里 file/title 必然是别的
    finding 的)。工件无 findings(损坏)→ False(弃用真跑)。
    """
    return bool(vfs) and all(
        agg.norm_text(vfs[0].get(k, "")) == agg.norm_text(anchor.get(k, ""))
        for k in ("file", "title"))


def merge_verdicts(ranked: list[dict], top: list[dict],
                   instances: list, agg) -> tuple[list[dict], int]:
    """复核结论锚点回填聚合:全量 N 条(K 条覆盖复核结论,N-K 条原样
    verified=None + confidence 保留 analysis 初值)。

    锚点=各实例对应的原 analysis finding(按实例序与 top 对齐):复核结果
    回填到原槽位——实例返回的 finding 常缺 addr/func,按 dedup_key 会错位
    成新条目;以原 finding 的键锚定。只覆盖复核权威字段(verified/rationale/
    confidence/severity),不重排锚点——实例返回的 finding 可能缺 addr/func
    或改 title,一律忽略身份字段,防"换成别的 finding"混入(VERIFY_SYSTEM
    单条必达红线 + 代码兜底)。severity 在覆盖集(2026-09-03):verification
    是判级权威,实例死代码降级 low 曾被丢弃,聚合产物 severity=high 与
    rationale 自相矛盾;ADR-0003 精神延伸。

    返回(聚合 findings, 已复核条数);实例失败/无产出 → 该条保持未复核。
    """
    by_key = {agg.dedup_key(f): f for f in ranked}
    verified_n = 0
    for anchor, v in zip(top, instances):
        if not v.findings:
            continue                    # 实例失败/无产出:该条保持未复核
        vf = v.findings[0]
        merged = dict(by_key[agg.dedup_key(anchor)])
        merged["verified"] = vf.get("verified")      # True/False/None 照收
        if vf.get("rationale"):
            merged["rationale"] = vf["rationale"]    # 存疑项可能留空
        if vf.get("confidence"):
            merged["confidence"] = vf["confidence"]  # 存疑降级;无则留初值
        if vf.get("severity"):
            merged["severity"] = vf["severity"]      # 判级降级(见 docstring)
        merged["source_agent"] = "verification"
        merged["instance_seq"] = v.seq
        by_key[agg.dedup_key(anchor)] = merged
        if merged["verified"] is not None:
            verified_n += 1
    return list(by_key.values()), verified_n


def _lift_verify_verdict(loaded: dict | None, vfs: list) -> None:
    """0/N bug(2026-09-03):模型把复核结论写在实例工件**顶层**
    (verified/rationale),findings[] 只含 identity 字段(verified 空)。
    归一进 findings[0],聚合层才读得到——否则已复核条目被丢进未复核区
    (VERIFY_SYSTEM 虽要求写进 findings[],save_artifact 会保留未知顶层字段)。"""
    if not vfs or not loaded:
        return
    head = vfs[0]
    if head.get("verified") is None and "verified" in loaded:
        head["verified"] = loaded["verified"]
    if not head.get("rationale") and loaded.get("rationale"):
        head["rationale"] = loaded["rationale"]


def _run_verify_one(vseq: int, finding: dict, upstream: Path,
                    request: dict, *, cfg, agent_dir: Path,
                    process_dir: Path, base_llm, agg, force: bool) -> SubAgentResult:
    """单条 finding 的独立 verification 实例(ADR-0003)。

    输入=单条 finding + 工件指针(build_verify_single_brief),输出=单条
    verified finding;上下文隔离铁律不破(只从工件读,不传对话历史)。
    单实例不进主 dispatch_log(ADR-0003:逐实例留痕在其自身 transcript/obs +
    result.json 的 verification_instances;主 dispatch_log 只记编排调度(阶段))。
    """
    out_dir = agent_dir / f"{vseq}_verification"
    out_path = out_dir / cfg.output_name
    t0 = time.time()
    try:
        # 断点续跑(单实例):该实例 .json 工件已存在且未 force → skipped,
        # 加载前经 resume_identity_matches 校验工件身份(2026-09-03 错位 bug,
        # 见该函数 docstring);不一致或工件无 findings → 弃用工件真跑(如实
        # 上报不冒充;真跑产物写回同一路径,错位旧工件随之被覆盖)。
        if out_path.is_file() and not force:
            loaded = load_artifact(out_path) or {}
            vfs = [f for f in (loaded.get("findings") or [])
                   if isinstance(f, dict)]
            _lift_verify_verdict(loaded, vfs)
            if resume_identity_matches(vfs, finding, agg):
                return SubAgentResult(
                    seq=vseq, agent_name="verification",
                    status=DispatchStatus.SKIPPED,
                    artifact_path=out_path, summary=loaded.get("summary", ""),
                    findings=vfs, request=request,
                    duration_ms=int((time.time() - t0) * 1000))
        ares = run_agent(cfg, process_dir, base_llm, upstream,
                         output_dir=out_dir,
                         extra_brief=build_verify_single_brief(
                             process_dir, finding))
        elapsed = int((time.time() - t0) * 1000)
        status = post_run_status(ares)   # DispatchStatus 值域字符串(值即落盘值)
        loaded_v = (load_artifact(ares.artifact_path)
                    if ares.artifact_path else None)
        vfs = [f for f in (loaded_v or {}).get("findings", []) or []
               if isinstance(f, dict)]
        _lift_verify_verdict(loaded_v, vfs)
        stamp_provenance(vfs, "verification", vseq)  # 溯源:结论产自本实例
        react = ares.react
        budget_exhausted = bool(
            react and (react.steps >= cfg.max_iters or not react.finished))
        return SubAgentResult(
            seq=vseq, agent_name="verification", status=status,
            artifact_path=ares.artifact_path,
            summary=(loaded_v or {}).get("summary", ""),
            findings=vfs, error=ares.error, request=request,
            usage=dict(ares.usage), duration_ms=elapsed,
            steps=react.steps if react else 0,
            tool_calls=[c for c in (react.tool_calls if react else [])],
            budget_exhausted=budget_exhausted)
    except LLMError:
        raise  # 阶段层捕获并回填 interrupted


@dataclass
class VerifyPhaseOutcome:
    """阶段引擎产物(Observation + 待登记状态);登记动作仍归编排主体。

    done:阶段终态已达成(断点续跑 skipped / 真实执行落盘)——编排主体据它
    置防重复标记;异常路径(LLMError 上抛 / 兜底 failed)done=False。
    phase:待登记的阶段 SubAgentResult(异常路径 None,无登记物)。
    instances:逐实例明细(result.json 的 verification_instances 源)。
    """
    result: ToolResult
    done: bool = False
    phase: SubAgentResult | None = None
    instances: list = field(default_factory=list)


def run_verify_phase(cfg, *, agent_dir: Path, process_dir: Path, base_llm,
                     upstream: Path, findings: list, agg, force: bool,
                     dispatch_log, next_seq, budget_state,
                     task: str, request: dict, seq: int,
                     t0: float) -> VerifyPhaseOutcome:
    """verification 阶段(每疑点一实例):一次调度 → K 条独立实例 → 聚合工件。

    流程:读 analysis findings → severity 主排序 + confidence 次排序取前 K 条
    (STEP5_VERIFY_K,默认 10)→ 对每条派一个独立 verification 实例(max_iters=8,
    输入=单条 finding + 工件指针)→ 逐条产单条 verified finding → 聚合回
    verified_findings.json(全量 N 条:K 条带复核结论,N-K 条 verified=None,
    confidence 保留 analysis 初值)。补跑逻辑整体取消(每条必被验证)。
    阶段级留痕经 dispatch_log 四动词(发起即记 running,LLMError 回填
    interrupted 向上传播);调度史登记/防重复标记由编排主体据 Outcome 完成。
    """
    rec = dispatch_log.start(seq, "verification", task, request)
    try:
        # 断点续跑(阶段级):聚合工件已存在且未 force → skipped
        agg_path = agent_dir / cfg.output_name
        if agg_path.is_file() and not force:
            loaded = load_artifact(agg_path) or {}
            sub = SubAgentResult(
                seq=seq, agent_name="verification", status=DispatchStatus.SKIPPED,
                artifact_path=agg_path,
                summary=(loaded or {}).get("summary", ""),
                findings=(loaded or {}).get("findings", []) or [],
                request=request,
                duration_ms=int((time.time() - t0) * 1000))
            dispatch_log.finish(rec, DispatchStatus.SKIPPED,
                                artifact=str(agg_path), summary=sub.summary,
                                budget_state=budget_state("verification"))
            verified = sum(1 for f in sub.findings
                           if f.get("verified") is not None)
            return VerifyPhaseOutcome(done=True, phase=sub, result=ToolResult(
                ok=True, text=(
                    f"## verification Agent 结果(每疑点一实例,工件已存在,实例 {seq})\n"
                    f"已复核 {verified}/{len(sub.findings)} 条(其余未复核,verified=None)。"
                    f"工件: {agg_path.name}\n"
                    f"(下一步: 调用 summarize 取报告素材)")))

        # 源:analysis 已聚合 findings(跨多次调度去重合并后的全部候选 N 条)。
        # 不用最新 analysis 工件——多次调度时最新实例只有本轮的 findings,
        # 会丢前几轮已产出候选(ADR-0003 的 N 条候选 = 聚合全量)。
        ranked = rank_findings(findings)
        top = ranked[: verify_k()]

        # 逐条派独立实例(每条必跑;补跑逻辑整体取消);每实例启动前标
        # "实例 i/N"(#6):单实例 done 行恒 1 findings,不标序号会误导为
        # 全阶段只复核 1 条(阶段全貌由 phase_done 汇总行兜底)
        disp = make_display()
        instances = []
        for i, f in enumerate(top, 1):
            if disp.enabled:
                disp.instance_tag(i, len(top))
            instances.append(
                _run_verify_one(next_seq(), f, upstream, request,
                                cfg=cfg, agent_dir=agent_dir,
                                process_dir=process_dir, base_llm=base_llm,
                                agg=agg, force=force))

        # 聚合:锚点回填(见 merge_verdicts docstring)
        phase_findings, verified_n = merge_verdicts(ranked, top, instances, agg)

        phase_summary = (f"已复核 {verified_n}/{len(ranked)} 条"
                         f"(未进入前 {len(top)} 的 {len(ranked) - len(top)}"
                         " 条未复核,verified=None,confidence 保留 analysis 初值)")
        out_path = save_aggregate(agent_dir / cfg.output_name, "verification",
                                  phase_summary, phase_findings)

        # 阶段终态:全部实例 SUCCESS/SKIPPED → success;任一 FAILED/DEGRADED
        # (仅 .md 降级工件,该条结论不完整)→ 阶段降级/失败,如实上报不冒充
        bad = [v for v in instances
               if v.status in (DispatchStatus.FAILED, DispatchStatus.DEGRADED)]
        if not bad:
            status = DispatchStatus.SUCCESS
        elif all(v.status == DispatchStatus.DEGRADED for v in bad):
            status = DispatchStatus.DEGRADED
        else:
            status = DispatchStatus.FAILED
        phase = SubAgentResult(
            seq=seq, agent_name="verification", status=status,
            artifact_path=out_path, summary=phase_summary,
            findings=phase_findings,
            error="; ".join(v.error for v in bad),
            request=request,
            duration_ms=int((time.time() - t0) * 1000),
            steps=sum(v.steps for v in instances),
            tool_calls=[c for v in instances for c in v.tool_calls],
            budget_exhausted=any(v.budget_exhausted for v in instances))
        dispatch_log.finish(rec, status, duration_ms=phase.duration_ms,
                            artifact=str(out_path), summary=phase_summary,
                            error=phase.error,
                            budget_state=budget_state("verification"))
        # 阶段级汇总行(#6,2026-09-03):每实例 done 行是单实例计数(恒
        # 1 findings),阶段真实全貌(实例数/已复核 x/N/合计)在此汇总,
        # 不再误导"只复核了 1 条"
        if disp.enabled:
            usage_sum = {}
            for v in instances:
                for k, n in (v.usage or {}).items():
                    usage_sum[k] = usage_sum.get(k, 0) + n
            disp.phase_done("verification", out_path.name,
                            len(instances), verified_n, len(ranked),
                            phase.steps, usage_sum,
                            elapsed_s=phase.duration_ms / 1000)
        if status == DispatchStatus.SUCCESS:
            return VerifyPhaseOutcome(
                done=True, phase=phase, instances=instances,
                result=ToolResult(ok=True, text=(
                    f"## verification Agent 结果(每疑点一实例,成功,实例 {seq})\n"
                    f"已复核 {verified_n}/{len(ranked)} 条(共 {len(ranked)} 条;"
                    f"未进入前 {len(top)} 的未复核,verified=None)\n"
                    f"工件: {out_path.name}\n"
                    f"(下一步: 调用 summarize 取报告素材)\n"
                    + "budget_state: " + json.dumps(
                        budget_state("verification"), ensure_ascii=False))))
        return VerifyPhaseOutcome(
            done=True, phase=phase, instances=instances,
            result=ToolResult(ok=False, text="", error=(
                f"verification 阶段失败(实例 {seq}): {phase.error}")))
    except LLMError:
        dispatch_log.interrupted(rec)
        raise
    except Exception as e:
        dispatch_log.finish(rec, DispatchStatus.FAILED,
                            error=f"{type(e).__name__}: {e}",
                            budget_state=budget_state("verification"))
        return VerifyPhaseOutcome(result=ToolResult(ok=False, text="", error=(
            f"verification 阶段失败(实例 {seq}): {type(e).__name__}: {e}")))


__all__ = ["DEFAULT_VERIFY_K", "verify_k", "rank_findings",
           "resume_identity_matches", "merge_verdicts", "run_verify_phase",
           "VerifyPhaseOutcome"]

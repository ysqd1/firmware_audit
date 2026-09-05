"""verify_phase 聚焦单测(ADR-0009 T5:复核引擎下沉;T6 补执行后状态判定)。

排序取 K(rank_findings + verify_k)/ 单实例续跑身份校验
(resume_identity_matches)/ 锚点回填聚合(merge_verdicts)三块核心逻辑
零 Orchestrator 零 LLM 直测——"为测一段复核逻辑构造整个编排器"正是本票
要消灭的耦合。编排级行为(每疑点一实例调度语义/续跑错位弃用重跑/顶层结论
归一/LLMError 传播/阶段产物形态)仍在 test_orchestrator.py 与
test_step5_pipeline.py,照绿即回归锁定。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.aggregator import FindingAggregator
from firmware_audit.step5_agent.orchestration.state import (
    DispatchStatus,
    SubAgentResult,
)
from firmware_audit.step5_agent.orchestration.verify_phase import (
    DEFAULT_VERIFY_K,
    merge_verdicts,
    rank_findings,
    resume_identity_matches,
    verify_k,
)
from firmware_audit.step5_agent.runner import VERIFY_CFG, AgentRunResult, post_run_status


def test_rank_findings_and_k_budget() -> list[str]:
    """排序取 K:severity 主排序 + confidence 次排序(从高到低),非 dict
    过滤、未知枚举落末尾;verify_k 缺失/非法回落默认、下限钳 1、env 生效。"""
    fails: list[str] = []
    findings = [
        {"title": "l", "severity": "low", "confidence": "high"},
        {"title": "h_m", "severity": "high", "confidence": "medium"},
        {"title": "c", "severity": "critical", "confidence": "low"},
        {"title": "m", "severity": "medium", "confidence": "high"},
        {"title": "h_h", "severity": "high", "confidence": "high"},
        {"title": "u", "severity": "weird", "confidence": "nope"},
        {"title": "h_l", "severity": "high", "confidence": "low"},
        "junk",
    ]
    order = [f.get("title") for f in rank_findings(findings)]
    if order != ["c", "h_h", "h_m", "h_l", "m", "l", "u"]:
        fails.append(f"排序应为 severity 主+confidence 次(非 dict 过滤): {order}")
    top = rank_findings(findings)[:3]
    if [f["title"] for f in top] != ["c", "h_h", "h_m"]:
        fails.append(f"K 切片应取排序后前 K: {[f['title'] for f in top]}")

    old = os.environ.pop("STEP5_VERIFY_K", None)
    try:
        if verify_k() != DEFAULT_VERIFY_K:
            fails.append(f"env 缺失应回落默认 {DEFAULT_VERIFY_K}: {verify_k()}")
        os.environ["STEP5_VERIFY_K"] = "abc"
        if verify_k() != DEFAULT_VERIFY_K:
            fails.append(f"非法值应回落默认: {verify_k()}")
        os.environ["STEP5_VERIFY_K"] = "0"
        if verify_k() != 1:
            fails.append(f"下限应钳 1: {verify_k()}")
        os.environ["STEP5_VERIFY_K"] = "2"
        if verify_k() != 2:
            fails.append(f"env 合法值应生效: {verify_k()}")
    finally:
        if old is None:
            os.environ.pop("STEP5_VERIFY_K", None)
        else:
            os.environ["STEP5_VERIFY_K"] = old
    return fails


def test_resume_identity_check() -> list[str]:
    """续跑身份校验:file+title 归一化比对,容忍实例工件缺 func/addr 与
    分隔符/空白/大小写差异;身份不一致(错位旧工件)或空 findings 拒绝。"""
    fails: list[str] = []
    agg = FindingAggregator()
    anchor = {"title": "硬编码口令", "file": "extracted/unitree/bin/idlc",
              "func": "main", "addr": "0010d000"}
    # 宽松匹配(target/1 实例工件真实形态:缺 func/addr):同一条 → True
    ok = [{"title": "  硬编码口令 ", "file": "extracted\\unitree\\BIN\\idlc",
           "verified": True}]
    if not resume_identity_matches(ok, anchor, agg):
        fails.append("file+title 归一化一致(缺 func/addr)应匹配(合法工件不得误拒)")
    # 错位场景:目录里躺着的是前一条 finding 的旧工件 → False(弃用真跑)
    stale = [{"title": "别的疑点", "file": "extracted/unitree/bin/netswitch",
              "verified": True, "rationale": "旧结论"}]
    if resume_identity_matches(stale, anchor, agg):
        fails.append("file+title 不一致应拒绝(防复核结论整体错配)")
    if resume_identity_matches([], anchor, agg):
        fails.append("工件无 findings(损坏)应拒绝")
    return fails


def test_merge_verdicts_authoritative_fields_only() -> list[str]:
    """锚点回填:只覆盖复核权威字段(verified/rationale/confidence/severity)
    + 溯源(source_agent/instance_seq);锚点身份/证据字段不被实例改写;
    失败实例该条保持未复核;未进前 K 原样保留(verified=None + 初值);
    verified_n 只计有结论条目(False 也是结论)。"""
    fails: list[str] = []
    agg = FindingAggregator()
    ranked = [
        {"title": "f1", "severity": "high", "file": "a", "func": "fa",
         "addr": "0x1", "confidence": "medium", "evidence": "ev1"},
        {"title": "f2", "severity": "medium", "file": "b", "confidence": "high"},
        {"title": "f3", "severity": "low", "file": "c", "confidence": "high"},
    ]
    top = ranked[:2]
    instances = [
        SubAgentResult(seq=7, agent_name="verification", findings=[
            # 实例返回常缺 addr/func:身份字段必须以锚点为准,不得错位成新条目
            {"title": "f1", "file": "a", "verified": False, "rationale": "误报",
             "confidence": "low", "severity": "low"},
        ]),
        SubAgentResult(seq=8, agent_name="verification", findings=[]),  # 失败实例
    ]
    merged, verified_n = merge_verdicts(ranked, top, instances, agg)
    if len(merged) != 3:
        fails.append(f"聚合应保留全量 N 条(去重不增不减): {len(merged)}")
    by_title = {f["title"]: f for f in merged}
    f1, f2, f3 = by_title["f1"], by_title["f2"], by_title["f3"]
    if f1.get("verified") is not False or f1.get("rationale") != "误报":
        fails.append(f"f1 权威字段(verified/rationale)应覆盖: {f1}")
    if f1.get("confidence") != "low" or f1.get("severity") != "low":
        fails.append(f"f1 复核降级(confidence/severity)应覆盖初值: {f1}")
    if f1.get("func") != "fa" or f1.get("addr") != "0x1" or f1.get("evidence") != "ev1":
        fails.append(f"f1 锚点身份/证据字段不得被实例改写: {f1}")
    if f1.get("source_agent") != "verification" or f1.get("instance_seq") != 7:
        fails.append(f"f1 应带溯源(source_agent/instance_seq): {f1}")
    if f2.get("verified") is not None or f2.get("source_agent") is not None:
        fails.append(f"失败实例对应的 f2 应保持未复核无溯源: {f2}")
    if f3.get("verified") is not None or f3.get("confidence") != "high":
        fails.append(f"未进前 K 的 f3 应原样(verified=None + 初值): {f3}")
    if verified_n != 1:
        fails.append(f"verified_n 应只计有结论条目(verified=False 也算): {verified_n}")
    return fails


def test_post_run_status_three_way() -> list[str]:
    """执行后状态三岔判定单一出处(T6 收编到 runner.post_run_status):
    success / degraded(仅 .md 降级工件)/ failed,判据与收编前两处
    (actions 调度回填、verify_phase 单实例)内联 if/elif 逐字一致。"""
    fails: list[str] = []
    ok = AgentRunResult(cfg=VERIFY_CFG, artifact_path=Path("agent/0_recon/survey.json"))
    if post_run_status(ok) != "success":
        fails.append(f"ok+json 工件应为 success: {post_run_status(ok)}")
    degraded = AgentRunResult(cfg=VERIFY_CFG, artifact_path=Path("agent/1_analysis/findings.md"),
                              error="未产出可解析 Final Answer(工件已降级 .md)")
    if post_run_status(degraded) != "degraded":
        fails.append(f"仅 .md 降级工件应为 degraded: {post_run_status(degraded)}")
    failed = AgentRunResult(cfg=VERIFY_CFG, artifact_path=None, error="boom")
    if post_run_status(failed) != "failed":
        fails.append(f"无工件应为 failed: {post_run_status(failed)}")
    if post_run_status(AgentRunResult(cfg=VERIFY_CFG)) != "failed":
        fails.append("缺省(无工件无错误)应按 failed 处理")
    # 跨层字面量对齐(ADR-0009:runner 不 import orchestration,字符串契约
    # 靠本断言机器锁定——state 值域变更时此处先红,防消费点相等比较静默失配)
    for got, want in ((post_run_status(ok), DispatchStatus.SUCCESS),
                      (post_run_status(degraded), DispatchStatus.DEGRADED),
                      (post_run_status(failed), DispatchStatus.FAILED)):
        if got != want:
            fails.append(f"post_run_status 字面量应与 DispatchStatus 对齐: {got} != {want}")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("rank_findings_and_k_budget", test_rank_findings_and_k_budget),
        ("resume_identity_check", test_resume_identity_check),
        ("merge_verdicts_authoritative_fields_only",
         test_merge_verdicts_authoritative_fields_only),
        ("post_run_status_three_way", test_post_run_status_three_way),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())

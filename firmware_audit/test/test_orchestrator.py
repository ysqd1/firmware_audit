"""Orchestrator 单测:结果封装 / 调度守卫(顺序/重复/上限) / 多次调用与交接 / 日志字段。

ScriptedLLM + 临时 process_dir,零 API 零 Docker。覆盖 v2(2026-08-27):
- 类型+任务唯一性:相同任务拒绝并返回历史结果;不同任务支持同类型多次调用
- 调度次数上限:同类型最多 MAX_DISPATCH_PER_AGENT 次,超出拒绝
- 严格单向顺序门:跳序(前段未完成)与回退(后段已启动)均拒绝
- 交接流程:交接块注入简报(前序状态/第 N 次调用/上游工件链续传)
- 日志系统:transcript 事件 ts、工具发起即记(tool_call 先于 tool)、
  assistant in_chars/usage/elapsed;dispatch_log 状态变迁 running→终态、
  started_at/finished_at、拒绝/重复留痕
- Task8(2026-08-29):动态分配端到端(Orchestrator.run 全链:耗尽→补跑→
  verification→summarize,budget_state 逐实例断言)与重合适配 e2e(高重合
  补跑 overlap_ratio≥0.5 + 提示词红线生效)
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.orchestrator import (
    Orchestrator,
    SubAgentResult,
    DispatchAgentTool,
    SummarizeTool,
    build_orchestrator_prompt,
    MAX_DISPATCH_PER_AGENT,
)
from firmware_audit.step5_agent.data.artifacts import load_artifact
from firmware_audit.step5_agent.providers.tools import ToolContext
from firmware_audit.test.scripted_llm import ScriptedLLM

D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
D2 = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "%s", "context": ""}'
RECON_FINAL = ('Final Answer: {"summary": "攻击面", "findings": [{"title": "危险导入", '
               '"severity": "high", "file": "unitree/bin/idlc"}]}')
TOOL = 'Thought: 先看工件\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.imports.json", "limit": 10}'
FA = 'Final Answer: {"summary": "首轮取证", "findings": [{"title": "fa", "severity": "high", "file": "unitree/bin/idlc"}]}'
FB = 'Final Answer: {"summary": "补充深挖", "findings": [{"title": "fb", "severity": "medium", "file": "unitree/bin/idlc"}]}'
FV = 'Final Answer: {"summary": "复核", "findings": [{"title": "fa", "severity": "high", "file": "unitree/bin/idlc", "verified": true}]}'
# ADR-0003 每疑点一实例:verification 单实例只复核一条(单条 finals)
VERIFY_F1 = ('Final Answer: {"summary": "复核fa", "findings": [{"title": "fa", '
             '"severity": "high", "file": "unitree/bin/idlc", "verified": true}]}')
VERIFY_F2 = ('Final Answer: {"summary": "复核fb", "findings": [{"title": "fb", '
             '"severity": "medium", "file": "unitree/bin/idlc", "verified": true}]}')
VERIFY_FC = ('Final Answer: {"summary": "复核fc", "findings": [{"title": "fc", '
             '"severity": "medium", "file": "unitree/bin/netswitch", "verified": true}]}')

# Task6 用例 fixture:v3 recon survey(recommended_actions 含 high/medium/low 各一,
# high_risk_areas 锚定 idlc 顺序)+ 补跑实例的部分重复 findings(fa 重复 + fc 新增)
RECON_V3_FINAL = ('Final Answer: {"schema_version": 3, "summary": "v3 侦察", '
                  '"arch_snapshot": {"top_level_dirs": ["unitree", "etc"], '
                  '"components_grouped": [], "os_or_runtime": "busybox-linux"}, '
                  '"components": [], '
                  '"entry_points": [{"file": "etc/init.d/lighttpd", "reason": "web/cgi 入口"}], '
                  '"high_risk_areas": [{"file": "unitree/bin/idlc", "metric": "注入模式命中", '
                  '"detail": "semgrep R2 @ unitree/bin/idlc:42"}], '
                  '"recommended_actions": ['
                  '{"priority": "high", "action": "对 unitree/bin/idlc 取证,关注 system 拼接"}, '
                  '{"priority": "medium", "action": "对 unitree/bin/netswitch 取证,关注硬编码口令"}, '
                  '{"priority": "low", "action": "低优先级,不应进入 pending"}]}')
FDUP_MIX = ('Final Answer: {"summary": "补跑取证", "findings": ['
            '{"title": "fa", "severity": "high", "file": "unitree/bin/idlc"}, '
            '{"title": "fc", "severity": "medium", "file": "unitree/bin/netswitch"}]}')

# Task8.3 高重合 fixture:实例 1 产 3 条(全在 idlc);实例 2 与其 (title,file)
# 全部相同再 +1 条新(netswitch)→ overlap_ratio = 3/4 = 0.75(超 0.5 阈值)
FA3 = ('Final Answer: {"summary": "首轮取证", "findings": ['
       '{"title": "fa", "severity": "high", "file": "unitree/bin/idlc"}, '
       '{"title": "fb", "severity": "high", "file": "unitree/bin/idlc"}, '
       '{"title": "fx", "severity": "medium", "file": "unitree/bin/idlc"}]}')
FDUP_HIGH = ('Final Answer: {"summary": "高重合补跑", "findings": ['
             '{"title": "fa", "severity": "high", "file": "unitree/bin/idlc"}, '
             '{"title": "fb", "severity": "high", "file": "unitree/bin/idlc"}, '
             '{"title": "fx", "severity": "medium", "file": "unitree/bin/idlc"}, '
             '{"title": "fc", "severity": "medium", "file": "unitree/bin/netswitch"}]}')


def _make_process(td: Path) -> Path:
    ana = td / "process" / "analysis" / "unitree" / "bin"
    ana.mkdir(parents=True)
    (ana / "idlc.imports.json").write_text(json.dumps([
        {"name": "system", "address": "EXTERNAL:0001", "ref_count": 2, "call_sites": []},
    ]), encoding="utf-8")
    (ana / "idlc.strings.json").write_text(json.dumps({
        "program": "idlc", "version": 2,
        "strings": [{"address": "0010d6a1", "value": "password=unitree2018", "refs": []}],
    }), encoding="utf-8")
    (ana / "idlc.functions.json").write_text(json.dumps([
        {"name": "main", "address": "0010d000", "callers": [], "callees": ["system"]},
    ]), encoding="utf-8")
    (ana / "idlc.c").write_text("int main(void){ return 0; }\n", encoding="utf-8")
    return td


def _orch(td: Path, llm, force: bool = False) -> Orchestrator:
    return Orchestrator(td / "process", llm, force=force)


def _tool(orch: Orchestrator) -> DispatchAgentTool:
    return DispatchAgentTool(ToolContext(process_dir=orch.process_dir), orch)


# ---- 轮次上限 env 覆盖(STEP5_<NAME>_MAX_ITERS)----

def test_max_iters_env_override() -> list[str]:
    """resolve_max_iters:缺失/非法回落默认、下限钳 1;Orchestrator 消费点
    生效且不污染模块常量(env 名统一 STEP5_<NAME>_MAX_ITERS)。"""
    fails: list[str] = []
    import os
    from firmware_audit.step5_agent.runner import (
        RECON_CFG, ANALYSIS_CFG, VERIFY_CFG, resolve_max_iters)

    # 缺失 → 默认
    os.environ.pop("STEP5_RECON_MAX_ITERS", None)
    if resolve_max_iters("recon", 20) != 20:
        fails.append("env 缺失应回落默认 20")
    # 合法值 → 生效
    os.environ["STEP5_RECON_MAX_ITERS"] = "5"
    try:
        if resolve_max_iters("recon", 20) != 5:
            fails.append("env=5 应生效")
        # 非法值 → 默认
        os.environ["STEP5_RECON_MAX_ITERS"] = "abc"
        if resolve_max_iters("recon", 20) != 20:
            fails.append("非法值应回落默认")
        # 0/负数 → 钳到 1
        for bad in ("0", "-3"):
            os.environ["STEP5_RECON_MAX_ITERS"] = bad
            if resolve_max_iters("recon", 20) != 1:
                fails.append(f"env={bad} 应钳到 1")
    finally:
        del os.environ["STEP5_RECON_MAX_ITERS"]

    # 四个 config 名与 env 名对齐(消费点构造副本,模块常量不动)
    os.environ["STEP5_VERIFICATION_MAX_ITERS"] = "3"
    try:
        if VERIFY_CFG.max_iters != 8:
            fails.append("模块常量 VERIFY_CFG 不应被 env 污染")
        orch = _orch(Path(tempfile.mkdtemp()), ScriptedLLM([]))
        if orch._sub_cfgs["verification"].max_iters != 3:
            fails.append("Orchestrator 应消费 env 覆盖后的 verification max_iters=3")
        if orch._sub_cfgs["recon"].max_iters != RECON_CFG.max_iters:
            fails.append("未覆盖的 agent 应保持默认")
        if orch._sub_cfgs["analysis"].max_iters != ANALYSIS_CFG.max_iters:
            fails.append("未覆盖的 analysis 应保持默认")
    finally:
        del os.environ["STEP5_VERIFICATION_MAX_ITERS"]

    # orchestrator 自身轮次 env(run() 内消费点同名规则)
    os.environ["STEP5_ORCHESTRATOR_MAX_ITERS"] = "7"
    try:
        if resolve_max_iters("orchestrator", 12) != 7:
            fails.append("orchestrator env=7 应生效")
    finally:
        del os.environ["STEP5_ORCHESTRATOR_MAX_ITERS"]
    return fails


# ---- SubAgentResult ----

def test_sub_agent_result() -> list[str]:
    fails: list[str] = []
    sub = SubAgentResult(seq=0, agent_name="recon")
    if sub.status != "running" or sub.ok:
        fails.append(f"默认 running 且 not ok: {sub.status}/{sub.ok}")
    sub.status = "success"
    if not sub.ok:
        fails.append("success 应 ok")
    sub.error = "boom"
    if sub.ok:
        fails.append("success+error 不应 ok")
    sub2 = SubAgentResult(seq=1, agent_name="analysis", status="skipped")
    if not sub2.ok:
        fails.append("skipped 应 ok")
    d = sub2.to_dict()
    if d["agent"] != "analysis" or d["status"] != "skipped" or d["artifact_path"] is not None:
        fails.append(f"to_dict 字段不符: {d}")
    # v2:request 里的 task 应进入 to_dict(调度史可读)
    sub3 = SubAgentResult(seq=2, agent_name="verification",
                          request={"agent": "verification", "task": "复核"})
    if sub3.to_dict().get("task") != "复核":
        fails.append("to_dict 应含 task 字段")
    return fails


# ---- prompts ----

def test_build_orchestrator_prompt() -> list[str]:
    """提示词结构(统一 8 节骨架 2026-08-29):角色/子Agent/输入输出/流程/判定/
    红线/输出协议/重要原则齐备。"""
    fails: list[str] = []
    prompt = build_orchestrator_prompt({}, max_iters=10)
    for needle in ("dispatch_agent", "recon", "analysis", "verification", "finish",
                   "执行流程", "输出协议", "预算状态解读", "重要原则",
                   "Thought:", "Action:", "Action Input:"):
        if needle not in prompt:
            fails.append(f"提示词应含 '{needle}'")
    # Ticket 04:报告未复核疑点独立区段(⚠ 未经复核,confidence 为 analysis 初值)
    for needle in ("未复核疑点", "未经复核,confidence 为 analysis 初值",
                   "只含**已复核** finding"):
        if needle not in prompt:
            fails.append(f"提示词报告结构应含未复核区段要求 '{needle}'")
    if f"最多调度 {MAX_DISPATCH_PER_AGENT} 次" not in prompt:
        fails.append(f"提示词应明确调度次数上限 {MAX_DISPATCH_PER_AGENT}")
    for banned in ("同一时间仅允许一个", "串行执行"):
        if banned in prompt:
            fails.append(f"提示词不应再强调 '{banned}'(同步调用天然串行)")
    if "迭代预算" not in prompt:
        fails.append("应含迭代预算说明")
    # Task7:预算状态解读小节(budget_state/补跑指导/重合红线)
    for needle in ("budget_state", "补跑", "pending_focuses", "overlap_ratio",
                   "第 N 轮补跑", "差分"):
        if needle not in prompt:
            fails.append(f"提示词应含 budget_state 解读小节关键词 '{needle}'")
    return fails


# ---- DispatchAgentTool 守卫分支 ----

def test_unknown_agent() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([])
        orch = _orch(td, llm)
        tr = _tool(orch).execute(agent="hacker", task="x")
        if tr.ok or "不存在" not in (tr.error or ""):
            fails.append(f"未知 agent 应返回错误: {tr}")
        if orch.dispatches:
            fails.append("未知 agent 不应登记为实际执行")
        log = json.loads((td / "process" / "agent" / "orchestrator" / "dispatch_log.json").read_text(encoding="utf-8"))
        if not any(x.get("status") == "rejected" for x in log):
            fails.append("未知 agent 尝试应在 dispatch_log 留痕(rejected)")
    return fails


def test_order_gate_skip_forward() -> list[str]:
    """跳序拒绝:recon 未完成时不得调度 analysis/verification。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([])
        orch = _orch(td, llm)
        tool = _tool(orch)
        r = tool.execute(agent="analysis", task="x")
        if r.ok or "顺序违规" not in (r.error or ""):
            fails.append(f"recon 未完成时应拒绝 analysis: {r.error}")
        r2 = tool.execute(agent="verification", task="x")
        if r2.ok or "顺序违规" not in (r2.error or ""):
            fails.append("recon 未完成时应拒绝 verification")
        if orch.dispatches:
            fails.append("被拒调度不应登记为实际执行")
        log = json.loads((td / "process" / "agent" / "orchestrator" / "dispatch_log.json").read_text(encoding="utf-8"))
        if not any(x.get("status") == "rejected" for x in log):
            fails.append("被拒调度应在 dispatch_log 留痕(rejected)")
    return fails


def test_order_gate_backward() -> list[str]:
    """回退拒绝:verification 已启动后不得回头调度 analysis/recon。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([TOOL, RECON_FINAL, TOOL, FA, TOOL, FV])
        orch = _orch(td, llm)
        tool = _tool(orch)
        tool.execute(agent="recon", task="a")
        tool.execute(agent="analysis", task="b")
        tool.execute(agent="verification", task="c")
        r = tool.execute(agent="analysis", task="another-scope")  # 不同任务,单测顺序门本身
        if r.ok or "顺序违规" not in (r.error or ""):
            fails.append(f"verification 启动后不得回退调度 analysis: {r.error}")
        r2 = tool.execute(agent="recon", task="re-scan")
        if r2.ok or "顺序违规" not in (r2.error or ""):
            fails.append("verification 启动后不得回退调度 recon")
    return fails


def test_max_dispatch_limit() -> list[str]:
    """调度次数上限(Task6.1 后):同类型最多 MAX_DISPATCH_PER_AGENT(3)次,
    第 3 次(第 2 轮补跑)仍允许,第 4 次被拒。"""
    fails: list[str] = []
    if MAX_DISPATCH_PER_AGENT != 3:
        fails.append(f"MAX_DISPATCH_PER_AGENT 应为 3(动态分配,1 次默认+2 次补跑),"
                     f"got {MAX_DISPATCH_PER_AGENT}")
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([TOOL, RECON_FINAL, TOOL, FA, TOOL, FB, TOOL, FA])
        orch = _orch(td, llm)
        tool = _tool(orch)
        tool.execute(agent="recon", task="t0")
        tool.execute(agent="analysis", task="t1")
        tool.execute(agent="analysis", task="t2")   # 第 2 次:补跑,允许
        r3 = tool.execute(agent="analysis", task="t3")   # 第 3 次:第 2 轮补跑,允许
        if not r3.ok:
            fails.append(f"第 3 次调度在上限 3 内应允许: {r3.error}")
        r4 = tool.execute(agent="analysis", task="t4")   # 第 4 次:超上限
        if r4.ok or "上限" not in (r4.error or ""):
            fails.append(f"超过调度上限应被拒: {r4.error}")
        if len(orch.dispatches) != 4:
            fails.append(f"实际执行应 4 次(recon+analysis×3), got {len(orch.dispatches)}")
        log = json.loads((td / "process" / "agent" / "orchestrator" / "dispatch_log.json").read_text(encoding="utf-8"))
        if not any(r.get("status") == "rejected" and "上限" in (r.get("error") or "")
                   for r in log):
            fails.append("超上限拒绝应在 dispatch_log 留痕")
    return fails


def test_duplicate_of_failed() -> list[str]:
    """失败过的同任务重试也应被唯一性检查拒绝(改任务或 finish)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([])   # 首次执行即耗尽 → failed
        orch = _orch(td, llm)
        tool = _tool(orch)
        r1 = tool.execute(agent="recon", task="t")
        if r1.ok:
            fails.append("脚本耗尽时 recon 应失败")
        r2 = tool.execute(agent="recon", task="t")
        if r2.ok or "已失败" not in (r2.error or ""):
            fails.append(f"同任务重试失败过的 agent 应被拒: {r2.error}")
    return fails


def test_dispatch_success() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([TOOL, RECON_FINAL])
        orch = _orch(td, llm)
        tr = _tool(orch).execute(agent="recon", task="侦察")
        if not tr.ok:
            fails.append(f"recon 正常执行应成功: {tr.error}")
        res = orch.agent_results.get("recon")
        if res is None or res.status != "success":
            fails.append(f"recon 应为 success: {res.status if res else None}")
        art = td / "process" / "agent" / "0_recon" / "survey.json"
        if not art.is_file():
            fails.append("recon 工件(survey.json)未落盘到 0_recon/")
        if res and res.artifact_path and res.artifact_path.name != "survey.json":
            fails.append(f"artifact_path 应为 survey 工件: {res.artifact_path}")
        if res.findings:  # recon v3 无 findings(判级移交 analysis)
            fails.append(f"recon v3 survey 不应聚合 findings: {res.findings}")
        # v2:交接块应注入子 Agent 简报
        init = llm.calls[0][1]["content"]
        if "交接信息" not in init:
            fails.append(f"子 Agent 简报应含编排器交接块: {init[:120]}")
        # dispatch_log 落盘
        log = json.loads((td / "process" / "agent" / "orchestrator" / "dispatch_log.json").read_text(encoding="utf-8"))
        if not log or log[0]["agent"] != "recon" or log[0]["status"] != "success":
            fails.append(f"dispatch_log 记录不符: {log}")
    return fails


def test_dispatch_skipped() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        out = td / "process" / "agent" / "0_recon" / "survey.json"
        out.parent.mkdir(parents=True)
        out.write_text(json.dumps({"schema": 1, "agent": "recon", "summary": "旧",
                                   "findings": [{"title": "old"}]}), encoding="utf-8")
        llm = ScriptedLLM([])
        orch = _orch(td, llm)
        tr = _tool(orch).execute(agent="recon", task="x")
        if not tr.ok:
            fails.append(f"已存在工件应跳过(success result): {tr}")
        res = orch.agent_results.get("recon")
        if res is None or res.status != "skipped":
            fails.append(f"应记为 skipped: {res.status if res else None}")
        if res and res.summary != "旧":
            fails.append(f"skipped 应加载已有工件摘要: {res.summary}")
        if llm.calls:
            fails.append("跳过路径不应调 LLM(子 Agent)")
    return fails


# ---- 多次调用与交接(调度器级) ----

def test_multi_dispatch_and_duplicate() -> list[str]:
    """多次调用:同类型不同任务各建实例;相同任务被唯一性检查拒绝且不新建实例。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        # ADR-0003:verification 每疑点一实例——analysis 聚合 fa+fb 两条 → 2 个复核实例
        llm = ScriptedLLM([TOOL, RECON_FINAL, TOOL, FA, TOOL, FB,
                           TOOL, VERIFY_F1, TOOL, VERIFY_F2])
        orch = _orch(td, llm)
        tool = _tool(orch)
        tool.execute(agent="recon", task="t0")
        tool.execute(agent="analysis", task="t1")
        tool.execute(agent="analysis", task="t2")       # 同类型第二次调用(不同任务)
        dup = tool.execute(agent="analysis", task="t1")  # 重复任务
        tool.execute(agent="verification", task="t3")
        agent_dir = td / "process" / "agent"
        # verification 阶段 seq=3(聚合到 verified_findings.json,无目录),
        # 两个独立复核实例 seq=4/5(目录 4/5_verification)
        for d in ("0_recon", "1_analysis", "2_analysis", "4_verification",
                  "5_verification"):
            if not (agent_dir / d).is_dir():
                fails.append(f"多次调用应生成实例目录 {d}/")
        if not (agent_dir / "verified_findings.json").is_file():
            fails.append("verification 阶段应聚合 verified_findings.json")
        if (agent_dir / "4_analysis").exists():
            fails.append("重复任务不应新建实例目录")
        if not dup.ok or "重复" not in dup.text:
            fails.append(f"重复调度应返回历史结果并说明被拒: ok={dup.ok}, text={dup.text[:80]}")
        if len(orch.dispatches) != 4:
            fails.append(f"实际执行调度应为 4 次(重复不计;verification 阶段计 1 次),"
                         f" got {len(orch.dispatches)}")
        # 交接:analysis#2 简报应说明第 2 次调用
        a2_init = llm.calls[4][1]["content"]
        if "第 2 次调用" not in a2_init:
            fails.append(f"analysis#2 简报应含交接说明: {a2_init[:150]}")
        # verification 实例简报(ADR-0003):注入单条待复核 finding(fa),不 dump 全量
        verify_init = llm.calls[6][1]["content"]
        if "待复核 finding" not in verify_init or "fa" not in verify_init:
            fails.append(f"verification 实例简报应含单条待复核 finding(fa): {verify_init[:150]}")
        log = json.loads((agent_dir / "orchestrator" / "dispatch_log.json").read_text(encoding="utf-8"))
        if not any(r.get("status") == "duplicate" for r in log):
            fails.append("dispatch_log 应记录 duplicate 尝试")
    return fails


# ---- 日志系统字段 ----

def test_dispatch_log_lifecycle_fields() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([TOOL, RECON_FINAL])
        orch = _orch(td, llm)
        _tool(orch).execute(agent="recon", task="侦察")
        agent_dir = td / "process" / "agent"
        log = json.loads((agent_dir / "orchestrator" / "dispatch_log.json").read_text(encoding="utf-8"))
        rec = log[0]
        for k in ("seq", "agent", "task", "status", "request", "started_at",
                  "finished_at", "duration_ms", "artifact_path", "summary",
                  "error", "status_history"):
            if k not in rec:
                fails.append(f"dispatch 记录缺字段 {k}")
        hist = [h.get("status") for h in rec.get("status_history", [])]
        if hist != ["running", "success"]:
            fails.append(f"状态变迁应为 running→success: {hist}")
        if not all(h.get("ts") for h in rec.get("status_history", [])):
            fails.append("状态变迁应带时间戳")
        # transcript:事件带 ts;工具发起即记(tool_call 先于 tool 结果);
        # assistant 事件带 in_chars/usage/elapsed
        entries = [json.loads(l) for l in
                   (agent_dir / "0_recon" / "transcript.jsonl").read_text(encoding="utf-8").splitlines()]
        if not entries or not all("ts" in e for e in entries):
            fails.append("transcript 事件应带 ts 时间戳")
        phases = [e["phase"] for e in entries]
        if "tool_call" not in phases:
            fails.append("工具发起应立即记录(tool_call 事件)")
        elif "tool" in phases and phases.index("tool_call") > phases.index("tool"):
            fails.append("tool_call(发起)应先于 tool(结果)记录")
        a = [e for e in entries if e["phase"] == "assistant"]
        if not a or not all(("in_chars" in e and "usage" in e and "elapsed" in e) for e in a):
            fails.append("assistant 事件应带 in_chars/usage/elapsed(LLM 调用留痕)")
    return fails


# ---- Orchestrator 集成 ----

def test_orchestrator_integration_dirs() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        h = [
            D % "recon", TOOL, RECON_FINAL,             # 0/1/2
            D % "analysis", TOOL,
            'Final Answer: {"summary": "取证", "findings": [{"title": "注入", "severity": "high", "file": "unitree/bin/idlc"}]}',  # 5
            D % "verification", TOOL,                   # 6 阶段
            'Final Answer: {"summary": "复核", "findings": [{"title": "注入", "severity": "high", "file": "unitree/bin/idlc", "verified": true}]}',  # 8
            'Final Answer: {"summary": "编排完成", "conclusion": "ok"}',  # 9
        ]
        llm = ScriptedLLM(h)
        orch = _orch(td, llm)
        orch.run()
        agent = td / "process" / "agent"
        for sub in ("0_recon", "1_analysis", "3_verification"):
            if not (agent / sub).is_dir():
                fails.append(f"子 Agent 目录缺失: {sub}")
            if not (agent / sub / "transcript.jsonl").is_file():
                fails.append(f"{sub} transcript 缺失")
        if not (agent / "verified_findings.json").is_file():
            fails.append("agent/verified_findings.json 缺失(verification 每疑点一实例聚合)")
        for fn in ("transcript.jsonl", "dispatch_log.json", "result.json"):
            if not (agent / "orchestrator" / fn).is_file():
                fails.append(f"orchestrator/{fn} 缺失")
        result = json.loads((agent / "orchestrator" / "result.json").read_text(encoding="utf-8"))
        if not result.get("success"):
            fails.append(f"编排终态应 success: {result.get('error')}")
        if not {"recon", "analysis", "verification"} <= set(result.get("stages", {})):
            fails.append(f"result.stages 应含三子 Agent: {list(result.get('stages', {}).keys())}")
        # 去重聚合:analysis 与 verification 同为「注入」应合并为 1 条
        findings = [f for f in result.get("findings", []) if isinstance(f, dict)]
        injection = [f for f in findings if f.get("title") == "注入"]
        if len(injection) != 1:
            fails.append(f"同 title 跨 Agent 应去重为 1: {[f.get('title') for f in findings]}")
    return fails


def test_orchestrator_multi_dispatch_integration() -> list[str]:
    """编排级多次调用:recon → analysis ×2(不同任务) → verification → finish。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        h = [
            D2 % ("recon", "侦察攻击面"), TOOL, RECON_FINAL,       # 0/1/2
            D2 % ("analysis", "首轮取证"), TOOL, FA,               # 3/4/5
            D2 % ("analysis", "补充深挖"), TOOL, FB,               # 6/7/8
            D2 % ("verification", "复核结论"),                     # 9 阶段
            TOOL, VERIFY_F1, TOOL, VERIFY_F2,                      # 10..13 复核实例×2
            'Final Answer: {"summary": "编排完成", "conclusion": "ok"}',  # 14
        ]
        llm = ScriptedLLM(h)
        orch = _orch(td, llm)
        orch.run()
        agent = td / "process" / "agent"
        # 阶段 seq=3(无目录),两个复核实例 seq=4/5
        for sub in ("0_recon", "1_analysis", "2_analysis", "4_verification",
                    "5_verification"):
            if not (agent / sub / "transcript.jsonl").is_file():
                fails.append(f"实例目录/转录缺失: {sub}")
        for fn in ("transcript.jsonl", "dispatch_log.json", "result.json"):
            if not (agent / "orchestrator" / fn).is_file():
                fails.append(f"orchestrator/{fn} 缺失")
        result = json.loads((agent / "orchestrator" / "result.json").read_text(encoding="utf-8"))
        if not result.get("success"):
            fails.append(f"编排终态应 success: {result.get('error')}")
        if len(result.get("dispatches", [])) != 4:
            fails.append(f"dispatches 应 4 次(含 analysis 二次调用), got {len(result.get('dispatches', []))}")
        titles = {f.get("title") for f in result.get("findings", []) if isinstance(f, dict)}
        if titles != {"fa", "fb"}:
            fails.append(f"findings 聚合应含两个 analysis 实例去重结果(recon v3 无 findings): {titles}")
        # Task6.8:result.json 顶层 budget 汇总(各类型最新实例 budget_state)
        budget = result.get("budget", {})
        if not {"recon", "analysis", "verification"} <= set(budget):
            fails.append(f"result.json 顶层 budget 汇总应含三类型: {list(budget)}")
        for k in ("agent", "exhausted", "steps", "max_iters",
                  "pending_count", "pending_focuses", "overlap_ratio"):
            if k not in budget.get("analysis", {}):
                fails.append(f"budget.analysis 缺字段 {k}: {budget.get('analysis')}")
        if budget.get("analysis", {}).get("exhausted"):
            fails.append("短跑实例不应标记 exhausted")
    return fails


# ---- v3(2026-08-28):summarize / degraded / handoff 快照 / 状态全集 ----

SUM = 'Thought: 收尾\nAction: summarize\nAction Input: {"conclusion": "ok"}'
REPORT_MD = ('Final Answer: # 固件安全审计报告\n## 发现清单\n- [high] ✓ 注入\n'
             '## 误报剔除\n- 误报条目')


def test_summarize_tool_and_report() -> list[str]:
    """summarize 动作:取素材 → Final Answer 报告落盘 orchestrator/report.md。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        h = [
            D % "recon", TOOL, RECON_FINAL,        # 0/1/2
            D % "analysis", TOOL, FA,              # 3/4/5
            D % "verification", TOOL, FV,          # 6/7/8
            SUM,                                    # 9 取报告素材
            REPORT_MD,                              # 10 Final Answer = 报告
        ]
        llm = ScriptedLLM(h)
        orch = _orch(td, llm)
        orch.run()
        agent = td / "process" / "agent"
        md = agent / "orchestrator" / "report.md"
        if not md.is_file():
            fails.append("summarize+Final Answer 后应产出 orchestrator/report.md")
        else:
            text = md.read_text(encoding="utf-8")
            if "发现清单" not in text or "误报剔除" not in text:
                fails.append(f"report.md 应为 Final Answer 原样落盘: {text[:80]}")
        if not orch.summarize_called:
            fails.append("orchestrator 应记录 summarize_called=True")
        # result.json 记录 report_path
        res = json.loads((agent / "orchestrator" / "result.json").read_text(encoding="utf-8"))
        if not res.get("report_path"):
            fails.append("result.json 应含 report_path")
        # 素材 Observation 注入 verification 工件明细(Final Answer 前一轮 user 消息)
        # 消费位置:10 号调用前最后一轮 user 消息(索引 10)
        material_msg = llm.calls[10][-1]["content"]
        if "报告写作素材" not in material_msg:
            fails.append(f"summarize 后应注入报告素材: {material_msg[:120]}")
    return fails


REPORT_MD_04 = ('Final Answer: # 固件安全审计报告\n## 发现清单\n'
                '- [high] ✓ f1\n- [medium] ✗ f2(误报)\n'
                '## 未复核疑点\n- [low] ⚠ f3 未经复核,confidence 为 analysis 初值\n'
                '## 误报剔除\n- f2(实为默认文档示例)')


def test_report_unreviewed_section() -> list[str]:
    """Ticket 04:summarize 素材把 verified=None 的 finding 拆进独立未复核区
    (⚠,confidence 保留 analysis 初值、rationale 为空),不混入已复核区;
    report.md 落盘含独立未复核区段(未经复核标注)。"""
    fails: list[str] = []
    import os
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
    # 3 条 findings:K=2 → 复核 f1/f2,f3(low)未复核 verified=None
    ANALYSIS3 = ('Final Answer: {"summary": "取证3", "findings": ['
                 '{"title": "f1", "severity": "high", "file": "unitree/bin/idlc", "confidence": "high"},'
                 '{"title": "f2", "severity": "medium", "file": "unitree/bin/idlc", "confidence": "high"},'
                 '{"title": "f3", "severity": "low", "file": "unitree/bin/idlc", "confidence": "high"}]}')
    VF1 = ('Final Answer: {"summary": "复核f1", "findings": [{"title": "f1", '
           '"severity": "high", "file": "unitree/bin/idlc", "verified": true, "rationale": "r1"}]}')
    VF2 = ('Final Answer: {"summary": "复核f2", "findings": [{"title": "f2", '
           '"severity": "medium", "file": "unitree/bin/idlc", "verified": false, "rationale": "r2"}]}')
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        os.environ["STEP5_VERIFY_K"] = "2"
        try:
            llm = ScriptedLLM([
                D % "recon", TOOL, RECON_FINAL,        # 0/1/2
                D % "analysis", TOOL, ANALYSIS3,        # 3/4/5
                D % "verification",                      # 6 阶段
                VTOOL, VF1,                              # 7/8 复核 f1
                VTOOL, VF2,                              # 9/10 复核 f2
                SUM,                                     # 11 summarize 取素材
                REPORT_MD_04,                            # 12 Final Answer = 报告
            ])
            orch = _orch(td, llm)
            orch.run()
        finally:
            del os.environ["STEP5_VERIFY_K"]

        agent = td / "process" / "agent"
        # 素材:Report Final Answer 前一轮 user 消息(Final 调用即 llm.calls[-1])
        material = llm.calls[-1][-1]["content"]
        if "#### 已复核 findings" not in material or "#### 未复核疑点" not in material:
            fails.append("素材应拆已复核/未复核独立区段")
        # 未复核区:⚠ + confidence 初值 + rationale 空;不含已验证条目/复核结论
        unrev = material[material.find("#### 未复核疑点"):]
        for needle in ("f3", "⚠", "confidence 保留 analysis 初值", "rationale 为空"):
            if needle not in unrev:
                fails.append(f"未复核区应含 '{needle}': {unrev[:200]}")
        for banned in ("f1", "f2", "r1", "r2"):
            if banned in unrev:
                fails.append(f"未复核区不得混入已验证条目/结论 '{banned}'")
        # 已复核区:完整 confidence + rationale,含 ✓/✗ 两种复核结论
        rev = material[material.find("#### 已复核 findings"):material.find("#### 未复核疑点")]
        for needle in ("f1", "f2", "✓", "✗", "verified=True", "verified=False",
                       "rationale: r1", "rationale: r2"):
            if needle not in rev:
                fails.append(f"已复核区应含 '{needle}': {rev[:200]}")
        # report.md:独立未复核区段落盘 + 未经复核标注
        md = agent / "orchestrator" / "report.md"
        if not md.is_file():
            fails.append("summarize+Final Answer 后应产出 report.md")
        else:
            text = md.read_text(encoding="utf-8")
            for needle in ("## 未复核疑点", "未经复核", "f3"):
                if needle not in text:
                    fails.append(f"报告应含未复核区段 '{needle}': {text[:200]}")
        # 数据层:verified_findings.json 未复核条目的 confidence 保留 analysis 初值
        vf = load_artifact(agent / "verified_findings.json")
        if vf is not None:
            by_title = {f.get("title"): f for f in vf["findings"]}
            f3 = by_title.get("f3")
            if f3 is None or f3.get("verified") is not None:
                fails.append(f"f3 应 verified=None 保留在 verified_findings: {f3}")
            elif f3.get("confidence") != "high":
                fails.append(f"未复核 f3 的 confidence 应保留 analysis 初值: {f3}")
    return fails


def test_verify_toplevel_verdict_merged() -> list[str]:
    """0/N bug(2026-09-03):verification 实例把结论写在**顶层**(verified/rationale,
    findings[].verified 为空)时,聚合必须保留结论——不得把已复核条目丢进未复核区。

    复现形态:模型实际输出为顶层 verified/rationale + findings[] 只含 identity 字段
    (VERIFY_SYSTEM 虽要求写进 findings[],但 save_artifact 会把未知顶层字段原样保留,
    于是落盘工件即"顶层有结论、findings[] 空")。修复前聚合只读 findings[0].verified
    → null → summary 写"已复核 0/N"。"""
    fails: list[str] = []
    import os
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
    ANALYSIS2 = ('Final Answer: {"summary": "取证2", "findings": ['
                 '{"title": "f1", "severity": "high", "file": "unitree/bin/idlc", "confidence": "high"},'
                 '{"title": "f2", "severity": "medium", "file": "unitree/bin/idlc", "confidence": "high"}]}')
    # 模型实际输出形态:结论在顶层,findings[] 只含 identity 字段(verified 空)
    VF1_TOP = ('Final Answer: {"summary": "复核f1", "verified": true, "rationale": "r1", '
               '"findings": [{"title": "f1", "severity": "high", "file": "unitree/bin/idlc"}]}')
    VF2_TOP = ('Final Answer: {"summary": "复核f2", "verified": false, "rationale": "r2-误报", '
               '"findings": [{"title": "f2", "severity": "medium", "file": "unitree/bin/idlc"}]}')
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        os.environ["STEP5_VERIFY_K"] = "2"
        try:
            llm = ScriptedLLM([
                D % "recon", TOOL, RECON_FINAL,        # 0/1/2
                D % "analysis", TOOL, ANALYSIS2,        # 3/4/5
                D % "verification",                      # 6 阶段
                VTOOL, VF1_TOP,                          # 7/8 复核 f1(顶层结论)
                VTOOL, VF2_TOP,                          # 9/10 复核 f2(顶层结论)
                SUM,                                     # 11 summarize 取素材
                'Final Answer: {"summary": "完成", "conclusion": "ok"}',  # 12
            ])
            orch = _orch(td, llm)
            orch.run()
        finally:
            del os.environ["STEP5_VERIFY_K"]

        agent = td / "process" / "agent"
        vf = load_artifact(agent / "verified_findings.json")
        if vf is None:
            fails.append("verified_findings.json 缺失(verification 每疑点一实例聚合)")
        else:
            by_title = {f.get("title"): f for f in vf["findings"]}
            f1 = by_title.get("f1")
            f2 = by_title.get("f2")
            if f1 is None or f1.get("verified") is not True:
                fails.append(f"f1 顶层 verified=true 应在聚合中被保留: {f1}")
            if f1 is None or f1.get("rationale") != "r1":
                fails.append(f"f1 顶层 rationale 应在聚合中被保留: {f1}")
            if f2 is None or f2.get("verified") is not False:
                fails.append(f"f2 顶层 verified=false 应在聚合中被保留: {f2}")
            if f2 is None or f2.get("rationale") != "r2-误报":
                fails.append(f"f2 顶层 rationale 应在聚合中被保留: {f2}")
            if "已复核 0/2" in vf.get("summary", ""):
                fails.append(f"聚合 summary 不应再写'已复核 0/2': {vf.get('summary')}")
    return fails


def test_verify_severity_downgrade_preserved() -> list[str]:
    """severity 覆盖 bug(2026-09-03):verification 实例的降级判级(severity)
    在聚合时被丢弃——锚点回填循环与 aggregator ingest 的复核权威覆盖集都
    只有 verified/rationale/confidence,缺 severity。现场 target/1 实例 9:
    pet_go 判死代码降级 severity=low,聚合产物却保留 analysis 初值 high,
    与 rationale"从 severity high 降为 low"自相矛盾。修复:两处覆盖集补
    severity(verification 是判级权威,ADR-0003 精神延伸)。"""
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
    ANALYSIS1 = ('Final Answer: {"summary": "取证", "findings": [{"title": "f1", '
                 '"severity": "high", "file": "unitree/bin/idlc", "confidence": "medium"}]}')
    # 实例复核结论:降级 severity=low/confidence=low(现场形态:target/1 实例 9)
    VF_DOWNGRADE = ('Final Answer: {"summary": "复核f1:降级", "findings": [{"title": "f1", '
                    '"severity": "low", "file": "unitree/bin/idlc", "confidence": "low", '
                    '"verified": true, "rationale": "无可达攻击路径,从 severity high 降为 low"}]}')
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([
            D % "recon", TOOL, RECON_FINAL,        # 0/1/2
            D % "analysis", TOOL, ANALYSIS1,       # 3/4/5
            D % "verification",                    # 6 阶段(1 条 finding → 1 实例)
            VTOOL, VF_DOWNGRADE,                   # 7/8 复核 f1(降级 low)
            SUM,                                   # 9 summarize 取素材
            'Final Answer: {"summary": "完成", "conclusion": "ok"}',  # 10
        ])
        orch = _orch(td, llm)
        orch.run()

        agent = td / "process" / "agent"
        vf = load_artifact(agent / "verified_findings.json")
        if vf is None:
            fails.append("verified_findings.json 缺失(verification 每疑点一实例聚合)")
        else:
            by_title = {f.get("title"): f for f in vf["findings"]}
            f1 = by_title.get("f1")
            if f1 is None:
                fails.append("f1 应保留在聚合 findings")
            else:
                if f1.get("severity") != "low":
                    fails.append(f"复核降级 severity=low 应覆盖 analysis 初值 high: {f1.get('severity')}")
                if f1.get("confidence") != "low":
                    fails.append(f"复核降级 confidence=low 应覆盖初值 medium: {f1.get('confidence')}")
                if f1.get("verified") is not True:
                    fails.append(f"verified 应取自实例: {f1.get('verified')}")
                if "降为 low" not in (f1.get("rationale") or ""):
                    fails.append(f"rationale 应取自实例: {f1.get('rationale')}")
    return fails


def test_verify_resume_artifact_identity_guard() -> list[str]:
    """续跑实例工件错位 bug(2026-09-03):实例目录按全局 seq 命名(<seq>_verification),
    续跑时编排调度路径与原跑不一致(原跑 analysis×2 消耗 2 个 seq,续跑 analysis×1),
    seq 整体前移 → 第 N 条 finding 找到 <N-1>_verification 目录里**前一条 finding**
    的旧复核工件,skip 分支只判文件存在就加载,zip 位置配对把复核结论整体错配到
    相邻 finding(新[N].rationale==旧[N-1].rationale),全程无告警。

    修复:_run_verify_one skip 加载前校验工件 finding 身份与当前锚点一致
    (dedup_key 比对);不一致 → 弃用工件,真实重跑该实例(如实上报不冒充)。"""
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
    # 2 条 findings:analysis 初值(f1 high / f2 medium),K=2 全复核
    ANALYSIS2 = ('Final Answer: {"summary": "取证2", "findings": ['
                 '{"title": "f1", "severity": "high", "file": "unitree/bin/idlc", "confidence": "high"},'
                 '{"title": "f2", "severity": "medium", "file": "unitree/bin/netswitch", "confidence": "high"}]}')
    # 现场形态(target/1 实测):原跑 analysis×2 → 实例目录 4_/5_;续跑 analysis×1,
    # seq 前移一位——本次实例 f1→3_(不存在,真跑)、f2→4_(存在,但躺着的是
    # **f1** 的旧复核工件)→ 修复前 f2 静默拿到 f1 的结论(rationale/verified 全错配)。
    # 最小复现只需预设 4_verification = f1 的旧工件(带可辨识 rationale)。

    # 实例真跑时的 Scripted 回复(f1/f2 各一组:工具调用+结论)
    VF1 = ('Final Answer: {"summary": "复核f1", "findings": [{"title": "f1", '
           '"severity": "high", "file": "unitree/bin/idlc", "verified": true, "rationale": "f1-真跑结论"}]}')
    VF2 = ('Final Answer: {"summary": "复核f2", "findings": [{"title": "f2", '
           '"severity": "medium", "file": "unitree/bin/netswitch", "verified": false, "rationale": "f2-真跑结论"}]}')

    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        old = td / "process" / "agent" / "4_verification" / "verified_findings.json"
        old.parent.mkdir(parents=True, exist_ok=True)
        old.write_text(json.dumps({
            "schema": 2, "agent": "verification", "summary": "旧复核(f1)",
            "findings": [{"title": "f1", "severity": "high",
                          "file": "unitree/bin/idlc",
                          "verified": True, "rationale": "f1-旧工件结论"}],
        }, ensure_ascii=False), encoding="utf-8")
        llm = ScriptedLLM([
            D % "recon", TOOL, RECON_FINAL,        # 0/1/2 recon(真跑,seq 0)
            D % "analysis", TOOL, ANALYSIS2,       # 3/4/5(真跑,seq 1)
            D % "verification",                    # 6 阶段(seq 2)
            VTOOL, VF1,                            # 7/8 f1→3_ 不存在,真跑(seq 3)
            VTOOL, VF2,                            # 9/10 f2→4_ 存在 f1 旧工件:
                                                   #   修复前静默错配(skip,不消耗);
                                                   #   修复后弃用重跑(seq 4)
            SUM,                                   # 11
            'Final Answer: {"summary": "完成", "conclusion": "ok"}',  # 12
        ])
        orch = _orch(td, llm)
        orch.run()

        agent = td / "process" / "agent"
        vf = load_artifact(agent / "verified_findings.json")
        if vf is None:
            fails.append("verified_findings.json 缺失")
            return fails
        by_title = {f.get("title"): f for f in vf["findings"]}
        f1 = by_title.get("f1")
        f2 = by_title.get("f2")
        if f1 is None or f2 is None:
            fails.append(f"f1/f2 应保留在聚合: {sorted(by_title)}")
            return fails
        # 核心断言:结论归属正确,f2 不得错配 f1 旧工件的结论
        if "f1-旧工件结论" in (f2.get("rationale") or ""):
            fails.append(f"f2 拿到了 f1 旧工件的复核结论(错位): {f2.get('rationale')}")
        if f1.get("rationale") != "f1-真跑结论":
            fails.append(f"f1 应为真跑结论: {f1.get('rationale')}")
        if f2.get("rationale") != "f2-真跑结论":
            fails.append(f"f2 应为真跑结论(弃用错位工件重跑): {f2.get('rationale')}")
    return fails


def test_verify_resume_identity_tolerant_match() -> list[str]:
    """身份校验宽松匹配(2026-09-03 review 修复):实例工件 finding 常缺
    func/addr(锚点回填注释 L727 自注,anchor finding 有 func 而实例工件没有),
    完整 dedup_key 四元组全等会把合法工件误拒 → 每次续跑全部真跑、静默烧预算。
    修复:身份匹配只比 file+title(归一化),容忍实例工件缺 func/addr。"""
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    # 2 条 findings:锚点带 func(analysis 取证形态)
    ANALYSIS2 = ('Final Answer: {"summary": "取证2", "findings": ['
                 '{"title": "f1", "severity": "high", "file": "unitree/bin/idlc", '
                 '"func": "perform_cmd", "confidence": "high"},'
                 '{"title": "f2", "severity": "medium", "file": "unitree/bin/netswitch", '
                 '"func": "run_command", "confidence": "high"}]}')
    # 实例真跑回复(若被误拒重跑会消耗这两组;修复后 f1/f2 都应 skip 不真跑)
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
    VF1 = ('Final Answer: {"summary": "复核f1", "findings": [{"title": "f1", '
           '"severity": "high", "file": "unitree/bin/idlc", "verified": true, "rationale": "r1"}]}')
    VF2 = ('Final Answer: {"summary": "复核f2", "findings": [{"title": "f2", '
           '"severity": "medium", "file": "unitree/bin/netswitch", "verified": false, "rationale": "r2"}]}')

    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        # 预设合法旧工件:file+title 与锚点一致但**缺 func/addr**(target/1 实例
        # 工件真实形态);目录 3_/4_ 与本次编排实例序号对齐(recon 0→analysis 1→
        # 阶段 2→实例 3,4)
        for seq, title, file_, verdict, rat in (
                (3, "f1", "unitree/bin/idlc", True, "f1-旧工件结论"),
                (4, "f2", "unitree/bin/netswitch", False, "f2-旧工件结论")):
            p = td / "process" / "agent" / f"{seq}_verification" / "verified_findings.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({
                "schema": 2, "agent": "verification", "summary": "旧复核",
                "findings": [{"title": title, "severity": "high", "file": file_,
                              "verified": verdict, "rationale": rat}],
            }, ensure_ascii=False), encoding="utf-8")
        # ScriptedLLM 只提供编排自身轮次;若实例被误拒重跑会耗尽脚本触发失败
        llm = ScriptedLLM([
            D % "recon", TOOL, RECON_FINAL,        # 0/1/2
            D % "analysis", TOOL, ANALYSIS2,       # 3/4/5
            D % "verification",                    # 6 阶段
            SUM,                                   # 7 summarize(实例应全 skip,零实例轮次)
            'Final Answer: {"summary": "完成", "conclusion": "ok"}',  # 8
        ])
        orch = _orch(td, llm)
        orch.run()

        agent = td / "process" / "agent"
        vf = load_artifact(agent / "verified_findings.json")
        if vf is None:
            fails.append("verified_findings.json 缺失")
            return fails
        by_title = {f.get("title"): f for f in vf["findings"]}
        f1 = by_title.get("f1")
        f2 = by_title.get("f2")
        if f1 is None or f2 is None:
            fails.append(f"f1/f2 应保留在聚合: {sorted(by_title)}")
            return fails
        # 缺 func/addr 的合法工件应被复用(skip),不得重跑丢结论
        if f1.get("rationale") != "f1-旧工件结论":
            fails.append(f"f1 旧工件(file+title 匹配,缺 func)应被 skip 复用: {f1.get('rationale')}")
        if f1.get("verified") is not True:
            fails.append(f"f1 旧工件 verified 应被保留: {f1.get('verified')}")
        if f2.get("rationale") != "f2-旧工件结论":
            fails.append(f"f2 旧工件应被 skip 复用: {f2.get('rationale')}")
        if f2.get("verified") is not False:
            fails.append(f"f2 旧工件 verified=false 应被保留: {f2.get('verified')}")
        # 编排轮次自证:9 个编排回复恰好走完且总请求数==9(实例全 skip,零实例轮次;
        # 若被误拒重跑,脚本会在第 10 次调用耗尽抛错)
        if len(llm.calls) != 9:
            fails.append(f"实例应全 skip,总 LLM 请求数应恰为 9: {len(llm.calls)}")
    return fails


def test_verification_phase_display_summary() -> list[str]:
    """#6 显示层(2026-09-03):verification 每疑点一实例(ADR-0003)后,每实例
    各打一行"verification 完成 · 1 findings"(单实例计数,误导为全阶段只复核
    1 条;target/1 实际 10 实例)。修复:阶段聚合落盘后经 display 打**阶段级**
    汇总行(K 实例/已复核 x/N/steps 合计);每实例完成行标注实例序号可辨识。"""
    import io
    import os
    from unittest.mock import patch
    from firmware_audit.step5_agent.engine.display import TerminalDisplay
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
    # 3 条 findings,K=3 → 3 个实例
    ANALYSIS3 = ('Final Answer: {"summary": "取证3", "findings": ['
                 '{"title": "f1", "severity": "high", "file": "unitree/bin/idlc", "confidence": "high"},'
                 '{"title": "f2", "severity": "medium", "file": "unitree/bin/idlc", "confidence": "high"},'
                 '{"title": "f3", "severity": "low", "file": "unitree/bin/idlc", "confidence": "high"}]}')
    VF = ['Final Answer: {"summary": "复核", "findings": [{"title": "f1", '
          '"severity": "high", "file": "unitree/bin/idlc", "verified": true}]}'] * 3
    sink = io.StringIO()
    cap_disp = TerminalDisplay(mode="compact", use_color=False,
                               width=200, out=sink)
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        os.environ["STEP5_VERIFY_K"] = "3"
        try:
            with patch("firmware_audit.step5_agent.orchestrator.make_display",
                       return_value=cap_disp):
                llm = ScriptedLLM([
                    D % "recon", TOOL, RECON_FINAL,        # 0/1/2
                    D % "analysis", TOOL, ANALYSIS3,       # 3/4/5
                    D % "verification",                    # 6 阶段
                    VTOOL, VF[0],                          # 7/8 实例1
                    VTOOL, VF[1],                          # 9/10 实例2
                    VTOOL, VF[2],                          # 11/12 实例3
                    SUM,                                   # 13
                    'Final Answer: {"summary": "完成", "conclusion": "ok"}',  # 14
                ])
                orch = _orch(td, llm)
                orch.run()
        finally:
            del os.environ["STEP5_VERIFY_K"]

        out = sink.getvalue()
        # 阶段级汇总行:实例数/已复核 x/N(修复核心)
        for want in ("verification 阶段完成", "3 实例", "已复核 3/3"):
            if want not in out:
                fails.append(f"阶段汇总行缺 '{want}':\n{out}")
        # 实例序号标注(实例 i/N):阶段层派发前逐实例打出(run_agent 内部
        # done 行走各自 display 进 stdout,不在本 sink,不在此断言)
        for i in (1, 2, 3):
            if f"实例 {i}/3" not in out:
                fails.append(f"实例序号标注缺 '实例 {i}/3':\n{out}")
    return fails


def test_report_absent_without_summarize() -> list[str]:
    """未调用 summarize 直接 finish → 不出报告(不静默降级)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        h = [
            D % "recon", TOOL, RECON_FINAL,
            D % "analysis", TOOL, FA,
            D % "verification", TOOL, FV,
            'Final Answer: {"summary": "完成", "conclusion": "ok"}',  # 直接收尾,无 summarize
        ]
        llm = ScriptedLLM(h)
        orch = _orch(td, llm)
        orch.run()
        agent = td / "process" / "agent"
        if (agent / "orchestrator" / "report.md").is_file():
            fails.append("未调用 summarize 时不应产出 report.md")
        if orch.report_path is not None:
            fails.append("report_path 应为 None")
        res = json.loads((agent / "orchestrator" / "result.json").read_text(encoding="utf-8"))
        if res.get("report_path") is not None or res.get("summarize_called"):
            fails.append("result.json 应如实记录未产出报告")
    return fails


def test_degraded_resume_rerun() -> list[str]:
    """仅 .md 降级工件 → degraded(ok=False);默认复跑(重执行);关开关则按旧语义跳过。"""
    import os
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        # 预置 0_recon 只有 .md 降级工件
        md = td / "process" / "agent" / "0_recon" / "survey.md"
        md.parent.mkdir(parents=True)
        md.write_text("# recon 原始输出(JSON 解析失败降级)\n\n旧内容", encoding="utf-8")
        llm = ScriptedLLM([TOOL, RECON_FINAL])  # 复跑时正常执行
        orch = _orch(td, llm)
        tr = _tool(orch).execute(agent="recon", task="x")
        if not tr.ok:
            fails.append(f"degraded 续跑默认应进入执行路径并成功: {tr.error}")
        # dispatch_log 应留 degraded 痕迹(复跑原因)
        log = json.loads((td / "process" / "agent" / "orchestrator" / "dispatch_log.json").read_text(encoding="utf-8"))
        if not any(x.get("status") == "degraded" for x in log):
            fails.append("复跑应在 dispatch_log 留 degraded 痕")
        res = orch.agent_results.get("recon")
        if res is None or res.status != "success":
            fails.append(f"复跑后 recon 应 success: {res and res.status}")
        if not (td / "process" / "agent" / "0_recon" / "survey.json").is_file():
            fails.append("复跑应产出 .json 工件")
        # 关掉开关:降级工件按旧语义当 skipped
        td2 = Path(tempfile.mkdtemp())
        try:
            _make_process(td2)
            md2 = td2 / "process" / "agent" / "0_recon" / "survey.md"
            md2.parent.mkdir(parents=True)
            md2.write_text("# recon 原始输出(降级)", encoding="utf-8")
            os.environ["STEP5_RESUME_DEGRADED"] = "0"
            try:
                llm2 = ScriptedLLM([])
                orch2 = _orch(td2, llm2)
                _tool(orch2).execute(agent="recon", task="x")  # 副作用:登记到 orch2
                res2 = orch2.agent_results.get("recon")
                if res2 is None or res2.status != "skipped":
                    fails.append(f"开关关闭时降级工件应按 skipped: {res2 and res2.status}")
                if llm2.calls:
                    fails.append("开关关闭时不应调 LLM")
            finally:
                del os.environ["STEP5_RESUME_DEGRADED"]
        finally:
            import shutil
            shutil.rmtree(td2, ignore_errors=True)
    return fails


def test_handoff_snapshot_file() -> list[str]:
    """交接快照:每次真实调度落盘 handoff_<seq>_<type>.json(结构化可消费)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([TOOL, RECON_FINAL, TOOL, FA, TOOL, FV])
        orch = _orch(td, llm)
        tool = _tool(orch)
        tool.execute(agent="recon", task="t0")
        tool.execute(agent="analysis", task="t1")
        snap = td / "process" / "agent" / "orchestrator" / "handoff_1_analysis.json"
        if not snap.is_file():
            fails.append("应落盘 handoff_1_analysis.json")
        else:
            obj = json.loads(snap.read_text(encoding="utf-8"))
            for k in ("seq", "to_agent", "task", "context", "prior_dispatches",
                      "cumulative_findings", "ts"):
                if k not in obj:
                    fails.append(f"交接快照缺字段 {k}")
            if obj.get("to_agent") != "analysis" or obj.get("seq") != 1:
                fails.append(f"快照归属不符: {obj.get('to_agent')}/{obj.get('seq')}")
            if not obj.get("prior_dispatches"):
                fails.append("快照应含前序调度状态表")
    return fails


def test_status_enum_closed() -> list[str]:
    """状态值域闭合:DispatchStatus.ALL 覆盖全部标签;_STATUS_LABEL 键一致。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.orchestrator import DispatchStatus, _STATUS_LABEL
    if len(set(DispatchStatus.ALL)) != len(DispatchStatus.ALL):
        fails.append("DispatchStatus.ALL 不应有重复值")
    if set(_STATUS_LABEL) != set(DispatchStatus.ALL):
        fails.append(f"_STATUS_LABEL 键集应与 DispatchStatus.ALL 一致: "
                     f"{set(_STATUS_LABEL) ^ set(DispatchStatus.ALL)}")
    # 常量即落盘字符串
    if DispatchStatus.DEGRADED != "degraded":
        fails.append("DEGRADED 值应为 'degraded'(落盘值)")
    return fails


def test_ingest_merge_dedup() -> list[str]:
    """聚合去重升级:同键合并而非丢弃(analysis 深化版本补 confidence/verified)。
    Task5 起 recon 不聚合(只铺面不判级),故用两轮 analysis 模拟同键深化。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([])
        orch = _orch(td, llm)
        # 同 file+func+addr+title,不同字段完整度
        f1 = {"title": "注入", "file": "unitree/bin/idlc", "func": "main",
              "addr": "0x1000", "evidence": "system(cmd)", "severity": "high"}
        f2 = {"title": "注入", "file": "unitree/bin/idlc", "func": "main",
              "addr": "0x1000", "confidence": "high", "verified": True}
        from firmware_audit.step5_agent.orchestrator import SubAgentResult
        orch._register(SubAgentResult(seq=0, agent_name="analysis", status="success",
                                      findings=[f1], request={}))
        orch._register(SubAgentResult(seq=1, agent_name="analysis", status="success",
                                      findings=[f2], request={}))
        if len(orch.all_findings) != 1:
            fails.append(f"同键应合并为 1 条: {len(orch.all_findings)}")
        else:
            m = orch.all_findings[0]
            if not m.get("verified") or m.get("confidence") != "high":
                fails.append(f"合并应保留双方字段: {m}")
            if m.get("evidence") != "system(cmd)":
                fails.append(f"已有 evidence 不应被覆盖: {m.get('evidence')}")
            if m.get("source_agent") != "analysis" or m.get("instance_seq") != 0:
                fails.append(f"溯源应保留首次产出: {m.get('source_agent')}/{m.get('instance_seq')}")
    return fails


def test_aggregator_module() -> list[str]:
    """FindingAggregator 独立模块契约(不经 Orchestrator 壳):聚合/去重/
    重合计分/recon 跳过,纯逻辑可直接单测。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.aggregator import FindingAggregator
    from firmware_audit.step5_agent.orchestrator import SubAgentResult

    # 1. 聚合 + 同键去重合并
    agg = FindingAggregator()
    f1 = {"title": "注入", "file": "unitree/bin/idlc", "func": "main",
          "addr": "0x1000", "evidence": "system(cmd)", "severity": "high"}
    f2 = {"title": "注入", "file": "unitree/bin/idlc", "func": "main",
          "addr": "0x1000", "confidence": "high", "verified": True}
    agg.ingest(SubAgentResult(seq=0, agent_name="analysis", status="success",
                              findings=[f1], request={}))
    agg.ingest(SubAgentResult(seq=1, agent_name="analysis", status="success",
                              findings=[f2], request={}))
    if len(agg.all_findings) != 1:
        fails.append(f"同键应合并为 1 条: {len(agg.all_findings)}")
    else:
        m = agg.all_findings[0]
        if m.get("evidence") != "system(cmd)":
            fails.append(f"已有 evidence 不应被覆盖: {m.get('evidence')}")
        if m.get("instance_seq") != 0 or m.get("source_agent") != "analysis":
            fails.append(f"溯源应保留首次产出: {m.get('instance_seq')}/{m.get('source_agent')}")

    # 2. verification 复核权威覆盖
    agg2 = FindingAggregator()
    agg2.ingest(SubAgentResult(seq=0, agent_name="analysis", status="success",
                               findings=[dict(f1)], request={}))
    fv = dict(f1)
    fv["verified"], fv["rationale"] = True, "证据链完整"
    agg2.ingest(SubAgentResult(seq=1, agent_name="verification", status="success",
                               findings=[fv], request={}))
    m2 = agg2.all_findings[0]
    if m2.get("verified") is not True or m2.get("rationale") != "证据链完整":
        fails.append(f"verification 应覆盖 verified/rationale: {m2}")

    # 3. recon v3 跳过(不聚合 finding)
    agg3 = FindingAggregator()
    agg3.ingest(SubAgentResult(seq=0, agent_name="recon", status="success",
                               findings=[dict(f1)], request={}))
    if agg3.all_findings:
        fails.append(f"recon v3 不应聚合任何 finding: {agg3.all_findings}")

    # 4. overlap_ratio:标题+文件归一化匹配
    agg4 = FindingAggregator(all_findings=[dict(f1)])
    same = [dict(f1)]                       # 完全重复
    diff = [{"title": "别的", "file": "unitree/bin/other", "func": "x"}]
    if agg4.overlap_ratio(same) != 1.0:
        fails.append(f"完全重复 overlap 应 1.0: {agg4.overlap_ratio(same)}")
    if agg4.overlap_ratio(diff) != 0.0:
        fails.append(f"无关 overlap 应 0.0: {agg4.overlap_ratio(diff)}")
    if agg4.overlap_ratio([]) != 0.0:
        fails.append("空输入 overlap 应 0.0")

    # 5. dedup_key:规范化(压空白 + 小写)
    k1 = FindingAggregator.dedup_key({"title": "  A B ", "file": "x", "func": "y", "addr": "z"})
    k2 = FindingAggregator.dedup_key({"title": "a b", "file": "x", "func": "y", "addr": "z"})
    if k1 != k2:
        fails.append(f"dedup_key 应规范化标题: {k1} != {k2}")

    # 6. norm_text:路径分隔符归一化(反斜杠 → 正斜杠)+ 压空白 + 小写
    n1 = FindingAggregator.norm_text(r"unitree\bin\idlc")
    n2 = FindingAggregator.norm_text("unitree/bin/idlc")
    if n1 != n2:
        fails.append(f"norm_text 应归一化路径分隔符: {n1!r} != {n2!r}")
    if FindingAggregator.norm_text("  A  B ") != "a b":
        fails.append(f"norm_text 应压空白 + 小写: {FindingAggregator.norm_text('  A  B ')!r}")

    return fails


def test_planner_removed() -> list[str]:
    """ADR-0006:ticket 05——planner 参数移除,step5_run 只剩 LLM 编排一条路径。

    不再有 pipeline 快速模式:传 planner 应直接抛 TypeError(参数已删),
    不再接受任何分支选择;所有 Step5 运行都是 LLM 编排 + 产报告。
    行为断言(而非实现细节):绑定期即炸,无需造 process/脚本。
    """
    fails: list[str] = []
    from firmware_audit.step5_agent.run_step5 import step5_run
    try:
        step5_run(Path("not-a-workspace"), planner="pipeline")
        fails.append("step5_run 传 planner 应抛 TypeError(参数已移除)")
    except TypeError:
        pass
    return fails


def test_report_json_byproduct() -> list[str]:
    """report.json 副产品:Final Answer 含可解析 JSON 时另存;
    我方保留字段(schema/report_markdown)优先,LLM 同名键不覆盖。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        h = [
            D % "recon", TOOL, RECON_FINAL,
            D % "analysis", TOOL, FA,
            D % "verification", TOOL, FV,
            SUM,
            # Final Answer = 报告文本 + 末尾 JSON 摘要(LLM 附带结构化结论)
            ('Final Answer: # 固件安全审计报告\n- [high] ✓ 注入\n'
             '```json\n{"conclusion": "高危1条", "findings": [{"title": "注入"}], '
             '"schema": 999, "report_markdown": "FAKE"}\n```'),
        ]
        llm = ScriptedLLM(h)
        orch = _orch(td, llm)
        orch.run()
        rj = td / "process" / "agent" / "orchestrator" / "report.json"
        if not rj.is_file():
            fails.append("Final Answer 含可解析 JSON 时应另存 report.json")
        else:
            obj = json.loads(rj.read_text(encoding="utf-8"))
            if obj.get("conclusion") != "高危1条":
                fails.append(f"report.json 应保留 LLM 结构化结论: {obj.get('conclusion')}")
            if obj.get("schema") != 1 or obj.get("report_markdown") == "FAKE":
                fails.append("我方保留字段应优先(LLM 同名键不得覆盖)")
        if not (td / "process" / "agent" / "orchestrator" / "report.md").is_file():
            fails.append("主产物 report.md 应同时存在")
    return fails


def test_artifact_instance_seq_backfilled() -> list[str]:
    """工件级溯源:子 Agent 工件落盘后由 orchestrator 回填 instance_seq。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([TOOL, RECON_FINAL, TOOL, FA])
        orch = _orch(td, llm)
        tool = _tool(orch)
        tool.execute(agent="recon", task="t0")
        tool.execute(agent="analysis", task="t1")
        for d, seq in (("0_recon", 0), ("1_analysis", 1)):
            p = td / "process" / "agent" / d / (
                "survey.json" if d == "0_recon" else "findings.json")
            obj = json.loads(p.read_text(encoding="utf-8"))
            for f in obj.get("findings", []):
                if f.get("instance_seq") != seq:
                    fails.append(f"{d} 工件 finding 的 instance_seq 应为 {seq}: {f.get('instance_seq')}")
    return fails


def test_ingest_verification_overrides() -> list[str]:
    """复核权威字段:verification 实例的 verified/rationale/severity 覆盖聚合中旧值。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([])
        orch = _orch(td, llm)
        f1 = {"title": "注入", "file": "unitree/bin/idlc", "func": "main",
              "addr": "0x1000", "severity": "high", "confidence": "medium",
              "verified": True, "rationale": "初判成立"}
        f2 = {"title": "注入", "file": "unitree/bin/idlc", "func": "main",
              "addr": "0x1000", "severity": "low", "confidence": "low",
              "verified": False, "rationale": "证据与工件不符"}
        from firmware_audit.step5_agent.orchestrator import SubAgentResult
        orch._register(SubAgentResult(seq=0, agent_name="analysis", status="success",
                                      findings=[f1], request={}))
        orch._register(SubAgentResult(seq=1, agent_name="verification", status="success",
                                      findings=[f2], request={}))
        m = orch.all_findings[0]
        if m.get("verified") is not False or m.get("rationale") != "证据与工件不符":
            fails.append(f"verification 的复核结论应覆盖前段: {m.get('verified')}/{m.get('rationale')}")
        if m.get("severity") != "low":
            fails.append(f"ingest 路径 severity 降级应覆盖(_OVERRIDE_KEYS): {m.get('severity')}")
        if m.get("confidence") != "low":
            fails.append(f"ingest 路径 confidence 降级应覆盖: {m.get('confidence')}")
    return fails


def test_ingest_skips_recon_v3() -> list[str]:
    """Task5:recon v3 工件提交后 _ingest 不聚合任何 recon finding;
    即便 SubAgentResult 携带残留 findings(模拟旧磁盘残留)也显式忽略,
    聚合仅收敛 analysis/verification 条目。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([])
        orch = _orch(td, llm)
        # recon v3:哪怕带残留 findings 也不得进 _all_findings
        orch._register(SubAgentResult(seq=0, agent_name="recon", status="success",
                                      findings=[{"title": "残留", "severity": "high",
                                                 "file": "unitree/bin/idlc"}],
                                      request={}))
        if orch.all_findings:
            fails.append(f"recon v3 不应聚合任何 finding: {orch.all_findings}")
        # analysis/verification 正常聚合
        orch._register(SubAgentResult(seq=1, agent_name="analysis", status="success",
                                      findings=[{"title": "真发现", "severity": "high",
                                                 "file": "unitree/bin/idlc"}],
                                      request={}))
        orch._register(SubAgentResult(seq=2, agent_name="verification", status="success",
                                      findings=[{"title": "真发现", "severity": "high",
                                                 "file": "unitree/bin/idlc",
                                                 "verified": True}],
                                      request={}))
        titles = {f.get("title") for f in orch.all_findings}
        if titles != {"真发现"}:
            fails.append(f"_all_findings 仅应含 analysis/verification,got {titles}")
    return fails


# ---- Task6(2026-08-29):动态分配 + 重合检测 ----

def test_analysis_exhausted_rerun_overlap() -> list[str]:
    """Task6.9 主链路:analysis 预算耗尽(30 轮 + FORCE_FINAL)→ dispatch
    Observation 附补跑建议(含 pending 疑点)→ 第 2 次调度(补跑简报注入
    已覆盖清单/差分提示)→ 聚合合并去重 + dispatch_log 上报 budget_state
    (实例 2 overlap_ratio=0.5:fa 重复、fc 新增)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        # 实例 1:30 轮 TOOL(同参守卫只拦执行,轮次照耗)→ FORCE_FINAL 兜底
        # 产出 FA(steps=30=max_iters → exhausted);实例 2:正常 2 轮收尾
        llm = ScriptedLLM([TOOL, RECON_V3_FINAL]
                          + [TOOL] * 30 + [FA]
                          + [TOOL, FDUP_MIX])
        orch = _orch(td, llm)
        tool = _tool(orch)
        tool.execute(agent="recon", task="侦察")
        r1 = tool.execute(agent="analysis", task="首轮取证")
        r2 = tool.execute(agent="analysis", task="补跑:未覆盖疑点差分")
        # ---- 实例 1 完成态:耗尽 + 未覆盖疑点 → 附 budget_state 与补跑建议 ----
        if not r1.ok:
            fails.append(f"实例 1 应成功(FORCE_FINAL 产出可解析 FA): {r1.error}")
        if "budget_state" not in r1.text:
            fails.append("dispatch Observation 尾部应含 budget_state")
        if "补跑建议" not in r1.text:
            fails.append(f"耗尽+pending>0 应附补跑建议: {r1.text[-200:]}")
        for needle in ("第 2 轮补跑", "还剩 2 次", "netswitch", "差分"):
            if needle not in r1.text:
                fails.append(f"补跑建议应含 '{needle}': {r1.text[-200:]}")
        # ---- 实例 2 完成态:未耗尽 → 不附补跑建议 ----
        if not r2.ok:
            fails.append(f"实例 2 应成功: {r2.error}")
        if "补跑建议" in r2.text:
            fails.append("实例 2 未耗尽(steps=2<30)不应附补跑建议")
        # ---- 补跑简报(Task6.7):交接块外追加已覆盖清单 + 差分 task 提示 ----
        a2_init = llm.calls[33][1]["content"]
        for needle in ("已覆盖清单", "fa @ unitree/bin/idlc", "第 2 轮补跑",
                       "禁止重复提交已存在标题"):
            if needle not in a2_init:
                fails.append(f"补跑简报应含 '{needle}': {a2_init[-200:]}")
        # ---- 聚合合并:fa 跨实例去重,fc 新增 ----
        titles = sorted(f.get("title") for f in orch.all_findings)
        if titles != ["fa", "fc"]:
            fails.append(f"聚合应合并去重为 fa+fc: {titles}")
        # ---- dispatch_log 上报(Task6.5/6.8):实例条目含 budget_state ----
        log = json.loads((td / "process" / "agent" / "orchestrator"
                          / "dispatch_log.json").read_text(encoding="utf-8"))
        ana = [r for r in log if r.get("agent") == "analysis"]
        if len(ana) != 2:
            fails.append(f"dispatch_log 应有 2 条 analysis 实例: {len(ana)}")
        for r in ana:
            if "budget_state" not in r:
                fails.append(f"analysis 实例条目应含 budget_state: {sorted(r)}")
        b1 = (ana[0] if ana else {}).get("budget_state", {})
        b2 = (ana[1] if len(ana) > 1 else {}).get("budget_state", {})
        if not b1.get("exhausted"):
            fails.append(f"实例 1 steps==max_iters 应 exhausted=True: {b1}")
        if b1.get("overlap_ratio", -1) != 0.0:
            fails.append(f"实例 1 首轮无既有聚合应 overlap=0.0: {b1}")
        if b1.get("pending_count", 0) < 1:
            fails.append(f"实例 1 后应剩 netswitch 未覆盖: {b1}")
        if "netswitch" not in " ".join(b1.get("pending_focuses", [])):
            fails.append(f"pending_focuses 应含 netswitch 疑点: {b1}")
        if b2.get("exhausted"):
            fails.append(f"实例 2 两轮收尾应 exhausted=False: {b2}")
        if abs(b2.get("overlap_ratio", -1) - 0.5) > 1e-6:
            fails.append(f"实例 2 应 overlap_ratio=0.5(fa 重复/fc 新增): {b2}")
        if b2.get("pending_count", -1) != 0:
            fails.append(f"实例 2 覆盖 netswitch 后应 pending=0: {b2}")
        if b1.get("max_iters") != 30 or b2.get("steps") != 2:
            fails.append(f"budget_state 应带 steps/max_iters 实况: {b1}/{b2}")
    return fails


def test_budget_state_not_exhausted_no_suggestion() -> list[str]:
    """Task6.9:recon/analysis/verification 均未耗尽(短跑收尾)时
    budget_state.exhausted=False,即使 analysis 仍有 pending 疑点也不出
    补跑建议(门条件=analysis+耗尽+pending+次数余量,四者同时满足)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        llm = ScriptedLLM([TOOL, RECON_V3_FINAL, TOOL, FA, TOOL, FV])
        orch = _orch(td, llm)
        tool = _tool(orch)
        for agent, task in (("recon", "r"), ("analysis", "a"), ("verification", "v")):
            r = tool.execute(agent=agent, task=task)
            if not r.ok:
                fails.append(f"{agent} 正常短跑应成功: {r.error}")
            if "补跑建议" in r.text:
                fails.append(f"{agent} 未耗尽不应附补跑建议: {r.text[-150:]}")
        log = json.loads((td / "process" / "agent" / "orchestrator"
                          / "dispatch_log.json").read_text(encoding="utf-8"))
        states = {r.get("agent"): r.get("budget_state", {}) for r in log}
        for agent in ("recon", "analysis", "verification"):
            b = states.get(agent, {})
            if not b:
                fails.append(f"{agent} dispatch_log 条目应含 budget_state")
            elif b.get("exhausted"):
                fails.append(f"{agent} 短跑(steps=2)不应耗尽: {b}")
        # analysis 有 pending(netswitch 未覆盖)但未耗尽 → 不出建议(门控生效)
        if states.get("analysis", {}).get("pending_count", 0) < 1:
            fails.append(f"analysis 应仍有未覆盖疑点: {states.get('analysis')}")
        # summarize Observation 呈现三类 Agent 的 budget_state(Task6.3)
        s = SummarizeTool(ToolContext(process_dir=orch.process_dir), orch)
        res = s.execute(conclusion="查看进展")
        if not res.ok or res.text.count("budget_state:") != 3:
            fails.append(f"summarize 应呈现 3 条 budget_state(recon/analysis/"
                         f"verification): {res.text.count('budget_state:')}")
        if "exhausted" not in res.text:
            fails.append("summarize budget_state 应含 exhausted 键")
    return fails


# ---- Task8(2026-08-29):动态分配端到端 + 重合适配 e2e ----

def test_dynamic_dispatch_full_chain_budget() -> list[str]:
    """Task8.2 动态分配端到端(ScriptedLLM 全链,Orchestrator.run()):
    recon v3 → analysis#1 30 轮 TOOL 耗尽(FORCE_FINAL 兜底出 FA)→ 编排器依
    dispatch Observation 的补跑建议追加 analysis#2 → verification → summarize →
    Final Answer 报告。断言:
    - dispatch_log.json 每实例含 budget_state 键(exhausted/steps/max_iters/
      pending_count/overlap_ratio);
    - 第 2 次 analysis 实例简报含"已覆盖清单"与"第 2 轮补跑";
    - 补跑后聚合合并去重(fa 跨实例只留 1 条,fc 新增)。
    Task8.6 质量指标可采集性(数值断言):
    - recon high_risk_areas 条目数(survey 工件可数);
    - analysis pending 覆盖比例(pending_count 从 >0 到 0 的变化);
    - 补跑触发率(exhausted 且有建议的 analysis 实例占比,可从 dispatch_log 计算);
    - overlap_ratio 分布(实例 1=0.0 / 实例 2=0.5)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        # 编排动作序列:dispatch recon → analysis → analysis(补跑) → verification
        # → summarize → Final Answer;子 Agent 脚本交错其间:
        # analysis#1 = 30 轮 TOOL(同参守卫只拦执行,轮次照耗)+ FORCE_FINAL 收尾
        h = [
            D2 % ("recon", "侦察攻击面"),                    # 0
            TOOL, RECON_V3_FINAL,                             # 1/2 recon
            D2 % ("analysis", "首轮取证"),                    # 3
            *([TOOL] * 30),                                   # 4..33 30 轮耗尽
            FA,                                               # 34 FORCE_FINAL 兜底
            D2 % ("analysis", "补跑:未覆盖 netswitch 疑点"),    # 35 依补跑建议追加
            TOOL, FDUP_MIX,                                   # 36/37 补跑实例
            D2 % ("verification", "复核结论"),                 # 38 阶段(每疑点一实例)
            TOOL, FV,                                         # 39/40 复核 fa
            TOOL, VERIFY_FC,                                  # 41/42 复核 fc
            SUM,                                              # 43 取报告素材
            REPORT_MD,                                        # 44 Final Answer
        ]
        llm = ScriptedLLM(h)
        orch = _orch(td, llm)
        orch.run()
        agent = td / "process" / "agent"

        # 编排终态:success + report.md 落盘(summarize → Final Answer)
        result = json.loads((agent / "orchestrator" / "result.json").read_text(encoding="utf-8"))
        if not result.get("success"):
            fails.append(f"全链编排应 success: {result.get('error')}")
        if not (agent / "orchestrator" / "report.md").is_file():
            fails.append("summarize+Final Answer 后应产出 orchestrator/report.md")

        # dispatch_log 每实例含 budget_state 键(五要素齐)
        log = json.loads((agent / "orchestrator" / "dispatch_log.json").read_text(encoding="utf-8"))
        executed = [r for r in log if r.get("status") == "success"]
        if len(executed) != 4:
            fails.append(f"实际执行应 4 次(recon+analysis×2+verification), got {len(executed)}")
        for r in executed:
            b = r.get("budget_state")
            if not isinstance(b, dict):
                fails.append(f"实例 seq={r.get('seq')} 的 dispatch_log 缺 budget_state 键")
                continue
            for k in ("exhausted", "steps", "max_iters", "pending_count", "overlap_ratio"):
                if k not in b:
                    fails.append(f"实例 seq={r.get('seq')} budget_state 缺字段 {k}: {b}")

        # analysis 两实例的预算细节(实例 1 耗尽 / 实例 2 补跑收尾)
        ana = [r for r in log if r.get("agent") == "analysis"]
        if len(ana) != 2:
            fails.append(f"dispatch_log 应有 2 条 analysis 实例: {len(ana)}")
        b1 = (ana[0] if ana else {}).get("budget_state", {})
        b2 = (ana[1] if len(ana) > 1 else {}).get("budget_state", {})
        if not b1.get("exhausted") or b1.get("steps") != 30 or b1.get("max_iters") != 30:
            fails.append(f"实例 1 应 30 轮耗尽(steps=30/max_iters=30): {b1}")
        if b2.get("exhausted") or b2.get("steps") != 2:
            fails.append(f"实例 2 两轮收尾应未耗尽(steps=2): {b2}")
        # 8.6 指标:pending 覆盖比例(pending_count 从 >0 到 0 的变化)
        if not (b1.get("pending_count", 0) > 0 and b2.get("pending_count", -1) == 0):
            fails.append(f"pending_count 应从 >0 收敛到 0(netswitch 已被 fc 覆盖): {b1} → {b2}")
        # 8.6 指标:overlap_ratio 分布(数值断言)
        if abs(b1.get("overlap_ratio", -1) - 0.0) > 1e-6:
            fails.append(f"实例 1 首轮无既有聚合应 overlap_ratio=0.0: {b1}")
        if abs(b2.get("overlap_ratio", -1) - 0.5) > 1e-6:
            fails.append(f"实例 2 应 overlap_ratio=0.5(fa 重复/fc 新增): {b2}")
        # 8.6 指标:补跑触发率(exhausted 且有建议的 analysis 实例占比;
        # 建议门 = analysis+耗尽+pending>0+次数余量,全部可从 dispatch_log 复算)
        trig = sum(1 for i, r in enumerate(ana)
                   if r.get("budget_state", {}).get("exhausted")
                   and r.get("budget_state", {}).get("pending_count", 0) > 0
                   and (i + 1) < MAX_DISPATCH_PER_AGENT)
        if len(ana) and trig / len(ana) != 0.5:
            fails.append(f"补跑触发率应为 1/2=0.5(实例 1 耗尽有建议,实例 2 未耗尽): {trig}/{len(ana)}")

        # 8.6 指标:recon high_risk_areas 条目数(survey 工件可数)
        survey = json.loads((agent / "0_recon" / "survey.json").read_text(encoding="utf-8"))
        if len(survey.get("high_risk_areas") or []) < 1:
            fails.append(f"survey 工件应可数出 high_risk_areas 条目: {survey.get('high_risk_areas')}")

        # 补跑建议随 analysis#1 的 dispatch Observation 注入编排上下文
        # (编排器下一轮决策的最后一 user 消息 = 该 Observation)
        obs1 = llm.calls[35][-1]["content"]
        for needle in ("补跑建议", "budget_state", "netswitch", "第 2 轮补跑"):
            if needle not in obs1:
                fails.append(f"analysis#1 Observation 应含 '{needle}': {obs1[-200:]}")
                break
        # 第 2 次 analysis 实例简报:已覆盖清单 + 第 2 轮补跑(调用序见 h 注释)
        a2_init = llm.calls[36][1]["content"]
        for needle in ("已覆盖清单", "第 2 轮补跑", "fa @ unitree/bin/idlc"):
            if needle not in a2_init:
                fails.append(f"补跑实例简报应含 '{needle}': {a2_init[-200:]}")
                break

        # 补跑后聚合合并去重:fa 跨实例只留 1 条(verification 复核 fa),fc 新增
        findings = [f for f in result.get("findings", []) if isinstance(f, dict)]
        titles = sorted(f.get("title") for f in findings)
        if titles != ["fa", "fc"]:
            fails.append(f"聚合应合并去重为 fa+fc: {titles}")
        if sum(1 for f in findings if f.get("title") == "fa") != 1:
            fails.append("fa 跨实例应去重为 1 条")
    return fails


def test_rerun_high_overlap_adapt() -> list[str]:
    """Task8.3 重合适配 e2e:构造高重合补跑场景——实例 2(补跑)的 findings 与
    实例 1 的 (title,file) 全部相同(3 条)+ 1 条新(netswitch)→ overlap_ratio
    = 0.75 ≥ 0.5 触发重合适配预案。断言:
    - 实例 2 budget_state.overlap_ratio ≥ 0.5(阈值触发的证据);
    - 补跑建议(实例 1 Observation)与已覆盖清单(实例 2 简报)仍注入
      (预案:交接不因重合而丢,task 强制差分措辞);
    - 聚合结果条目数 = 实例 1 条数 + 1(合并去重);
    - ANALYSIS_SYSTEM 红线文本含"只处理未覆盖疑点"/"禁止重复提交已存在标题"
      (提示词红线生效),且补跑实例落盘的 system_prompt.txt 同样携带红线。
    Task8.6 指标:pending 1→0、补跑触发率 0.5、overlap 分布 [0.0, 0.75]、
    high_risk_areas 条目数可数。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        # 实例 1:30 轮耗尽 + FA3(3 条全在 idlc → netswitch pending);
        # 实例 2(补跑):fa/fb/fx 与实例 1 (title,file) 全同 + fc 新增
        llm = ScriptedLLM([TOOL, RECON_V3_FINAL]
                          + [TOOL] * 30 + [FA3]
                          + [TOOL, FDUP_HIGH])
        orch = _orch(td, llm)
        tool = _tool(orch)
        tool.execute(agent="recon", task="侦察")
        r1 = tool.execute(agent="analysis", task="首轮取证")
        r2 = tool.execute(agent="analysis", task="补跑:未覆盖 netswitch 疑点差分")

        # 补跑建议仍注入(实例 1 耗尽 + netswitch pending + 次数余量四门齐)
        if not r1.ok:
            fails.append(f"实例 1 应成功(FORCE_FINAL 产出可解析 FA3): {r1.error}")
        else:
            for needle in ("补跑建议", "budget_state", "netswitch"):
                if needle not in r1.text:
                    fails.append(f"实例 1 Observation 应含 '{needle}': {r1.text[-200:]}")
                    break
        if not r2.ok:
            fails.append(f"实例 2 应成功: {r2.error}")

        # 实例 2 budget_state:overlap_ratio ≥ 0.5(3/4 高重合,数值断言)
        log = json.loads((td / "process" / "agent" / "orchestrator"
                          / "dispatch_log.json").read_text(encoding="utf-8"))
        ana = [r for r in log if r.get("agent") == "analysis"]
        if len(ana) != 2:
            fails.append(f"dispatch_log 应有 2 条 analysis 实例: {len(ana)}")
        b1 = (ana[0] if ana else {}).get("budget_state", {})
        b2 = (ana[1] if len(ana) > 1 else {}).get("budget_state", {})
        if b2.get("overlap_ratio", -1) < 0.5:
            fails.append(f"高重合补跑实例 overlap_ratio 应 ≥0.5(阈值触发): {b2}")
        if abs(b2.get("overlap_ratio", -1) - 0.75) > 1e-6:
            fails.append(f"实例 2 应 overlap_ratio=0.75(fa/fb/fx 重复+fc 新增): {b2}")
        if abs(b1.get("overlap_ratio", -1)) > 1e-6:
            fails.append(f"实例 1 首轮无既有聚合应 overlap_ratio=0.0: {b1}")
        # 8.6 指标:pending 覆盖比例(1 → 0,fc 覆盖 netswitch)
        if not (b1.get("pending_count", 0) >= 1 and b2.get("pending_count", -1) == 0):
            fails.append(f"pending_count 应 1→0: {b1} → {b2}")
        # 8.6 指标:补跑触发率(exhausted 且有建议的实例占比,dispatch_log 可算)
        trig = sum(1 for i, r in enumerate(ana)
                   if r.get("budget_state", {}).get("exhausted")
                   and r.get("budget_state", {}).get("pending_count", 0) > 0
                   and (i + 1) < MAX_DISPATCH_PER_AGENT)
        if len(ana) and trig / len(ana) != 0.5:
            fails.append(f"补跑触发率应为 1/2=0.5: {trig}/{len(ana)}")
        # 8.6 指标:recon high_risk_areas 条目数(survey 工件可数)
        survey = json.loads((td / "process" / "agent" / "0_recon" / "survey.json")
                            .read_text(encoding="utf-8"))
        if len(survey.get("high_risk_areas") or []) < 1:
            fails.append("survey 工件应可数出 high_risk_areas 条目")

        # 已覆盖清单仍注入(重合场景下交接不丢):3 条既有 title 全列出 + 差分提示
        # (调用序:0/1=recon,2..32=analysis#1(30 TOOL+FA3),33/34=analysis#2)
        a2_init = llm.calls[33][1]["content"]
        for needle in ("已覆盖清单", "fa @ unitree/bin/idlc", "fb @ unitree/bin/idlc",
                       "fx @ unitree/bin/idlc", "第 2 轮补跑",
                       "禁止重复提交已存在标题"):
            if needle not in a2_init:
                fails.append(f"补跑简报应含 '{needle}': {a2_init[-300:]}")
                break

        # 聚合合并去重:实例 1 的 3 条 + fc 新增 = 4 条(合并而非丢弃)
        if len(orch.all_findings) != 4:
            fails.append(f"聚合条目数应为实例1条数+1=4: {len(orch.all_findings)}")
        titles = sorted(f.get("title") for f in orch.all_findings)
        if titles != ["fa", "fb", "fc", "fx"]:
            fails.append(f"聚合标题应为 fa/fb/fx 去重 + fc 新增: {titles}")

        # 提示词红线生效:ANALYSIS_SYSTEM 常量 + 补跑实例落盘 system_prompt.txt
        from firmware_audit.step5_agent.data.prompts import ANALYSIS_SYSTEM
        if ("只处理未覆盖疑点" not in ANALYSIS_SYSTEM
                and "禁止重复提交已存在标题" not in ANALYSIS_SYSTEM):
            fails.append("ANALYSIS_SYSTEM 应含补跑红线(只处理未覆盖疑点/禁止重复提交已存在标题)")
        sp = td / "process" / "agent" / "2_analysis" / "system_prompt.txt"
        if not sp.is_file():
            fails.append("补跑实例应落盘 system_prompt.txt")
        elif "只处理未覆盖疑点" not in sp.read_text(encoding="utf-8"):
            fails.append("补跑实例 system_prompt.txt 应携带 ANALYSIS_SYSTEM 补跑红线")
    return fails


def test_analysis_brief_v3_survey() -> list[str]:
    """Task4:recon v3 工件作上游时分析简报(补跑 analysis 经同一函数,契约成立)
    应含 v3 摘要(entry_points/high_risk_areas/recommended_actions/components),
    不再有 findings 摘要;v2 兼容层已移除(2026-08-29),旧 attack_surface.json 命名
    不回退读取、无 survey 上游时不产出 findings 兼容摘要。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        from firmware_audit.step5_agent.data.prompts import (
            build_analysis_brief, build_recon_brief)
        agent = td / "process" / "agent"
        agent.mkdir(parents=True)
        # 顶层 agent/survey.json:build_recon_brief 经 _resolve_survey_path(agent/) 命中;
        # 同时作为 analysis 的上游工件(build_analysis_brief upstream_path)
        surf = agent / "survey.json"
        surf.write_text(json.dumps({
            "schema_version": 3, "agent": "recon",
            "summary": "攻击面:一个自研二进制,网络入口在 lighttpd",
            "arch_snapshot": {"top_level_dirs": ["unitree", "etc"],
                              "components_grouped": [], "os_or_runtime": "busybox-linux"},
            "components": [{"name": "busybox", "version": "1.34", "cve": [],
                            "source": "cve_bin_tool_scan"}],
            "entry_points": [{"file": "etc/init.d/lighttpd", "reason": "web/cgi 入口"}],
            "high_risk_areas": [{"file": "unitree/bin/idlc", "metric": "注入模式命中",
                                 "detail": "semgrep R2 @ unitree/bin/idlc:42"}],
            "recommended_actions": [{"priority": "high",
                                     "action": "对 unitree/bin/idlc 取证"}],
        }), encoding="utf-8")
        brief = build_analysis_brief(td / "process", upstream_path=surf)
        for needle in ("entry_points", "etc/init.d/lighttpd", "high_risk_areas",
                       "unitree/bin/idlc", "recommended_actions", "busybox v1.34"):
            if needle not in brief:
                fails.append(f"analysis brief(v3 survey)应含 '{needle}': {brief[:200]}")
        # build_recon_brief:断点/补跑 recon 前置 v3 摘要
        rbrief = build_recon_brief(td / "process")
        for needle in ("entry_points", "high_risk_areas", "recommended_actions", "busybox"):
            if needle not in rbrief:
                fails.append(f"recon brief 应前置 v3 摘要'{needle}': {rbrief[:200]}")
        # v2 兼容层已移除(2026-08-29):不存在 attack_surface.json 命名概念,
        # _resolve_survey_path 只认 survey.json;无 survey 时不产出 findings 摘要
        nono = td / "process" / "agent3"
        nono.mkdir(parents=True)
        missing = build_analysis_brief(td / "process", upstream_path=nono / "survey.json")
        if missing is None or "[high] 旧F" in missing:
            fails.append(f"无 survey 上游时不应产出 findings 兼容摘要: {missing}")
    return fails


# ---- ADR-0007(2026-09-03):report_reconciliation 事后对账 ----
# 三处失真(现场 target/1):
# 1) 置信度错报: report 写 high、工件为 low/medium
# 2) 限定被吞: 工件 rationale 的限定事实被报告省略
# 3) 理由被编造(跨条目串条): report 详情逐字抄了别的条目的 rationale

RECONCILED_FINDINGS = [
    {"title": "硬编码 Unitree 账户 JWT Token", "severity": "high",
     "file": "unitree/module/pet_go/tests/encrypt_post.py", "func": "", "addr": "",
     "confidence": "medium", "verified": True,
     "rationale": "文件存在且证据完全吻合。但实际可利用性受限:该JWT令牌已于"
                  "2025-01-29过期(当前过期582天),无法直接用于认证,因此verified=true"
                  "但confidence降为medium。"},
    {"title": "pet_go perform_cmd 同源命令注入模式", "severity": "low",
     "file": "unitree/module/pet_go/shell_manger.py", "func": "perform_cmd", "addr": "",
     "confidence": "low", "verified": True,
     "rationale": "代码模式成立:shell_manger.py 第7行 subprocess.run(cmd, shell=True) "
                  "确实存在。但关键限制:该函数在 pet_go 模块内为死代码——整个 pet_go "
                  "目录无任何文件导入或调用 perform_cmd,不可达、无攻击面,severity 降级为 low。"},
    {"title": "net_switcher shell=True run_command（硬编码命令常量）", "severity": "info",
     "file": "unitree/module/net_switcher/net_switcher.py", "func": "run_command", "addr": "",
     "confidence": "high", "verified": True,
     "rationale": "源码确认:run_command 函数(第176-183行)使用 subprocess.Popen(command, "
                  "shell=True);所有调用点均传入硬编码字符串常量,没有任何函数参数或外部数据"
                  "被拼接进命令字符串。shell=True 配合硬编码常量在安全上不可被利用。"},
    {"title": "multicast_responder shell=True（WebRTC 入口）", "severity": "info",
     "file": "unitree/module/webrtc_bridge/src/webrtc_dds_bridge/multicast_responder.py",
     "func": "get_ip_address", "addr": "",
     "confidence": "high", "verified": None, "rationale": ""},
]

# 报告形态 = 现场 report.md 的浓缩(### 分区 + #### N. 条目 + 置信度:/复核结论:/详情: 标签行)
RECONCILE_MD = """# 固件安全审计报告
## 发现清单
### HIGH
#### 1. 硬编码 Unitree 账户 JWT Token
- **位置：** `unitree/module/pet_go/tests/encrypt_post.py`
- **置信度：** high → **复核结论：✓ 已证实**
- **详情：** 明文硬编码了 Unitree 平台的 JWT Token 及 refresh_token，可用于冒充用户身份访问 Unitree 云服务 API。
- **证据：** `encrypt_post.py` 中 `token` 和 `refresh_token` 字段为完整 JWT 字符串
### LOW
#### 2. pet_go perform_cmd 同源命令注入模式
- **位置：** `unitree/module/pet_go/shell_manger.py :: perform_cmd`
- **置信度：** high → **复核结论：✓ 已证实，severity 降级为 low**
- **详情：** 调用点当前均为硬编码命令常量拼接，无远程可达输入源，实际可利用性较低。
- **证据：** `subprocess.run(cmd, shell=True)`（注：此句逐字来自 net_switcher 条目）
### INFO（已复核）
#### 3. net_switcher shell=True run_command（硬编码命令常量）
- **位置：** `unitree/module/net_switcher/net_switcher.py :: run_command`
- **置信度：** high → **复核结论：✓ 已证实（低风险代码规范提醒）**
- **详情：** run_command 函数使用 subprocess.Popen(command, shell=True)，但所有调用点均传入硬编码字符串常量，无外部输入拼接，安全上不可被利用。
- **证据：** `net_switcher.py:178 process = subprocess.Popen(command, shell=True)`
## 未复核疑点
#### 4. multicast_responder shell=True（WebRTC 入口）
- **位置：** `unitree/module/webrtc_bridge/src/webrtc_dds_bridge/multicast_responder.py`
- **置信度（初值）：** high → **复核结论：⚠ 未经复核**
- **详情：** 接口名硬编码，非生产服务入口。
"""


def _recon_statuses_by_title(result: dict) -> dict:
    return {it.get("title"): it.get("status") for it in result.get("items", [])}


def _recon_check(result: dict, title: str, field: str) -> dict:
    for it in result.get("items", []):
        if it.get("title") == title:
            return (it.get("checks", {}).get(field) or {})
    return {}


def test_reconcile_report() -> list[str]:
    """ADR-0007 对账纯函数(reconcile_report):解析 report.md 正文 → 与
    verified_findings 逐条比对确定性事实(file + severity/confidence/verified
    三枚举)→ 差异清单。

    (2026-09-03 用户决策:rationale/evidence 内容不检查,理由溯源回归人工,
    故本测试只核 file + 枚举值。)
    验收:
    1. 失真 1 置信度错报:JWT 条目工件 confidence=medium、报告写 high → mismatch(error)
    2. file 一致性:位置行(含 :: func 剥离)与工件 file 全等 → ok
    3. 正常转述 net_switcher:file + 三枚举全对齐 → ok,不误报
    4. 未复核条目(⚠)与工件 verified=None 对齐 → verified 检查 ok;
       severity 提取失败(未复核区无分区)→ unparsed(显式报出,不静默)
    5. index 序号、字段原值携带(差异清单可读)
    """
    fails: list[str] = []
    from firmware_audit.step5_agent.orchestrator import reconcile_report
    result = reconcile_report(RECONCILE_MD, RECONCILED_FINDINGS)
    items = result.get("items", [])
    if len(items) != 4:
        fails.append(f"report 应有 4 个条目被解析: {len(items)}")
        return fails
    # 失真 1:JWT confidence 错报(medium → high,mismatch)
    j = _recon_check(result, "硬编码 Unitree 账户 JWT Token", "confidence")
    if not j:
        fails.append("JWT 条目应有 confidence 比对结果")
    elif j.get("ok") or j.get("artifact") != "medium" or j.get("report") != "high":
        fails.append(f"JWT confidence 应为 mismatch(工件 medium/报告 high): {j}")
    jsev = _recon_check(result, "硬编码 Unitree 账户 JWT Token", "severity")
    if not jsev or not jsev.get("ok") or jsev.get("artifact") != "high":
        fails.append(f"JWT 分区 HIGH 应推断 severity=high 且一致: {jsev}")
    if _recon_statuses_by_title(result).get("硬编码 Unitree 账户 JWT Token") != "mismatch":
        fails.append("JWT 条目整体状态应为 mismatch")
    # 失真 1 变体:pet_go 报告置信度 high vs 工件 low(severity 降级如实转述,confidence 没有)
    pconf = _recon_check(result, "pet_go perform_cmd 同源命令注入模式", "confidence")
    if not pconf or pconf.get("ok") or pconf.get("artifact") != "low":
        fails.append(f"pet_go confidence 应为 mismatch(工件 low/报告 high): {pconf}")
    if _recon_check(result, "pet_go perform_cmd 同源命令注入模式", "severity").get("ok") is not True:
        fails.append("pet_go 分区 LOW 与工件 severity=low 应一致")
    # file 一致性:位置行剥离 :: func 后与工件 file 全等
    pfile = _recon_check(result, "pet_go perform_cmd 同源命令注入模式", "file")
    if not pfile or pfile.get("ok") is not True:
        fails.append(f"pet_go 位置行(含 :: func)应剥离并匹配工件 file: {pfile}")
    # 正常转述 net_switcher:file + 三枚举全对齐 → ok,不误报
    nconf = _recon_check(result, "net_switcher shell=True run_command（硬编码命令常量）",
                         "confidence")
    if not nconf or not nconf.get("ok"):
        fails.append(f"net_switcher 正常转述应 ok: {nconf}")
    nfile = _recon_check(result, "net_switcher shell=True run_command（硬编码命令常量）",
                         "file")
    if not nfile or nfile.get("ok") is not True:
        fails.append(f"net_switcher 位置行应匹配工件 file: {nfile}")
    if _recon_statuses_by_title(result).get(
            "net_switcher shell=True run_command（硬编码命令常量）") != "ok":
        fails.append("net_switcher 整体状态应为 ok")
    # 未复核条目:工件 verified=None vs 报告 ⚠ → verified 检查一致;
    # severity 提取失败(⚠ 区无分区)→ unparsed(显式报出,不静默)
    vcheck = _recon_check(result, "multicast_responder shell=True（WebRTC 入口）", "verified")
    if not vcheck or vcheck.get("ok") is not True or vcheck.get("report") is not None:
        fails.append(f"未复核条目 verified 检查应 ok(None==None): {vcheck}")
    if _recon_statuses_by_title(result).get(
            "multicast_responder shell=True（WebRTC 入口）") != "unparsed":
        fails.append("未复核条目 severity 提取失败应显式标 unparsed(不静默)")
    # 差异清单可读性:index 序号 + 文件全名携带;清单含 summary
    it = items[1]
    if it.get("index") != 2 or it.get("file") != "unitree/module/pet_go/shell_manger.py":
        fails.append(f"条目应带 index/文件全名: {it}")
    if "summary" not in result:
        fails.append("结果应带 summary 汇总")
    return fails


def test_reconcile_file_check() -> list[str]:
    """file 存在性检查(2026-09-03 用户决策新增):位置行一致 → ok;无位置行 →
    提取失败(ok=None→unparsed);位置写错 → mismatch。理由内容不再检查。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.orchestrator import reconcile_report
    md = """# 报告
### HIGH
#### 1. 正常条目
- **位置：** unitree/bin/a.py
- **置信度：** high → **复核结论：** ✓ 已证实
#### 2. 位置写错条目
- **位置：** unitree/bin/typo.py
- **置信度：** high → **复核结论：** ✓ 已证实
#### 3. 无位置条目
- **置信度：** high → **复核结论：** ✓ 已证实
"""
    findings = [
        {"title": "正常条目", "severity": "high", "file": "unitree/bin/a.py",
         "confidence": "high", "verified": True},
        {"title": "位置写错条目", "severity": "high", "file": "unitree/bin/b.py",
         "confidence": "high", "verified": True},
        {"title": "无位置条目", "severity": "high", "file": "unitree/bin/c.py",
         "confidence": "high", "verified": True},
    ]
    result = reconcile_report(md, findings)
    by_title = {it.get("title"): it for it in result.get("items", [])}
    a = by_title.get("正常条目", {}).get("checks", {}).get("file", {})
    if a.get("ok") is not True:
        fails.append(f"位置一致应 file ok=True: {a}")
    b = by_title.get("位置写错条目", {}).get("checks", {}).get("file", {})
    if b.get("ok") is not False or b.get("artifact") != "unitree/bin/b.py" \
            or b.get("report") != "unitree/bin/typo.py":
        fails.append(f"位置错配应 file ok=False 并带双方原值: {b}")
    if by_title.get("位置写错条目", {}).get("status") != "mismatch":
        fails.append("位置错配条目整体状态应为 mismatch")
    c = by_title.get("无位置条目", {}).get("checks", {}).get("file", {})
    if c.get("ok") is not None:
        fails.append(f"无位置行应 file ok=None(提取失败): {c}")
    if by_title.get("无位置条目", {}).get("status") != "unparsed":
        fails.append("无位置条目应显式标 unparsed")
    # 契约:理由内容不再检查(无 rationale_warnings 键,无 rationale check)
    items = result.get("items", [])
    if any("rationale" in (it.get("checks") or {}) for it in items):
        fails.append("按用户决策,不应再产出 rationale 检查结果")
    if "rationale_warnings" in result.get("summary", {}):
        fails.append("summary 不应再含 rationale_warnings")
    return fails


def test_reconcile_unparsed_mismatch_fields() -> list[str]:
    """显式报出(ADR 决策 2/3):提取不到枚举值的条目显式标 unparsed(不静默);
    报告有的条目工件对不上 → unmatched;清单携带字段名。”

    - 无分区标题 + 无 severity 标签 → severity 提取失败(unparsed,显式报出)
    - 工件无对应 title 的条目 → unmatched
    - 报告缺失的工件条目 → 不被报告(只对报告条目负责),不以篇幅回写
    """
    fails: list[str] = []
    from firmware_audit.step5_agent.orchestrator import reconcile_report
    md = """# 固件安全审计报告
## 发现清单
#### X. 只存在于报告的条目
- **位置：** unitree/module/ghost/ghost.py
- **置信度：** high → **复核结论：✓ 已证实**
- **详情：** 来源不明。
"""
    # 工件只有一条与报告标题不同 → 该 report 条目 unmatched
    findings = [{"title": "真实工件条目", "severity": "high",
                 "file": "unitree/bin/real", "confidence": "high",
                 "verified": True, "rationale": "实际存在"}]
    result = reconcile_report(md, findings)
    item = (result.get("items") or [])[0]
    if item.get("status") != "unmatched":
        fails.append(f"报告条目在工件无对应 title → unmatched: {item.get('status')}")
    if item.get("matched") is not False:
        fails.append(f"unmatched 条目应 matched=False: {item}")
    if "只存在于报告的条目" not in item.get("title", ""):
        fails.append(f"unmatched 条目应保留原标题: {item.get('title')}")
    # 已复核条目缺枚举标签 + 无分区 → unparsed(显式报出,不静默)
    md2 = """# 固件安全审计报告
## 发现清单
#### 1. 无标签条目
- **详情：** 没有任何标签行。
"""
    r2 = reconcile_report(md2, [{"title": "无标签条目", "severity": "high",
                                 "file": "x/y.py", "confidence": "high",
                                 "verified": True, "rationale": "存在"}])
    it2 = (r2.get("items") or [])[0]
    if it2.get("status") != "unparsed":
        fails.append(f"既有已复核条目但提取不到枚举值 → unparsed: {it2.get('status')}")
    if not it2.get("checks") or it2["checks"].get("severity", {}).get("ok") is not None:
        fails.append(f"unparsed 条目 severity 检查应为提取失败(ok=None): {it2.get('checks')}")
    return fails


def test_report_reconciliation_integration() -> list[str]:
    """ADR-0007 集成:Orchestrator.run 落盘 report.md 后自动事后对账——
    report_reconciliation.json 落盘差异清单 + stderr 警告;report.md 原样保留
    (仅告警,不自动重生成、不阻塞)。"""
    fails: list[str] = []
    import io
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        _make_process(td)
        # Final Answer = 失真报告:fa 工件 confidence=high、报告写 medium(错报)
        MISMATCH_MD = ("Final Answer: # 固件安全审计报告\n## 发现清单\n### HIGH\n"
                       "#### 1. fa\n- **位置：** unitree/bin/idlc\n"
                       "- **置信度：** medium → **复核结论：✓ 已证实**\n"
                       "- **详情：** fa 复核结论,证据链完整,危险函数确认。\n"
                       "## 误报剔除\n- 无误报")
        FA_RECHECK = ('Final Answer: {"summary": "复核fa", "findings": [{"title": "fa", '
                      '"severity": "high", "file": "unitree/bin/idlc", "confidence": "high", '
                      '"verified": true, "rationale": "fa 复核结论,证据链完整"}]}')
        h = [
            D % "recon", TOOL, RECON_FINAL,        # 0/1/2
            D % "analysis", TOOL, FA,              # 3/4/5
            D % "verification",                    # 6 阶段(1 条 finding → 1 实例)
            TOOL, FA_RECHECK,                      # 7/8 复核 fa
            SUM,                                   # 9 取报告素材
            MISMATCH_MD,                           # 10 Final Answer = 报告(含错报)
        ]
        err = io.StringIO()
        with patch("sys.stderr", err):
            llm = ScriptedLLM(h)
            orch = _orch(td, llm)
            orch.run()
        agent = td / "process" / "agent"
        rc = agent / "orchestrator" / "report_reconciliation.json"
        if not rc.is_file():
            fails.append("对账后应落盘 report_reconciliation.json")
        else:
            obj = json.loads(rc.read_text(encoding="utf-8"))
            if obj.get("summary", {}).get("mismatch") != 1:
                fails.append(f"summary.mismatch 应为 1(confidence 错报): {obj.get('summary')}")
            it = (obj.get("items") or [])[0]
            if it.get("status") != "mismatch":
                fails.append(f"错报条目应按 mismatch 报出: {it.get('status')}")
            conf = it.get("checks", {}).get("confidence", {})
            if conf.get("ok") is not False or conf.get("artifact") != "high" \
                    or conf.get("report") != "medium":
                fails.append(f"清单应带字段名与双方原值: {conf}")
        # stderr 警告(显式,不静默)
        warn = err.getvalue()
        for needle in ("[reconcile]", "mismatch=1"):
            if needle not in warn:
                fails.append(f"stderr 应含 '{needle}': {warn!r}")
        # report.md 原样保留,不被重生成、不被修改
        md = (agent / "orchestrator" / "report.md").read_text(encoding="utf-8")
        if "### HIGH" not in md or "置信度：" not in md:
            fails.append(f"report.md 应保持 Final Answer 原样: {md[:80]}")
    return fails


def test_orchestrator_prompt_reconcile_redlines() -> list[str]:
    """ADR-0007 素材侧:summarize 提示词须携带报告写作纪律红线——
    枚举值逐字抄写素材(唯一真值)、禁止跨条目串条、限定语不许吞、标签行约定。
    素材收敛不保真,但对账要能提取,标签行约定让对账解析稳定。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.orchestrator import build_orchestrator_prompt
    prompt = build_orchestrator_prompt({}, max_iters=10)
    for needle in ("逐字抄写", "唯一真值", "禁止引用或", "转述其他条目的 rationale",
                   "跨条目串条", "保留工件 rationale 的核心事实与限定", "**位置：**",
                   "**severity：**", "**置信度：**", "**复核结论：**", "初值",
                   "不得只写在详情散文里"):
        if needle not in prompt:
            fails.append(f"提示词应含对账红线 '{needle}'")
    return fails


def test_reconcile_edge_robustness() -> list[str]:
    """Review 缺口锁定(2026-09-03 code-review 后):
    1. `### N. 标题`(3# 带编号)必须识别为条目,不得被当分区吞掉(静默丢条)
    2. 条目内 `severity: critical|info` 标签行必须解析 5 值(此前 regex 只认 3 值
       high/medium/low,critical/info 静默失效)
    3. 条目缺详情行不影响对账(2026-09-03 起 rationale 内容不检查)
    """
    fails: list[str] = []
    from firmware_audit.step5_agent.orchestrator import reconcile_report
    md = """# 报告
## 发现清单
### HIGH
### 1. 三级井号编号条目（未被 #### 约束）
- **位置：** unitree/bin/a.py
- **置信度：** high → **复核结论：** ✓ 已证实
### 2. severity 标签五值条目
- **位置：** unitree/bin/b.c
- **severity：** critical
- **置信度：** high → **复核结论：** ✓ 已证实
#### 3. 详情缺失条目
- **位置：** unitree/bin/c.py
- **置信度：** high → **复核结论：** ✓ 已证实
"""
    findings = [
        {"title": "三级井号编号条目（未被 #### 约束）", "severity": "high",
         "file": "unitree/bin/a.py", "confidence": "high", "verified": True},
        {"title": "severity 标签五值条目", "severity": "critical",
         "file": "unitree/bin/b.c", "confidence": "high", "verified": True},
        {"title": "详情缺失条目", "severity": "high",
         "file": "unitree/bin/c.py", "confidence": "high", "verified": True},
    ]
    result = reconcile_report(md, findings)
    by_title = {it.get("title"): it for it in result.get("items", [])}
    # 1. ### 带编号 → 条目,不丢失
    a = by_title.get("三级井号编号条目（未被 #### 约束）")
    if not a or a.get("matched") is not True:
        fails.append(f"### 编号条目应被识别(matched=True),不得当分区吞掉: {a}")
    elif a.get("checks", {}).get("confidence", {}).get("ok") is not True:
        fails.append(f"### 编号条目的枚举应对齐: {a.get('checks')}")
    # 2. severity 标签行 5 值
    b = by_title.get("severity 标签五值条目")
    if not b:
        fails.append("severity 标签条目应存在")
    elif b.get("checks", {}).get("severity", {}).get("ok") is not True:
        fails.append(f"severity: critical 标签行应解析为 critical 且一致: "
                     f"{b.get('checks', {}).get('severity')}")
    # 3. 详情缺失不影响对账:枚举+file 全对齐 → ok;无 rationale 检查(用户决策)
    s = result.get("summary", {})
    if s.get("ok") != 3:
        fails.append(f"三条枚举+file 全对齐应为 ok(缺详情不影响): {s}")
    if s.get("unparsed") != 0:
        fails.append(f"HIGH 分区下三条 severity 均应提取成功,不得 unparsed: {s}")
    if "rationale_warnings" in s:
        fails.append("summary 不应再含 rationale_warnings(理由内容不检查)")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("sub_agent_result", test_sub_agent_result),
        ("build_orchestrator_prompt", test_build_orchestrator_prompt),
        ("unknown_agent", test_unknown_agent),
        ("order_gate_skip_forward", test_order_gate_skip_forward),
        ("order_gate_backward", test_order_gate_backward),
        ("max_dispatch_limit", test_max_dispatch_limit),
        ("duplicate_of_failed", test_duplicate_of_failed),
        ("dispatch_success", test_dispatch_success),
        ("dispatch_skipped", test_dispatch_skipped),
        ("multi_dispatch_and_duplicate", test_multi_dispatch_and_duplicate),
        ("dispatch_log_lifecycle_fields", test_dispatch_log_lifecycle_fields),
        ("orchestrator_integration_dirs", test_orchestrator_integration_dirs),
        ("orchestrator_multi_dispatch_integration", test_orchestrator_multi_dispatch_integration),
        ("summarize_tool_and_report", test_summarize_tool_and_report),
        ("report_unreviewed_section", test_report_unreviewed_section),
        ("verify_toplevel_verdict_merged", test_verify_toplevel_verdict_merged),
        ("report_absent_without_summarize", test_report_absent_without_summarize),
        ("degraded_resume_rerun", test_degraded_resume_rerun),
        ("handoff_snapshot_file", test_handoff_snapshot_file),
        ("status_enum_closed", test_status_enum_closed),
        ("ingest_merge_dedup", test_ingest_merge_dedup),
        ("aggregator_module", test_aggregator_module),
        ("ingest_verification_overrides", test_ingest_verification_overrides),
        ("planner_removed", test_planner_removed),
        ("report_json_byproduct", test_report_json_byproduct),
        ("artifact_instance_seq_backfilled", test_artifact_instance_seq_backfilled),
        ("ingest_skips_recon_v3", test_ingest_skips_recon_v3),
        ("analysis_brief_v3_survey", test_analysis_brief_v3_survey),
        ("analysis_exhausted_rerun_overlap", test_analysis_exhausted_rerun_overlap),
        ("budget_state_not_exhausted_no_suggestion", test_budget_state_not_exhausted_no_suggestion),
        ("dynamic_dispatch_full_chain_budget", test_dynamic_dispatch_full_chain_budget),
        ("rerun_high_overlap_adapt", test_rerun_high_overlap_adapt),
        ("reconcile_report", test_reconcile_report),
        ("reconcile_file_check", test_reconcile_file_check),
        ("reconcile_unparsed_mismatch_fields", test_reconcile_unparsed_mismatch_fields),
        ("report_reconciliation_integration", test_report_reconciliation_integration),
        ("orchestrator_prompt_reconcile_redlines", test_orchestrator_prompt_reconcile_redlines),
        ("reconcile_edge_robustness", test_reconcile_edge_robustness),
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
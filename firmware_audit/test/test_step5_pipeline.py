"""Step5 工件/上下文/流水线单测(ScriptedLLM,零 API 零 Docker)。

覆盖 2026-08-17 新增三层:
  artifacts  Finding 宽容解析 / parse_artifact 各降级路径 / 存取回读 / 摘要
  context    四分区构建 / 阈值触发压缩(assistant 边界对齐) / 压缩失败还原
  pipeline   三 Agent 串行全链路 / 下游简报注入 / 断点续跑跳过 / 误报分节报告
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.data.artifacts import (
    Finding,
    artifact_summary,
    load_artifact,
    parse_artifact,
    save_artifact,
)
from firmware_audit.step5_agent.engine.context import ContextManager, est_tokens
from firmware_audit.step5_agent.orchestration.orchestrator import Orchestrator
from firmware_audit.step5_agent.orchestration.actions import DispatchAgentTool
from firmware_audit.step5_agent.providers.tools import ToolContext
from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.step5_agent.run_step5 import step5_run


# ---- fixtures ----

def _make_process(td: Path) -> Path:
    """伪造最小工作区:extracted/(启动门)+ 1 个二进制的三件套 sidecar。"""
    ext = td / "process" / "extracted" / "unitree" / "bin"
    ext.mkdir(parents=True)
    (ext / "idlc").write_bytes(b"\x7fELF")
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


RECON_FINAL = 'Final Answer: {"summary": "攻击面:1 个自研二进制,导入 system", "findings": [{"title": "危险函数导入 system", "severity": "high", "file": "unitree/bin/idlc", "evidence": "imports ref_count=2"}], "components": [{"name": "idlc", "version": "", "cve": [], "source": "strings"}]}'

# recon v3 正统输出:无 findings/判级字段,结构 = survey schema v3
RECON_FINAL_V3 = ('Final Answer: {"schema_version": 3, '
                  '"summary": "自研二进制 idlc + web 入口,存在注入模式命中", '
                  '"arch_snapshot": {"top_level_dirs": ["unitree", "etc"], '
                  '"components_grouped": [{"name": "idlc", "size": 40960, '
                  '"role": "web server", "role_evidence": ["binds TCP/80 (imports)"]}], '
                  '"os_or_runtime": "busybox-linux"}, '
                  '"components": [{"name": "busybox", "version": "1.34", "cve": [], '
                  '"source": "cve_bin_tool_scan"}], '
                  '"entry_points": [{"file": "etc/init.d/lighttpd", "reason": "web/cgi 入口"}], '
                  '"high_risk_areas": [{"file": "unitree/bin/idlc", "metric": "注入模式命中", '
                  '"detail": "semgrep R2 @ unitree/bin/idlc:42"}], '
                  '"recommended_actions": [{"priority": "high", '
                  '"action": "对 unitree/bin/idlc 用 find_decompiled_function 取证,关注 system 拼接"}]}')

ANALYSIS_EXTRA_FINAL = 'Final Answer: {"summary": "补跑取证", "findings": [{"title": "fb2", "severity": "medium", "file": "unitree/bin/idlc", "evidence": "strings 命中", "confidence": "low"}]}'

ANALYSIS_FINAL = 'Final Answer: {"summary": "取证完成", "findings": [{"title": "main 经 system 执行拼接命令", "severity": "high", "file": "unitree/bin/idlc", "func": "main", "addr": "0010d000", "evidence": "decompile: system(cmd)", "confidence": "medium"}, {"title": "硬编码口令", "severity": "high", "file": "unitree/bin/idlc", "evidence": "password=unitree2018", "confidence": "low"}]}'

VERIFY_FINAL = 'Final Answer: {"summary": "复核完成", "findings": [{"title": "main 经 system 执行拼接命令", "severity": "high", "file": "unitree/bin/idlc", "func": "main", "verified": true, "rationale": "调用链确认", "confidence": "high"}, {"title": "硬编码口令", "severity": "high", "file": "unitree/bin/idlc", "verified": false, "rationale": "实为默认文档示例", "confidence": "low"}]}'

# ADR-0003 每疑点一实例:verification 单实例只复核一条(拆 VERIFY_FINAL 为单条 finals)
VERIFY_FINAL_F1 = ('Final Answer: {"summary": "复核1", "findings": [{"title": '
                   '"main 经 system 执行拼接命令", "severity": "high", "file": "unitree/bin/idlc", '
                   '"func": "main", "verified": true, "rationale": "调用链确认", "confidence": "high"}]}')
VERIFY_FINAL_F2 = ('Final Answer: {"summary": "复核2", "findings": [{"title": "硬编码口令", '
                   '"severity": "high", "file": "unitree/bin/idlc", "verified": false, '
                   '"rationale": "实为默认文档示例", "confidence": "low"}]}')


# ---- artifacts ----

def test_finding_from_dict() -> list[str]:
    fails: list[str] = []
    f = Finding.from_dict({"title": "x"})
    if (f.severity, f.cve, f.verified) != ("info", "", None):
        fails.append(f"缺字段默认值错误: {f.severity}/{f.cve}/{f.verified}")
    f2 = Finding.from_dict({"title": "y", "severity": "SUPER", "unknown_field": 1})
    if f2.severity != "info":
        fails.append("非法 severity 应归一为 info")
    if f2.extras != {"unknown_field": 1}:
        fails.append(f"未知字段应进 extras: {f2.extras}")
    f3 = Finding.from_dict("不是 dict")
    if f3.title != "不是 dict":
        fails.append("非 dict 输入应包成标题")
    return fails


def test_parse_artifact() -> list[str]:
    fails: list[str] = []
    obj = parse_artifact('{"summary": "s", "findings": [{"title": "a"}]}')
    if not obj or len(obj["findings"]) != 1:
        fails.append("正常 JSON 解析失败")
    fenced = parse_artifact('```json\n{"summary": "s", "findings": []}\n```')
    if not fenced or fenced["findings"] != []:
        fails.append("围栏 JSON 解析失败")
    # 前后带说明文字
    prose = parse_artifact('结论如下:\n{"summary": "s", "findings": [{"title": "a"}]}\n以上。')
    if not prose or len(prose["findings"]) != 1:
        fails.append("前后缀文本容忍失败")
    # 顶层裸数组
    arr = parse_artifact('[{"title": "a"}, {"title": "b"}]')
    if not arr or len(arr["findings"]) != 2 or arr.get("summary", "") != "":
        fails.append("顶层 list 应包成容器")
    # 彻底失败
    if parse_artifact("完全不是 JSON") is not None:
        fails.append("垃圾文本应返回 None")
    if parse_artifact("") is not None:
        fails.append("空串应返回 None")
    return fails


def test_save_load_summary() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "a.json"
        parsed = parse_artifact('{"summary": "摘要X", "findings": [{"title": "标题Y", "severity": "high", "zzz": 1}]}')
        save_artifact(p, "recon", parsed, "raw")
        obj = load_artifact(p)
        if obj is None or obj.get("schema") != 2:
            fails.append(f"回读缺 schema: 2, got {obj and obj.get('schema')}")
        if obj["agent"] != "recon" or obj["summary"] != "摘要X":
            fails.append("agent/summary 回读不符")
        f0 = obj["findings"][0]
        if f0["title"] != "标题Y" or f0.get("extras") != {"zzz": 1}:
            fails.append(f"finding 回读不符: {f0}")
        if f0.get("source_agent") != "recon":
            fails.append(f"finding 应带 source_agent 溯源(schema v2): {f0.get('source_agent')}")
        text = artifact_summary(p)
        if "摘要X" not in text or "[high] 标题Y" not in text:
            fails.append(f"摘要应含 summary 与 finding 行: {text[:80]}")
        # 降级:.md 落盘 + 摘要仍可读
        p2 = Path(td) / "b.json"
        out = save_artifact(p2, "analysis", None, "Final Answer: 纯文本降级")
        if out.suffix != ".md":
            fails.append("解析失败应降级 .md")
        text2 = artifact_summary(p2)
        if "纯文本降级" not in text2:
            fails.append(".md 降级摘要应含原文")
    return fails


# ---- context ----

def test_build_messages_partitions() -> list[str]:
    fails: list[str] = []
    cm = ContextManager("SYS", "INIT")
    cm.append("assistant", "a1")
    cm.append("user", "o1")
    msgs = cm.build_messages()
    if [m["content"] for m in msgs] != ["SYS", "INIT", "a1", "o1"]:
        fails.append("无压缩时应是 system+init+recent")
    cm.summaries.append("SUM1")
    msgs2 = cm.build_messages()
    if len(msgs2) != 5 or "SUM1" not in msgs2[2]["content"] or msgs2[2]["role"] != "user":
        fails.append("概括区应插在 init 与 recent 之间")
    if cm.needs_compaction():  # 默认阈值高,小上下文不应触发
        fails.append("小上下文误触发压缩")
    return fails


def test_compaction_boundary_and_failure() -> list[str]:
    fails: list[str] = []
    # 低阈值强制触发:6 条 recent(a/o×3),压缩最老一半并对齐 assistant 边界
    llm = ScriptedLLM(["压缩摘要:已确认事实若干"])
    cm = ContextManager("SYS", "INIT", max_est_tokens=10, trigger_ratio=0.5)
    for i in range(3):
        cm.append("assistant", f"a{i}")
        cm.append("user", f"o{i}")
    done = cm.maybe_compact(llm)
    if not done or cm.compactions != 1:
        fails.append("超阈值应触发压缩")
    if len(cm.recent) != 2 or cm.recent[0]["content"] != "a2":
        fails.append(f"压缩后应保留最近一轮对: {[m['content'] for m in cm.recent]}")
    if "压缩摘要" not in cm.summaries[0]:
        fails.append("摘要未写入概括区")
    if not llm.calls or "a0" not in llm.calls[0][1]["content"]:
        fails.append("压缩调用应携带被压缩的原文")

    # 压缩失败(LLM 抛错):还原保留区,不丢历史
    class BoomLLM(ScriptedLLM):
        def chat(self, messages, **kw):
            self.calls.append(list(messages))
            raise RuntimeError("压缩网络炸了")

    cm2 = ContextManager("SYS", "INIT", max_est_tokens=10, trigger_ratio=0.5)
    for i in range(3):
        cm2.append("assistant", f"a{i}")
        cm2.append("user", f"o{i}")
    n_before = len(cm2.recent)
    if cm2.maybe_compact(BoomLLM([])):
        fails.append("LLM 失败时 compact 应返回 False")
    if len(cm2.recent) != n_before or cm2.summaries != []:
        fails.append("压缩失败必须还原保留区")
    return fails


# ---- pipeline 全链路 ----

def test_full_chain_and_resume() -> list[str]:
    """Orchestrator 全链路(recon→analysis→verification)→finish,含断点续跑(子 Agent 跳过)。"""
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 10}'
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        # 脚本顺序(共享一个 ScriptedLLM):orchestrator 决策 + 子 Agent(工具+终)交错。
        # ADR-0003:verification 每疑点一实例——2 条 analysis findings → 2 个独立实例
        S = 'Thought: 收尾\nAction: summarize\nAction Input: {"conclusion": "全链路完成"}'
        REPORT_MD = ('Final Answer: # 固件安全审计报告\n## 发现清单\n'
                     '- [high] ✓ main 经 system 注入(unitree/bin/idlc)\n'
                     '## 误报剔除\n- 实为默认文档示例\n复核完成')
        h = [
            D % "recon",        # 0 orchestrator 调度 recon
            'Thought: 先看工件\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.imports.json", "limit": 10}',
            RECON_FINAL,        # 2 recon 终
            D % "analysis",     # 3 orchestrator 调度 analysis
            'Thought: 取证\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.strings.json", "limit": 10}',
            ANALYSIS_FINAL,     # 5 analysis 终
            D % "verification",  # 6 orchestrator 调度 verification(阶段)
            VTOOL, VERIFY_FINAL_F1,   # 7/8  复核实例 1(首条 finding)
            VTOOL, VERIFY_FINAL_F2,   # 9/10 复核实例 2(次条 finding)
            S,                  # 11 orchestrator summarize(取素材)
            REPORT_MD,          # 12 Final Answer = 报告正文
        ]
        llm = ScriptedLLM(h)
        summary = step5_run(target, llm=llm)
        if summary["mode"] != "llm":
            fails.append(f"应走 LLM 模式: {summary['mode']}")
        if not summary.get("report"):
            fails.append("summarize 后应产出报告路径")
        agent = target / "process" / "agent"

        # 规范化目录:子 Agent 按 <seq>_<type> 落盘;recon v3 工件名 survey.json
        surf = load_artifact(agent / "0_recon" / "survey.json")
        if surf is None or surf.get("components") != [{"name": "idlc", "version": "", "cve": [], "source": "strings"}]:
            fails.append(f"0_recon survey 缺 components 或内容不符: {surf and surf.get('components')}")
        find = load_artifact(agent / "1_analysis" / "findings.json")
        if find is None or len(find["findings"]) != 2:
            fails.append(f"1_analysis findings 应有 2 条: {find and len(find['findings'])}")
        # ADR-0003:verified_findings.json 聚合到 agent 根(阶段级产物)
        ver = load_artifact(agent / "verified_findings.json")
        if ver is None:
            fails.append("agent/verified_findings.json 缺失(verification 每疑点一实例聚合)")
        else:
            v_counts = [f.get("verified") for f in ver["findings"]]
            if v_counts != [True, False]:
                fails.append(f"verified 标记应 1 真 1 假: {v_counts}")

        # orchestrator 目录三件套
        for fn in ("transcript.jsonl", "dispatch_log.json", "result.json"):
            if not (agent / "orchestrator" / fn).is_file():
                fails.append(f"orchestrator/{fn} 缺失")

        # 下游简报注入:analysis 首轮 init 应含上游摘要与工件名(recon v3 = survey.json)
        analysis_init = llm.calls[4][1]["content"]
        if "survey.json" not in analysis_init or "攻击面" not in analysis_init:
            fails.append(f"analysis 简报应含上游 survey 摘要: {analysis_init[:100]}")
        # verification 实例简报(ADR-0003):注入单条 finding 全字段,不 dump 全量
        verify_init = llm.calls[7][1]["content"]
        if "待复核 finding" not in verify_init or "main 经 system" not in verify_init:
            fails.append("verification 实例简报应含单条待复核 finding")

        # 子 Agent transcript 落盘(编号目录)+ orchestrator transcript
        for base in ("0_recon", "1_analysis", "3_verification", "4_verification"):
            tr = agent / base / "transcript.jsonl"
            if not tr.is_file():
                fails.append(f"{base} transcript 缺失")
                continue
            phases = [json.loads(l)["phase"] for l in tr.read_text(encoding="utf-8").splitlines()]
            if "assistant" not in phases:
                fails.append(f"{base} transcript 无 assistant 记录: {phases}")

        # 报告(v3):orchestrator summarize 产出,位于 orchestrator/report.md
        report = (agent / "orchestrator" / "report.md").read_text(encoding="utf-8")
        if "✓" not in report or "main 经 system" not in report:
            fails.append("报告应含已证实发现(✓)")
        if "误报剔除" not in report or "实为默认文档示例" not in report:
            fails.append("报告应含误报分节")
        if "复核完成" not in report:
            fails.append("报告正文应含 verification summary 字样")
        if summary["report"] != str(agent / "orchestrator" / "report.md"):
            fails.append(f"summary['report'] 应指向 orchestrator/report.md: {summary['report']}")
        # 续跑后旧 report.md 不冒充新报告:本轮未删旧文件,但 result.json 记录 report_path
        res = json.loads((agent / "orchestrator" / "result.json").read_text(encoding="utf-8"))
        if not res.get("summarize_called") or not res.get("report_path"):
            fails.append("result.json 应记录 summarize_called 与 report_path")

        # 断点续跑:recon/analysis/verified_findings 工件齐 → 子 Agent 全跳过,
        # 仅 orchestrator 消耗 5 次决策(3×dispatch + summarize + Final)
        llm2 = ScriptedLLM([D % "recon", D % "analysis", D % "verification",
                            S, REPORT_MD])
        s2 = step5_run(target, llm=llm2)
        if len(llm2.calls) != 5:
            fails.append(f"续跑 orchestrator 应 5 次调用(子 Agent 全跳过+summarize),"
                         f" got {len(llm2.calls)}")
        stages = s2.get("stages", {})
        if not stages or not all(v.get("ok") for v in stages.values()):
            fails.append(f"续跑各阶段应 ok: {stages}")
    return fails


def test_recon_v3_orchestration_boundary() -> list[str]:
    """Task4/5 集成:recon v3 + analysis 编排后 _all_findings 仅含 analysis/verification
    条目(recon 只铺面不判级,聚合唯一来源 = analysis/verification);磁盘 survey.json
    不含 findings 键——orchestrator dispatch 后的 instance_seq 回填对 recon 跳过,
    load_artifact 注入的空 findings:[] 不会被写回工件。
    Task8.1 补维度:判级/证据链字段(severity/confidence/verified/evidence/rationale)
    任意层级不出现(递归扫键);analysis 能消费(ScriptedLLM 跑 analysis 的首轮
    简报非空且含 recon v3 摘要关键词)。"""
    fails: list[str] = []
    TOOL = ('Thought: 先看工件\nAction: read_file\nAction Input: '
            '{"path": "analysis/unitree/bin/idlc.imports.json", "limit": 10}')
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        process = target / "process"
        llm = ScriptedLLM([TOOL, RECON_FINAL_V3, TOOL, ANALYSIS_FINAL])
        orch = Orchestrator(process, llm)
        tool = DispatchAgentTool(ToolContext(process_dir=process), orch)
        tool.execute(agent="recon", task="广度侦察")
        tool.execute(agent="analysis", task="逐点取证")
        # findings 唯一来源 = analysis/verification:recon v3(含 v2 残留)不进聚合
        expect = {"main 经 system 执行拼接命令", "硬编码口令"}
        titles = {f.get("title") for f in orch.all_findings}
        if titles != expect:
            fails.append(f"_all_findings 应仅含 analysis 条目 {sorted(expect)}, got {sorted(titles)}")
        for f in orch.all_findings:
            if f.get("source_agent") != "analysis" or f.get("instance_seq") != 1:
                fails.append(f"聚合条目应溯源 analysis/实例1: {f.get('title')}")
                break
        # 磁盘 survey.json:v3 无 findings 键(即便 orchestrator 跑过回填逻辑)
        surf_file = process / "agent" / "0_recon" / "survey.json"
        if not surf_file.is_file():
            fails.append("recon v3 应产出 0_recon/survey.json")
        else:
            surf = json.loads(surf_file.read_text(encoding="utf-8"))
            if "findings" in surf:
                fails.append(f"survey.json 磁盘工件不得被塞入 findings 键: {sorted(surf)}")
            if surf.get("schema_version") != 3:
                fails.append(f"survey 应为 schema_version=3: {surf.get('schema_version')}")
            for k in ("entry_points", "high_risk_areas", "recommended_actions", "components"):
                if not surf.get(k):
                    fails.append(f"survey 工件缺 v3 结构键内容 {k}")

            # Task8.1:判级/证据链字段任意层级不出现(递归扫全部键;role_evidence
            # 是 v3 合法键,不在禁止集——按精确键名比对,不做子串匹配)
            def _walk_keys(node):
                if isinstance(node, dict):
                    for k, v in node.items():
                        yield k
                        yield from _walk_keys(v)
                elif isinstance(node, list):
                    for item in node:
                        yield from _walk_keys(item)

            banned = ({"findings", "severity", "confidence", "verified",
                       "evidence", "rationale"} & set(_walk_keys(surf)))
            if banned:
                fails.append(f"survey 工件任意层级不得出现判级/证据链键: {sorted(banned)}")
        # Task8.1:analysis 能消费——首轮简报非空且含 recon v3 摘要关键词
        # (调用序:0/1=recon 工具+终;2=analysis 首轮,init = calls[2][1])
        a1_brief = llm.calls[2][1]["content"]
        if not a1_brief.strip():
            fails.append("analysis 首轮简报不应为空(recon v3 工件可被消费)")
        for needle in ("entry_points", "high_risk_areas", "recommended_actions",
                       "etc/init.d/lighttpd"):
            if needle not in a1_brief:
                fails.append(f"analysis 简报应含 recon v3 摘要关键词 '{needle}': {a1_brief[:160]}")
                break
    return fails


def test_redispatch_analysis_brief_carries_recon_summary() -> list[str]:
    """Task4 上下文流转契约:补跑 analysis(第 2 次调度,上游为前次 findings.json)的
    init 简报仍携带同一份 recon 摘要(entry_points/high_risk_areas/recommended_actions/
    components),不依赖首个实例的私有上下文;首次简报与补跑简报同源。"""
    fails: list[str] = []
    TOOL = ('Thought: 先看工件\nAction: read_file\nAction Input: '
            '{"path": "analysis/unitree/bin/idlc.imports.json", "limit": 10}')
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        process = target / "process"
        llm = ScriptedLLM([TOOL, RECON_FINAL_V3, TOOL, ANALYSIS_FINAL,
                           TOOL, ANALYSIS_EXTRA_FINAL])
        orch = Orchestrator(process, llm)
        tool = DispatchAgentTool(ToolContext(process_dir=process), orch)
        tool.execute(agent="recon", task="t0")
        tool.execute(agent="analysis", task="t1")
        tool.execute(agent="analysis", task="t2-补跑")   # 不同任务 → 允许第 2 次调度
        # 调用序:0/1=recon,2/3=analysis#1,4/5=analysis#2(补跑);init = calls[N][1]
        a1_init = llm.calls[2][1]["content"]
        a2_init = llm.calls[4][1]["content"]
        for needle in ("entry_points", "etc/init.d/lighttpd", "high_risk_areas",
                       "unitree/bin/idlc", "recommended_actions", "busybox v1.34"):
            if needle not in a2_init:
                fails.append(f"补跑 analysis 简报应含 recon 摘要 '{needle}': {a2_init[:200]}")
                break
        # 首次简报同样携带 v3 结构摘要(同一来源)
        for needle in ("etc/init.d/lighttpd", "high_risk_areas", "recommended_actions"):
            if needle not in a1_init:
                fails.append(f"首次 analysis 简报应含 v3 recon 摘要 '{needle}': {a1_init[:200]}")
                break
        # 补跑简报两类信息并存:前次 findings 摘要(上游)+ recon 摘要(附加)
        if "取证完成" not in a2_init:
            fails.append(f"补跑简报应含前次 analysis findings 摘要: {a2_init[:200]}")
        # 同源:两实例携带的 recon 摘要特征行一致(同一份,而非各自拼凑)
        for line in ("etc/init.d/lighttpd(web/cgi 入口)",
                     "unitree/bin/idlc — 注入模式命中"):
            if line not in a1_init or line not in a2_init:
                fails.append(f"两实例简报应含同一条 recon 摘要行 '{line}'")
    return fails


def test_fresh_run_with_tool_call() -> list[str]:
    """recon 先调一次 read_file(真实工具)再收尾,验证工具分发在 orchestrator 编排下也通。"""
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.functions.json", "limit": 10}'
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        # ADR-0003:verification 每疑点一实例——2 条 findings → 2 个实例各 1 次 read_file
        llm = ScriptedLLM([
            D % "recon",        # 0
            'Thought: 先看工件\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.strings.json", "limit": 10}',
            RECON_FINAL,        # 2
            D % "analysis",     # 3
            'Thought: 取证\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.imports.json", "limit": 10}',
            ANALYSIS_FINAL,     # 5
            D % "verification",  # 6
            VTOOL, VERIFY_FINAL_F1,   # 7/8  复核实例 1
            VTOOL, VERIFY_FINAL_F2,   # 9/10 复核实例 2
            'Final Answer: {"summary": "完成", "conclusion": ""}',  # 11
        ])
        summary = step5_run(target, llm=llm)
        # recon 末轮 chat 的最后一条消息 = read_file 的 Observation
        obs = llm.calls[2][-1]["content"]
        if "password=unitree2018" not in obs:
            fails.append(f"read_file Observation 应含字符串值: {obs[:120]}")
        surf = load_artifact(target / "process" / "agent" / "0_recon" / "survey.json")
        if surf is None:
            fails.append("带工具调用的 recon 未产出工件")
        recon_stats = summary["stages"]["recon"]["tool_calls"]
        if recon_stats.get("read_file") != 1:
            fails.append(f"recon tool_calls 应为 {{read_file: 1}}, got: {recon_stats}")
        # 全局 read_file = recon 1 + analysis 1 + verification 2 实例各 1 = 4
        if summary["tool_calls"].get("read_file") != 4:
            fails.append(f"全局 tool_calls 合计错误(应 recon1+analysis1+verify2): "
                         f"{summary['tool_calls']}")
        if summary["stages"]["recon"]["steps"] < 1:
            fails.append(f"recon steps 应 ≥1, got: {summary['stages']['recon']['steps']}")
    return fails


def test_no_key_error_locates_env_file() -> list[str]:
    """无 key 报错(2026-08-19):.env 规范位置在 firmware_audit/ 下并自动加载;
    报错需写清找到的文件与缺 key 诊断,或给出创建模板。"""
    fails: list[str] = []
    import os
    from firmware_audit.step5_agent.providers import llm_client
    from firmware_audit.step5_agent.providers.llm_client import LLMClient, LLMError
    from firmware_audit.step5_agent.run_step5 import _no_key_error

    keys = ("FIRMWARE_AUDIT_LLM_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY",
            "FIRMWARE_AUDIT_LLM_BASE_URL", "FIRMWARE_AUDIT_LLM_MODEL",
            "LLM_BASE_URL", "LLM_MODEL")
    saved = {k: os.environ.pop(k, None) for k in keys}
    old_anchors = llm_client._ENV_ANCHORS
    try:
        # 正向:.env 自动加载生效(有 key 行 → LLMClient 可用,且环境变量优先不覆盖)
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".env").write_text(
                "# 注释行\nFIRMWARE_AUDIT_LLM_API_KEY=sk-from-file\n"
                "FIRMWARE_AUDIT_LLM_MODEL=model-from-file\n", encoding="utf-8")
            llm_client._ENV_ANCHORS = [Path(td)]
            c = LLMClient()
            if not c.available or c.api_key != "sk-from-file":
                fails.append(f".env 自动加载失败: {c.api_key[:8] if c.api_key else '空'}")
            os.environ["FIRMWARE_AUDIT_LLM_API_KEY"] = "sk-from-env"
            c2 = LLMClient()
            if c2.api_key != "sk-from-env":
                fails.append("已设环境变量应优先于 .env,不被覆盖")

        # 分支一:.env 存在但无有效 key 行 → 报错指出该文件缺 key
        for k in keys:  # 清掉正向分支注入的残留,保证"仍无 key"前置成立
            os.environ.pop(k, None)
        with tempfile.TemporaryDirectory() as td:
            envf = Path(td) / ".env"
            envf.write_text("# 只有注释,没有 key\n", encoding="utf-8")
            llm_client._ENV_ANCHORS = [Path(td)]
            (Path(td) / "extracted").mkdir()  # 过 step5_run 的解包启动门(ADR-0011)
            try:
                step5_run(Path(td))
                fails.append("无 key 时应抛 LLMError")
            except LLMError as e:
                msg = str(e)
                if str(envf) not in msg:
                    fails.append(f"报错应含 .env 绝对路径: {msg[:120]}")
                if "API key" not in msg:
                    fails.append("报错应诊断缺 key 行")

        # 分支二:.env 完全不存在 → 给出 firmware_audit/ 下的创建模板
        with tempfile.TemporaryDirectory() as td:
            llm_client._ENV_ANCHORS = [Path(td)]  # 空目录,锚点重定向后不搜默认链
            err = str(_no_key_error())
            if "未找到 .env" not in err or "创建 .env" not in err:
                fails.append(f"未找到分支应给创建建议: {err[:150]}")
            if "FIRMWARE_AUDIT_LLM_API_KEY=sk-" not in err:
                fails.append("创建模板应含 key 行示例")
    finally:
        llm_client._ENV_ANCHORS = old_anchors
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
    return fails


def test_tool_permissions_and_threshold() -> list[str]:
    """权限矩阵与压缩阈值守护:CFG 工具 ⊆ 注册表;新增授权到位;阈值=600k。

    v3(2026-08-28)权限收敛:recon 移除 strings_query/imports_query/checksec
    (深挖归 analysis/verification),list_files 三 Agent 全授权。
    """
    fails: list[str] = []
    from firmware_audit.step5_agent.runner import ALL_CONFIGS
    from firmware_audit.step5_agent.providers.tools import make_tools
    from firmware_audit.step5_agent.providers.tools.base import ToolContext

    registry = set(make_tools(ToolContext(process_dir=Path("."))))
    perms = {cfg.name: set(cfg.tool_names) for cfg in ALL_CONFIGS}
    for name, tools in perms.items():
        unregistered = tools - registry
        if unregistered:
            fails.append(f"{name} 引用未注册工具: {sorted(unregistered)}")
    # recon 收敛:三个深挖工具不得在 recon 手里
    for t in ("strings_query", "imports_query", "checksec"):
        if t in perms.get("recon", set()):
            fails.append(f"recon 不应再持有 {t}(v3 收敛,深挖归 analysis/verification)")
    # list_files: 三 Agent 全授权
    for name in ("recon", "analysis", "verification"):
        if "list_files" not in perms.get(name, set()):
            fails.append(f"{name} 应授权 list_files(全 Agent 开放)")
    if "checksec" not in perms.get("analysis", set()):
        fails.append("analysis 应授权 checksec")
    if not {"strings_query", "imports_query"} <= perms.get("verification", set()):
        fails.append("verification 应授权 strings_query/imports_query")

    # recon 工具集精确匹配(spec v3)
    if perms.get("recon") != {"list_files", "read_file", "cve_bin_tool_scan",
                              "semgrep_scan", "gitleaks_scan", "binwalk_rescan"}:
        fails.append(f"recon 工具集应为 6 件套: {sorted(perms.get('recon', set()))}")

    # search_code:analysis/verification 授权,recon 不授权(铺面不正文检索)
    if "search_code" not in perms.get("analysis", set()):
        fails.append("analysis 应授权 search_code")
    if "search_code" not in perms.get("verification", set()):
        fails.append("verification 应授权 search_code")
    if "search_code" in perms.get("recon", set()):
        fails.append("recon 不应授权 search_code(铺面枚举阶段不做正文检索)")

    # r2 族 + ghidra_decompile(ADR-0010):仅授 analysis/verification,
    # recon 保持广度角色不授(深挖/分钟级升级调用不进铺面阶段)
    r2_family = {"r2_list_functions", "r2_disassemble_function", "r2_xref_query",
                 "ghidra_decompile"}
    for name in ("analysis", "verification"):
        missing = r2_family - perms.get(name, set())
        if missing:
            fails.append(f"{name} 应授权 r2 工具族: {sorted(missing)}")
    leak = r2_family & perms.get("recon", set())
    if leak:
        fails.append(f"recon 不应授权 r2 工具族(广度角色不深挖): {sorted(leak)}")

    # v3 守护:recon max_iters 保持 20(spec 明确不变)
    from firmware_audit.step5_agent.runner import RECON_CFG
    if RECON_CFG.max_iters != 20:
        fails.append(f"RECON_CFG.max_iters 应保持 20, got {RECON_CFG.max_iters}")

    cm = ContextManager("s", "i")
    threshold = int(cm.max_est_tokens * cm.trigger_ratio)
    if threshold != 600_000:
        fails.append(f"压缩阈值应为 600k, got {threshold}"
                     f"(window={cm.max_est_tokens}, ratio={cm.trigger_ratio})")
    return fails


def test_recon_system_prompt_needles() -> list[str]:
    """v3 recon 提示词重构守护:首动 list_files/防幻觉红线/components 规则齐备。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.data.prompts import RECON_SYSTEM
    for needle in ("list_files", "枚举", "防幻觉红线", "禁止猜测", "cve_bin_tool_scan",
                   "components", "禁止凭记忆补 CVE"):
        if needle not in RECON_SYSTEM:
            fails.append(f"RECON_SYSTEM 应含 '{needle}'")
    # 深挖工具不得再出现在 recon 提示词的流程指引里(已移出工具集)
    for banned_tool_call in ("imports_query 查", "strings_query 按", "checksec 看"):
        if banned_tool_call in RECON_SYSTEM:
            fails.append(f"RECON_SYSTEM 不应再指引 '{banned_tool_call}'(v3 收敛)")
    return fails


def test_analysis_verify_prompt_examples() -> list[str]:
    """✅/❌ 正误对照 + Harness 模板守护(2026-08-28 学 deepaudit)。

    - 两 Agent 均含正误对照(❌ 形态:Markdown 加粗/角括号/散文开场/自写 Observation)
    - VERIFY 含 Fuzzing Harness 模板(mock 危险函数+多 payload+判定读输出)
    """
    fails: list[str] = []
    from firmware_audit.step5_agent.data.prompts import ANALYSIS_SYSTEM, VERIFY_SYSTEM
    for name, prompt in (("ANALYSIS_SYSTEM", ANALYSIS_SYSTEM),
                         ("VERIFY_SYSTEM", VERIFY_SYSTEM)):
        if "✅ 正确" not in prompt or "❌ 错误" not in prompt:
            fails.append(f"{name} 应含正误对照示例(✅/❌)")
        # ❌ 反例必须列出这三类协议漂移形态
        if "Markdown 加粗" not in prompt:
            fails.append(f"{name} ❌ 应列出 Markdown 加粗形态")
        if "XML 角括号" not in prompt and "<Thought>" not in prompt:
            fails.append(f"{name} ❌ 应列出 XML 角括号形态")
        if "散文" not in prompt:
            fails.append(f"{name} ❌ 应列出计划散文开头形态")
    # VERIFY 专属:Harness 模板 + Final Answer 正误
    for needle in ("Fuzzing Harness 模板", "sandbox_verify", "subprocess.run",
                   "[VULN]", "[DETECTED]", "; id", "$(id)",
                   "✅ 正确 Final Answer", "围栏"):
        if needle not in VERIFY_SYSTEM:
            fails.append(f"VERIFY_SYSTEM 应含 '{needle}'")
    # analysis 的 ❌ 应含自写 Observation 形态(2026-08-20 实测坑)
    if "自写/预写 Observation" not in ANALYSIS_SYSTEM:
        fails.append("ANALYSIS_SYSTEM ❌ 应列出自写 Observation 形态")
    return fails


def test_v1_artifact_compat_read() -> list[str]:
    """v1 工件(无 source_agent/instance_seq)兼容读:补默认值,消费方无感。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "old.json"
        # v1 形态:schema 1,finding 无溯源字段
        p.write_text(json.dumps({
            "schema": 1, "agent": "recon", "summary": "旧工件",
            "findings": [{"title": "老发现", "severity": "high"}],
        }), encoding="utf-8")
        obj = load_artifact(p)
        if obj is None:
            fails.append("v1 工件应可读")
        else:
            f0 = obj["findings"][0]
            if f0.get("source_agent") != "recon":
                fails.append(f"v1 兼容读应补 source_agent=工件 agent: {f0.get('source_agent')}")
            if "instance_seq" not in f0:
                fails.append("v1 兼容读应补 instance_seq 键(None)")
    return fails


def test_compact_at_600k_threshold() -> list[str]:
    """600k 阈值规模化稳定性:~700k est tokens 上下文触发压缩,边界对齐/构建正常。"""
    fails: list[str] = []
    llm = ScriptedLLM(["600k 摘要:已确认事实/已排除项/未决问题/证据指针", "备用"])
    cm = ContextManager("SYS", "INIT")  # 默认 1M 窗口 × 0.6 = 600k 阈值
    # 350 轮 × (assistant+user),每条 ~2000 字符 → est ≈ 700k > 600k
    for i in range(350):
        cm.append("assistant", f"a{i} " + "x" * 2000)
        cm.append("user", f"o{i} " + "y" * 2000)
    if not cm.needs_compaction():
        fails.append(f"~700k est tokens 应超过 600k 阈值, est={est_tokens(cm.build_messages())}")
    before = len(cm.recent)
    if not cm.maybe_compact(llm):
        fails.append("超阈值时 maybe_compact 应执行压缩")
    if cm.compactions != 1 or not cm.summaries:
        fails.append("压缩产物应写入概括区")
    if not (0 < len(cm.recent) < before):
        fails.append(f"压缩后保留区应收缩: {before} → {len(cm.recent)}")
    if cm.recent and cm.recent[0]["role"] != "assistant":
        fails.append("压缩后保留区开头应对齐 assistant 边界")
    msgs = cm.build_messages()
    if len(msgs) != 3 + len(cm.recent):  # system+init+summary+recent
        fails.append(f"构建消息数不符: {len(msgs)}")
    return fails


def test_startup_gate_requires_extracted() -> list[str]:
    """启动门新语义(ADR-0011):仅 extracted/ 的工作区放行;无解包产物拒绝
    且文案指向 Step1;老工作区(analysis/ 边车当缓存)照样放行。"""
    from firmware_audit.step5_agent.providers.llm_client import LLMError
    from firmware_audit.step5_agent.run_step5 import step5_run

    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        # 仅 extracted/(无任何 analysis/ 工件)→ 过门,死在无 key(而非 FileNotFoundError)
        only_ext = root / "fresh"
        (only_ext / "extracted").mkdir(parents=True)
        class _NoKeyLLM:
            available = False
        try:
            step5_run(only_ext, llm=_NoKeyLLM())
            fails.append("无 key 应抛 LLMError(启动门已过)")
        except LLMError:
            pass
        except FileNotFoundError as e:
            fails.append(f"仅 extracted/ 的工作区应过启动门: {e}")

        # 无 extracted/ → 拒绝,文案指向 Step1
        empty = root / "bare"
        empty.mkdir()
        try:
            step5_run(empty, llm=_NoKeyLLM())
            fails.append("无 extracted/ 应被启动门拒绝")
        except LLMError:
            fails.append("无 extracted/ 应在无 key 检查之前被门拒绝")
        except FileNotFoundError as e:
            if "extracted/" not in str(e) or "Step1" not in str(e):
                fails.append(f"拒绝文案应指向 extracted/ 与 Step1: {e}")
    return fails


def test_resolve_workspace_absolute() -> list[str]:
    """resolve_workspace 必须返回绝对路径(2026-08-19 checksec/xref 实发 bug)。

    CLI 常以相对路径调用(python -m ...run_step5 target/1),若原样透传,
    docker -v 收到相对宿主路径 → Docker 当命名卷(卷名禁含 "/")→
    daemon 报 create <path>: invalid characters → exit 125。"""
    import os
    import tempfile
    from firmware_audit.step5_agent.run_step5 import resolve_workspace

    fails: list[str] = []
    old_cwd = os.getcwd()
    try:
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            (Path(td) / "t1" / "process").mkdir(parents=True)
            # 分支一:入参含 process/ 子目录(普通 target 形态)
            ws = resolve_workspace(Path("t1"))
            if not ws.is_absolute():
                fails.append(f"target 分支应返回绝对路径: {ws}")
            elif ws != (Path(td) / "t1" / "process").resolve():
                fails.append(f"应定位到 t1/process: {ws}")
            # 分支二:入参本身即工作区(分区子工作区/直传 process 形态)
            ws2 = resolve_workspace(Path("t1") / "process")
            if not ws2.is_absolute():
                fails.append(f"工作区直传分支也应绝对: {ws2}")
            os.chdir(old_cwd)  # Windows:先离开 td,TemporaryDirectory 才能清理
    finally:
        os.chdir(old_cwd)
    return fails


def _verify_single_final(title: str, verified: bool) -> str:
    """ADR-0003 单实例复核 Final:一条 finding,verified/rationale 必填。"""
    return ('Final Answer: {"summary": "复核%s", "findings": [{"title": "%s", '
            '"file": "unitree/bin/idlc", "verified": %s, "rationale": "r-%s"}]}'
            % (title, title, "true" if verified else "false", title))


def test_verification_per_finding_flow() -> list[str]:
    """ADR-0003 流程级验收(Seam 1):喂含 N 条 findings 的 fixtures → 断言
    verified_findings.json 全量 N 条、已验证恰好 K 条(其余 verified=None +
    confidence 保留 analysis 初值)、每实例 max_iters=8、补跑逻辑取消
    (verification 只调度一次,不适用同类型 3 次上限)。"""
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
    # 4 条 findings:两条同 severity=high(confidence 不同)验证 confidence 次排序,
    # 再加 medium/low → K=3 应复核 high+high(confidence 高的先)+medium,low 未复核
    ANALYSIS3 = ('Final Answer: {"summary": "取证3", "findings": ['
                 '{"title": "f1", "severity": "high", "file": "unitree/bin/idlc", "confidence": "low"},'
                 '{"title": "f2", "severity": "high", "file": "unitree/bin/idlc", "confidence": "high"},'
                 '{"title": "f3", "severity": "medium", "file": "unitree/bin/idlc", "confidence": "high"},'
                 '{"title": "f4", "severity": "low", "file": "unitree/bin/idlc", "confidence": "high"}]}')
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        # K=3:复核 f1/f2(两条 high,f2 confidence=high 应先)+f3(medium);f4 未复核
        os.environ["STEP5_VERIFY_K"] = "3"
        try:
            llm = ScriptedLLM([
                D % "recon",
                'Thought: 先看工件\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.imports.json", "limit": 5}',
                RECON_FINAL,
                D % "analysis",
                'Thought: 取证\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.strings.json", "limit": 5}',
                ANALYSIS3,
                D % "verification",
                VTOOL, _verify_single_final("f2", True),   # high+confidence=high 排最前
                VTOOL, _verify_single_final("f1", True),   # high+confidence=low
                VTOOL, _verify_single_final("f3", True),   # medium
                'Final Answer: {"summary": "完成", "conclusion": ""}',
            ])
            summary = step5_run(target, llm=llm)
        finally:
            del os.environ["STEP5_VERIFY_K"]

        agent = target / "process" / "agent"
        vf = load_artifact(agent / "verified_findings.json")
        if vf is None:
            fails.append("verified_findings.json 缺失(verification 每疑点一实例聚合)")
        else:
            findings = vf["findings"]
            if len(findings) != 4:
                fails.append(f"verified_findings.json 应全量 N=4 条(未复核也保留), got {len(findings)}")
            by_title = {f.get("title"): f for f in findings}
            # K=3 复核:f1/f2/f3 有 verified;f4 未复核 verified=None
            if by_title["f1"].get("verified") is not True:
                fails.append(f"f1(high)应复核 verified=True: {by_title['f1']}")
            if by_title["f2"].get("verified") is not True:
                fails.append(f"f2(high,confidence=high)应复核 verified=True: {by_title['f2']}")
            if by_title["f3"].get("verified") is not True:
                fails.append(f"f3(medium)应复核 verified=True: {by_title['f3']}")
            f4 = by_title.get("f4")
            if f4 is None:
                fails.append("f4(low)不应被丢弃(未复核也要保留在 verified_findings)")
            elif f4.get("verified") is not None:
                fails.append(f"f4(未进入前 K)应 verified=None: {f4}")
            elif f4.get("confidence") != "high":
                fails.append(f"未复核 f4 的 confidence 应保留 analysis 初值 high: {f4}")
            if f4 is not None and f4.get("rationale", "") != "":
                fails.append(f"未复核 f4 的 rationale 应为空: {f4.get('rationale')}")
            # 复核的 3 条有 rationale
            if not all(by_title[t].get("rationale") for t in ("f1", "f2", "f3")):
                fails.append("已复核 finding 应带 rationale")
            # confidence 次排序验证:同 severity=high 时 confidence=high 的 f2 先复核
            # 每实例两轮 LLM 调用(工具+Final),init 重复出现两次——按序去重取首个
            brief_titles = []
            for i in range(len(llm.calls)):
                content = llm.calls[i][1]["content"]
                if "待复核 finding" not in content:
                    continue
                t = json.loads(content[content.find("{"):content.rfind("}") + 1]).get("title")
                if t and (not brief_titles or brief_titles[-1] != t):
                    brief_titles.append(t)
            f2_before_f1 = (brief_titles[:2] == ["f2", "f1"])
            if not f2_before_f1:
                fails.append(f"confidence 次排序:high+conf=high 的 f2 应先于 high+conf=low 的 f1"
                             f"复核(实例简报序): {brief_titles}")

        # 每实例 max_iters=8(ADR-0003):从实例落盘 system_prompt 校验
        sp = agent / "4_verification" / "system_prompt.txt"
        if sp.is_file() and "最多 8 轮" not in sp.read_text(encoding="utf-8"):
            fails.append(f"verification 实例 system_prompt 应 max_iters=8: {sp}")
        # 补跑逻辑取消:verification 只调度一次(阶段 seq=2),实例目录恰好 K=3 个
        dispatch_log = json.loads((agent / "orchestrator" / "dispatch_log.json")
                                  .read_text(encoding="utf-8"))
        ver_logs = [r for r in dispatch_log if r.get("agent") == "verification"]
        if len(ver_logs) != 1:
            fails.append(f"verification 应只调度一次(补跑取消), got {len(ver_logs)}")
        vdirs = sorted(p.name for p in agent.glob("*_verification")
                       if p.is_dir())
        if len(vdirs) != 3:
            fails.append(f"应恰好 K=3 个独立复核实例目录, got {vdirs}")
        # 阶段 steps = 各实例轮次累加(每实例 2 轮:工具 + Final → 共 4)
        if summary["stages"]["verification"]["steps"] < 1:
            fails.append("verification 阶段 steps 应 >0")
    return fails


def test_verification_k_cap() -> list[str]:
    """K 上限语义:analysis findings 超过 K 时只复核前 K 条,其余 verified=None;
    K 可配置(STEP5_VERIFY_K),默认 10。"""
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        # 4 条 findings,默认 K=10 → 全复核;无未复核条目
        ANALYSIS4 = ('Final Answer: {"summary": "取证4", "findings": ['
                     '{"title": "a", "severity": "critical", "file": "unitree/bin/idlc"},'
                     '{"title": "b", "severity": "high", "file": "unitree/bin/idlc"},'
                     '{"title": "c", "severity": "medium", "file": "unitree/bin/idlc"},'
                     '{"title": "d", "severity": "low", "file": "unitree/bin/idlc"}]}')
        llm = ScriptedLLM([
            D % "recon", 'Thought: 先看工件\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.imports.json", "limit": 5}', RECON_FINAL,
            D % "analysis", 'Thought: 取证\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.strings.json", "limit": 5}', ANALYSIS4,
            D % "verification",
            VTOOL, _verify_single_final("a", True),
            VTOOL, _verify_single_final("b", True),
            VTOOL, _verify_single_final("c", True),
            VTOOL, _verify_single_final("d", True),
            'Final Answer: {"summary": "完成", "conclusion": ""}',
        ])
        step5_run(target, llm=llm)
        agent = target / "process" / "agent"
        vf = load_artifact(agent / "verified_findings.json")
        if vf is None or len(vf["findings"]) != 4:
            fails.append(f"N=4 条应全量保留: {vf and len(vf['findings'])}")
        elif not all(f.get("verified") is not None for f in vf["findings"]):
            fails.append("默认 K=10 ≥ N → 全部应复核")
        if len(list(agent.glob("*_verification"))) != 4:
            fails.append(f"默认 K=10 时 4 条应 4 个实例")
    return fails


def test_unreviewed_section_through_step5_run() -> list[str]:
    """ADR-0003/ticket 04 流程级验收(Seam 1):走公开 step5_run() 全流程,
    断言最终产出报告含独立未复核区段(⚠ 未经复核、confidence 保留 analysis 初值),
    未复核疑点不混入已验证区;verified_findings.json 全量 N 条、已验证恰好 K 条、
    未复核 verified=None。

    与 test_orchestrator.test_report_unreviewed_section(Orchestrator seam)互补:
    本用例从 step5_run 入口驱动,覆盖"所有 Step5 运行都产出报告"的公开契约。"""
    fails: list[str] = []
    D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
    TOOL = ('Thought: 先看工件\nAction: read_file\nAction Input: '
            '{"path": "analysis/unitree/bin/idlc.imports.json", "limit": 10}')
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
    S = 'Thought: 收尾\nAction: summarize\nAction Input: {"conclusion": "全链路完成"}'
    REPORT_MD = ('Final Answer: # 固件安全审计报告\n## 发现清单\n'
                 '- [high] ✓ f1\n- [medium] ✗ f2(误报)\n'
                 '## 未复核疑点\n- [low] ⚠ f3 未经复核,confidence 为 analysis 初值\n'
                 '## 误报剔除\n- f2(实为默认文档示例)')
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        os.environ["STEP5_VERIFY_K"] = "2"
        try:
            llm = ScriptedLLM([
                D % "recon", TOOL, RECON_FINAL,
                D % "analysis", TOOL, ANALYSIS3,
                D % "verification",
                VTOOL, VF1,
                VTOOL, VF2,
                S,
                REPORT_MD,
            ])
            summary = step5_run(target, llm=llm)
        finally:
            del os.environ["STEP5_VERIFY_K"]

        # planner 参数移除的行为断言由 test_orchestrator.test_planner_removed 负责
        # (传 planner="pipeline" 应抛 TypeError);本用例从 step5_run 入口驱动,
        # 专注"所有 Step5 运行都产出报告"的未复核区段验收(ADR-0003/ticket 04)。
        agent = target / "process" / "agent"

        # 数据层:verified_findings.json 全量 N=3,已验证 K=2,未复核 verified=None
        vf = load_artifact(agent / "verified_findings.json")
        if vf is None:
            fails.append("verified_findings.json 缺失(verification 每疑点一实例聚合)")
        else:
            findings = vf["findings"]
            if len(findings) != 3:
                fails.append(f"verified_findings.json 应全量 N=3 条, got {len(findings)}")
            by_title = {f.get("title"): f for f in findings}
            if by_title["f1"].get("verified") is not True or by_title["f2"].get("verified") is not False:
                fails.append("f1/f2 应复核(verified True/False)")
            f3 = by_title.get("f3")
            if f3 is None or f3.get("verified") is not None:
                fails.append(f"f3 应 verified=None 保留: {f3}")
            elif f3.get("confidence") != "high":
                fails.append(f"未复核 f3 的 confidence 应保留 analysis 初值: {f3}")

        # 报告:step5_run 全流程产出报告(不再有"不产报告"快速模式),report.md 落盘
        if not summary.get("report"):
            fails.append("所有 Step5 运行都应产出报告(planner 快速模式已删)")
        else:
            md = Path(summary["report"])
            if not md.is_file():
                fails.append(f"报告文件不存在: {md}")
            else:
                text = md.read_text(encoding="utf-8")
                # 独立未复核区段:⚠ + 未经复核标注 + 未复核 f3 在区内
                if "## 未复核疑点" not in text:
                    fails.append("报告应含独立未复核区段(## 未复核疑点)")
                else:
                    unrev = text[text.find("## 未复核疑点"):]
                    for needle in ("⚠", "f3", "未经复核"):
                        if needle not in unrev:
                            fails.append(f"未复核区应含 '{needle}': {unrev[:200]}")
                    for banned in ("✓ f1", "✗ f2", "r1", "r2"):
                        if banned in unrev:
                            fails.append(f"未复核区不得混入已验证条目/结论 '{banned}'")
                if "## 发现清单" not in text or "✓ f1" not in text:
                    fails.append("报告应含已复核发现清单")

        # 素材层:summarize 注入的写作素材把已复核/未复核拆独立区段(报告据此画区段)
        material = llm.calls[-1][-1]["content"]
        if "#### 已复核 findings" not in material or "#### 未复核疑点" not in material:
            fails.append("素材应拆已复核/未复核独立区段")
        unrev_mat = material[material.find("#### 未复核疑点"):] if "#### 未复核疑点" in material else ""
        for needle in ("f3", "⚠", "confidence 保留 analysis 初值", "rationale 为空"):
            if needle not in unrev_mat:
                fails.append(f"未复核素材应含 '{needle}': {unrev_mat[:200]}")
        for banned in ("f1", "f2", "r1", "r2"):
            if banned in unrev_mat:
                fails.append(f"未复核素材不得混入已验证条目 '{banned}'")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("finding_from_dict", test_finding_from_dict),
        ("parse_artifact", test_parse_artifact),
        ("save_load_summary", test_save_load_summary),
        ("build_messages_partitions", test_build_messages_partitions),
        ("compaction_boundary_and_failure", test_compaction_boundary_and_failure),
        ("full_chain_and_resume", test_full_chain_and_resume),
        ("verification_per_finding_flow", test_verification_per_finding_flow),
        ("verification_k_cap", test_verification_k_cap),
        ("unreviewed_section_through_step5_run", test_unreviewed_section_through_step5_run),
        ("recon_v3_orchestration_boundary", test_recon_v3_orchestration_boundary),
        ("redispatch_analysis_brief_carries_recon_summary", test_redispatch_analysis_brief_carries_recon_summary),
        ("fresh_run_with_tool_call", test_fresh_run_with_tool_call),
        ("no_key_error_locates_env_file", test_no_key_error_locates_env_file),
        ("tool_permissions_and_threshold", test_tool_permissions_and_threshold),
        ("recon_system_prompt_needles", test_recon_system_prompt_needles),
        ("analysis_verify_prompt_examples", test_analysis_verify_prompt_examples),
        ("v1_artifact_compat_read", test_v1_artifact_compat_read),
        ("compact_at_600k_threshold", test_compact_at_600k_threshold),
        ("resolve_workspace_absolute", test_resolve_workspace_absolute),
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

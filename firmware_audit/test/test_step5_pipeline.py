"""Step5 工件/上下文/流水线单测(ScriptedLLM,零 API 零 Docker)。

覆盖 2026-08-17 新增三层:
  artifacts  Finding 宽容解析 / parse_artifact 各降级路径 / 存取回读 / 摘要
  context    四分区构建 / 阈值触发压缩(assistant 边界对齐) / 压缩失败还原
  pipeline   三 Agent 串行全链路 / 下游简报注入 / 断点续跑跳过 / 误报分节报告
"""
from __future__ import annotations

import json
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
from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.step5_agent.run_step5 import step5_run


# ---- fixtures ----

def _make_process(td: Path) -> Path:
    """伪造最小 Step4 工件:1 个二进制的三件套 sidecar。"""
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

ANALYSIS_FINAL = 'Final Answer: {"summary": "取证完成", "findings": [{"title": "main 经 system 执行拼接命令", "severity": "high", "file": "unitree/bin/idlc", "func": "main", "addr": "0010d000", "evidence": "decompile: system(cmd)", "confidence": "medium"}, {"title": "硬编码口令", "severity": "high", "file": "unitree/bin/idlc", "evidence": "password=unitree2018", "confidence": "low"}]}'

VERIFY_FINAL = 'Final Answer: {"summary": "复核完成", "findings": [{"title": "main 经 system 执行拼接命令", "severity": "high", "file": "unitree/bin/idlc", "func": "main", "verified": true, "rationale": "调用链确认", "confidence": "high"}, {"title": "硬编码口令", "severity": "high", "file": "unitree/bin/idlc", "verified": false, "rationale": "实为默认文档示例", "confidence": "low"}]}'


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
        if obj is None or obj.get("schema") != 1:
            fails.append(f"回读缺 schema: {obj and obj.get('schema')}")
        if obj["agent"] != "recon" or obj["summary"] != "摘要X":
            fails.append("agent/summary 回读不符")
        f0 = obj["findings"][0]
        if f0["title"] != "标题Y" or f0.get("extras") != {"zzz": 1}:
            fails.append(f"finding 回读不符: {f0}")
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
    if len(cm2.recent) != n_before or not cm2.summaries == []:
        fails.append("压缩失败必须还原保留区")
    return fails


# ---- pipeline 全链路 ----

def test_full_chain_and_resume() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        # 2026-08-18 工具先行守卫:零工具 Final 会被拒绝退回,故每 Agent 先调一次
        # read_file(真实工具)再收尾——脚本顺序 = recon工具,recon终,analysis工具,
        # analysis终,verify工具,verify终;chat 索引据此为 0/1,2/3,4/5。
        llm = ScriptedLLM([
            'Thought: 先看工件\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.imports.json", "limit": 10}',
            RECON_FINAL,
            'Thought: 取证\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.strings.json", "limit": 10}',
            ANALYSIS_FINAL,
            'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 10}',
            VERIFY_FINAL,
        ])
        summary = step5_run(target, llm=llm)
        if summary["mode"] != "llm":
            fails.append(f"应走 LLM 模式: {summary['mode']}")
        agent = target / "process" / "agent"

        surf = load_artifact(agent / "attack_surface.json")
        if surf is None or surf.get("components") != [{"name": "idlc", "version": "", "cve": [], "source": "strings"}]:
            fails.append(f"attack_surface 缺 components 或内容不符: {surf and surf.get('components')}")
        find = load_artifact(agent / "findings.json")
        if find is None or len(find["findings"]) != 2:
            fails.append(f"findings 应有 2 条: {find and len(find['findings'])}")
        ver = load_artifact(agent / "verified_findings.json")
        if ver is None:
            fails.append("verified_findings 缺失")
        else:
            v_counts = [f.get("verified") for f in ver["findings"]]
            if v_counts != [True, False]:
                fails.append(f"verified 标记应 1 真 1 假: {v_counts}")

        # 下游简报注入:analysis 首轮 init 应含上游摘要与工件名
        analysis_init = llm.calls[2][1]["content"]
        if "attack_surface.json" not in analysis_init or "攻击面" not in analysis_init:
            fails.append(f"analysis 简报应含上游摘要: {analysis_init[:100]}")
        verify_init = llm.calls[4][1]["content"]
        if "findings.json" not in verify_init or "取证完成" not in verify_init:
            fails.append("verification 简报应含 findings 摘要")

        # 每阶段各 1 次 read_file,全局合计 3(工具先行守卫的副作用验证)
        for stage in ("recon", "analysis", "verification"):
            st = summary["stages"][stage]["tool_calls"]
            if st.get("read_file") != 1:
                fails.append(f"{stage} 应各 1 次 read_file, got {st}")
        if summary["tool_calls"].get("read_file") != 3:
            fails.append(f"全局 read_file 合计应为 3, got {summary['tool_calls']}")

        # 三 Agent transcript 落盘
        for name in ("recon", "analysis", "verification"):
            tr = agent / name / "transcript.jsonl"
            if not tr.is_file():
                fails.append(f"{name} transcript 缺失")
                continue
            phases = [json.loads(l)["phase"] for l in tr.read_text(encoding="utf-8").splitlines()]
            if "assistant" not in phases:
                fails.append(f"{name} transcript 无 assistant 记录: {phases}")

        # 报告:成立节 + 误报分节
        report = (agent / "report.md").read_text(encoding="utf-8")
        if "✓" not in report or "main 经 system" not in report:
            fails.append("报告应含已证实发现(✓)")
        if "误报剔除" not in report or "实为默认文档示例" not in report:
            fails.append("报告应含误报分节与 rationale")
        if "复核完成" not in report:
            fails.append("报告概要应含 verification summary")

        # 断点续跑:三工件齐 → 全跳过,LLM 零调用
        llm2 = ScriptedLLM([])
        s2 = step5_run(target, llm=llm2)
        if llm2.calls:
            fails.append("工件齐备时续跑不应调 LLM")
        stages = s2.get("stages", {})
        if not stages or not all(v.get("ok") for v in stages.values()):
            fails.append(f"续跑各阶段应 ok: {stages}")
    return fails


def test_fresh_run_with_tool_call() -> list[str]:
    """recon 先调一次 read_file(真实工具)再收尾,验证工具分发在编排层也通。
    2026-08-18 工具先行守卫:三 Agent 均需先调工具再 Final,脚本同步升级。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        target = _make_process(Path(td))
        llm = ScriptedLLM([
            'Thought: 先看工件\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.strings.json", "limit": 10}',
            RECON_FINAL,
            'Thought: 取证\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.imports.json", "limit": 10}',
            ANALYSIS_FINAL,
            'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.functions.json", "limit": 10}',
            VERIFY_FINAL,
        ])
        summary = step5_run(target, llm=llm)
        obs = llm.calls[1][-1]["content"]
        if "password=unitree2018" not in obs:
            fails.append(f"read_file Observation 应含字符串值: {obs[:120]}")
        surf = load_artifact(target / "process" / "agent" / "attack_surface.json")
        if surf is None:
            fails.append("带工具调用的 recon 未产出工件")
        # summary 统计:recon 阶段应记 1 次 read_file,全局合计一致
        recon_stats = summary["stages"]["recon"]["tool_calls"]
        if recon_stats.get("read_file") != 1:
            fails.append(f"recon tool_calls 应为 {{read_file: 1}}, got: {recon_stats}")
        if summary["tool_calls"].get("read_file") != 3:
            fails.append(f"全局 tool_calls 合计错误(三 Agent 各 1 次 read_file): {summary['tool_calls']}")
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
            (Path(td) / "analysis").mkdir()  # 过 step5_run 的工件前置检查
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
    """权限矩阵与压缩阈值守护:CFG 工具 ⊆ 注册表;新增授权到位;阈值=600k。"""
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
    if "checksec" not in perms.get("analysis", set()):
        fails.append("analysis 应授权 checksec")
    if not {"strings_query", "imports_query"} <= perms.get("verification", set()):
        fails.append("verification 应授权 strings_query/imports_query")

    cm = ContextManager("s", "i")
    threshold = int(cm.max_est_tokens * cm.trigger_ratio)
    if threshold != 600_000:
        fails.append(f"压缩阈值应为 600k, got {threshold}"
                     f"(window={cm.max_est_tokens}, ratio={cm.trigger_ratio})")
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


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("finding_from_dict", test_finding_from_dict),
        ("parse_artifact", test_parse_artifact),
        ("save_load_summary", test_save_load_summary),
        ("build_messages_partitions", test_build_messages_partitions),
        ("compaction_boundary_and_failure", test_compaction_boundary_and_failure),
        ("full_chain_and_resume", test_full_chain_and_resume),
        ("fresh_run_with_tool_call", test_fresh_run_with_tool_call),
        ("no_key_error_locates_env_file", test_no_key_error_locates_env_file),
        ("tool_permissions_and_threshold", test_tool_permissions_and_threshold),
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

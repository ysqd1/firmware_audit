"""Step5 ReAct 循环单测(ScriptedLLM,不打真网)。

覆盖:正常工具循环 / 协议解析失败回喂恢复 / 连续失败终止 /
迭代上限强制收尾 / 未知工具错误 / parse_reply 与 parse_action_input 边界。
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.step5_agent.engine.react_loop import (
    parse_action_input,
    parse_reply,
    run_react_agent,
)
from firmware_audit.step5_agent.engine.transcript import reset_transcript
from firmware_audit.step5_agent.providers.tools.base import AgentTool, ToolContext, ToolResult


class EchoTool(AgentTool):
    name = "echo"
    description = "test"
    params_doc = ""

    def _run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, text=f"echo:{sorted(kw.items())}")


class FailTool(AgentTool):
    name = "boom"
    description = "test"
    params_doc = ""

    def _run(self, **kw) -> ToolResult:
        raise RuntimeError("工具内部炸了")


class BigTool(AgentTool):
    """返回 >16KB 文本,验证截断策略与全文落盘。"""

    name = "big"
    description = "test"
    params_doc = ""

    def _run(self, **kw) -> ToolResult:
        # 全长 17019 > 16000;MIDDLE_LOST 位于 ~12000(head 12000 与 tail 3200 之间的省略区)
        body = "HEAD" + "A" * 12000 + "MIDDLE_LOST" + "B" * 5000 + "TAIL"
        return ToolResult(ok=True, text=body)


class WideCapTool(AgentTool):
    """声明 64k 覆盖(summarize 同值):20000 字符应全量通过。"""

    name = "cap64k"
    description = "test"
    params_doc = ""
    max_text_chars = 64000

    def _run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, text="B" * 20000)


class NarrowCapTool(AgentTool):
    """声明小覆盖:按声明值截断。"""

    name = "captiny"
    description = "test"
    params_doc = ""
    max_text_chars = 100

    def _run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, text="C" * 500)


class FakeFS(AgentTool):
    """模拟固件目录结构的 list_files(测试用,不打真盘)。"""

    name = "list_files"
    description = "test"
    params_doc = ""

    def _run(self, **kw) -> ToolResult:
        table = {
            ".": "[. 列出 5 项(上限 50)]\nagent/\nanalysis/\nextracted/\nfileinfo.json",
            "extracted": "[extracted 列出 8 项(上限 50)]\nextracted/etc/\nextracted/unitree/",
            "extracted/unitree": "[extracted/unitree 列出 3 项(上限 50)]\nextracted/unitree/bin/",
            "extracted/unitree/module": "[extracted/unitree/module 列出 2 项(上限 50)]\nnet_switcher/",
        }
        return ToolResult(ok=True, text=table.get(kw.get("directory"), "[]"))


class ReasoningLLM(ScriptedLLM):
    """ScriptedLLM + 思考注入:content 是正文,思考随 usage.reasoning_content 返回。

    模拟 llm_client 拆分后的真实语义(2026-08-30),供循环级验证:
    思考草稿不参与解析、不进上下文,仅 transcript 留档。"""

    def __init__(self, replies: list[str], reasoning: str = ""):
        super().__init__(replies)
        self._reasoning = reasoning

    def chat(self, messages: list[dict], **kw) -> tuple[str, dict]:
        content, usage = super().chat(messages, **kw)
        if self._reasoning:
            usage = dict(usage)
            usage["reasoning_content"] = self._reasoning
        return content, usage


def _tools():
    ctx = ToolContext(process_dir=Path("."))
    return {"echo": EchoTool(ctx), "boom": FailTool(ctx)}


def test_parse_reply() -> list[str]:
    fails: list[str] = []
    cases = [
        ("Thought: 我要查\nAction: echo\nAction Input: {\"a\": 1}\n",
         ("action", "echo|{\"a\": 1}")),
        ("Final Answer: 没问题", ("final", "没问题")),
        # 模型自问自答:Action 后接 Observation,Input 应截断
        ("Action: echo\nAction Input: {\"a\": 1}\nObservation: fake\n",
         ("action", 'echo|{"a": 1}')),
        # 两者同现,取后者(Final 在后)
        ("Action: echo\nAction Input: {}\nFinal Answer: done",
         ("final", "done")),
        # 两者同现,Action 在后
        ("Final Answer: early\n然后改主意\nAction: echo\nAction Input: {}",
         ("action", "echo|{}")),
        ("我想想但没有输出任何块", ("fail", None)),
        # XML 角括号漂移(2026-08-20 verification 实发):<Action>x</Action> 应归一化
        ("<Thought>查</Thought>\n<Action>echo</Action>\n<Action Input>{\"a\": 1}</Action Input>",
         ("action", 'echo|{"a": 1}')),
        ("<Final Answer>{\"k\": 1}</Final Answer>", ("final", '{"k": 1}')),
        # 混合:角括号 Action + 文本 Final,取后者
        ("<Action>echo</Action>\n<Action Input>{}</Action Input>\nFinal Answer: done",
         ("final", "done")),
        # 无空格变体(2026-08-22 analysis step1 实发):<ActionInput> 须归一化
        ("<Thought>t</Thought>\n<Action>read_file</Action>\n<ActionInput>{\"path\": \"x\"}</ActionInput>",
         ("action", 'read_file|{"path": "x"}')),
        # 闭标签不配对(2026-08-22 analysis step4 实发):<Action Input>...</Action>
        ("<Action>read_file</Action>\n\n<Action Input>{\"path\": \"agent/a.json\"}</Action>",
         ("action", 'read_file|{"path": "agent/a.json"}')),
        # 大小写变体
        ("<action>echo</action>\n<action input>{\"n\": 1}</action input>",
         ("action", 'echo|{"n": 1}')),
        # B1(2026-08-29 实发):行首锚定——句内 "Final Answer:" 字样不匹配
        ("句中提到 Final Answer: 协议说明 不做\nFinal Answer: ok",
         ("final", "ok")),
        # B1:多个行首 Final Answer 块 → 取最后一个(模型收尾前自写草稿)
        ("Thought: 先写\nFinal Answer: {\"summary\": \"半成品\"}\n"
         "Final Answer: {\"summary\": \"成品\", \"findings\": []}",
         ("final", '{"summary": "成品", "findings": []}')),
        # B1 经典场景:超长报告散文里最终才出现 Final Answer(行首),前文垃圾不入 payload
        ("作为开头？让我尝试严格按照协议格式输出。\n"
         "Final Answer: # 报告\n## 正文\n- 发现1",
         ("final", "# 报告\n## 正文\n- 发现1")),
        # function-calling 串扰(2026-08-29 recon 实发 [03]):<tool_call> JSON 应还原为 action
        ("Now let me look at unitree/bin.\n<tool_call>\n"
         '{"name": "list_files", "arguments": {"directory": "extracted/unitree/bin", '
         '"recursive": false, "max_files": 50}}\n</tool_call>',
         ("action", 'list_files|{"directory": "extracted/unitree/bin", '
                    '"recursive": false, "max_files": 50}')),
        # 同一形态,多个 tool_call → 只取第一个(单轮单动作纪律由后续轮次纠正)
        ("<tool_call>{\"name\": \"list_files\", \"arguments\": {\"directory\": \".\"}}</tool_call>\n"
         "<tool_call>{\"name\": \"read_file\", \"arguments\": {\"path\": \"x\"}}</tool_call>",
         ("action", 'list_files|{"directory": "."}')),
        # arguments 为字符串形态
        ("<tool_call>{\"name\": \"echo\", \"arguments\": \"hi\"}</tool_call>",
         ("action", "echo|hi")),
        # arguments 缺失 → 空参数,仍还原为 action
        ("<tool_call>{\"name\": \"finish\"}</tool_call>",
         ("action", "finish|{}")),
        # ---- 2026-08-30 recon 实发 [03][07][10][14]:<reasoning>/<text> 包装 ----
        # 包装标签独占一行 + 内部严格两行 Action → 剥标签后照常解析
        ("<reasoning>\n先看顶层结构。\n</reasoning>\n<text>\n"
         'Action: list_files\nAction Input: {"directory": ".", "recursive": false, "max_files": 50}\n</text>',
         ("action", 'list_files|{"directory": ".", "recursive": false, "max_files": 50}')),
        # <text> 包裹 Final Answer → 剥标签后仍是 final
        ("<text>\nFinal Answer: {\"summary\": \"ok\"}\n</text>",
         ("final", '{"summary": "ok"}')),
        # [11] 实发布局:Thought 后直接 <text>,Action 在标签内部两行
        ("Thought: <text>\nAction: read_file\n"
         'Action Input: {"path": "extracted/unitree/module/net_switcher/net_switcher.py"}\n</text>',
         ("action", 'read_file|{"path": "extracted/unitree/module/net_switcher/net_switcher.py"}')),
        # 包装 + 单行 Action(fc 惯性):"Action: 工具({JSON})" → 兜底还原
        ("<reasoning>unitree 是重点。</reasoning>\n<text>\n"
         'Action: list_files({"directory": "extracted/unitree", "recursive": false, "max_files": 50})\n</text>',
         ("action", 'list_files|{"directory": "extracted/unitree", "recursive": false, "max_files": 50}')),
        # 裸单行 Action:JSON 与 Action 同行(无标签) → 兜底还原
        ("Thought: 下钻 unitree。\n"
         'Action: list_files {"directory": "extracted/unitree", "recursive": true}',
         ("action", 'list_files|{"directory": "extracted/unitree", "recursive": true}')),
        # 包装内只有计划散文(无协议块)→ 仍判 fail(不误吞,正确语义)
        ("<reasoning>extracted 有 8 项,unitree 是重点。</reasoning>\n"
         "<text>下一步应下钻 unitree/ 目录查看厂商程序。</text>",
         ("fail", None)),
        # 仅 "Action: 名字" 且无参数 JSON → 保持 fail(单行兜底要配平到 dict 才接受)
        ("Action: echo", ("fail", None)),
        # <tool_call> 缺闭标签 + arguments 内嵌套花括号 → 配平提取(旧成对正则救不了)
        ("<tool_call>{\"name\": \"list_files\", "
         '"arguments": {"directory": "we{rd}/x", "recursive": false}}',
         ("action", 'list_files|{"directory": "we{rd}/x", "recursive": false}')),
        # 重复 Action 块(模型整块自重复)→ 取首个截断,第二个块不进 raw
        ("Action: read_file\nAction Input: {\"path\": \"a\"}\n"
         "Action: read_file\nAction Input: {\"path\": \"a\"}",
         ("action", 'read_file|{"path": "a"}')),
        # JSON 字符串内联 "<text>" 字样不被剥(包装标签剥离是行锚定,防误伤)
        ('Final Answer: {"summary": "see <text> here"}',
         ("final", '{"summary": "see <text> here"}')),
        # 裸 JSON(无 <tool_call> 标签)不做解码(避免误吞散文),维持 fail 语义
        ('{"name": "list_files", "arguments": {}}',
         ("fail", None)),
    ]
    for reply, (want_kind, want_payload) in cases:
        kind, payload = parse_reply(reply)
        if kind != want_kind:
            fails.append(f"{reply[:30]!r} → {kind},期望 {want_kind}")
        elif want_payload is not None and payload != want_payload:
            fails.append(f"{reply[:30]!r} → {payload!r},期望 {want_payload!r}")
    return fails


def test_parse_action_input() -> list[str]:
    fails: list[str] = []
    if parse_action_input('{"file_ref": "a", "n": 1}') != {"file_ref": "a", "n": 1}:
        fails.append("正常 JSON 解析失败")
    if parse_action_input('```json\n{"a": 1}\n```') != {"a": 1}:
        fails.append("围栏 JSON 解析失败")
    if parse_action_input("") != {}:
        fails.append("空串应给 {}")
    if parse_action_input("裸符号") != {"value": "裸符号"}:
        fails.append("裸字符串容错失败")
    if parse_action_input("[1,2]") != {"_raw": "[1,2]"}:
        fails.append("非 dict JSON 应包 _raw")
    # 尾随散文宽容(2026-08-20 实发):合法 JSON 后跟思考文字 → 救回首段 JSON,
    # 而非包成 {"value": 整串}(无工具接受 value,会 TypeError 空转)
    trailing = ('{"path": "analysis/x.functions.json", "offset": 0, "limit": 200}\n\n'
                "等等,read_file 的 path 相对 process/,前序工件路径格式是 process/analysis/...")
    if parse_action_input(trailing) != {"path": "analysis/x.functions.json",
                                        "offset": 0, "limit": 200}:
        fails.append(f"尾随散文应救回首段 JSON: {parse_action_input(trailing)}")
    # 字符串内花括号不干扰配平
    tricky = '{"pattern": "re:{.+}", "n": 1} 然后是散文 { 还有花括号'
    if parse_action_input(tricky) != {"pattern": "re:{.+}", "n": 1}:
        fails.append(f"字符串内花括号配平失败: {parse_action_input(tricky)}")
    # JSON 本身残缺(无法配平)→ 仍走 value 兜底
    if parse_action_input('{"path": "x" 后面没有闭合') != {"value": '{"path": "x" 后面没有闭合'}:
        fails.append("残缺 JSON 应回退 value 兜底")
    return fails


def test_normal_loop() -> list[str]:
    fails: list[str] = []
    llm = ScriptedLLM([
        "Thought: 查一下\nAction: echo\nAction Input: {\"q\": \"x\"}",
        "Final Answer: 结论:""echo 返回了 x",
    ])
    with tempfile.TemporaryDirectory() as td:
        tr = Path(td) / "t.jsonl"
        r = run_react_agent(llm, _tools(), "sys", "init", max_iters=5, transcript=tr)
        if not r.ok:
            fails.append(f"正常循环应完成: steps={r.steps}")
        if len(r.tool_calls) != 1:
            fails.append(f"应调 1 次工具, got {r.tool_calls}")
        if not tr.exists() or len(tr.read_text(encoding='utf-8').splitlines()) < 3:
            fails.append("transcript 应逐轮落盘")
    # Observation 正确回喂:第 2 次调用的 messages 应含 echo 输出
    obs_seen = any("echo:" in m.get("content", "") for m in llm.calls[1])
    if not obs_seen:
        fails.append("Observation 未回喂到下一轮")
    return fails


def test_parse_fail_recovery() -> list[str]:
    fails: list[str] = []
    llm = ScriptedLLM([
        "我忘了格式直接说话",
        "Action: echo\nAction Input: {}",
        "Final Answer: 恢复了",
    ])
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=6)
    if not r.ok:
        fails.append("解析失败后应恢复")
    if llm.calls[1][-1]["content"].startswith("Observation: [协议错误]"):
        pass
    else:
        fails.append("协议错误应作为 Observation 回喂")
    return fails


def test_wrapper_drift_recon_flow() -> list[str]:
    """2026-08-30 recon 实录场景端到端回归:<reasoning>/<text> 包装、
    单行 Action(fc 惯性)与一次"纯散文"协议失败,循环都能正确走完。

    对应终端 [03][07][10][14]:失败紧跟在 list_files 观察之后;修复后
    包装+单行形态直接解析成功,仅"包装内纯散文"仍按协议失败回喂(不误吞)——
    模型下一轮自纠,流程整体零中断收尾。
    """
    fails: list[str] = []
    tools = {"list_files": FakeFS(ToolContext(process_dir=Path(".")))}
    llm = ScriptedLLM([
        # [01] 包装 + 严格两行 Action
        "<reasoning>\n先枚举顶层目录结构。\n</reasoning>\n<text>\n"
        "Action: list_files\nAction Input: {\"directory\": \".\", "
        "\"recursive\": false, \"max_files\": 50}\n</text>",
        # [02] 包装 + 单行 Action("Action: 工具({JSON})",fc 惯性)→ 现在能解析
        "<reasoning>extracted 有 2 个顶层目录。</reasoning>\n<text>\n"
        "Action: list_files({\"directory\": \"extracted\", "
        "\"recursive\": false, \"max_files\": 50})\n</text>",
        # [03]=复现:包装里只有计划散文、无协议块 → 协议失败回喂(修复后仍按
        #    语义判 fail,模型自纠);此前 [03][07][10][14] 同型
        "<reasoning>unitree 是最高优先级。</reasoning>\n"
        "<text>下一步应下钻 unitree/ 目录,查看厂商自研二进制与模块。</text>",
        # 受回喂纠正后的合规两行 Action
        "Thought: 下钻 unitree。\nAction: list_files\n"
        "Action Input: {\"directory\": \"extracted/unitree\", "
        "\"recursive\": false, \"max_files\": 50}",
        # 单行 Action(无标签)继续下钻 module
        "Thought: 看模块清单。\n"
        "Action: list_files {\"directory\": \"extracted/unitree/module\", "
        "\"recursive\": false, \"max_files\": 50}",
        "Final Answer: {\"summary\": \"侦察完成\", \"findings\": []}",
    ])
    r = run_react_agent(llm, tools, "sys", "init", max_iters=10)
    if not r.ok:
        fails.append(f"包装漂移流程应正常收尾: steps={r.steps} finished={r.finished}")
    # 4 次 list_files 成功执行([01][02][04][05];[03] 判失败未调工具)
    if len(r.tool_calls) != 4:
        fails.append(f"应执行 4 次 list_files, got {len(r.tool_calls)}: {r.tool_calls}")
    # 协议失败确实回喂过(第 4 次 LLM 调用:失败在第 3 次回复解析时发生,回喂后进入第 4 轮)
    if not llm.calls[3][-1]["content"].startswith("Observation: [协议错误]"):
        fails.append(f"纯散文应回喂协议错误: {llm.calls[3][-1]['content'][:60]!r}")
    return fails


def test_reasoning_kept_out_of_context() -> list[str]:
    """2026-08-30 正文/思考拆分:思考草稿只入 transcript,不参与解析、不回喂上下文。"""
    fails: list[str] = []
    import json as _json

    llm = ReasoningLLM([
        "Thought: 查真参数。\nAction: echo\nAction Input: {\"q\": \"real\"}",
        "Final Answer: 完成",
    ], reasoning="草稿里想先试 echo q=draft。")
    with tempfile.TemporaryDirectory() as td:
        tr = Path(td) / "t.jsonl"
        r = run_react_agent(llm, _tools(), "sys", "init", max_iters=5, transcript=tr)
        if not r.ok:
            fails.append(f"应正常收尾: steps={r.steps}")
        # 第 2 轮 messages:思考(含草稿)不得回喂上下文
        ctx = [m.get("content", "") for m in llm.calls[1]]
        if any("draft" in c or "草稿" in c for c in ctx):
            fails.append("思考不应回喂到上下文")
        # 实际执行的是正文参数 real,草稿 draft 未被执行
        if not any("'q', 'real'" in c for c in ctx):
            fails.append("应执行正文参数 real")
        if any("'q', 'draft'" in c for c in ctx):
            fails.append("草稿参数 draft 不应出现在调用中")
        # transcript:assistant 条目保留思考全文(留档审计)
        entries = [_json.loads(l) for l in tr.read_text(encoding="utf-8").splitlines()]
        first = next(e for e in entries if e.get("phase") == "assistant")
        if "草稿" not in first.get("content", ""):
            fails.append("transcript 应保留思考全文")
        if first.get("usage", {}).get("reasoning_content") is not None:
            fails.append("usage 中的 reasoning_content 应被 pop(避免 JSONL 冗余)")
    return fails


def test_persistent_fail_terminates() -> list[str]:
    fails: list[str]
    # 连续协议失败达 MAX_PARSE_FAILS(现为 4)次 → 强制收尾仍失败 → finished=False。
    # 回复条数 = MAX_PARSE_FAILS + 1(第 4 次失败触发强制 Final 要求,
    # 第 5 次仍不合规 → 终止);2026-08-22 放宽 2→4 后同步适配。
    from firmware_audit.step5_agent.engine.protocol import MAX_PARSE_FAILS
    llm = ScriptedLLM(["nope"] * (MAX_PARSE_FAILS + 1))
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=10)
    fails = ["连续协议失败应终止且 finished=False"] if r.finished else []
    return fails


def test_iter_limit_force_final() -> list[str]:
    fails: list[str] = []
    # 3 轮预算内一直要调工具,强制收尾轮给出答案
    replies = ["Action: echo\nAction Input: {}"] * 3 + ["Final Answer: 被迫收尾"]
    llm = ScriptedLLM(replies)
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=3)
    if not r.finished or r.final_answer != "被迫收尾":
        fails.append(f"迭代上限后强制收尾失败: {r.final_answer!r}")
    # 强收尾仍发 Action 时:best-effort 截尾,不崩
    llm2 = ScriptedLLM(["Action: echo\nAction Input: {}"] * 5)
    r2 = run_react_agent(llm2, _tools(), "sys", "init", max_iters=2)
    if r2.finished and "Action" not in r2.final_answer:
        fails.append("强收尾仍发 Action 时应取原文尾部(best-effort)")
    return fails


def test_unknown_tool_and_crash() -> list[str]:
    fails: list[str] = []
    llm = ScriptedLLM([
        "Action: no_such_tool\nAction Input: {}",
        "Action: boom\nAction Input: {}",
        "Final Answer: 都见过错误了",
    ])
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=6)
    if not r.ok:
        fails.append("未知工具后应能继续")
    obs1 = llm.calls[1][-1]["content"]
    obs2 = llm.calls[2][-1]["content"]
    if "未知工具" not in obs1:
        fails.append("未知工具错误未回喂")
    if "Error" not in obs2 or "炸了" not in obs2:
        fails.append("工具内部异常应被捕获回喂,不崩循环")
    return fails


def test_final_without_tools_rejected() -> list[str]:
    """零工具 Final 守卫(2026-08-18):不查证直接出结论 → 拒绝退回;
    调过工具后放行;模型坚持不调工具时第二次放行(防死锁烧迭代)。"""
    fails: list[str] = []
    llm = ScriptedLLM([
        "Final Answer: 不查就下结论",
        "Thought: 先查证\nAction: echo\nAction Input: {\"q\": \"x\"}",
        "Final Answer: 查证后的结论",
    ])
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=6)
    if not r.ok or r.final_answer != "查证后的结论":
        fails.append(f"拒绝后应先调工具再收尾: {r.final_answer!r}")
    if len(r.tool_calls) != 1:
        fails.append(f"应恰好 1 次工具调用, got {len(r.tool_calls)}")
    reject_obs = llm.calls[1][-1]["content"]
    if "系统拒绝" not in reject_obs:
        fails.append(f"拒绝提示应作为 Observation 回喂: {reject_obs[:80]}")

    llm2 = ScriptedLLM(["Final Answer: 我就是不调", "Final Answer: 我就是不调"])
    r2 = run_react_agent(llm2, _tools(), "sys", "init", max_iters=6)
    if not r2.finished or r2.final_answer != "我就是不调":
        fails.append(f"坚持不调工具时第二次 Final 应放行: {r2.final_answer!r}")
    return fails


def test_repeat_call_intervention() -> list[str]:
    """同参循环守卫(2026-08-18):同一工具+相同参数第 4 次起拦截不执行,
    注入干预提示;实际执行次数封顶 3。"""
    fails: list[str] = []
    replies = ["Action: echo\nAction Input: {\"q\": \"same\"}"] * 4 + ["Final Answer: 换路后收尾"]
    llm = ScriptedLLM(replies)
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=8)
    if not r.ok:
        fails.append(f"干预后应能收尾: steps={r.steps}")
    if len(r.tool_calls) != 3:
        fails.append(f"echo 实际执行应 3 次, got {len(r.tool_calls)}")
    if r.steps != 5:
        fails.append(f"总步数应为 5(4 action + 1 final), got {r.steps}")
    intervene_obs = llm.calls[4][-1]["content"]  # 第 4 次 action 后的回喂
    if "系统干预" not in intervene_obs:
        fails.append(f"干预提示应作为 Observation 回喂: {intervene_obs[:80]}")

    # 参数不同不受限:4 次不同参数的调用全部执行
    llm2 = ScriptedLLM([
        f"Action: echo\nAction Input: {{\"q\": \"v{i}\"}}" for i in range(4)
    ] + ["Final Answer: 不同参数不受限"])
    r2 = run_react_agent(llm2, _tools(), "sys", "init", max_iters=8)
    if len(r2.tool_calls) != 4:
        fails.append(f"不同参数 4 次应全执行, got {len(r2.tool_calls)}")
    return fails


def test_truncate_headtail_and_obs_fulltext() -> list[str]:
    """学 DeepAudit:截断带总量提示+头尾保留;原文全文落盘 obs/(可回查)。"""
    fails: list[str] = []
    import json as _json

    from firmware_audit.step5_agent.providers.tools.base import truncate_text

    big = BigTool(ToolContext(process_dir=Path(".")))
    r = big.execute()
    # 头尾保留:开头 HEAD 与结尾 TAIL 都在,中间被省略
    if not (r.text.startswith("HEAD") and r.text.rstrip().endswith("TAIL")):
        fails.append("截断后应保留头尾(HEAD...TAIL)")
    if "MIDDLE_LOST" in r.text:
        fails.append("截断后中间段应被省略")
    # 总量提示:LLM 需知道全文总长与省略量,才会改分页重读
    if "共 17019 字符" not in r.text or "省略中间" not in r.text:
        fails.append(f"截断提示应含总字符数与省略量: {r.text[:120]}")
    if r.raw != "HEAD" + "A" * 12000 + "MIDDLE_LOST" + "B" * 5000 + "TAIL":
        fails.append("raw 应保留截断前全文")
    # 短文本不动
    if truncate_text("short") != "short":
        fails.append("短文本不应被截断")

    # 循环层:obs/ 全文落盘 + transcript observation 条目带 obs_file
    llm = ScriptedLLM([
        "Action: big\nAction Input: {}",
        "Final Answer: done",
    ])
    tools = {"big": BigTool(ToolContext(process_dir=Path(".")))}
    with tempfile.TemporaryDirectory() as td:
        tr = Path(td) / "t.jsonl"
        run_react_agent(llm, tools, "sys", "init", max_iters=3, transcript=tr)
        obs_file = tr.parent / "obs" / "step001_big.txt"
        if not obs_file.is_file():
            fails.append(f"obs 全文文件缺失: {obs_file}")
        else:
            content = obs_file.read_text(encoding="utf-8")
            if "MIDDLE_LOST" not in content or len(content) < 16000:
                fails.append("obs 文件应含未截断全文(含中间段)")
        entries = [_json.loads(l) for l in tr.read_text(encoding="utf-8").splitlines()]
        obs_entries = [e for e in entries if e.get("phase") == "observation"]
        if not obs_entries:
            fails.append("transcript 应含 observation 条目")
        elif not obs_entries[0].get("obs_file"):
            fails.append(f"observation 条目应带 obs_file 指针: {obs_entries[0]}")
    return fails


def test_per_tool_truncation_override() -> list[str]:
    """票01 per-tool 覆盖属性:未声明用全局默认 16000;声明 64000 的工具
    20000 字符全量通过(summarize 素材护栏语义);声明小值按声明截断,
    截断行为模型不变(头 75% 保留 + 省略提示)。"""
    fails: list[str] = []
    ctx = ToolContext(process_dir=Path("."))
    # 未声明覆盖 → 全局默认 16000:BigTool 17019 字符被截断
    r_big = BigTool(ctx).execute()
    if len(r_big.text) > 16000 + 200 or "已截断" not in r_big.text:
        fails.append(f"未声明覆盖应按全局默认 16000 截断: len={len(r_big.text)}")
    # 声明 64000(summarize 同值)→ 20000 字符全量通过
    r_wide = WideCapTool(ctx).execute()
    if r_wide.text != "B" * 20000:
        fails.append(f"声明 64000 时 20000 字符应全量通过: len={len(r_wide.text)}")
    # 声明小值 100 → 按声明截断,头 75% 保留
    r_narrow = NarrowCapTool(ctx).execute()
    if len(r_narrow.text) > 300 or "已截断" not in r_narrow.text:
        fails.append(f"声明 100 应按 100 截断: len={len(r_narrow.text)}")
    if not r_narrow.text.startswith("C" * 75):
        fails.append("覆盖截断仍应头 75% 保留")
    return fails


def test_obs_readback_via_read_file() -> list[str]:
    """端到端:截断提示带具体路径 → LLM 下一步 read_file 分页 → 取回中间段。

    这是"超长结果可回读"闭环的验收:不只是落盘,LLM 能按提示自己找回。
    """
    fails: list[str] = []
    from firmware_audit.step5_agent.providers.tools.read_file import ReadFileTool

    with tempfile.TemporaryDirectory() as td:
        ctx = ToolContext(process_dir=Path(td))
        tools = {"big": BigTool(ctx), "read_file": ReadFileTool(ctx)}
        llm = ScriptedLLM(["Action: big\nAction Input: {}"])
        transcript = Path(td) / "agent" / "t" / "transcript.jsonl"
        r1 = run_react_agent(llm, tools, "sys", "init", max_iters=1, transcript=transcript)
        if r1.finished:
            fails.append("max_iters=1 不应完成")
        # 截断提示在回喂后的消息里:第一次 chat 时 Observation 尚未生成;
        # 第二次(强制收尾轮)末条是收尾指令,带提示的 Observation 在倒数第二
        step1_obs = llm.calls[1][-2]["content"]
        if "全文已存 agent/t/obs/step001_big.txt" not in step1_obs:
            fails.append(f"截断提示应带具体 obs 路径: {step1_obs[-160:]}")

        # 模拟 LLM 按提示发 read_file(白名单内相对路径,分页读中段;
        # MIDDLE_LOST 在 ~12000 字符处 → 4000 软折行的第 4 行)
        rr = tools["read_file"].execute(path="agent/t/obs/step001_big.txt", offset=3, limit=1)
        if not rr.ok:
            fails.append(f"read_file 读 obs 失败: {rr.error}")
        elif "MIDDLE_LOST" not in rr.text:
            fails.append(f"分页应能取回中间段 MIDDLE_LOST: {rr.text[:150]}")
        # 折行生效:17019+13 字符单行 → 5 行左右,行式分页可定位
        obs_lines = (Path(td) / "agent" / "t" / "obs" / "step001_big.txt").read_text(
            encoding="utf-8").splitlines()
        if not (4 <= len(obs_lines) <= 6):
            fails.append(f"折行后行数应 4-6, got {len(obs_lines)}")
    return fails


def test_last_round_notice_and_summary_force() -> list[str]:
    """r3/r4(2026-08-19):最后一轮注入总结要求;强制收尾指令要求执行总结三要素。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.engine.react_loop import (
        FORCE_FINAL_PROMPT, LAST_ROUND_NOTICE,
    )

    # 最后一轮提示注入:第 max_iters 轮 LLM 调用的 messages 末尾可见
    llm = ScriptedLLM([
        "Action: echo\nAction Input: {}",
        "Final Answer: 最后一轮主动收尾",
    ])
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=2)
    if not r.finished or r.final_answer != "最后一轮主动收尾":
        fails.append(f"最后一轮应能自主收尾: {r.final_answer!r}")
    last_msgs = llm.calls[1]  # 第 2 轮(=max_iters)的调用
    if not any("最后一次循环机会" in m.get("content", "") for m in last_msgs):
        fails.append("第 max_iters 轮 messages 应含 LAST_ROUND_NOTICE")
    if not any("后续建议" in m.get("content", "") for m in last_msgs):
        fails.append("最后一轮提示应要求执行总结三要素")
    # 常量本身含三要素关键词(强制收尾指令同样)
    for kw in ("执行情况", "已完成", "后续建议"):
        if kw not in LAST_ROUND_NOTICE or kw not in FORCE_FINAL_PROMPT:
            fails.append(f"总结指令缺关键词 {kw}")

    # 强制收尾兜底:最后一轮仍发 Action → FORCE_FINAL_PROMPT 含执行总结要求
    llm2 = ScriptedLLM([
        "Action: echo\nAction Input: {}",
        "Action: echo\nAction Input: {}",
        "Final Answer: 被迫总结收尾",
    ])
    r2 = run_react_agent(llm2, _tools(), "sys", "init", max_iters=2)
    if not r2.finished or r2.final_answer != "被迫总结收尾":
        fails.append(f"强制收尾应产出答案: {r2.final_answer!r}")
    final_msgs = llm2.calls[2]  # 强制收尾轮
    if not any("执行总结" in m.get("content", "") for m in final_msgs):
        fails.append("强制收尾指令应要求执行总结")
    return fails


def test_force_final_30_rounds() -> list[str]:
    """r5(2026-08-29):ANALYSIS_CFG.max_iters=30 的 30 轮专项强制收尾用例。

    脚本:每轮都发 Action(共 30 条,参数逐一不同以避开同参循环守卫),
    强制收尾轮前才给 Final Answer。断言:
    第 30 轮 LLM 调用注入 LAST_ROUND_NOTICE(最后一轮提示);
    第 31 轮调用前由 FORCE_FINAL_PROMPT 兜底强制要求 Final Answer;
    最终 ReactResult.steps==30 且 finished=True。
    """
    fails: list[str] = []
    from firmware_audit.step5_agent.engine.react_loop import (
        FORCE_FINAL_PROMPT, LAST_ROUND_NOTICE,
    )

    acts = [f"Action: echo\nAction Input: {{\"q\": \"x{i}\"}}" for i in range(30)]
    acts.append("Final Answer: 30轮强制收尾结论")
    llm = ScriptedLLM(acts)
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=30)

    # 第 30 轮(max_iters)LLM 调用前注入 LAST_ROUND_NOTICE(最后一轮提示)
    if not any("最后一次循环机会" in m.get("content", "")
               or "最后一轮" in m.get("content", "") for m in llm.calls[29]):
        fails.append("第 30 轮 messages 应注入 LAST_ROUND_NOTICE(最后一轮提示)")
    if not any("最后" in m.get("content", "") for m in llm.calls[29]):
        fails.append("第 30 轮 messages 应含最后一轮相关提示")
    # 第 31 轮(强制收尾)调用前由 FORCE_FINAL_PROMPT 兜底
    if not any("已达到迭代上限" in m.get("content", "") for m in llm.calls[30]):
        fails.append("第 31 轮调用前应注入 FORCE_FINAL_PROMPT 兜底")
    # 强制收尾后 steps 精确停在 30,finished 为 True,产出最终结论
    if r.steps != 30:
        fails.append(f"steps 应为 30, got {r.steps}")
    if not r.finished:
        fails.append("强制收尾应让 finished=True")
    if r.final_answer != "30轮强制收尾结论":
        fails.append(f"应产出 30 轮强制收尾结论: {r.final_answer!r}")
    return fails


def test_system_prompt_budget_injection() -> list[str]:
    """r3(2026-08-19):build_system_prompt 将 max_iters 变量注入系统提示词。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.data.prompts import build_system_prompt

    tools = {"echo": EchoTool(Path("."))}
    for n in (20, 24):
        sp = build_system_prompt("BASE", tools, max_iters=n)
        if f"最多 {n} 轮" not in sp:
            fails.append(f"max_iters={n} 未注入提示词")
    sp24 = build_system_prompt("BASE", tools, max_iters=24)
    if "最多 20 轮" in sp24:
        fails.append("预算数字应随变量变化,不是写死")
    # 工具清单在前,预算段在后(预算作为收尾提醒)
    if sp24.index("echo") > sp24.index("迭代预算"):
        fails.append("工具清单应在预算段之前")
    return fails


def test_reset_transcript_unified_entry() -> list[str]:
    """跑前清空 transcript 统一入口(T6 收编):runner 与编排层两处
    write_text("") 的同源知识收敛到 engine 层——旧记录清空 + 父目录自动建。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "agent" / "1_analysis" / "transcript.jsonl"
        p.parent.mkdir(parents=True)
        p.write_text("stale", encoding="utf-8")
        reset_transcript(p)
        if p.read_text(encoding="utf-8") != "":
            fails.append("已有旧记录应被清空(重跑覆盖)")
        p2 = Path(td) / "deep" / "nested" / "transcript.jsonl"
        reset_transcript(p2)
        if not p2.parent.is_dir() or p2.read_text(encoding="utf-8") != "":
            fails.append("父目录缺失时应一并创建并清空")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("parse_reply", test_parse_reply),
        ("parse_action_input", test_parse_action_input),
        ("normal_loop", test_normal_loop),
        ("parse_fail_recovery", test_parse_fail_recovery),
        ("wrapper_drift_recon_flow", test_wrapper_drift_recon_flow),
        ("reasoning_kept_out_of_context", test_reasoning_kept_out_of_context),
        ("persistent_fail_terminates", test_persistent_fail_terminates),
        ("iter_limit_force_final", test_iter_limit_force_final),
        ("unknown_tool_and_crash", test_unknown_tool_and_crash),
        ("final_without_tools_rejected", test_final_without_tools_rejected),
        ("repeat_call_intervention", test_repeat_call_intervention),
        ("truncate_headtail_and_obs_fulltext", test_truncate_headtail_and_obs_fulltext),
        ("per_tool_truncation_override", test_per_tool_truncation_override),
        ("obs_readback_via_read_file", test_obs_readback_via_read_file),
        ("last_round_notice_and_summary_force", test_last_round_notice_and_summary_force),
        ("force_final_30_rounds", test_force_final_30_rounds),
        ("system_prompt_budget_injection", test_system_prompt_budget_injection),
        ("reset_transcript_unified_entry", test_reset_transcript_unified_entry),
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

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
    """返回 >8KB 文本,验证截断策略与全文落盘。"""

    name = "big"
    description = "test"
    params_doc = ""

    def _run(self, **kw) -> ToolResult:
        # 全长 8019 > 8000;MIDDLE_LOST 位于 ~6000(head 6000 与 tail 1600 之间的省略区)
        body = "HEAD" + "A" * 6000 + "MIDDLE_LOST" + "B" * 2000 + "TAIL"
        return ToolResult(ok=True, text=body)


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


def test_persistent_fail_terminates() -> list[str]:
    fails: list[str] = []
    llm = ScriptedLLM(["nope", "still nope", "never", "ever"])
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=10)
    if r.finished:
        fails.append("连续协议失败应终止且 finished=False")
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
    if "共 8019 字符" not in r.text or "省略中间" not in r.text:
        fails.append(f"截断提示应含总字符数与省略量: {r.text[:120]}")
    if r.raw != "HEAD" + "A" * 6000 + "MIDDLE_LOST" + "B" * 2000 + "TAIL":
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
            if "MIDDLE_LOST" not in content or len(content) < 8000:
                fails.append("obs 文件应含未截断全文(含中间段)")
        entries = [_json.loads(l) for l in tr.read_text(encoding="utf-8").splitlines()]
        obs_entries = [e for e in entries if e.get("phase") == "observation"]
        if not obs_entries:
            fails.append("transcript 应含 observation 条目")
        elif not obs_entries[0].get("obs_file"):
            fails.append(f"observation 条目应带 obs_file 指针: {obs_entries[0]}")
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

        # 模拟 LLM 按提示发 read_file(白名单内相对路径,分页读中段)
        rr = tools["read_file"].execute(path="agent/t/obs/step001_big.txt", offset=1, limit=1)
        if not rr.ok:
            fails.append(f"read_file 读 obs 失败: {rr.error}")
        elif "MIDDLE_LOST" not in rr.text:
            fails.append(f"分页应能取回中间段 MIDDLE_LOST: {rr.text[:150]}")
        # 折行生效:8019+12 字符单行 → 3 行左右,行式分页可定位
        obs_lines = (Path(td) / "agent" / "t" / "obs" / "step001_big.txt").read_text(
            encoding="utf-8").splitlines()
        if not (2 <= len(obs_lines) <= 4):
            fails.append(f"折行后行数应 2-4, got {len(obs_lines)}")
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


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("parse_reply", test_parse_reply),
        ("parse_action_input", test_parse_action_input),
        ("normal_loop", test_normal_loop),
        ("parse_fail_recovery", test_parse_fail_recovery),
        ("persistent_fail_terminates", test_persistent_fail_terminates),
        ("iter_limit_force_final", test_iter_limit_force_final),
        ("unknown_tool_and_crash", test_unknown_tool_and_crash),
        ("final_without_tools_rejected", test_final_without_tools_rejected),
        ("repeat_call_intervention", test_repeat_call_intervention),
        ("truncate_headtail_and_obs_fulltext", test_truncate_headtail_and_obs_fulltext),
        ("obs_readback_via_read_file", test_obs_readback_via_read_file),
        ("last_round_notice_and_summary_force", test_last_round_notice_and_summary_force),
        ("system_prompt_budget_injection", test_system_prompt_budget_injection),
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

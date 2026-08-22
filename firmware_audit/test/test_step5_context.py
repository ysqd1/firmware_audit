"""Step5 上下文集成测试:Observation→ContextManager 完整性。

react 循环守卫/截断回读已由 test_step5_react.py 覆盖;
本文件专测 ContextManager 四分区结构与压缩路径(agents.md §上下文):
  1. 四分区布局:system/init 不动,summary 单条 user,recent 交替
  2. 压缩触发:阈值判定 → recent 减半对齐 assistant 边界 → 摘要并入 summary
  3. 压缩失败还原(LLM 异常不丢历史)
  4. 多轮压缩累积
  5. 真实循环中 Observation 前缀与交替完整性
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.engine.context import (
    ContextManager, est_tokens,
)
from firmware_audit.step5_agent.engine.react_loop import run_react_agent
from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.step5_agent.providers.tools.base import (
    AgentTool, ToolContext, ToolResult,
)


class EchoTool(AgentTool):
    name = "echo"
    description = "test"
    params_doc = ""

    def _run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, text=f"echo:{kw}")


class SummaryLLM:
    """压缩专用桩:chat 返回固定摘要,记录调用。"""

    def __init__(self):
        self.calls: list = []

    def chat(self, messages, **kw):
        self.calls.append(messages)
        return "摘要:已确认事实X;已排除Y;未决Z;证据 unitree/bin/idlc", {}


def test_est_tokens() -> list[str]:
    fails: list[str] = []
    msgs = [{"role": "user", "content": "a" * 100}, {"role": "user", "content": "b" * 50}]
    if est_tokens(msgs) != 75:
        fails.append(f"150 字符应估 75 token, got {est_tokens(msgs)}")
    if est_tokens([]) != 0:
        fails.append("空消息应为 0")
    return fails


def test_four_zone_layout() -> list[str]:
    fails: list[str] = []
    cm = ContextManager("SYS", "INIT", max_est_tokens=1000)
    cm.append("assistant", "Thought: t1\nAction: a")
    cm.append("user", "Observation: o1")
    cm.append("assistant", "Final Answer: f")
    msgs = cm.build_messages()
    # 布局:system, init, recent(3 条)
    if [m["role"] for m in msgs] != ["system", "user", "assistant", "user", "assistant"]:
        fails.append(f"分区顺序异常: {[m['role'] for m in msgs]}")
    if msgs[0]["content"] != "SYS" or msgs[1]["content"] != "INIT":
        fails.append("system/init 应原样保留")
    # 副本语义:改返回值不影响内部状态
    msgs[2]["content"] = "tampered"
    if cm.build_messages()[2]["content"] == "tampered":
        fails.append("build_messages 应返回副本")
    return fails


def test_compact_threshold_and_boundary() -> list[str]:
    fails: list[str] = []
    # 小窗口强触发:max=1000×0.6=600 est token(≈1200 字符)阈值
    cm = ContextManager("S", "I", max_est_tokens=1000)
    for i in range(6):  # 6 轮 assistant/user,约 2400+ 字符
        cm.append("assistant", f"Thought: 第{i}轮分析 " + "x" * 200)
        cm.append("user", f"Observation: 第{i}轮结果 " + "y" * 200)
    llm = SummaryLLM()
    if not cm.needs_compaction():
        fails.append("超阈值应判定需压缩")
    if not cm.maybe_compact(llm):
        fails.append("maybe_compact 应执行压缩")
    else:
        if cm.compactions != 1:
            fails.append("compactions 应计 1")
        if not cm.summaries or "已确认事实X" not in cm.summaries[0]:
            fails.append("摘要应并入 summary 区")
        # recent 减半后首条必须是 assistant(对齐边界,不悬空)
        if not cm.recent or cm.recent[0]["role"] != "assistant":
            fails.append(f"压缩后 recent 应以 assistant 开头, got "
                         f"{[m['role'] for m in cm.recent][:3]}")
        # system/init 不动
        msgs = cm.build_messages()
        if msgs[0]["content"] != "S" or msgs[1]["content"] != "I":
            fails.append("压缩不应动 system/init")
        # summary 以单条 user 插在 init 之后、recent 之前
        if msgs[2]["role"] != "user" or "前情摘要" not in msgs[2]["content"]:
            fails.append(f"summary 应为单条 user 插入第 3 位: {msgs[2]['content'][:60]}")
        if msgs[3]["role"] != "assistant":
            fails.append("summary 之后应直接接 recent 的 assistant")
        # 压缩对话历史传给 LLM 的是被移除的旧轮
        if "第0轮" not in llm.calls[0][-1]["content"]:
            fails.append("压缩输入应含最老轮次")
    return fails


def test_compact_llm_failure_restore() -> list[str]:
    fails: list[str] = []
    cm = ContextManager("S", "I", max_est_tokens=1000)
    for i in range(6):
        cm.append("assistant", f"a{i} " + "x" * 200)
        cm.append("user", f"Observation: o{i} " + "y" * 200)
    before = list(cm.recent)

    class BoomLLM:
        def chat(self, messages, **kw):
            raise RuntimeError("api down")

    if cm.maybe_compact(BoomLLM()):
        fails.append("LLM 失败时 compact 应返回 False")
    if cm.recent != before:
        fails.append("压缩失败必须还原保留区(不丢历史)")
    if cm.compactions != 0 or cm.summaries:
        fails.append("失败不应计入压缩次数")
    return fails


def test_compact_min_rounds_and_no_need() -> list[str]:
    fails: list[str] = []
    # recent < 4 不压缩(哪怕超阈值)
    cm = ContextManager("S", "I", max_est_tokens=10)
    cm.append("assistant", "x" * 500)
    cm.append("user", "y" * 500)
    if cm.compact(SummaryLLM()):
        fails.append("recent<4 不应压缩")
    # 未超阈值不触发
    cm2 = ContextManager("S", "I", max_est_tokens=10_000_000)
    for i in range(6):
        cm2.append("assistant", f"a{i}")
        cm2.append("user", f"Observation: o{i}")
    llm = SummaryLLM()
    if cm2.maybe_compact(llm):
        fails.append("未超阈值不应压缩")
    if llm.calls:
        fails.append("不应调用压缩 LLM")
    return fails


def test_multiple_compactions_accumulate() -> list[str]:
    fails: list[str] = []
    cm = ContextManager("S", "I", max_est_tokens=1000)
    # 两轮压缩:每次补 6 轮再压
    for round_ in range(2):
        for i in range(6):
            cm.append("assistant", f"r{round_}a{i} " + "x" * 300)
            cm.append("user", f"Observation: r{round_}o{i} " + "y" * 300)
        if not cm.maybe_compact(SummaryLLM()):
            fails.append(f"第 {round_ + 1} 次压缩应执行")
            break
    if cm.compactions != 2:
        fails.append(f"应累积 2 次压缩, got {cm.compactions}")
    msgs = cm.build_messages()
    # 两次摘要并入同一条 user summary(--- 分隔)
    if msgs[2]["content"].count("已确认事实X") != 2:
        fails.append("多次压缩摘要应拼接在同一条 summary 消息")
    if "前情摘要" not in msgs[2]["content"] or msgs[2]["content"].count("---") < 1:
        fails.append("多摘要应以 --- 分隔")
    return fails


def test_observation_prefix_and_alternation_in_loop() -> list[str]:
    """真实循环:所有 Observation 以固定前缀入上下文,assistant/user 严格交替。"""
    fails: list[str] = []
    llm = ScriptedLLM([
        "Thought: t1\nAction: echo\nAction Input: {\"q\": 1}",
        "Thought: t2\nAction: echo\nAction Input: {\"q\": 2}",
        "Final Answer: done",
    ])
    ctx = ToolContext(process_dir=Path("."))
    tools = {"echo": EchoTool(ctx)}
    cm = ContextManager("SYS", "INIT")
    with tempfile.TemporaryDirectory() as td:
        run_react_agent(llm, tools, "SYS", "INIT", max_iters=5,
                        transcript=Path(td) / "t.jsonl", context=cm)
        # recent 结构:assistant/user ×2 + final assistant = 5 条
        roles = [m["role"] for m in cm.recent]
        if roles != ["assistant", "user", "assistant", "user", "assistant"]:
            fails.append(f"recent 应严格交替, got {roles}")
        for i, m in enumerate(cm.recent):
            if m["role"] == "user" and not m["content"].startswith("Observation: "):
                fails.append(f"recent[{i}] user 消息缺 Observation 前缀: {m['content'][:60]}")
        # 完整消息链给 LLM 的形态:system+init+[round_note 进度 system]+交替 recent
        full = cm.build_messages()
        if len(full) != 2 + (1 if cm.round_note else 0) + len(cm.recent):
            fails.append("build_messages 应为 system+init+[进度]+recent 全量")
        # 每轮进度提示:非空且含总轮数(总数由 max_iters 实参注入,不硬编码)
        if not cm.round_note:
            fails.append("round_note 应为每轮注入的非空进度提示")
        elif "共 5 轮" not in cm.round_note:
            fails.append(f"round_note 应含总轮数(max_iters), got: {cm.round_note[:60]}")
        # 第 2 次 LLM 调用能看到第 1 次 Observation(echo 结果在上下文)
        if not any("echo:" in m["content"] for m in llm.calls[1]):
            fails.append("工具结果未进入第 2 轮上下文")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("est_tokens", test_est_tokens),
        ("four_zone_layout", test_four_zone_layout),
        ("compact_threshold_and_boundary", test_compact_threshold_and_boundary),
        ("compact_llm_failure_restore", test_compact_llm_failure_restore),
        ("compact_min_rounds_and_no_need", test_compact_min_rounds_and_no_need),
        ("multiple_compactions_accumulate", test_multiple_compactions_accumulate),
        ("observation_prefix_and_alternation", test_observation_prefix_and_alternation_in_loop),
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

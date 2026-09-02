"""Step5 终端监控显示单测(engine/display.py,零 API 零 Docker)。

覆盖:六类事件格式化(无色/截断/指针)/NullDisplay no-op/
make_display 环境变量矩阵/react_loop 事件接线/runner 端到端横幅。
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.engine.display import (
    NullDisplay,
    TerminalDisplay,
    make_display,
)
from firmware_audit.step5_agent.engine.react_loop import run_react_agent
from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.step5_agent.providers.tools.base import (
    AgentTool,
    ToolContext,
    ToolResult,
)


class EchoTool(AgentTool):
    name, description, params_doc = "echo", "test", "{}"

    def _run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, text="echo 回显正常")


class BoomTool(AgentTool):
    name, description, params_doc = "boom", "test", "{}"

    def _run(self, **kw) -> ToolResult:
        raise RuntimeError("炸了")


def _cap_display(**kw) -> TerminalDisplay:
    """捕获输出的显示实例(无色,固定宽度,out=StringIO 可 getvalue)。"""
    return TerminalDisplay(mode=kw.pop("mode", "compact"), use_color=False,
                           width=100, out=io.StringIO(), **kw)


def _tools() -> dict:
    ctx = ToolContext(process_dir=Path("."))
    return {"echo": EchoTool(ctx), "boom": BoomTool(ctx)}


# ---- 格式化单测 ----

def test_six_event_formats() -> list[str]:
    fails: list[str] = []
    d = _cap_display()
    d.stage("recon", "侦察", 8, "deepseek-v4-flash", 20)
    d.assistant(1, "Thought: 先查保护属性。\nAction: echo\nAction Input: {\"q\": 1}")
    d.observation(1, "echo", "echo 回显正常", True, 0.123)
    d.system(2, "同参调用拦截: echo 相同参数>3 次")
    d.final(3, '{"summary": "s", "findings": [{"title": "a"}, {"title": "b"}]}')
    d.done("recon", "attack_surface.json", 2, 3,
           {"prompt_tokens": 10, "completion_tokens": 5})

    out = d.out.getvalue()
    for want in ("recon · 侦察", "工具 8 · 模型 deepseek-v4-flash",
                 "思考  先查保护属性", '调用  echo({"q": 1})',
                 "OK 0.12s · echo 回显正常",
                 "系统  同参调用拦截", "结论  2 findings",
                 "recon 完成 · attack_surface.json · 2 findings · 3 轮"):
        if want not in out:
            fails.append(f"缺: {want!r}\n输出:\n{out}")
    if "\033[" in out:
        fails.append("use_color=False 时不应出现 ANSI 转义")
    # 时间顺序:思考 在 结果 前,结果 在 结论 前
    if not (out.index("思考") < out.index("结果") < out.index("结论")):
        fails.append("事件顺序应按时间排列")
    return fails


def test_error_observation_and_clip() -> list[str]:
    fails: list[str] = []
    d = _cap_display()
    d.observation(1, "boom", "Error: RuntimeError: 炸了", False)
    d.observation(2, "big", "X" * 300 + " 尾部", True, 1.0, truncated=True,
                  obs_file="agent/recon/obs/step002_big.txt")
    out = d.out.getvalue()
    if "Error · Error: RuntimeError: 炸了" not in out:
        fails.append("Error 结果行异常")
    # 正文截断:连续 X 不超过 _content_width(100-14),尾部标记被省略
    if "X" * 87 in out:
        fails.append("超长 Observation 正文应截断到内容宽度内")
    if "尾部" in out:
        fails.append("被截断的尾部内容不应出现")
    if "…全文 agent/recon/obs/step002_big.txt" not in out:
        fails.append("截断指针应展示 obs 文件路径")
    return fails


def test_full_mode_multiline() -> list[str]:
    fails: list[str] = []
    text = "\n".join(f"第{i}行内容" for i in range(1, 21))
    compact = _cap_display(mode="compact")
    full = _cap_display(mode="full")
    compact.observation(1, "t", text, True)
    full.observation(1, "t", text, True)
    c_out, f_out = compact.out.getvalue(), full.out.getvalue()
    if "第2行" in c_out:
        fails.append("compact 模式只应显示首行")
    if "第2行" not in f_out or "第12行" not in f_out:
        fails.append("full 模式应展示多行(前 12 行)")
    if "第13行" in f_out:
        fails.append("full 模式最多 12 行")
    return fails


def test_final_summary_fallback() -> list[str]:
    fails: list[str] = []
    d = _cap_display()
    d.final(1, "这不是 JSON 的结论文本")
    if "这不是 JSON 的结论文本" not in d.out.getvalue():
        fails.append("非 JSON Final 应回退展示原文")
    d2 = _cap_display()
    d2.final(1, '```json\n{"summary": "s", "findings": []}\n```')
    if "0 findings" not in d2.out.getvalue():
        fails.append("围栏 JSON 的 Final 应解析 findings 数")
    return fails


# ---- NullDisplay / make_display 配置矩阵 ----

def test_make_display_env() -> list[str]:
    fails: list[str] = []
    keys = ("STEP5_DISPLAY", "STEP5_COLOR")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for val, want_null, want_mode in (
            ("0", True, ""), ("none", True, ""), ("off", True, ""),
            ("", False, "compact"), ("1", False, "compact"),
            ("compact", False, "compact"), ("2", False, "full"), ("full", False, "full"),
        ):
            os.environ["STEP5_DISPLAY"] = val
            d = make_display()
            if want_null:
                if not isinstance(d, NullDisplay) or d.enabled:
                    fails.append(f"STEP5_DISPLAY={val!r} 应为 NullDisplay")
                # no-op:全部事件方法可安全调用
                d.stage("a", "b", 1, "m", 1)
                d.assistant(1, "x")
                d.observation(1, "t", "x", True)
                d.system(1, "x")
                d.final(1, "x")
                d.done("a", "b", 0, 1, {})
            elif d.mode != want_mode:
                fails.append(f"STEP5_DISPLAY={val!r} → mode={d.mode},期望 {want_mode}")

        # 颜色:STEP5_COLOR=1 强制开(即使非终端);=0 强制关
        os.environ["STEP5_DISPLAY"], os.environ["STEP5_COLOR"] = "1", "1"
        if not make_display().color:
            fails.append("STEP5_COLOR=1 应强制彩色")
        os.environ["STEP5_COLOR"] = "0"
        if make_display().color:
            fails.append("STEP5_COLOR=0 应强制无色")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return fails


# ---- react_loop 事件接线 ----

def test_react_loop_emits_events() -> list[str]:
    fails: list[str] = []
    d = _cap_display()
    llm = ScriptedLLM([
        "Thought: 先查证。\nAction: echo\nAction Input: {\"q\": 1}",
        "Final Answer: {\"summary\": \"s\", \"findings\": [{\"title\": \"a\"}]}",
    ])
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=4, display=d)
    if not r.ok:
        fails.append("循环应正常完成")
    out = d.out.getvalue()
    for want in ("思考  先查证", '调用  echo({"q": 1})',
                 "OK", "echo 回显正常", "结论  1 findings"):
        if want not in out:
            fails.append(f"缺事件输出: {want!r}\n输出:\n{out}")
    return fails


def test_react_loop_guard_events_shown() -> list[str]:
    fails: list[str] = []
    # 零工具拒绝 → 补查证 → 收尾
    d = _cap_display()
    llm = ScriptedLLM([
        'Final Answer: {"findings": []}',
        "Action: echo\nAction Input: {}",
        'Final Answer: {"findings": []}',
    ])
    run_react_agent(llm, _tools(), "sys", "init", max_iters=5, display=d)
    out = d.out.getvalue()
    if "零工具 Final 被拒绝" not in out:
        fails.append("零工具拒绝应显示系统事件")
    # 同参拦截(第 4 次)
    d2 = _cap_display()
    llm2 = ScriptedLLM(["Action: echo\nAction Input: {}"] * 4 +
                       ["Final Answer: done"])
    run_react_agent(llm2, _tools(), "sys", "init", max_iters=8, display=d2)
    if "同参调用拦截" not in d2.out.getvalue():
        fails.append("同参拦截应显示系统事件")
    # 工具崩溃显示 Error
    d3 = _cap_display()
    llm3 = ScriptedLLM(["Action: boom\nAction Input: {}",
                        "Final Answer: ok"])
    run_react_agent(llm3, _tools(), "sys", "init", max_iters=4, display=d3)
    if "Error" not in d3.out.getvalue():
        fails.append("工具崩溃应显示 Error 结果")
    return fails


def test_display_none_no_regression() -> list[str]:
    """display 缺省(None):循环行为与结果与无显示完全一致(零侵入)。"""
    fails: list[str] = []
    llm = ScriptedLLM([
        "Action: echo\nAction Input: {}",
        'Final Answer: {"findings": []}',
    ])
    r = run_react_agent(llm, _tools(), "sys", "init", max_iters=3)
    if not r.ok or len(r.tool_calls) != 1:
        fails.append("display=None 时行为不应变化")
    return fails


class _FlushCounting(io.StringIO):
    """统计 flush 次数的输出流:验证 _emit 每行都刷(管道/后台不积压)。"""

    def __init__(self):
        super().__init__()
        self.flushes = 0

    def flush(self) -> None:
        self.flushes += 1
        super().flush()


def test_emit_flushes_stream() -> list[str]:
    """实时反馈守护(2026-08-27):stdout 被管道/重定向时 Python 走块缓冲,
    _emit 必须 flush——否则后台运行/CI 日志要等缓冲满才可见(实测踩坑)。"""
    fails: list[str] = []
    out = _FlushCounting()
    d = TerminalDisplay(mode="compact", use_color=False, width=100, out=out)
    d.stage("recon", "侦察", 8, "m", 20)
    d.assistant(1, "Thought: x\nAction: echo\nAction Input: {}")
    d.observation(1, "echo", "ok", True, 0.1)
    d.final(2, '{"findings": []}')
    d.done("recon", "a.json", 0, 2, {})
    if out.flushes < 5:
        fails.append(f"每个事件都应 flush(实时性,至少 5 行),got {out.flushes} 次")
    return fails


def test_emit_narrow_encoding_degrades() -> list[str]:
    """窄编码 stdout 守护(2026-09-01):Windows 默认 GBK 控制台页打 ✓/⚠ 等
    不可编码字符会抛 UnicodeEncodeError 并中断整个管线——违反本模块契约
    "显示失败也不改变 Agent 行为"。_emit 应按输出流编码降级重打,流程照常;
    失败原因按铁律 4/10 记录一次(防每条 ✓/⚠ 刷屏)。"""
    fails: list[str] = []
    # 真实 GBK 输出流(Windows 默认控制台页):UTF-8 可编码但 GBK 不可编码的
    # 字符(✓/⚠)写入时抛 UnicodeEncodeError——修复前会中断整个管线
    with tempfile.TemporaryDirectory() as td:
        out_path = Path(td) / "narrow.txt"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            with open(out_path, "w", encoding="gbk") as out:
                d = TerminalDisplay(mode="compact", use_color=False, width=100, out=out)
                # 不抛异常即通过(修复前 _emit 会抛 UnicodeEncodeError 中断管线)
                d.observation(1, "read_file", "✓ 命中 ⚠ 注意", True, 0.1)
                d.final(2, '{"findings": []}')
        # 失败原因只记录一次(多条窄编码行不刷屏)
        if err.getvalue().count("[display]") != 1:
            fails.append(f"窄编码降级应只记录一次失败原因, got {err.getvalue().count('[display]')}")
        if "[display]" in err.getvalue() and "不影响 Agent 结果" not in err.getvalue():
            fails.append("降级提示应说明不影响 Agent 结果")
        # 降级后仍输出到流:不可编码字符被替换(? 占位)而非吞行——
        # 行骨架(步骤号/工具名/耗时)应保留,原始 ✓/⚠ 不落盘
        text = out_path.read_text(encoding="gbk")
        if "[01]" not in text or "OK" not in text or "0.10s" not in text:
            fails.append(f"窄编码降级不应吞行(应保留行骨架): {text[:80]!r}")
        if "✓" in text or "⚠" in text:
            fails.append("不可编码字符应按输出流编码替换(不应原样落盘)")
    return fails


# ---- runner 端到端(真实编排层走 make_display) ----

def test_runner_banner_end_to_end(capsys) -> list[str]:
    fails: list[str] = []
    from firmware_audit.test.test_step5_pipeline import (
        ANALYSIS_FINAL,
        RECON_FINAL,
        VERIFY_FINAL_F1,
        VERIFY_FINAL_F2,
        _make_process,
    )
    from firmware_audit.step5_agent.run_step5 import step5_run

    saved = os.environ.get("STEP5_DISPLAY")
    try:
        os.environ["STEP5_DISPLAY"] = "compact"
        with tempfile.TemporaryDirectory() as td:
            target = _make_process(Path(td))
            D = 'Thought: 调度\nAction: dispatch_agent\nAction Input: {"agent": "%s", "task": "x", "context": ""}'
            VTOOL = 'Thought: 复核\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.c", "limit": 5}'
            # ADR-0003:verification 每疑点一实例——2 条 findings → 2 个独立实例
            llm = ScriptedLLM([
                D % "recon",
                'Thought: 先看工件\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.imports.json", "limit": 5}',
                RECON_FINAL,
                D % "analysis",
                'Thought: 取证\nAction: read_file\nAction Input: {"path": "analysis/unitree/bin/idlc.strings.json", "limit": 5}',
                ANALYSIS_FINAL,
                D % "verification",
                VTOOL, VERIFY_FINAL_F1,
                VTOOL, VERIFY_FINAL_F2,
                'Final Answer: {"summary": "完成", "conclusion": ""}',
            ])
            step5_run(target, llm=llm)
        out = capsys.readouterr().out
        for want in ("── recon · 侦察", "── analysis · 深度分析",
                     "── verification · 复核", "── orchestrator · 编排",
                     "调用  read_file", "调用  dispatch_agent",
                     "recon 完成 · survey.json"):
            if want not in out:
                fails.append(f"runner 端到端缺: {want!r}")
    finally:
        if saved is None:
            os.environ.pop("STEP5_DISPLAY", None)
        else:
            os.environ["STEP5_DISPLAY"] = saved
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("six_event_formats", test_six_event_formats),
        ("error_observation_and_clip", test_error_observation_and_clip),
        ("full_mode_multiline", test_full_mode_multiline),
        ("final_summary_fallback", test_final_summary_fallback),
        ("make_display_env", test_make_display_env),
        ("react_loop_emits_events", test_react_loop_emits_events),
        ("react_loop_guard_events_shown", test_react_loop_guard_events_shown),
        ("display_none_no_regression", test_display_none_no_regression),
        ("emit_narrow_encoding_degrades", test_emit_narrow_encoding_degrades),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}"
          "(runner 端到端仅 pytest 模式)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())

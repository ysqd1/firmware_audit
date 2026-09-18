"""Step5 终端监控显示单测(engine/display.py,零 API 零 Docker)。

覆盖:六类事件格式化(无色/截断/指针)/NullDisplay no-op/
make_display 环境变量矩阵/逐行 flush/窄编码降级。

票 14 公开切换后:display 的旧接线对象(react_loop/legacy runner)已删除,
本文件只守护显示层自身的格式化与配置契约;Host 侧显示接线另行工单。
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


def _cap_display(**kw) -> TerminalDisplay:
    """捕获输出的显示实例(无色,固定宽度,out=StringIO 可 getvalue)。"""
    return TerminalDisplay(mode=kw.pop("mode", "compact"), use_color=False,
                           width=100, out=io.StringIO(), **kw)


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


def test_recon_observe_label() -> list[str]:
    """票03(target5-e2e-fixes):recon 显示标签改"观察点"——recon v3 明令禁止
    findings 字段(CONTEXT.md 词汇纪律),完成行/结论行按 findings 渲染曾把
    survey 观察点误报成 "11 findings",e2e 时被误读为守护被绕过。

    验收:
    1. recon done 行:调用方传 label="观察点" → "N 观察点",不含 findings
    2. recon 结论行:载荷为 survey JSON(high_risk_areas,无 findings 键)
       → 报 "N 观察点(详见工件)"
    3. analysis/verification 不变:默认 label 仍 findings;findings 载荷优先于
       观察点分支(容器可同时带两键)
    """
    fails: list[str] = []
    # recon:done 标签随调用方传入 + 结论行观察点分支
    d = _cap_display()
    d.final(3, '{"schema_version": 3, "high_risk_areas": [{}, {}, {}]}')
    d.done("recon", "survey.json", 3, 5, {}, label="观察点")
    out = d.out.getvalue()
    if "recon 完成 · survey.json · 3 观察点" not in out:
        fails.append(f"recon 完成行应显示 观察点 计数: {out}")
    if "3 观察点(详见工件)" not in out:
        fails.append(f"recon 结论行(survey 载荷)应报观察点数: {out}")
    if "findings" in out:
        fails.append(f"recon 输出不得含 findings 标签: {out}")
    # analysis/verification:默认 label 与 findings 载荷分支不变
    d2 = _cap_display()
    d2.final(1, '{"summary": "s", "findings": [{"title": "a"}]}')
    d2.done("analysis", "findings.json", 1, 4, {})
    out2 = d2.out.getvalue()
    if "1 findings" not in out2 or "观察点" in out2:
        fails.append(f"analysis/verification 输出应保持 findings 标签: {out2}")
    # 载荷同时含两键时 findings 优先(不破坏既有容器判读)
    d3 = _cap_display()
    d3.final(1, '{"findings": [{"title": "a"}], "high_risk_areas": [{}, {}]}')
    if "1 findings" not in d3.out.getvalue():
        fails.append("findings 载荷应优先于观察点分支")
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


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("six_event_formats", test_six_event_formats),
        ("error_observation_and_clip", test_error_observation_and_clip),
        ("full_mode_multiline", test_full_mode_multiline),
        ("final_summary_fallback", test_final_summary_fallback),
        ("recon_observe_label", test_recon_observe_label),
        ("make_display_env", test_make_display_env),
        ("emit_flushes_stream", test_emit_flushes_stream),
        ("emit_narrow_encoding_degrades", test_emit_narrow_encoding_degrades),
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

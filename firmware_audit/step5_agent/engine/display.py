"""终端监控显示(Claude Code 风格,非流式)。

ReAct 循环的可选观察层:react_loop 在各事件点喂本模块,这里只做格式化
与打印,不参与控制流;display=None / NullDisplay 完全 no-op,零侵入
(铁律:监控不影响执行;显示失败也不改变 Agent 行为)。

六类事件(与 react_loop 钩子一一对应):
  stage(name,label,tools,model,max_iters)   阶段横幅(起计时)
  assistant(step,reply)                     LLM 回复 → 自动拆"思考/调用"行
  observation(step,tool,text,ok,elapsed,truncated,obs_file)
                                            工具结果(OK/Error/耗时/截断指针)
  system(step,text)                         系统事件(协议错误/同参拦截/零工具拒绝/强制收尾)
  final(step,payload)                       Final Answer 被接受输出(findings 计数)
  done(name,artifact,findings,steps,usage)  阶段完成(轮数/总耗时/token)

配置(环境变量,统一走 make_display 构造):
  STEP5_DISPLAY  0|none|off = 关闭; 2|full = 完整模式(Observation 多行);
                 空|1|compact = 紧凑单行(默认)
  STEP5_COLOR    1 = 强制 ANSI 色; 0 = 强制关; 缺省 = stdout 是终端才开
                 (Windows 终端自动启用 VT;重定向/CI 等非终端自动无色)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time

from .protocol import parse_reply

_THOUGHT_RE = re.compile(
    r"Thought:\s*(.*?)(?=\nAction:|\nAction Input:|\nFinal Answer:|\Z)", re.S)
_FENCE_RE = re.compile(r"```(?:json)?\s*(.+?)```", re.S)

# ANSI 转义(无色模式下全部原样返回)
_RESET, _DIM, _BOLD = "\033[0m", "\033[2m", "\033[1m"
_CYAN, _GREEN, _YELLOW, _RED, _BLUE, _MAGENTA = (
    "\033[36m", "\033[32m", "\033[33m", "\033[31m", "\033[34m", "\033[35m")


def _enable_win_ansi() -> None:
    """Windows 终端启用 ANSI VT 处理(经典 os.system("") 触发法);其他平台 no-op。"""
    if sys.platform == "win32":
        os.system("")


class NullDisplay:
    """显示关闭:所有事件 no-op(enabled=False 供调用方分支判断)。"""

    enabled = False

    def stage(self, *a, **k): ...
    def assistant(self, *a, **k): ...
    def observation(self, *a, **k): ...
    def system(self, *a, **k): ...
    def final(self, *a, **k): ...
    def done(self, *a, **k): ...
    def phase_done(self, *a, **k): ...
    def instance_tag(self, *a, **k): ...


class TerminalDisplay:
    """格式化事件并打印到 stdout。状态只有计时起点,无累积结构(无泄漏面)。"""

    enabled = True

    def __init__(self, mode: str = "compact", use_color: bool = True,
                 width: int | None = None, out=None):
        self.mode = mode
        self.out = out if out is not None else sys.stdout
        self.color = use_color
        self.width = width or shutil.get_terminal_size((100, 24)).columns
        self._t0 = 0.0
        self._narrow_warned = False  # 窄编码降级仅提示一次(防每条 ✓/⚠ 刷屏)
        if use_color:
            _enable_win_ansi()

    # ---- 基础设施 ----

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.color else text

    def _emit(self, line: str) -> None:
        # flush=True:stdout 接管道/重定向/后台运行时 Python 走块缓冲,
        # 不刷会把实时反馈积压到缓冲满才可见(2026-08-27 后台运行实测:
        # STEP5_DISPLAY=1 但捕获输出零显示行,仅 stderr 的 llm-retry 可见)。
        try:
            print(line, file=self.out, flush=True)
        except UnicodeEncodeError:
            # 窄编码 stdout(Windows 默认 GBK 控制台页)打 ✓/⚠ 等字符会抛
            # UnicodeEncodeError 并中断整个管线——违反本模块契约
            # "显示失败也不改变 Agent 行为"(2026-09-01 独立测试模式实发)。
            # 降级为按输出流编码替换不可编码字符后重打,流程照常推进。
            # 记录失败原因(铁律 4/10),仅提示一次防刷屏。
            enc = getattr(self.out, "encoding", None) or "utf-8"
            safe = line.encode(enc, errors="replace").decode(enc)
            if not self._narrow_warned:
                self._narrow_warned = True
                print(f"[display] 输出流编码 {enc} 无法表达部分字符,"
                      f"已降级替换(不影响 Agent 结果)", file=sys.stderr, flush=True)
            print(safe, file=self.out, flush=True)

    def _clip(self, text: str, limit: int) -> str:
        """压成单行并截断;超长以省略号结尾(全文已由 obs/ 与 transcript 兜底)。"""
        s = " ".join(text.split())
        return s if len(s) <= limit else s[: limit - 1] + "…"

    def _content_width(self) -> int:
        return max(40, self.width - 14)

    def _tag(self, step: int, color: str, label: str) -> str:
        return self._c(_DIM, f"[{step:02d}]") + " " + self._c(color, label)

    # ---- 事件方法(react_loop 钩子) ----

    def stage(self, name: str, label: str, tools: int, model: str,
              max_iters: int) -> None:
        self._t0 = time.time()
        self._emit("")
        self._emit(self._c(_CYAN, f"── {name} · {label} ") +
                   self._c(_DIM, "─" * 26))
        self._emit(self._c(_DIM,
                           f"   工具 {tools} · 模型 {model} · 迭代上限 {max_iters}"))

    def assistant(self, step: int, reply: str) -> None:
        """LLM 回复 → 思考行(有 Thought 就显)+ 调用行(Action 才显)。"""
        m = _THOUGHT_RE.search(reply)
        if m and m.group(1).strip():
            body = " ".join(m.group(1).split())
            self._emit(f"{self._tag(step, _YELLOW, '思考')}  "
                       + self._c(_DIM, self._clip(body, self._content_width())))
        kind, payload = parse_reply(reply)
        if kind == "action":
            name, _, raw = payload.partition("|")
            args = self._clip(raw, max(40, self.width - len(name) - 16))
            self._emit(f"{self._tag(step, _BLUE, '调用')}  "
                       + self._c(_BOLD, name) + self._c(_DIM, f"({args})"))

    def observation(self, step: int, tool: str, text: str, ok: bool,
                    elapsed: float | None = None, truncated: bool = False,
                    obs_file=None) -> None:
        if ok:
            status = self._c(_GREEN,
                             f"OK {elapsed:.2f}s" if elapsed is not None else "OK")
        else:
            status = self._c(_RED, "Error")
        # 紧凑取首行;完整模式取前 12 行(仍远小于入上下文的 16k 预算)
        lines = [l for l in text.splitlines() if l.strip()]
        if self.mode == "full" and len(lines) > 1:
            body = " | ".join(self._clip(l, self._content_width())
                              for l in lines[:12])
        else:
            body = self._clip(lines[0] if lines else text, self._content_width())
        pointer = ""
        if truncated and obs_file is not None:
            # save_obs 返回相对 process/ 的路径(str;测试可能传 Path,统一 str)
            pointer = self._c(_DIM, f"  …全文 {obs_file}")
        self._emit(f"{self._tag(step, _GREEN if ok else _RED, '结果')}  "
                   f"{status} · {body}{pointer}")

    def system(self, step: int, text: str) -> None:
        self._emit(f"{self._tag(step, _MAGENTA, '系统')}  "
                   + self._c(_MAGENTA, self._clip(text, self._content_width())))

    def final(self, step: int, payload: str) -> None:
        self._emit(f"{self._tag(step, _MAGENTA, '结论')}  {self._final_summary(payload)}")

    def done(self, name: str, artifact: str, findings: int, steps: int,
             usage: dict) -> None:
        dt = time.time() - self._t0 if self._t0 else 0.0
        tokens = sum(usage.get(k, 0) for k in ("prompt_tokens", "completion_tokens"))
        self._emit(self._c(
            _GREEN, f"── {name} 完成 · {artifact} · {findings} findings · "
                    f"{steps} 轮 · {dt:.1f}s · {tokens} tokens"))

    def phase_done(self, name: str, artifact: str, instances: int,
                   verified: int, total: int, steps: int, usage: dict,
                   elapsed_s: float = 0.0) -> None:
        """阶段级汇总行(#6,2026-09-03):verification 每疑点一实例后,单实例
        done 行(恒 1 findings)会误导为全阶段只复核 1 条——阶段聚合落盘后
        由 orchestrator 调本方法打真实全貌(实例数/已复核 x/N/合计)。
        耗时由调用方传入(阶段层 display 无 stage 计时起点,不能用 _t0)。"""
        tokens = sum(usage.get(k, 0) for k in ("prompt_tokens", "completion_tokens"))
        self._emit(self._c(
            _GREEN, f"── {name} 阶段完成 · {artifact} · {instances} 实例 · "
                    f"已复核 {verified}/{total} 条 · {steps} 轮 · "
                    f"{elapsed_s:.1f}s · {tokens} tokens"))

    def instance_tag(self, idx: int, total: int) -> None:
        """单实例完成前的序号标注(实例 i/N),让逐实例 done 行可辨识归属。"""
        self._emit(self._c(_DIM, f"── 实例 {idx}/{total}"))

    # ---- 内部 ----

    def _final_summary(self, payload: str) -> str:
        """Final Answer 摘要:能解析出 findings 就报数,否则截断原文。"""
        s = payload.strip()
        m = _FENCE_RE.search(s)
        if m:
            s = m.group(1)
        try:
            obj = json.loads(s)
            if isinstance(obj, dict) and isinstance(obj.get("findings"), list):
                return f"{len(obj['findings'])} findings(详见工件)"
        except (json.JSONDecodeError, ValueError):
            pass
        return self._clip(payload, 100)


def make_display() -> TerminalDisplay | NullDisplay:
    """按环境变量构造显示实例(runner 入口统一调用)。"""
    raw = os.environ.get("STEP5_DISPLAY", "").strip().lower()
    if raw in ("0", "none", "off"):
        return NullDisplay()
    mode = "full" if raw in ("2", "full") else "compact"
    color_env = os.environ.get("STEP5_COLOR", "").strip().lower()
    if color_env == "1":
        use_color = True
    elif color_env == "0":
        use_color = False
    else:
        use_color = sys.stdout.isatty()  # 非终端(管道/CI)自动无色
    return TerminalDisplay(mode=mode, use_color=use_color)

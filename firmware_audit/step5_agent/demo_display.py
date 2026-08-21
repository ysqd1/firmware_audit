"""终端监控显示演示(零 API 零 Docker,ScriptedLLM 回放)。

用法:
    python -m firmware_audit.step5_agent.demo_display            # 跟随环境变量
    STEP5_COLOR=1 python -m firmware_audit.step5_agent.demo_display   # 强制彩色
    STEP5_DISPLAY=full python -m firmware_audit.step5_agent.demo_display  # 完整模式

演示场景(三个 mini Agent,覆盖全部六类事件):
  场景1  正常流程: 思考 → 调用 → OK 结果 → 超长截断(带全文指针)→ 结论
  场景2  异常防御: 工具崩溃(Error)→ 同参调用第 4 次被拦截 → 收尾
  场景3  守卫触发: 零工具 Final 被拒 → 补查证 → 迭代上限强制收尾
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.engine.display import make_display
from firmware_audit.step5_agent.engine.react_loop import run_react_agent
from firmware_audit.step5_agent.providers.tools.base import (
    AgentTool,
    ToolContext,
    ToolResult,
)


class ScriptedLLM:
    """本地回放替身(demo 自包含,不依赖 test/ 目录)。"""

    def __init__(self, replies: list[str]):
        self.replies = list(replies)
        self.calls: list[list[dict]] = []
        self._idx = 0
        self.model = "scripted"

    def chat(self, messages: list[dict], **kw) -> tuple[str, dict]:
        self.calls.append(list(messages))
        return self.replies[self._idx], {"prompt_tokens": 0, "completion_tokens": 0}


class ChecksecTool(AgentTool):
    """回放 checksec 风格输出。"""

    name, description, params_doc = "checksec", "demo", "{}"

    def _run(self, **kw) -> ToolResult:
        return ToolResult(
            ok=True,
            text="unitree/bin/idlc: relro=partial  canary=no  nx=yes  pie=no",
        )


class BoomTool(AgentTool):
    """模拟工具内部崩溃(execute 捕获,循环不崩)。"""

    name, description, params_doc = "boom", "demo", "{}"

    def _run(self, **kw) -> ToolResult:
        raise RuntimeError("radare2 分析超时")


class BigTool(AgentTool):
    """返回 >8KB 文本,演示截断 + obs/ 全文指针。"""

    name, description, params_doc = "big", "demo", "{}"

    def _run(self, **kw) -> ToolResult:
        return ToolResult(
            ok=True,
            text="HEAD" + "A" * 6000 + "MIDDLE_LOST" + "B" * 2000 + "TAIL",
        )


def _tools():
    ctx = ToolContext(process_dir=Path("."))
    return {t.name: t(ctx) for t in (ChecksecTool, BoomTool, BigTool)}


def run_scene(title: str, replies: list[str], findings: int = 0,
              max_iters: int = 8) -> None:
    disp = make_display()
    disp.stage("demo-" + title.lower(), title, 3, "scripted", max_iters)
    with tempfile.TemporaryDirectory() as td:
        tr = Path(td) / "transcript.jsonl"
        r = run_react_agent(ScriptedLLM(replies), _tools(), "sys", "init",
                            max_iters=max_iters, transcript=tr, display=disp)
    disp.done("demo-" + title.lower(), "artifact.json", findings, r.steps,
              {"prompt_tokens": 1200, "completion_tokens": 300})


def main() -> int:
    # 场景1: 正常 + 超长截断
    run_scene("正常流程", [
        "Thought: 先确认这个自研二进制的保护属性,弱保护优先深挖。\n"
        'Action: checksec\nAction Input: {"file_ref": "unitree/bin/idlc"}',
        "Thought: 导入表太大,直接拉全文。\n"
        'Action: big\nAction Input: {}',
        'Final Answer: {"summary": "攻击面:1 个弱保护自研二进制", "findings": [{"title": "idlc 无 Canary", "severity": "medium"}]}',
    ], findings=1)

    # 场景2: 工具崩溃 + 同参拦截
    run_scene("异常防御", [
        "Thought: r2 查一下交叉引用。\nAction: boom\nAction Input: {}",
        "Thought: 再试一次。\nAction: boom\nAction Input: {}",
        "Thought: 还是失败,继续重试。\nAction: boom\nAction Input: {}",
        "Thought: 再来。\nAction: boom\nAction Input: {}",
        "Thought: 系统拦截了,换路收尾。\n"
        'Final Answer: {"summary": "boom 工具不可用", "findings": []}',
    ])

    # 场景3: 零工具拒绝 + 强制收尾(2 轮上限,第 2 轮仍发 Action → 强收尾)
    run_scene("守卫触发", [
        'Final Answer: {"summary": "不查就下结论", "findings": []}',
        "Thought: 被拒了,先查证。\n"
        'Action: checksec\nAction Input: {"file_ref": "unitree/bin/idlc"}',
        'Thought: 还想再查一个。\nAction: checksec\nAction Input: {"file_ref": "unitree/bin/idlc"}',
    ], max_iters=2)

    print("\n(demo 结束;STEP5_COLOR=1 看彩色,STEP5_DISPLAY=full 看多行模式)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

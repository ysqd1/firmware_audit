"""Step5 LLM 真机冒烟:deepseek-v4-flash 的 ReAct 协议遵循度。

默认 SKIP;需同时满足:
  - DEEPSEEK_API_KEY(或 LLM_API_KEY)已设
  - target/1 工件存在
跑法: $env:STEP5_SMOKE="1"; $env:DEEPSEEK_API_KEY="sk-..."; python test_step5_smoke.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.llm_client import LLMClient
from firmware_audit.step5_agent.engine.react_loop import run_react_agent
from firmware_audit.step5_agent.providers.tools import make_tools
from firmware_audit.step5_agent.providers.tools.base import ToolContext

PROCESS = Path(r"E:\固件\create\important\target\1\process")
SAMPLE_ELF = "unitree/bin/idlc"

SYSTEM_PROMPT = """你是固件安全审计助手。严格按 ReAct 协议输出,一次一块:

Thought: <推理>
Action: <工具名,必须来自可用工具表>
Action Input: <JSON 参数>

收到 Observation 后继续,调查充分后输出:

Final Answer: <结论>

可用工具:
{tool_docs}

规则:
- Action Input 必须是合法 JSON(单行)
- 一次只调一个工具
- Final Answer 用中文,证据带文件路径"""


def _ready() -> tuple[bool, str]:
    if os.environ.get("STEP5_SMOKE") != "1":
        return False, "未设 STEP5_SMOKE=1"
    # 与 llm_client 同一组别名(规范名 FIRMWARE_AUDIT_LLM_API_KEY 优先)
    if not (os.environ.get("FIRMWARE_AUDIT_LLM_API_KEY")
            or os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("LLM_API_KEY")):
        return False, "未设 API key"
    if not (PROCESS / "analysis" / "unitree" / "bin" / "idlc.c").exists():
        return False, "target/1 工件不存在"
    return True, ""


@pytest.fixture(scope="module")
def llm():
    """真机冒烟门控(同 _ready):STEP5_SMOKE=1 + API key + target/1 工件,缺一 SKIP。"""
    ok, why = _ready()
    if not ok:
        pytest.skip(why)
    return LLMClient()


def test_chat_roundtrip(llm) -> list[str]:
    fails: list[str] = []
    # v4-flash 是推理模型:思考耗 token,预算必须给足
    content, usage = llm.chat([{"role": "user", "content": "回复两个汉字:收到"}], max_tokens=2048)
    if not content.strip():
        fails.append(f"空回复: {content!r}")
    return fails


def test_react_real(llm, tools) -> list[str]:
    fails: list[str] = []
    docs = "\n".join(f"- {t.name}: {t.description}\n  参数: {t.params_doc}" for t in tools.values())
    prompt = SYSTEM_PROMPT.replace("{tool_docs}", docs)
    task = (f"审计对象清单在 process/fileinfo.json;样本 ELF: {SAMPLE_ELF}。\n"
            "任务:用 imports_query 查它的危险导入,若 popen/strcpy/sprintf 任一存在,"
            "用 find_decompiled_function 取一个调用者函数确认,然后 Final Answer 汇总(中文)。")
    result = run_react_agent(llm, tools, prompt, task, max_iters=8)
    if not result.finished:
        fails.append(f"未产出 Final Answer(steps={result.steps}, tool_calls={result.tool_calls})")
    if not result.tool_calls:
        fails.append("真机循环未调用任何工具(协议未遵循?)")
    print(f"  [INFO] steps={result.steps} tools={[c['tool'] for c in result.tool_calls]}")
    print(f"  [INFO] answer[:200]={result.final_answer[:200]}")
    return fails


def test_main() -> int:
    ok, why = _ready()
    if not ok:
        print(f"[SKIP] {why}")
        return 0
    llm = LLMClient()
    tools = make_tools(ToolContext(process_dir=PROCESS))

    failures = 0
    for name, fn in [
        ("chat_roundtrip", lambda: test_chat_roundtrip(llm)),
        ("react_real", lambda: test_react_real(llm, tools)),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"  [INFO] usage={llm.total_usage}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())

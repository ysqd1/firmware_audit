"""ReAct 纯文本协议解析(L3 纯函数层,零 IO 可独测)。

协议(agents.md 已定,不用 function calling):
  Thought: ...
  Action: tool_name
  Action Input: {"k": "v"}
  (Python 执行工具,回喂)
  Observation: ...
  Final Answer: ...

本模块只回答两个问题:这条回复是什么块(kind)、Action Input 是什么参数(dict)。
不关心循环、不落盘、不碰 LLM。react_loop 是唯一调用方(测试直接测这里)。
"""
from __future__ import annotations

import json
import re

ACTION_RE = re.compile(
    r"Action:\s*([A-Za-z_]\w*)\s*\n\s*Action Input:\s*(.+)",
    re.S,
)
FINAL_RE = re.compile(r"Final Answer:\s*(.+)", re.S)
JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.+?)```", re.S)
MAX_PARSE_FAILS = 2  # 连续解析失败达到此数即强制 Final Answer(react_loop 消费)


def parse_reply(reply: str) -> tuple[str, str]:
    """→ ('final', text) / ('action', 'name|input') / ('fail', reason)。

    Final Answer 与 Action 同现时,取原文中后出现者(模型常在收尾时补述)。
    """
    final_m = FINAL_RE.search(reply)
    act_m = ACTION_RE.search(reply)
    if final_m and (not act_m or final_m.start() > act_m.start()):
        return "final", final_m.group(1).strip()
    if act_m:
        name = act_m.group(1).strip()
        raw = act_m.group(2).strip()
        # Action Input 之后若跟着 Observation/Final Answer(模型自问自答),截断
        cut = re.split(r"\n\s*(?:Observation:|Final Answer:)", raw, maxsplit=1)[0].strip()
        return "action", f"{name}|{cut}"
    return "fail", "回复中没有 Action/Action Input 或 Final Answer 块"


def parse_action_input(raw: str) -> dict:
    """Action Input → dict;剥 ``` 围栏;空串/裸字符串容错为空参数。"""
    s = raw.strip()
    if not s:
        return {}
    m = JSON_FENCE_RE.search(s)
    if m:
        s = m.group(1).strip()
    try:
        data = json.loads(s)
        return data if isinstance(data, dict) else {"_raw": s}
    except json.JSONDecodeError:
        # 单值参数宽容:system(@ system) 这类裸符号 → {"value": ...}
        return {"value": s}

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
MAX_PARSE_FAILS = 4  # 连续解析失败达到此数即强制 Final Answer(react_loop 消费)
# 2026-08-22 从 2 放宽到 4: verification 的系统提示词长(防幻觉纪律多),模型
# 首轮概率性输出纯计划散文,连错 2 次就把整个复核阶段灭掉(实测 3 次运行 2 次崩);
# 放宽到 4 给自纠机会,死循环风险仍由同参守卫(MAX_REPEAT_CALLS)与迭代上限兜底。

# XML 角括号格式漂移归一化(2026-08-20 verification 实发,崩掉整个复核阶段):
# 推理模型偶发把协议块包成 <Action>x</Action> 形态(function calling 风格串扰),
# 正则匹配不上 → 连续协议错误 → 强制收尾。解析前先归一化成文本协议形态。
# 2026-08-22 实测两类变体(analysis 4 步崩的根因),归一化必须宽容:
#   ① <ActionInput>(无空格)与 <Action Input>(带空格)混用
#   ② 闭标签与开标签不配对: <Action Input>{...}</Action>(闭成 </Action>)
_ANGLE_TAG_RE = re.compile(
    r"<\s*(Action Input|ActionInput|Action|Final Answer|FinalAnswer)\s*>"
    r"\s*(.*?)\s*"
    r"<\s*/\s*(?:Action Input|ActionInput|Action|Final Answer|FinalAnswer)\s*>",
    re.S | re.I,
)
_TAG_CANON = {"action input": "Action Input", "actioninput": "Action Input",
              "action": "Action", "final answer": "Final Answer",
              "finalanswer": "Final Answer"}


def _normalize_tags(reply: str) -> str:
    """<Action>x</Action> → "Action: x"。开标签宽容(含无空格变体),
    闭标签不要求与开标签一致(LLM 常写错,见 _ANGLE_TAG_RE 注释);无标签原样返回。"""
    return _ANGLE_TAG_RE.sub(
        lambda m: f"{_TAG_CANON[m.group(1).lower()]}: {m.group(2)}", reply)


def parse_reply(reply: str) -> tuple[str, str]:
    """→ ('final', text) / ('action', 'name|input') / ('fail', reason)。

    Final Answer 与 Action 同现时,取原文中后出现者(模型常在收尾时补述)。
    解析前先做 XML 角括号归一化(见 _ANGLE_TAG_RE 注释)。
    """
    reply = _normalize_tags(reply)
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
        # 尾随散文宽容(2026-08-20 实发,烧 3 轮):推理模型常在合法 JSON 后
        # 继续输出思考文字 → 整串 loads 失败 → 旧逻辑包成 {"value": 整串},
        # 而没有任何工具接受 value 参数 → TypeError 空转。此处先救回首段 JSON。
        obj = _extract_leading_json(s)
        if obj is not None:
            return obj
        # 单值参数宽容:system(@ system) 这类裸符号 → {"value": ...}
        return {"value": s}


def _extract_leading_json(s: str) -> dict | None:
    """从"{...}尾随散文"形态提取首个完整 JSON 对象(花括号配平,字符串感知)。

    仅当提取物是合法 dict 时返回;否则 None(交由上层兜底)。
    """
    start = s.find("{")
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(s[start:i + 1])
                    return obj if isinstance(obj, dict) else None
                except json.JSONDecodeError:
                    return None
    return None

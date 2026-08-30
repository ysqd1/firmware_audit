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
# 行首锚定:只认行首的 Final Answer 块,句内出现的 "Final Answer:"(模型
# 自问自答/复述协议说明)不匹配——2026-08-29 实发 B1:模型长文本混入
# "Final Answer:" 字样,search 取到首个导致报告头部被垃圾污染。
FINAL_MARK = re.compile(r"(?m)^\s*Final Answer\s*:")
# 定位标记只找位置;内容提取在 parse_reply 对"最后一个标记"之后的文本做
# (re.S 贪婪会把后续块全吞进首个 match,finditer 无法逐块,故分两步)
FINAL_RE = re.compile(r"^\s*Final Answer\s*:\s*(.+)", re.S)
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

# 推理/正文包装标签剥离(2026-08-30 recon 实发 [03][07][10][14] 主因之二):
# mimo 系推理模型偶发把回复(正文里,或早期版本客户端拼接 thinking 后的整体)
# 包成 <reasoning>…</reasoning> / <text>…</text>。整行标签本身不破坏
# ACTION_RE 搜索,但当模型把工具调用写成"Action: 工具({JSON})" 单行、或
# <text> 里只写计划散文时整轮失效,且标签噪音污染显示与回喂。
# 行锚定只删"独占一行的标签",JSON 字符串里内联的 "<text>" 字样不受影响;
# llm_client 自 2026-08-30 起只把正文交给解析器,此处覆盖正文内仍带包装的形态。
_WRAP_TAG_RE = re.compile(
    r"(?m)^[ \t]*(?:</?(?:reasoning|thinking|thought|text)\b[^>\n]*>)[ \t]*\r?\n?")

# function-calling 风格串扰(2026-08-29 recon 实发):模型偶发把工具调用输出成
# OpenAI 工具语义 <tool_call>{"name": ..., "arguments": {...}}</tool_call>,
# 而非 ReAct 文本协议(Thought/Action/Action Input 行)——与纯文本 ReAct 体系
# 不兼容导致整个轮次被判协议失败(实测一跑 4 次:[03][07][10][14])。
# 解析兜底:定位 <tool_call 标记后做花括号配平提取,认证为工具调用形态才还原
# (容忍缺闭标签/arguments 内嵌套花括号,且只认开标签——闭标签 </tool_call>
# 之后的文本同属下一个块,不能当新调用的起点)。
_TOOL_CALL_MARK_RE = re.compile(r"<\s*tool_call\b", re.I)

# 单行 Action 兜底(2026-08-30 recon 实发 [03][07][10][14] 主因之一):
# function-calling 训练惯性的模型把调用写成"Action: 工具名 {JSON}"或
# "Action: 工具名({JSON})" 单行形态,而不是协议要求的"Action: 名 换行
# Action Input: JSON"两行结构;ACTION_RE 只认两行 → 整轮判协议失败。
# 兜底:行首找到 Action: 名字 后立即做花括号配平,JSON 是合法 dict 才接受。
_ACTION_INLINE_RE = re.compile(r"(?m)^[ \t]*Action:\s*([A-Za-z_]\w*)")


def _normalize_tags(reply: str) -> str:
    """<Action>x</Action> → "Action: x"。开标签宽容(含无空格变体),
    闭标签不要求与开标签一致(LLM 常写错,见 _ANGLE_TAG_RE 注释);无标签原样返回。"""
    return _ANGLE_TAG_RE.sub(
        lambda m: f"{_TAG_CANON[m.group(1).lower()]}: {m.group(2)}", reply)


def _strip_wrappers(reply: str) -> str:
    """剥 <reasoning>/<thinking>/<thought>/<text> 等独占一行的包装标签(见 _WRAP_TAG_RE)。"""
    return _WRAP_TAG_RE.sub("", reply)


def parse_reply(reply: str) -> tuple[str, str]:
    """→ ('final', text) / ('action', 'name|input') / ('fail', reason)。

    Final Answer 与 Action 同现时,取原文中后出现者(模型常在收尾时补述)。
    解析前先剥推理包装标签、再做 XML 角括号归一化(见 _ANGLE_TAG_RE 注释)。
    """
    reply = _strip_wrappers(_normalize_tags(reply))
    # 取**最后一个**行首 Final Answer 块(B1:模型收尾前可能多次自写/复述协议,
    # 真正的收尾在末尾;取最后避免把前文垃圾带进 payload)
    marks = list(FINAL_MARK.finditer(reply))
    final_m = marks[-1] if marks else None
    final_start = final_m.start() if final_m else -1
    act_m = ACTION_RE.search(reply)
    if final_m and (not act_m or final_start > act_m.start()):
        # 从最后一个标记处切到尾,剥掉 "Final Answer:" 前缀取正文
        seg = reply[final_start:]
        m = FINAL_RE.match(seg)
        return "final", m.group(1).strip() if m else ""
    if act_m:
        name = act_m.group(1).strip()
        raw = act_m.group(2).strip()
        # Action Input 之后若跟着 Observation/Final Answer/第二个 Action 块
        # (模型自问自答或整块重复),在首个 "换行 关键字" 处截断
        cut = re.split(r"\n\s*(?:Observation:|Final Answer:|Action:)", raw,
                       maxsplit=1)[0].strip()
        return "action", f"{name}|{cut}"
    # 单行 Action 兜底:"Action: 工具名 {JSON}" / "Action: 工具名({JSON})"
    # (严格两行结构与 Final 都缺席时才试,JSON 能配平成 dict 才接受)
    ia = _inline_action(reply)
    if ia is not None:
        return ia
    # function-calling 串扰兜底:<tool_call>{"name","arguments"}</tool_call>
    # (仅在常规块缺失时;缺闭标签/嵌套花括号同样可救)
    tc = _tool_call_action(reply)
    if tc is not None:
        return tc
    return "fail", "回复中没有 Action/Action Input 或 Final Answer 块"


def _inline_action(reply: str) -> tuple[str, str] | None:
    """行首 "Action: 名字" 后立即配平提取 JSON → ('action', 'name|json')。

    仅当 JSON 是合法 dict 才接受(防"Action: 建议换工具"这类散文字面被误判);
    JSON 需要补的第二行 "Action Input:" 缺失是模型常见漂移,这里代为补全。"""
    for m in _ACTION_INLINE_RE.finditer(reply):
        seg = reply[m.end():]
        obj = _extract_leading_json(seg)
        if obj is not None:
            return "action", f"{m.group(1)}|{json.dumps(obj, ensure_ascii=False)}"
    return None


def _tool_call_action(reply: str) -> tuple[str, str] | None:
    """定位首个 <tool_call 标记 → 花括号配平提取 JSON → 还原 action。

    无标记 / JSON 非工具调用形态返回 None(交由 fail 路径)。"""
    for m in _TOOL_CALL_MARK_RE.finditer(reply):
        obj = _extract_leading_json(reply[m.end():])
        if not isinstance(obj, dict):
            continue
        name = obj.get("name")
        args = obj.get("arguments")
        if not isinstance(name, str) or not name:
            continue
        if isinstance(args, dict):
            return "action", f"{name}|{json.dumps(args, ensure_ascii=False)}"
        if isinstance(args, str):
            return "action", f"{name}|{args}"
        return "action", f"{name}|{{}}"
    return None


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

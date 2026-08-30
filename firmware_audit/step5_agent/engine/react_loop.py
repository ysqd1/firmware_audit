"""ReAct 主循环(L2 状态机):拿到回复 → 解析 → 分发工具 → 回喂 → 收尾。

只负责状态流转,不做别的:
  协议解析   → protocol.py(纯函数)
  落盘       → transcript.py(Transcript)
  上下文     → context.py(ContextManager 四分区)
  工具执行   → tools/(AgentTool.execute,失败不崩,错误回喂)

失败语义:
  - 解析失败:回喂错误,连续 MAX_PARSE_FAILS 次后强制要求 Final Answer
  - 迭代上限:注入强制收尾指令,再给一次机会

循环守卫(2026-08-18,学 DeepAudit 实测坑):
  - 同参空转: 同一工具+完全相同参数超过 MAX_REPEAT_CALLS 次后不再执行,
    注入干预 Observation(改参数/换工具/收尾),防 LLM 卡死烧轮次
  - 工具先行: 从未调用任何工具就输出 Final Answer → 拒绝并退回
    (MAX_NO_TOOL_REJECTS 次);防 LLM 只看简报不查证直接下结论。
    强制收尾轮不设此门槛(上限已到,必须出答案)

终端监控(2026-08-19):display 参数为可选观察者(engine/display.py),
在各事件点喂事件,只格式化打印不参与控制流;None/NullDisplay 零开销。
"""
from __future__ import annotations

import json as _json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .context import ContextManager
from .display import NullDisplay
from .protocol import MAX_PARSE_FAILS, parse_action_input, parse_reply  # noqa: F401 (转发兼容旧 import)
from .transcript import Transcript

OBS_TRUNCATE_HINT = ("[本结果已截断;全文已存 {path},"
                     "可用 read_file 以 offset/limit 分页读取被省略的中间部分]")

# 同参循环干预:第 MAX_REPEAT_CALLS+1 次起拦截(前 3 次正常执行)
MAX_REPEAT_CALLS = 3
# 零工具 Final 拒绝次数上限:拒绝后仍坚持不调工具 → 放行(防死锁耗尽迭代)
MAX_NO_TOOL_REJECTS = 1

REPEAT_INTERVENE = ("Error: [系统干预] 工具 {name} 以完全相同参数已调用 {n} 次,"
                    "本次不再执行。请立即三选一:(1) 修改参数(缩小范围/换 file/换 pattern);"
                    "(2) 改用其他工具;(3) 基于已有 Observation 输出 Final Answer,"
                    "无法证实的项降低 confidence 或标注存疑。禁止原样重发同一调用。")
NO_TOOL_REJECT = ("Error: [系统拒绝] 你尚未调用任何工具就输出 Final Answer。"
                  "结论必须有 Observation 支撑:请先用至少一个工具查证"
                  "(如 read_file 读上游工件/目标产物),再输出 Final Answer。")

# 每轮进度提示(user 消息,每轮 LLM 调用前注入):让模型每次都知道"现在第几轮/总几轮"。
# 总数用函数实参 max_iters(由 AgentConfig 注入,不写死),模型可据此规划剩余取证深度。
ROUND_PROGRESS = ("[进度:{step}/{total}] 当前第 {step} 轮,共 {total} 轮,剩余 {left} 轮。"
                  "请控制取证深度,剩余预算优先投入高价值疑点(critical/high/网络入口)。")

# 最后一轮提示(r4,2026-08-19):第 max_iters 轮 LLM 调用前注入,给模型自主总结的机会;
# 若仍发 Action,由 FORCE_FINAL_PROMPT 兜底强制总结
LAST_ROUND_NOTICE = ("[系统提示] 本轮是最后一次循环机会(共 {n} 轮,已到上限)。"
                     "请不再发起新的取证,直接输出 Final Answer 收尾:"
                     "summary 字段写执行总结,必须包含三部分:"
                     "①当前任务执行情况(进行到哪一步);②已完成的工作与关键结论;"
                     "③未完成事项与后续建议(供下游 Agent 或人工接手)。"
                     "findings 字段输出已确认部分,已有证据不要丢弃。")
# 强制收尾指令(r4):要求结构化执行总结,不只是裸 Final Answer
FORCE_FINAL_PROMPT = ("已达到迭代上限,必须停止调用工具。立即输出 Final Answer:"
                      "summary 字段必须是执行总结,包含三部分:"
                      "①当前任务执行情况(进行到哪一步);②已完成的工作与关键结论;"
                      "③未完成事项与后续建议(供下游 Agent 或人工接手)。"
                      "findings 字段照常输出已确认部分,不要因收尾丢弃已取得的证据。")


@dataclass
class ReactResult:
    final_answer: str = ""
    steps: int = 0
    tool_calls: list = field(default_factory=list)
    finished: bool = False   # False = 迭代上限耗尽仍未给出 Final Answer

    @property
    def ok(self) -> bool:
        return self.finished and bool(self.final_answer)


def run_react_agent(
    llm,
    tools: dict,
    system_prompt: str,
    init_obs: str,
    max_iters: int = 20,
    transcript: Path | None = None,
    context: ContextManager | None = None,
    display=None,
) -> ReactResult:
    """跑一个 Agent 的 ReAct 循环。llm 需实现 chat(messages) -> (content, usage)。

    context 传入时用其四分区管理(超阈值自动压缩);None 时内部建默认实例。
    display 为终端监控观察者(engine/display.py),None 时零开销。
    """
    cm = context or ContextManager(system_prompt, init_obs)
    tr = Transcript(transcript)
    disp = display if display is not None else NullDisplay()
    result = ReactResult()
    parse_fails = 0
    force_final = False
    call_counts: dict[str, int] = {}   # 同参循环检测: name+kwargs 规范化键 → 次数
    no_tool_rejects = 0                # 零工具 Final 拒绝计数

    for step in range(1, max_iters + 1):
        result.steps = step
        cm.maybe_compact(llm)  # 每轮开跑前检查压缩
        # 每轮进度注入:以 system 角色注入(不进 recent,不破坏 user/assistant 交替),
        # 让 LLM 每次调用都明确"当前第几轮/总几轮"(max_iters 实参,不写死)。
        # 与 LAST_ROUND_NOTICE(最后一轮)、FORCE_FINAL_PROMPT(收尾)构成三层预算提示。
        cm.round_note = ROUND_PROGRESS.format(
            step=step, total=max_iters, left=max_iters - step)
        # 最后一轮(r4):LLM 调用前注入总结要求——模型有机会自主收尾;
        # 若仍发 Action,循环结束后由 _force_final_round 强制总结兜底
        if step == max_iters:
            cm.append("user", LAST_ROUND_NOTICE.format(n=max_iters))
            tr.log(step, "user", "[最后一轮提示] 要求输出含执行总结的 Final Answer")
            disp.system(step, f"最后一轮(上限 {max_iters}),要求总结收尾")
        messages = cm.build_messages()
        started = time.time()
        reply, usage = llm.chat(messages)
        # 正文/思考拆分(llm_client 2026-08-30):reply 只含正文——解析、
        # 上下文与回喂只用正文,防止推理段"草稿 Action"被当真执行;
        # 思考从 usage 取出拼回 transcript 留档审计(不参与解析/不长驻上下文)
        reasoning = usage.pop("reasoning_content", "") if usage else ""
        kind, payload = parse_reply(reply)
        # LLM 调用留痕:输出全文(思考+正文)+ 输入规模/usage/耗时
        # (完整输入可由 transcript 的 init/assistant/observation 序列重建)
        in_chars = sum(len(m.get("content", "")) for m in messages)
        tr.log(step, "assistant",
               f"{reasoning}\n{reply}".strip() if reasoning else reply,
               usage=usage,
               elapsed=time.time() - started, in_chars=in_chars)
        disp.assistant(step, reply)

        if kind == "final":
            # 工具先行守卫:零工具直接出结论 → 拒绝退回(限 MAX_NO_TOOL_REJECTS 次,
            # 防模型坚持不调工具时死锁烧光迭代;强制收尾路径不受此限)
            if not result.tool_calls and no_tool_rejects < MAX_NO_TOOL_REJECTS:
                no_tool_rejects += 1
                cm.append("assistant", reply)
                cm.append("user", f"Observation: {NO_TOOL_REJECT}")
                tr.log(step, "user", "[零工具 Final 拒绝] 退回要求先工具查证")
                disp.system(step, "零工具 Final 被拒绝,退回要求先工具查证")
                continue
            result.final_answer = payload
            result.finished = True
            # Final 也入上下文:保持 assistant/user 消息链完整
            # (拒绝分支已自行 append,此处在 return 前补正常路径)
            cm.append("assistant", reply)
            disp.final(step, payload)
            return result

        if kind == "fail":
            parse_fails, hint = _protocol_fail_hint(parse_fails, payload)
            force_final = parse_fails >= MAX_PARSE_FAILS
            cm.append("assistant", reply)
            cm.append("user", f"Observation: [协议错误] {hint}")
            tr.log(step, "user", f"[协议错误回喂] {hint}")
            disp.system(step, f"协议错误: {payload[:80]}")
            if force_final and parse_fails > MAX_PARSE_FAILS:
                result.final_answer = ""
                result.finished = False
                return result
            continue

        # ---- action ----
        name, _, raw_input = payload.partition("|")
        kwargs = parse_action_input(raw_input)

        # 立即留痕:调用发起即记(长耗时工具如 dispatch_agent 执行期间,
        # transcript 就能看到"已发起什么调用";结果由下方 tool/observation 补记)
        tr.log(step, "tool_call", f"{name}({raw_input[:200]})")

        # 同参循环守卫:同一工具+相同参数超过 3 次 → 拦截不执行,注入干预提示
        key = name.strip() + "|" + _json.dumps(
            kwargs, sort_keys=True, ensure_ascii=False, default=str)
        n = call_counts.get(key, 0) + 1
        call_counts[key] = n
        if n > MAX_REPEAT_CALLS:
            obs = REPEAT_INTERVENE.format(name=name.strip(), n=MAX_REPEAT_CALLS)
            cm.append("assistant", reply)
            cm.append("user", f"Observation: {obs}")
            tr.log(step, "user", f"[同参循环干预] {key[:160]}")
            disp.system(step, f"同参调用拦截: {name.strip()} 相同参数>{MAX_REPEAT_CALLS} 次")
            continue

        obs, obs_raw, truncated, log_extra = _dispatch(tools, name, raw_input, kwargs, result, step)
        # Observation 全文落盘(截断丢掉的部分可回查,兑现审计可回溯承诺)
        obs_file = tr.save_obs(step, name.strip(), f"Observation: {obs_raw}")
        # 截断发生时附加具体回读路径:相对 process/(与 read_file 白名单同根),
        # LLM 可直接 read_file(path=..., offset/limit) 分页取回省略的中间段
        disp.observation(step, name.strip(), obs, log_extra.get("ok", False),
                         log_extra.get("elapsed"), truncated, obs_file)
        if truncated and obs_file:
            obs += "\n" + OBS_TRUNCATE_HINT.format(path=obs_file)
        cm.append("assistant", reply)
        cm.append("user", f"Observation: {obs}")
        tr.log(step, "tool", f"{name}({raw_input[:200]})", **log_extra)
        tr.log(step, "observation", obs, obs_file=obs_file)

    return _force_final_round(llm, cm, tr, result, display=disp)


# ---- 循环内的三段小逻辑(抽出来让主循环四段一眼可读) ----

def _protocol_fail_hint(parse_fails: int, payload: str) -> tuple[int, str]:
    """解析失败计数 + 生成回喂提示。

    v3(2026-08-29,B3):提示同时给"继续调工具"与"已收尾直接 Final Answer"
    两条路——模型在总结/报告阶段常把报告散文当完整回复,仅教 ReAct 三步会
    把这一类散文回复继续引向多余 Action。
    """
    parse_fails += 1
    if parse_fails >= MAX_PARSE_FAILS:
        hint = ("连续解析失败。不要再输出 Action。"
                "立即输出 Final Answer(以已有信息总结)")
    else:
        hint = (f"格式错误: {payload}。严格用协议格式——两种形态只选其一:\n"
                "a) 仍需取证: Thought:<推理> 换行 Action:<工具名> 换行 "
                "Action Input:<JSON>;\n"
                "b) 已收尾/全部工作完成: 以行首 'Final Answer: ' 开头直接输出"
                "结论或报告正文(不要再发 Action)。\n"
                "注意: 工具名与参数 JSON 必须分别在 Action:/Action Input: 两行,"
                "不能把 JSON 直接放 Action 后,也不能用 <Action> 等标签包裹。")
    return parse_fails, hint


def _dispatch(tools: dict, name: str, raw_input: str, kwargs: dict,
              result: ReactResult, step: int):
    """执行工具 → (obs, obs_raw, truncated, log_extra)。未知工具/异常不崩。

    obs      入上下文的 Observation 文本(ok 时取截断后 text)
    obs_raw  截断前原文(落盘用);truncated 标记是否发生了截断
    """
    tool = tools.get(name.strip())
    if tool is None:
        obs = f"Error: 未知工具 '{name}'。可用: {', '.join(sorted(tools))}"
        return obs, obs, False, {"error": obs}
    tr = tool.execute(**kwargs)
    obs = tr.text if tr.ok else f"Error: {tr.error}"
    obs_raw = tr.raw if tr.ok else obs  # raw = 截断前原文
    truncated = tr.ok and len(obs_raw) > len(tr.text)
    log_extra = {"ok": tr.ok, "elapsed": tr.elapsed}
    result.tool_calls.append({"step": step, "tool": name.strip()})
    return obs, obs_raw, truncated, log_extra


def _force_final_round(llm, cm: ContextManager, tr: Transcript,
                       result: ReactResult, display=None) -> ReactResult:
    """迭代上限:注入强制收尾指令(要求结构化执行总结),给最后一次机会;收尾失败不抛。"""
    disp = display if display is not None else NullDisplay()
    cm.append("user", FORCE_FINAL_PROMPT)
    disp.system(result.steps + 1, "迭代上限,强制收尾(要求执行总结)")
    try:
        reply, usage = llm.chat(cm.build_messages())
        reasoning = usage.pop("reasoning_content", "") if usage else ""
        tr.log(result.steps + 1, "user", "[强制收尾指令]", usage=usage)
        tr.log(result.steps + 1, "assistant",
               f"{reasoning}\n{reply}".strip() if reasoning else reply)
        kind, payload = parse_reply(reply)
        if kind == "final":
            result.final_answer = payload
            result.finished = True
            disp.final(result.steps + 1, payload)
        else:
            # 收尾轮还在发 Action:截取全文当 best-effort 答案
            result.final_answer = reply[-2000:]
    except Exception:
        pass
    return result

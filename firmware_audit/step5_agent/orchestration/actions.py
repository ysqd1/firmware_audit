"""actions——编排动作与调度守卫(ADR-0009 T4)。

dispatch_agent/summarize/finish 三个编排动作工具类与其独享的前置校验同住
本模块:"一次调度的前置校验"不再跨类六连跳——顺序门/任务唯一性/次数上限/
上游工件/断点续跑判断/重复调度应答全部内聚在调度动作旁,编排主体
(orchestrator)只剩状态持有与登记。守卫行为与收编前逐字一致。

守卫为模块级纯函数(dispatches 显式传参,不读 host 状态):
order_violation / find_duplicate / agent_call_count / latest_upstream /
resume_degraded_enabled / executed_dispatches。

Host 回调面(依赖倒置:本模块永不 import orchestrator——orchestrator 构造
动作类时把自己作为 host 递入;对象层 orchestrator 装配三动作、被动作回调,
import 层单向 orchestrator → actions → handoff → state,环由 state 切断):
- 数据读: sub_cfgs / dispatches / agent_results / all_findings / process_dir /
  base_llm / agent_dir / force / verification_done
- 服务调: next_seq() / register(sub) / dispatch_log(T3 四动词对象) /
  budget_state(agent) / budget_state_text(agent) / rerun_suggestion(agent) /
  run_verification_phase(...)
- 状态写: summarize_called(property setter)
不上 typing.Protocol——单 adapter,第二个消费者出现再转正。

_VERIFY_SEVERITY_RANK/_VERIFY_CONFIDENCE_RANK 暂驻本模块(排序表是复核
引擎知识,不属共享词汇;SummarizeTool 与 orchestrator 的 verify 阶段双消费,
T5 迁 verify_phase 时一并带走)。
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .handoff import build_handoff, build_rerun_brief, save_handoff_snapshot
from .state import STATUS_LABEL, DispatchStatus, SubAgentResult
from ..aggregator import normalize_file_paths
from ..data.artifacts import load_artifact
from ..providers.llm_client import LLMError
from ..providers.tools import ToolContext
from ..providers.tools.base import AgentTool, ToolResult, truncate_text
from ..runner import run_agent

# 同一类型子 Agent 的调度次数上限(1 次默认 + 至多 2 次补跑;超出即拒绝)
MAX_DISPATCH_PER_AGENT = 3

# 阶段序(严格单向):recon → analysis → verification
_PHASE = {"recon": 0, "analysis": 1, "verification": 2}

# ADR-0003 排序 rank(severity 主排序 + confidence 次排序,从高到低)。
# 暂驻(见模块 docstring):T5 迁 verify_phase 时一并带走。
_VERIFY_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_VERIFY_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def _verified_mark(f: dict) -> str:
    """verified 三态标记:✓ 已证实 / ✗ 误报 / ⚠ 未复核(ADR-0003 报告要求)。

    verified=None(未进入前 K 的疑点)与 verified=False(复核为误报)必须区分:
    前者是"没复核",后者是"复核后否定"——报告若混用会把"漏审"伪装成"已否"。
    """
    if f.get("verified") is True:
        return "✓"
    if f.get("verified") is False:
        return "✗"
    return "⚠"


def _fmt_loc(f: dict) -> str:
    """finding 位置行(file + 可空的 func/addr)。已复核/未复核两区共用(去重)。"""
    return (f"   - 位置: {f.get('file', '')}"
            + (f" :: {f['func']}" if f.get('func') else "")
            + (f" @ {f['addr']}" if f.get('addr') else "")
            + "\n")


# ---- 调度守卫(模块级纯函数;dispatches 显式传参,逻辑与收编前逐字一致) ----

def order_violation(dispatches: list[SubAgentResult], agent: str) -> str | None:
    """顺序门:前段未完成不得调度后段;后段已启动不得回退(严格单向)。"""
    ph = _PHASE[agent]
    for lower, lph in _PHASE.items():
        if lph < ph and not any(
                d.agent_name == lower and d.status in DispatchStatus.DONE_OK
                for d in dispatches):
            return (f"顺序违规:调度 {agent} 前必须先完成 {lower} 阶段"
                    "(单向工作流 recon→analysis→verification,不得跳序)")
    if any(_PHASE[d.agent_name] > ph for d in dispatches):
        return (f"顺序违规:{agent} 所属阶段已被更后段阶段越过,"
                "不能回头调度(单向工作流 recon→analysis→verification)")
    return None


def find_duplicate(dispatches: list[SubAgentResult],
                   agent: str, task: str) -> SubAgentResult | None:
    """类型+任务唯一性检查:同 Agent 同任务(忽略大小写/空白)视为重复工作。"""
    key = " ".join(task.split()).lower()
    for d in dispatches:
        if d.agent_name == agent and d.status in (
                DispatchStatus.SUCCESS, DispatchStatus.SKIPPED,
                DispatchStatus.DEGRADED, DispatchStatus.FAILED):
            prior = " ".join((d.request.get("task") or "").split()).lower()
            if prior == key:
                return d
    return None


def agent_call_count(dispatches: list[SubAgentResult], agent: str) -> int:
    """同类型已调度次数(单一出处,T3 收敛):次数上限、补跑判定/轮次、
    剩余次数提示共用同一计数。"""
    return sum(1 for d in dispatches if d.agent_name == agent)


def latest_upstream(dispatches: list[SubAgentResult], agent: str) -> Path | None:
    """交接上游:最近一次已完成调度的工件(同类型多次调用时即其前次输出)。"""
    if _PHASE[agent] == 0:
        return None
    for d in reversed(dispatches):
        if (d.status in DispatchStatus.DONE_OK and d.artifact_path
                and d.artifact_path.is_file()
                and d.artifact_path.suffix == ".json"):
            return d.artifact_path
    return None


def resume_degraded_enabled() -> bool:
    """degraded 复跑开关:默认开启;STEP5_RESUME_DEGRADED=0 显式关闭。"""
    return (os.environ.get("STEP5_RESUME_DEGRADED", "1").strip()
            not in ("0", "false", "False"))


def executed_dispatches(dispatches: list[SubAgentResult]) -> list[SubAgentResult]:
    """已完成/实际执行的调度清单(单一出处,T3 收敛):summarize 统计、
    交接块、交接快照三处共用同一过滤,不再各拼一遍列表推导。"""
    return [d for d in dispatches if d.status in DispatchStatus.EXECUTED]


class DispatchAgentTool(AgentTool):
    """专用工具类:封装协调器对子 Agent 的调用逻辑(标准化 execute 接口)。

    内部委托 `run_agent`(同步执行,ReAct 循环天然串行),并按序强制守卫:
      1. 未知 agent 名拒绝
      2. 顺序门: 阶段单向 recon→analysis→verification,不得跳序/回退
      3. 类型+任务唯一性: 相同任务拒绝并返回历史结果,防工作内容重复
      4. 调度次数上限: 同类型最多 MAX_DISPATCH_PER_AGENT 次,超出拒绝
    另负责: 断点跳过、output_dir=<seq>_<type>、交接块注入、调度日志留痕
    (发起即记 running,返回后回填终态——子 Agent 执行细节不阻塞编排层记录)。
    API 失败(LLMError)不吞掉,向上传播立即终止(覆盖 execute 保留该语义)。
    """

    name = "dispatch_agent"
    description = ("调度并执行一个子 Agent(同步执行,返回其结果摘要)。"
                   f"recon/analysis 每个子 Agent 最多调度 {MAX_DISPATCH_PER_AGENT} 次,"
                   "且任务描述须与历史任务不同(相同任务会返回历史结果);"
                   "**verification 为每疑点一实例**:调度一次即对 analysis findings "
                   "按 severity+confidence 取前 K 条逐条派独立复核实例(不适用同类型"
                   "次数上限,K 上限见 STEP5_VERIFY_K);阶段顺序严格单向: "
                   "recon→analysis→verification。")
    params_doc = ('{"agent": "recon|analysis|verification", '
                  '"task": "<本次具体任务>", '
                  '"context": "<可选补充上下文>"}')

    def __init__(self, ctx: ToolContext, orch):
        # orch = 编排主体 host(回调面见模块 docstring;不上 Protocol——单 adapter)
        super().__init__(ctx)
        self.orch = orch

    def execute(self, **kw) -> ToolResult:
        """统一入口(同基类)但放行 LLMError:API 失败必须向上传播中止编排。"""
        start = time.time()
        try:
            result = self._run(**kw)
        except LLMError:
            raise
        except Exception as e:
            result = ToolResult(ok=False, text="", error=f"{type(e).__name__}: {e}")
        result.elapsed = round(time.time() - start, 3)
        result.raw = result.text
        result.text = truncate_text(result.text)
        return result

    def _run(self, agent: str = "", task: str = "", context: str = "", **kw) -> ToolResult:
        orch = self.orch
        agent = (agent or "").strip().lower()
        task = (task or "").strip()
        request = {"agent": agent, "task": task, "context": context}
        t0 = time.time()

        # ---- 1) 未知 agent ----
        if agent not in orch.sub_cfgs:
            msg = f"Agent '{agent}' 不存在,可用: recon, analysis, verification"
            orch.dispatch_log.attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=msg)
            return ToolResult(ok=False, text="", error=msg)

        # ---- 2) 顺序门:单向工作流(不得跳序/回退) ----
        violation = order_violation(orch.dispatches, agent)
        if violation:
            orch.dispatch_log.attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=violation)
            return ToolResult(ok=False, text="", error=violation)

        # ---- 3) 类型+任务唯一性:相同任务不重复执行 ----
        dup = find_duplicate(orch.dispatches, agent, task)
        if dup is not None:
            return self._duplicate_result(agent, task, request, dup, t0)

        # ---- 5) 上游工件(最近一次已完成调度的产出;数据层兜底) ----
        # 提前到上限检查之前:verification 需读上游 findings 才知道 N 与 K 切片
        upstream = latest_upstream(orch.dispatches, agent)
        if _PHASE[agent] > 0 and upstream is None:
            msg = (f"上游工件缺失,无法调度 {agent}"
                   "(单向工作流 recon→analysis→verification,请先完成前序阶段)")
            orch.dispatch_log.attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=msg)
            return ToolResult(ok=False, text="", error=msg)

        # ---- 4) 调度次数上限:同类型最多 MAX_DISPATCH_PER_AGENT 次 ----
        # verification 例外(ADR-0003):每疑点一实例,K 上限取代同类型次数上限,
        # 补跑逻辑整体取消;recon/analysis 维持原上限(动态分配机制保留)
        if agent != "verification":
            n_done = agent_call_count(orch.dispatches, agent)
            if n_done >= MAX_DISPATCH_PER_AGENT:
                msg = (f"{agent} 已调度 {n_done} 次,达到上限 {MAX_DISPATCH_PER_AGENT},"
                       "不可再调度;请推进下一阶段、summarize 或 finish")
                orch.dispatch_log.attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=msg)
                return ToolResult(ok=False, text="", error=msg)

        seq = orch.next_seq()

        # ---- verification 每疑点一实例(ADR-0003) ----
        if agent == "verification":
            if orch.verification_done:
                msg = ("verification 已完成(每疑点一实例:已按 severity+confidence "
                       "取前 K 条逐条复核);单向顺序门不允许重复调度,"
                       "请调用 summarize 取报告素材或 finish")
                orch.dispatch_log.attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=msg)
                return ToolResult(ok=False, text="", error=msg)
            assert upstream is not None  # 顺序门(上方)已保证 verification 有上游工件
            return orch.run_verification_phase(task, upstream, seq, request, t0)

        cfg = orch.sub_cfgs[agent]
        out_dir = orch.agent_dir / f"{seq}_{agent}"
        out_path = out_dir / cfg.output_name
        md_path = out_path.with_suffix(".md")
        has_json = out_path.is_file()
        has_md = md_path.is_file()

        # ---- 6) 断点续跑:.json 工件已存在且未 force → skipped ----
        #         仅 .md 降级工件:开关开 → 留痕 degraded 后落入执行路径**重跑**;
        #         开关关(STEP5_RESUME_DEGRADED=0) → 恢复旧跳过语义(该实例
        #         按 skipped 不再执行;注意下游仍需 .json 上游,见 latest_upstream)
        if (has_json or has_md) and not orch.force:
            if has_json:
                return self._resume_result(agent, task, request, seq, out_path,
                                           DispatchStatus.SKIPPED, t0)
            if not resume_degraded_enabled():
                # degraded 续跑被显式关闭:按旧语义当 skipped 跳过(兼容选项)
                return self._resume_result(agent, task, request, seq, md_path,
                                           DispatchStatus.SKIPPED, t0)
            # 默认:重跑该实例(防"失败被跳过"冒充成功);degraded 留痕供审计
            orch.dispatch_log.attempt(agent, task, request, DispatchStatus.DEGRADED, t0,
                                      artifact=str(md_path),
                                      error="仅存在降级 .md 工件,默认复跑")

        # ---- 7) 执行(交接块注入简报;发起即记 running,返回后回填终态) ----
        # 补跑(同类型第 2/3 次调度):交接块之外追加已覆盖清单 + 差分 task 提示,
        # 由 run_agent 经 extra_brief 透传给子 Agent 简报尾部(Task6.7)
        executed = executed_dispatches(orch.dispatches)
        handoff = build_handoff(agent, task, context, executed, orch.all_findings)
        if agent_call_count(orch.dispatches, agent) >= 1:
            handoff = build_rerun_brief(agent, handoff, orch.all_findings,
                                        agent_call_count(orch.dispatches, agent))
        save_handoff_snapshot(orch.orch_dir, seq, agent, task, context, handoff,
                              executed, len(orch.all_findings))
        rec = orch.dispatch_log.start(seq, agent, task, request)
        try:
            ares = run_agent(cfg, orch.process_dir, orch.base_llm, upstream,
                             output_dir=out_dir, extra_brief=handoff)
        except BaseException:
            # 异常向上传播(LLMError 终止整个 Step5 等):running 记录回填为
            # interrupted,不留悬挂的运行中状态
            orch.dispatch_log.interrupted(rec)
            raise
        elapsed = int((time.time() - t0) * 1000)
        if ares.ok and ares.artifact_path:
            status = DispatchStatus.SUCCESS
        elif ares.artifact_path and ares.artifact_path.suffix == ".md":
            status = DispatchStatus.DEGRADED   # 执行后仍只产出降级工件(ok=False)
        else:
            status = DispatchStatus.FAILED
        loaded = load_artifact(ares.artifact_path) if ares.artifact_path else None
        # 工件级溯源回填(schema v2):orchestrator 知道 seq,save 层不知道;
        # 把 instance_seq 写回子 Agent 工件,单看工件即可定位产出实例。
        # recon(v3 survey)跳过:survey 无 findings 字段,load_artifact 会注入空的
        # findings 键并回写磁盘——Task5 收口,不往 recon 工件塞 findings:[]。
        if loaded is not None and ares.artifact_path and agent != "recon":
            for f in loaded.get("findings", []) or []:
                if isinstance(f, dict) and f.get("instance_seq") is None:
                    f["instance_seq"] = seq
            if agent == "analysis":
                # file 字段归一成工具路径(ADR-0008,LLM 回退逻辑路径时兜底);
                # verification 不归一——title/file 不得改是它的硬纪律
                normalize_file_paths(loaded.get("findings", []) or [],
                                     orch.process_dir)
            try:  # noqa: SIM105 —— 保留 try-except:回填失败语义(pass + 注释)是明确意图
                ares.artifact_path.write_text(
                    json.dumps(loaded, ensure_ascii=False, indent=2),
                    encoding="utf-8")
            except OSError:
                pass  # 回填失败不阻塞调度(聚合层 _ingest 仍会补)
        react = ares.react
        # Task6.2 预算耗尽判定:steps 达到 max_iters(含最后一轮自主收尾/
        # FORCE_FINAL 强制收尾)或 react 未完成(finished=False,解析连续失败
        # 兜底终止)——ReactResult.finished 语义见 engine/react_loop.py
        budget_exhausted = bool(
            react and (react.steps >= cfg.max_iters or not react.finished))
        sub = SubAgentResult(
            seq=seq, agent_name=agent, status=status,
            artifact_path=ares.artifact_path,
            summary=(loaded or {}).get("summary", "") if loaded else "",
            findings=(loaded or {}).get("findings", []) or [],
            error=ares.error,
            request=request,
            usage=dict(ares.usage),
            duration_ms=elapsed,
            steps=react.steps if react else 0,
            tool_calls=[c for c in (react.tool_calls if react else [])],
            budget_exhausted=budget_exhausted,
        )
        orch.register(sub)
        # budget_state 于聚合后取(未覆盖疑点差分反映本实例产出后的最新状态),
        # overlap_ratio 为本实例 ingest 前与既有聚合的重合比例(register 内算)
        bstate = orch.budget_state(agent)
        orch.dispatch_log.finish(rec, status, duration_ms=elapsed,
                                 artifact=str(sub.artifact_path) if sub.artifact_path else None,
                                 summary=sub.summary, error=sub.error,
                                 budget_state=bstate)
        if status == DispatchStatus.SUCCESS:
            text = (f"## {agent} Agent 结果(成功,实例 {seq})\n"
                    f"发现数: {len(sub.findings)}\n摘要: {sub.summary}\n"
                    f"工件: {sub.artifact_path.name if sub.artifact_path else 'n/a'}\n"
                    f"(下一步: 推进下一阶段;全部完成后调用 summarize 取报告素材)\n"
                    + orch.budget_state_text(agent))
            suggestion = orch.rerun_suggestion(agent)
            if suggestion:
                text += "\n" + suggestion
            return ToolResult(ok=True, text=text)
        left = MAX_DISPATCH_PER_AGENT - agent_call_count(orch.dispatches, agent)
        return ToolResult(ok=False, text="",
                          error=(f"{agent} Agent 执行失败(实例 {seq}): {sub.error}\n"
                                 f"剩余可调度次数: {left} 次——可用**不同任务描述**"
                                 f"重试,或推进下一阶段/summarize 收尾"))

    def _resume_result(self, agent: str, task: str, request: dict, seq: int,
                       path: Path, status: str, t0: float) -> ToolResult:
        """断点续跑统一路径:skipped(.json 存在)/ degraded(仅 .md,ok=False)。"""
        orch = self.orch
        loaded = load_artifact(path)
        sub = SubAgentResult(
            seq=seq, agent_name=agent, status=status,
            artifact_path=path,
            summary=(loaded or {}).get("summary", "") if loaded else "",
            findings=(loaded or {}).get("findings", []) or [],
            error=("" if status == DispatchStatus.SKIPPED
                   else "仅存在降级 .md 工件(JSON 解析失败),结论不完整"),
            request=request,
            duration_ms=int((time.time() - t0) * 1000),
        )
        orch.register(sub)
        orch.dispatch_log.attempt(agent, task, request, status, t0, seq=seq,
                                  artifact=str(path), summary=sub.summary,
                                  error=sub.error, budget_state=orch.budget_state(agent))
        label = STATUS_LABEL.get(status, status)
        text = (f"## {agent} Agent 结果({label},实例 {seq})\n"
                f"发现数: {len(sub.findings)}")
        if status == DispatchStatus.DEGRADED:
            text += ("\n注意: 该实例仅有降级工件(.md),上一轮 JSON 解析失败,"
                     "findings 可能不完整;建议推进前评估是否需要补调。")
        return ToolResult(ok=(status == DispatchStatus.SKIPPED), text=text)

    def _duplicate_result(self, agent: str, task: str, request: dict,
                          dup: SubAgentResult, t0: float) -> ToolResult:
        """重复调度的 Observation:返回历史结果并指引改用不同任务描述。"""
        orch = self.orch
        art = dup.artifact_path.name if dup.artifact_path else "无"
        if dup.status in DispatchStatus.DONE_OK + (DispatchStatus.DEGRADED,):
            text = (f"## {agent} 重复调度被拒(类型+任务唯一性检查)\n"
                    f"历史实例 [seq={dup.seq}] 已用相同任务执行"
                    f"({STATUS_LABEL.get(dup.status, dup.status)})。\n"
                    f"结果摘要: {dup.summary or '(无摘要)'}\n"
                    f"工件: {art}(findings {len(dup.findings or [])} 条)\n"
                    "如确需补充工作,请给出**不同的任务描述**再次调度;"
                    "否则请推进下一阶段、summarize 或 finish。")
            orch.dispatch_log.attempt(agent, task, request, DispatchStatus.DUPLICATE, t0,
                                      artifact=str(dup.artifact_path) if dup.artifact_path else None,
                                      summary=dup.summary, duplicate_of=dup.seq)
            return ToolResult(ok=True, text=text)
        msg = (f"{agent} 相同任务此前已失败(实例 seq={dup.seq}): "
               f"{dup.error or '未知错误'};请改用不同任务描述,或基于已有结果收尾")
        orch.dispatch_log.attempt(agent, task, request, DispatchStatus.DUPLICATE, t0,
                                  error=dup.error, duplicate_of=dup.seq)
        return ToolResult(ok=False, text="", error=msg)


class SummarizeTool(AgentTool):
    """汇总动作(只读):聚合累计 findings 与各阶段统计,返回给协调器。

    双用途(参考 deepaudit _summarize_findings,但本工具不做 LLM 汇总):
    1. 决策辅助: 编排中途查看当前进展,决定补调/推进/收尾
    2. 报告素材: verification 完成后调用,Observation 即最终报告的写作素材
       (已复核/未复核**拆独立区段**:已复核带完整 confidence+rationale;
       未复核 verified=None 进 ⚠ 未复核区,confidence 保留 analysis 初值、
       rationale 为空——ticket 04,报告据此画未复核独立区段);协调器 LLM 的
       Final Answer 据此写报告,由 Orchestrator.run 落盘 report.md
    """

    name = "summarize"
    description = ("查看当前审计汇总(只读,不消耗子 Agent):累计 findings 清单、"
                   "各阶段统计与已复核明细。verification 完成后必须调用一次,"
                   "其返回值是最终总结报告的写作素材。")
    params_doc = '{"conclusion": "<可选:你当前的编排判断>"}'

    def __init__(self, ctx: ToolContext, orch):
        # orch = 编排主体 host(回调面见模块 docstring)
        super().__init__(ctx)
        self.orch = orch

    def _run(self, conclusion: str = "", **kw) -> ToolResult:
        orch = self.orch
        orch.summarize_called = True
        parts: list[str] = ["## 当前审计汇总"]
        if conclusion:
            parts.append(f"(编排判断: {conclusion})")

        # ---- 各阶段统计 ----
        done = executed_dispatches(orch.dispatches)
        parts.append(f"\n### 调度统计(实际执行 {len(done)} 次)")
        for d in done:
            art = d.artifact_path.name if d.artifact_path else "无"
            parts.append(
                f"- 实例[{d.seq}] {d.agent_name}「{(d.request.get('task') or '')[:40]}」:"
                f"{STATUS_LABEL.get(d.status, d.status)},工件 {art},"
                f"findings {len(d.findings or [])} 条,{d.steps} 轮,"
                f"{d.duration_ms}ms,usage={d.usage}")

        # ---- 预算状态(Task6:动态分配决策依据,LLM 可读单行 JSON) ----
        parts.append("\n### 预算状态(budget_state,补跑决策依据)")
        for name in orch.sub_cfgs:
            parts.append("- " + orch.budget_state_text(name))

        # ---- findings 分级清单(决策辅助) ----
        parts.append(f"\n### 累计 findings({len(orch.all_findings)} 条,已去重合并)")
        if orch.all_findings:
            for f in sorted(orch.all_findings,
                            key=lambda x: _VERIFY_SEVERITY_RANK.get(
                                str(x.get("severity", "info")).lower(), 9)):
                loc = f.get("file", "") + (f"::{f.get('func')}" if f.get("func") else "")
                parts.append(f"- [{f.get('severity', 'info')}] {_verified_mark(f)} {f.get('title', '?')} @ {loc}")
        else:
            parts.append("(暂无)")

        # ---- verification 完成时:注入报告写作素材(全量字段) ----
        vres = orch.agent_results.get("verification")
        if vres is not None and vres.artifact_path:
            loaded = load_artifact(vres.artifact_path) or {}
            vfindings = loaded.get("findings", []) or []
            # 单遍 partition:verified 非 None → 已复核;verified=None → 未复核
            verified_list = [f for f in vfindings if f.get("verified") is not None]
            unreviewed_list = [f for f in vfindings if f.get("verified") is None]
            verified_n = len(verified_list)
            parts.append(f"\n### 报告写作素材(verification 工件 {vres.artifact_path.name},"
                         f"已复核 {verified_n}/{len(vfindings)} 条;"
                         "已复核/未复核拆独立区段,全量字段如下)")
            parts.append(f"工件路径(read_file 可查): {vres.artifact_path}")
            parts.append(f"verification summary: {loaded.get('summary', '')}")

            # 已复核区:verified 非 None(true/false),完整 confidence + rationale
            parts.append(f"\n#### 已复核 findings({len(verified_list)} 条:"
                         "verified=true/false,完整 confidence + rationale)")
            for i, f in enumerate(verified_list, 1):
                parts.append(
                    f"{i}. [{f.get('severity', 'info')}] {_verified_mark(f)} {f.get('title', '?')}\n"
                    + _fmt_loc(f)
                    + f"   - confidence: {f.get('confidence', '') or '未标注'};"
                      f" verified={f.get('verified')}\n"
                    + f"   - rationale: {f.get('rationale', '')}\n"
                    + f"   - evidence: {str(f.get('evidence', ''))[:600]}\n")

            # 未复核区:verified=None(独立区段,⚠ 未经复核;confidence 保留 analysis 初值)
            parts.append(f"\n#### 未复核疑点({len(unreviewed_list)} 条,⚠ 未经复核:"
                         "verified=None 的疑点(未进入 verification 前 K 条,"
                         "或复核实例失败未产出结论),confidence 为 analysis 初值、"
                         "rationale 为空;禁止混入已复核区或标注为已证实)")
            for i, f in enumerate(unreviewed_list, 1):
                parts.append(
                    f"{i}. [{f.get('severity', 'info')}] {_verified_mark(f)} {f.get('title', '?')}\n"
                    + _fmt_loc(f)
                    + f"   - 未复核: confidence 保留 analysis 初值"
                      f"({f.get('confidence', '') or '未标注'}); rationale 为空\n")
            parts.append(
                "\n接下来: 输出 Final Answer —— 即最终 Markdown 审计报告正文"
                "(结构见系统提示词;内容只用以上素材,禁止编造)。")
        else:
            parts.append("\n(verification 未完成: 此汇总仅用于编排决策;"
                         "全部阶段完成后再次调用 summarize 取报告素材)")

        return ToolResult(ok=True, text="\n".join(parts))


class FinishTool(AgentTool):
    """声明编排完成的提示工具(收尾由协调器 LLM 以 Final Answer 汇总结论)。"""

    name = "finish"
    description = "声明审计编排完成,提示协调器汇总 audit 结论并输出 Final Answer。"
    params_doc = '{"conclusion": "<审计结论>"}'

    def _run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, text="编排完成。请输出 Final Answer 汇总 audit 结论。")


__all__ = ["MAX_DISPATCH_PER_AGENT",
           "order_violation", "find_duplicate", "agent_call_count",
           "latest_upstream", "resume_degraded_enabled", "executed_dispatches",
           "DispatchAgentTool", "SummarizeTool", "FinishTool"]

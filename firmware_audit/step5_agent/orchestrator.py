"""Orchestrator(协调器)——轻量 LLM 驱动的固件审计编排层(子 Agent 多次调用版)。

参考 deepaudit 的 OrchestratorAgent 思想做精简移植;v3(2026-08-28)在 v2 基础上:
- summarize 动作: verification 完成后由 orchestrator LLM 编写最终总结报告,
  主产物 process/agent/orchestrator/report.md(Final Answer 原样落盘);
  同时含可解析 JSON 时另存 report.json(可选结构化副产品)
- degraded 状态: 断点续跑只认 .json 成功工件;.md 降级工件标记 degraded
  (ok=False),复跑默认重跑该实例(防"失败被跳过"冒充成功)
- handoff 快照: 每次真实调度把交接结构化落盘 handoff_<seq>_<type>.json
- v2 保留: 多次调用(类型+任务唯一性)/严格顺序门/立即留痕 dispatch_log/
  中断回填 interrupted
- 动态分配(2026-08-29,Task6+Task7): 同类型上限 2→3;dispatch/summarize
  Observation 尾部呈现结构化 budget_state(exhausted/steps/pending_focuses/
  overlap_ratio);analysis 预算耗尽且仍有未覆盖疑点时附补跑建议;补跑
  dispatch 的简报追加已覆盖清单(前 30 条)与差分 task 提示

目录落盘 (以 process/agent/ 为根):
- orchestrator/  : transcript.jsonl(编排 LLM 输出)、dispatch_log.json(全量
                   调度史,含被拒尝试)、handoff_<seq>_<type>.json(交接快照)、
                   report.md(最终总结报告,summarize 产出)、result.json(终态)
- <seq>_<type>/  : 每次子 Agent 执行的 transcript.jsonl + obs/ + 产出工件

断点续跑: force=False 且该实例 .json 工件已存在 → status=skipped,加载已有工件;
.md 降级工件 → status=degraded,复跑(默认)。
API 失败(LLMError)不在工具层吞掉,向上传播立即终止(保持既有语义)。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .aggregator import FindingAggregator
from .data.artifacts import load_artifact, load_survey
from .data.prompts import build_system_prompt, build_verify_single_brief, save_system_prompt
from .engine.display import make_display
from .engine.react_loop import run_react_agent
from .providers.llm_client import LLMError
from .providers.tools import ToolContext
from .providers.tools.base import AgentTool, ToolResult, truncate_text
from .runner import ALL_CONFIGS, run_agent

# 多次调用下编排轮数上限:默认 3 次调度+summarize+收尾,余量留给补充调用
ORCH_MAX_ITERS = 12

# 同一类型子 Agent 的调度次数上限(1 次默认 + 至多 2 次补跑;超出即拒绝)
MAX_DISPATCH_PER_AGENT = 3

# budget_state 里 pending_focuses 的呈现上限(防异常大 survey 撑爆 Observation/
# 日志;pending_count 始终是全量数)
_BUDGET_FOCUS_LIMIT = 8

# ADR-0003:verification 每疑点一实例——K 上限(env STEP5_VERIFY_K,默认 10)
# 与排序 rank(severity 主排序 + confidence 次排序,从高到低)。
DEFAULT_VERIFY_K = 10
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


def _verify_k() -> int:
    """verification 每疑点一实例的调度预算(analysis findings 取前 K 条复核)。

    env STEP5_VERIFY_K 可配置(默认 10);非法值/缺失回落默认。K 即调度上限——
    同类型 3 次上限(MAX_DISPATCH_PER_AGENT)不适用于 verification:调度语义
    已改为按 finding 计数(K 上限),补跑逻辑整体取消(ADR-0003)。
    """
    raw = os.environ.get("STEP5_VERIFY_K", "").strip()
    try:
        k = int(raw) if raw else DEFAULT_VERIFY_K
    except ValueError:
        return DEFAULT_VERIFY_K
    return max(1, k)

# 阶段序(严格单向):recon → analysis → verification
_PHASE = {"recon": 0, "analysis": 1, "verification": 2}


# ---- 状态枚举(取代散落字符串;值即落盘值,与 dispatch_log/result.json 一致) ----

class DispatchStatus:
    """调度/实例状态全集(值域闭合,守卫测试断言)。"""
    RUNNING = "running"
    SUCCESS = "success"
    SKIPPED = "skipped"        # .json 工件已存在,跳过
    DEGRADED = "degraded"      # 仅 .md 降级工件存在(解析失败),复跑默认重跑
    FAILED = "failed"
    INTERRUPTED = "interrupted"  # 异常向上传播,running 记录回填
    REJECTED = "rejected"      # 顺序门/上限/未知 agent 等前置拒绝
    DUPLICATE = "duplicate"    # 类型+任务唯一性拒绝

    ALL = (RUNNING, SUCCESS, SKIPPED, DEGRADED, FAILED, INTERRUPTED, REJECTED, DUPLICATE)
    DONE_OK = (SUCCESS, SKIPPED)          # 视为完成的成功态
    EXECUTED = (SUCCESS, SKIPPED, DEGRADED, FAILED)  # 实际执行的调度(占 seq)


_STATUS_LABEL = {DispatchStatus.SUCCESS: "成功",
                 DispatchStatus.SKIPPED: "跳过(工件已存在)",
                 DispatchStatus.DEGRADED: "降级(仅 .md 工件,复跑)",
                 DispatchStatus.FAILED: "失败",
                 DispatchStatus.RUNNING: "运行中",
                 DispatchStatus.INTERRUPTED: "中断",
                 DispatchStatus.DUPLICATE: "重复(已拒绝)",
                 DispatchStatus.REJECTED: "拒绝"}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


# 提示词结构(2026-08-29 统一 8 节骨架,与三子 Agent 对齐):
# 角色 → 可调度子Agent/工作区 → 输入输出 → 执行流程 → 判定规范 → 红线 → 输出协议 → 纪律
_ORCH_TMPL = """## 1 角色与使命
你是固件安全审计的编排 Agent(Coordinator),负责自主协调整个固件审计流程。
你是整个审计流程的大脑,不是机械执行者:
1. 自主思考和决策,根据各子 Agent 的结果动态调整策略
2. 决定何时调度哪个子 Agent、何时完成审计
3. 审计完成后**亲自编写最终总结报告**(summarize 动作)

## 2 可调度的子 Agent
1. recon: 侦察 Agent —— 摸清固件攻击面,产出 survey.json(v3,无判级字段)
2. analysis: 深度分析 Agent —— 基于 survey.json 逐条取证,产出 findings.json
3. verification: 复核 Agent —— 基于 findings.json 逐条复核(**每疑点一实例**),
   产出 verified_findings.json(前 K 条带复核结论,未复核 verified=None)

## 3 输入与输出
- 数据流:子 Agent 工件链 survey.json → findings.json → verified_findings.json,
  你只经 dispatch_agent/summarize 的 Observation 摘要访问,不直接读文件
- 你的输出:审计完成后经 summarize 取素材,Final Answer 即最终报告(见 ## 5)

## 4 执行流程
可用操作(共 3 个,每轮只选一个):
### 1. 调度子 Agent(同步执行,返回其结果摘要)
Action: dispatch_agent
Action Input: {"agent": "recon|analysis|verification", "task": "<本次具体任务>", "context": "<可选补充上下文>"}

### 2. 查看汇总(只读,不消耗子 Agent)
Action: summarize
Action Input: {"conclusion": "<可选:你当前的编排判断>"}

summarize 返回当前累计 findings 清单与各阶段统计,供你决策;
**verification 完成后必须再调用一次 summarize**,它会返回报告写作素材
(已复核 findings + 阶段统计),随后你的 Final Answer 就是最终总结报告。

### 3. 完成审计
Action: finish
Action Input: {"conclusion": "<审计结论>"}

执行顺序与调度约束:
- 按序推进: recon → analysis → verification(上游工件是下游的输入,系统会校验顺序)
- recon/analysis 每个子 Agent 最多调度 %d 次: 默认各调度 1 次;仅当结果明显
  不完整(如 analysis 遗漏高危疑点)时,用**不同的任务描述**补充调度;相同
  任务描述会被视为重复工作直接拒绝并返回历史结果
- **verification 为每疑点一实例(ADR-0003)**:调度一次即自动对 analysis findings
  按 severity+confidence 取前 %d 条(env STEP5_VERIFY_K 可配置,默认 10)逐条派
  独立复核实例(不再适用同类型次数上限);每条必被验证,补跑逻辑整体取消;
  复核完成后不得重复调度(单向顺序门)
- 调度自动交接: 前序任务状态、最近工件与累计发现会自动注入子 Agent,
  你不需要手工搬运上下文

## 5 判定与输出规范
(summarize 之后)Final Answer 输出一份 Markdown 格式的固件安全审计报告,结构:
# 固件安全审计报告
## 执行概要(编排过程/各阶段轮次与耗时/结论一句话)
## 发现清单(按 severity 排列:每条含标题/位置/置信度/复核结论)
## 误报剔除(verified=false 的条目与理由)
## 编排判断与后续建议
报告内容必须来自 summarize Observation 提供的素材与各子 Agent 工件,
禁止编造未在素材中出现的 finding/路径/统计。

## 6 红线与边界
预算状态解读(budget_state):
summarize 与 dispatch_agent 的 Observation 尾部会给出结构化 budget_state
(单行 JSON: agent/exhausted/steps/max_iters/pending_count/pending_focuses/
overlap_ratio),用于动态分配决策:
- exhausted=true: 该子 Agent 已耗尽迭代预算(steps 达到 max_iters 或被系统
  强制收尾)。若为 analysis 且 pending_count>0,可对其追加调度(同类型累计
  不超过 %d 次),聚焦 pending_focuses 列出的未覆盖疑点
- pending_focuses: recon recommended_actions(priority=high/medium)中尚未
  被既有 findings 覆盖(title/file 差分)的疑点,已按 high_risk_areas 顺序
  排列;补跑的 task 必须与已覆盖项差分,并在任务描述中标注"第 N 轮补跑"
- overlap_ratio: 补跑实例与已有结果的重合比例(按 title/file 归一化匹配);
  overlap_ratio>0.5 说明重合严重,应聚焦差分——只查未覆盖疑点,不要重复
  提交已存在标题的 finding

## 7 输出协议
(每一步必须严格遵守;模板中 <...> 为占位符,输出时替换成实际内容,禁止原样输出尖括号占位符)
Thought: <你的思考过程>
Action: <dispatch_agent|summarize|finish>
Action Input: <JSON 参数,一行写完;此行之后立即停止输出,禁止追加任何文字>

禁止违反(违反即协议失败,系统回喂错误):
- Action: 工具({...}) 把 JSON 写在 Action 同行;或省略 Action Input: 行直接写 JSON/散文
- 用 <tool_call>/<text>/<reasoning> 等 XML 标签包裹协议块;先写计划散文再补协议块
- 自写/预写 Observation;同一轮出现两个 Action 块

收到 Observation(子 Agent 结果或系统提示)后再继续下一步;
全部阶段处理完毕后:调用 summarize 取报告素材 → 输出 Final Answer(即报告正文)。

## 8 重要原则
1. 你是大脑,不是执行器 —— 每一步都要思考,不要机械轮询
2. 质量优先 —— 宁可深入验证少量真实漏洞,不要浅尝辄止
3. 避免重复 —— 已完成的工作不重做;某子 Agent 失败则如实记入结论,
   换不同的任务描述补充或直接推进
4. 主动决策 —— 不等待不犹豫;全部阶段完成后 summarize → Final Answer 出报告"""

def _orch_system() -> str:
    """编排器系统提示词模板格式化(调度上限 + K 值在调用时注入)。

    K 取当前生效值 `_verify_k()`(env STEP5_VERIFY_K 可配置,默认 10),避免
    提示词与运行时实际复核条数不一致误导编排 LLM。无模块级常量:env 可能在
    import 之后才设置(测试/配置覆盖),延迟到构建时求值。
    """
    return _ORCH_TMPL % (MAX_DISPATCH_PER_AGENT, _verify_k(), MAX_DISPATCH_PER_AGENT)


@dataclass
class SubAgentResult:
    """单个子 Agent 执行的结果封装:状态/输出/错误/请求/统计,供协调器判断与传递。"""

    seq: int
    agent_name: str
    status: str = DispatchStatus.RUNNING   # DispatchStatus 值域
    artifact_path: Path | None = None
    summary: str = ""
    findings: list = field(default_factory=list)
    error: str = ""
    request: dict = field(default_factory=dict)      # dispatch_agent 请求参数
    usage: dict = field(default_factory=dict)
    duration_ms: int = 0
    steps: int = 0
    tool_calls: list = field(default_factory=list)
    # Task6 动态分配:预算耗尽标记(steps==max_iters 或 react 强制收尾未完成)
    budget_exhausted: bool = False
    # Task6 重合检测:该实例 findings 与既有聚合(title/file 归一化)的重复比例
    overlap_ratio: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status in DispatchStatus.DONE_OK and not self.error

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "agent": self.agent_name,
            "task": self.request.get("task", ""),
            "status": self.status,
            "artifact_path": str(self.artifact_path) if self.artifact_path else None,
            "summary": self.summary,
            "findings": self.findings,
            "error": self.error,
            "request": self.request,
            "usage": self.usage,
            "duration_ms": self.duration_ms,
            "steps": self.steps,
            "budget_exhausted": self.budget_exhausted,
            "overlap_ratio": self.overlap_ratio,
        }


def build_orchestrator_prompt(tools: dict, max_iters: int = ORCH_MAX_ITERS) -> str:
    """协调器系统提示词 = 角色/动作/纪律 + 工具清单 + 迭代预算。

    K 值动态注入(_orch_system),与运行时 STEP5_VERIFY_K 一致。
    """
    return build_system_prompt(_orch_system(), tools, max_iters=max_iters)


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

    def __init__(self, ctx: ToolContext, orchestrator: "Orchestrator"):
        super().__init__(ctx)
        self.orch = orchestrator

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
        if agent not in orch._sub_cfgs:
            msg = f"Agent '{agent}' 不存在,可用: recon, analysis, verification"
            orch._log_attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=msg)
            return ToolResult(ok=False, text="", error=msg)

        # ---- 2) 顺序门:单向工作流(不得跳序/回退) ----
        violation = orch._order_violation(agent)
        if violation:
            orch._log_attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=violation)
            return ToolResult(ok=False, text="", error=violation)

        # ---- 3) 类型+任务唯一性:相同任务不重复执行 ----
        dup = orch._find_duplicate(agent, task)
        if dup is not None:
            return orch._duplicate_result(agent, task, request, dup, t0)

        # ---- 5) 上游工件(最近一次已完成调度的产出;数据层兜底) ----
        # 提前到上限检查之前:verification 需读上游 findings 才知道 N 与 K 切片
        upstream = orch._latest_upstream(agent)
        if _PHASE[agent] > 0 and upstream is None:
            msg = (f"上游工件缺失,无法调度 {agent}"
                   "(单向工作流 recon→analysis→verification,请先完成前序阶段)")
            orch._log_attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=msg)
            return ToolResult(ok=False, text="", error=msg)

        # ---- 4) 调度次数上限:同类型最多 MAX_DISPATCH_PER_AGENT 次 ----
        # verification 例外(ADR-0003):每疑点一实例,K 上限取代同类型次数上限,
        # 补跑逻辑整体取消;recon/analysis 维持原上限(动态分配机制保留)
        if agent != "verification":
            n_done = sum(1 for d in orch._dispatches if d.agent_name == agent)
            if n_done >= MAX_DISPATCH_PER_AGENT:
                msg = (f"{agent} 已调度 {n_done} 次,达到上限 {MAX_DISPATCH_PER_AGENT},"
                       "不可再调度;请推进下一阶段、summarize 或 finish")
                orch._log_attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=msg)
                return ToolResult(ok=False, text="", error=msg)

        seq = orch._next_seq()

        # ---- verification 每疑点一实例(ADR-0003) ----
        if agent == "verification":
            if orch._verification_done:
                msg = ("verification 已完成(每疑点一实例:已按 severity+confidence "
                       "取前 K 条逐条复核);单向顺序门不允许重复调度,"
                       "请调用 summarize 取报告素材或 finish")
                orch._log_attempt(agent, task, request, DispatchStatus.REJECTED, t0, error=msg)
                return ToolResult(ok=False, text="", error=msg)
            assert upstream is not None  # 顺序门(上方)已保证 verification 有上游工件
            return orch._run_verification_phase(task, upstream, seq, request, t0)

        cfg = orch._sub_cfgs[agent]
        out_dir = orch.agent_dir / f"{seq}_{agent}"
        out_path = out_dir / cfg.output_name
        md_path = out_path.with_suffix(".md")
        has_json = out_path.is_file()
        has_md = md_path.is_file()

        # ---- 6) 断点续跑:.json 工件已存在且未 force → skipped ----
        #         仅 .md 降级工件:开关开 → 留痕 degraded 后落入执行路径**重跑**;
        #         开关关(STEP5_RESUME_DEGRADED=0) → 恢复旧跳过语义(该实例
        #         按 skipped 不再执行;注意下游仍需 .json 上游,见 _latest_upstream)
        if (has_json or has_md) and not orch.force:
            if has_json:
                return orch._resume_result(agent, task, request, seq, out_path,
                                           DispatchStatus.SKIPPED, t0)
            if not orch._resume_degraded_enabled():
                # degraded 续跑被显式关闭:按旧语义当 skipped 跳过(兼容选项)
                return orch._resume_result(agent, task, request, seq, md_path,
                                           DispatchStatus.SKIPPED, t0)
            # 默认:重跑该实例(防"失败被跳过"冒充成功);degraded 留痕供审计
            orch._log_attempt(agent, task, request, DispatchStatus.DEGRADED, t0,
                              artifact=str(md_path),
                              error="仅存在降级 .md 工件,默认复跑")

        # ---- 7) 执行(交接块注入简报;发起即记 running,返回后回填终态) ----
        # 补跑(同类型第 2/3 次调度):交接块之外追加已覆盖清单 + 差分 task 提示,
        # 由 run_agent 经 extra_brief 透传给子 Agent 简报尾部(Task6.7)
        handoff = orch._build_handoff(agent, task, context)
        if sum(1 for d in orch._dispatches if d.agent_name == agent) >= 1:
            handoff = orch._build_rerun_brief(agent, handoff)
        orch._save_handoff_snapshot(seq, agent, task, context, handoff)
        rec = orch._log_start(seq, agent, task, request)
        try:
            ares = run_agent(cfg, orch.process_dir, orch.base_llm, upstream,
                             output_dir=out_dir, extra_brief=handoff)
        except BaseException:
            # 异常向上传播(LLMError 终止整个 Step5 等):running 记录回填为
            # interrupted,不留悬挂的运行中状态
            orch._log_interrupted(rec)
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
        orch._register(sub)
        # budget_state 于聚合后取(未覆盖疑点差分反映本实例产出后的最新状态),
        # overlap_ratio 为本实例 ingest 前与既有聚合的重合比例(_register 内算)
        bstate = orch._budget_state(agent)
        orch._log_finish(rec, status, duration_ms=elapsed,
                         artifact=str(sub.artifact_path) if sub.artifact_path else None,
                         summary=sub.summary, error=sub.error,
                         budget_state=bstate)
        if status == DispatchStatus.SUCCESS:
            text = (f"## {agent} Agent 结果(成功,实例 {seq})\n"
                    f"发现数: {len(sub.findings)}\n摘要: {sub.summary}\n"
                    f"工件: {sub.artifact_path.name if sub.artifact_path else 'n/a'}\n"
                    f"(下一步: 推进下一阶段;全部完成后调用 summarize 取报告素材)\n"
                    + orch._budget_state_text(agent))
            suggestion = orch._rerun_suggestion(agent)
            if suggestion:
                text += "\n" + suggestion
            return ToolResult(ok=True, text=text)
        left = MAX_DISPATCH_PER_AGENT - sum(
            1 for d in orch._dispatches if d.agent_name == agent)
        return ToolResult(ok=False, text="",
                          error=(f"{agent} Agent 执行失败(实例 {seq}): {sub.error}\n"
                                 f"剩余可调度次数: {left} 次——可用**不同任务描述**"
                                 f"重试,或推进下一阶段/summarize 收尾"))


class SummarizeTool(AgentTool):
    """汇总动作(只读):聚合累计 findings 与各阶段统计,返回给协调器。

    双用途(参考 deepaudit _summarize_findings,但本工具不做 LLM 汇总):
    1. 决策辅助: 编排中途查看当前进展,决定补调/推进/收尾
    2. 报告素材: verification 完成后调用,Observation 即最终报告的写作素材
       (已复核 findings 全量字段 + 阶段统计);协调器 LLM 的 Final Answer
       据此写报告,由 Orchestrator.run 落盘 report.md
    """

    name = "summarize"
    description = ("查看当前审计汇总(只读,不消耗子 Agent):累计 findings 清单、"
                   "各阶段统计与已复核明细。verification 完成后必须调用一次,"
                   "其返回值是最终总结报告的写作素材。")
    params_doc = '{"conclusion": "<可选:你当前的编排判断>"}'

    def __init__(self, ctx: ToolContext, orchestrator: "Orchestrator"):
        super().__init__(ctx)
        self.orch = orchestrator

    def _run(self, conclusion: str = "", **kw) -> ToolResult:
        orch = self.orch
        orch._summarize_called = True
        parts: list[str] = ["## 当前审计汇总"]
        if conclusion:
            parts.append(f"(编排判断: {conclusion})")

        # ---- 各阶段统计 ----
        done = [d for d in orch._dispatches
                if d.status in DispatchStatus.EXECUTED]
        parts.append(f"\n### 调度统计(实际执行 {len(done)} 次)")
        for d in done:
            art = d.artifact_path.name if d.artifact_path else "无"
            parts.append(
                f"- 实例[{d.seq}] {d.agent_name}「{(d.request.get('task') or '')[:40]}」:"
                f"{_STATUS_LABEL.get(d.status, d.status)},工件 {art},"
                f"findings {len(d.findings or [])} 条,{d.steps} 轮,"
                f"{d.duration_ms}ms,usage={d.usage}")

        # ---- 预算状态(Task6:动态分配决策依据,LLM 可读单行 JSON) ----
        parts.append("\n### 预算状态(budget_state,补跑决策依据)")
        for name in orch._sub_cfgs:
            parts.append("- " + orch._budget_state_text(name))

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
        vres = orch._agent_results.get("verification")
        if vres is not None and vres.artifact_path:
            loaded = load_artifact(vres.artifact_path) or {}
            vfindings = loaded.get("findings", []) or []
            # 已复核数 = verified 非 None 的条数(未复核 verified=None 不计入)
            verified_n = sum(1 for f in vfindings
                             if f.get("verified") is not None)
            parts.append(f"\n### 报告写作素材(verification 工件 {vres.artifact_path.name},"
                         f"已复核 {verified_n}/{len(vfindings)} 条,全量字段如下)")
            parts.append(f"工件路径(read_file 可查): {vres.artifact_path}")
            parts.append(f"verification summary: {loaded.get('summary', '')}")
            for i, f in enumerate(vfindings, 1):
                lines = [
                    f"{i}. [{f.get('severity', 'info')}] {_verified_mark(f)} {f.get('title', '?')}\n",
                    f"   - 位置: {f.get('file', '')}"
                    f"{' :: ' + f['func'] if f.get('func') else ''}"
                    f"{' @ ' + f['addr'] if f.get('addr') else ''}\n",
                ]
                if f.get("verified") is None:
                    # 未复核疑点(ADR-0003):confidence 为 analysis 初值,rationale 空
                    lines.append(f"   - 未复核: confidence 保留 analysis 初值"
                                 f"({f.get('confidence', '') or '未标注'});"
                                 " rationale 为空\n")
                else:
                    lines.append(f"   - confidence: {f.get('confidence', '') or '未标注'};"
                                 f" verified={f.get('verified')}\n"
                                 f"   - rationale: {f.get('rationale', '')}\n"
                                 f"   - evidence: {str(f.get('evidence', ''))[:600]}\n")
                parts.append("".join(lines))
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


class Orchestrator:
    """协调器:统一调度三子 Agent(支持同类型多次调用),写编排痕迹并产出终态。

    调度史 _dispatches 记录所有实际执行(success/skipped/degraded/failed)的实例;
    _agent_results 按类型保留最新实例(供 step5_run 阶段统计与 summarize 消费)。
    """

    def __init__(self, process_dir: Path, base_llm, force: bool = False):
        self.process_dir = process_dir
        self.base_llm = base_llm
        self.force = force
        self.agent_dir = process_dir / "agent"
        self.orch_dir = self.agent_dir / "orchestrator"
        self._sub_cfgs = {c.name: c for c in ALL_CONFIGS}
        self._seq = 0
        self._agent_results: dict[str, SubAgentResult] = {}
        self._dispatches: list[SubAgentResult] = []   # 全部实际执行的调度(时序)
        self._dispatch_log: list[dict] = []           # 全量调度尝试(含拒绝/重复)
        self._agg = FindingAggregator()               # findings 聚合(去重/合并/重合计分)
        self._success = False
        self._final_answer = ""
        self._error = ""
        self._summarize_called = False
        self._report_path: Path | None = None
        # ADR-0003:verification 每疑点一实例——阶段已跑(防重复调度)与逐实例明细
        self._verification_done = False
        self._verification_instances: list[SubAgentResult] = []

    # ---- 调度辅助 ----

    def _next_seq(self) -> int:
        n = self._seq
        self._seq += 1
        return n

    def _register(self, sub: SubAgentResult) -> None:
        """登记一次实际执行:调度史 + 同类型取最新 + findings 聚合。

        聚合(委托 self._agg.ingest)前先计重合比例(Task6.5):新实例 findings
        与既有 all_findings 按(title+file 归一化)匹配的重复比例,存入实例供
        budget_state 与调度日志上报;recon 跳过(v3 无 findings,聚合层同跳)。
        """
        if sub.agent_name != "recon":
            sub.overlap_ratio = self._agg.overlap_ratio(sub.findings)
        self._dispatches.append(sub)
        self._agent_results[sub.agent_name] = sub
        self._agg.ingest(sub)

    # ---- ADR-0003: verification 每疑点一实例 ----

    def _run_verification_phase(self, task: str, upstream: Path,
                                seq: int, request: dict, t0: float) -> ToolResult:
        """verification 阶段(每疑点一实例):一次调度 → K 条独立实例 → 聚合工件。

        流程:读 analysis findings → severity 主排序 + confidence 次排序取前 K 条
        (STEP5_VERIFY_K,默认 10)→ 对每条派一个独立 verification 实例(max_iters=8,
        输入=单条 finding + 工件指针)→ 逐条产单条 verified finding → 聚合回
        verified_findings.json(全量 N 条:K 条带复核结论,N-K 条 verified=None,
        confidence 保留 analysis 初值)。补跑逻辑整体取消(每条必被验证)。
        """
        cfg = self._sub_cfgs["verification"]
        rec = self._log_start(seq, "verification", task, request)
        try:
            # 断点续跑(阶段级):聚合工件已存在且未 force → skipped
            agg_path = self.agent_dir / cfg.output_name
            if agg_path.is_file() and not self.force:
                loaded = load_artifact(agg_path) or {}
                sub = SubAgentResult(
                    seq=seq, agent_name="verification", status=DispatchStatus.SKIPPED,
                    artifact_path=agg_path,
                    summary=(loaded or {}).get("summary", ""),
                    findings=(loaded or {}).get("findings", []) or [],
                    request=request,
                    duration_ms=int((time.time() - t0) * 1000))
                self._register(sub)
                self._verification_done = True
                self._log_finish(rec, DispatchStatus.SKIPPED,
                                 artifact=str(agg_path), summary=sub.summary,
                                 budget_state=self._budget_state("verification"))
                verified = sum(1 for f in sub.findings
                               if f.get("verified") is not None)
                return ToolResult(ok=True, text=(
                    f"## verification Agent 结果(每疑点一实例,工件已存在,实例 {seq})\n"
                    f"已复核 {verified}/{len(sub.findings)} 条(其余未复核,verified=None)。"
                    f"工件: {agg_path.name}\n"
                    f"(下一步: 调用 summarize 取报告素材)"))

            # 源:analysis 已聚合 findings(跨多次调度去重合并后的全部候选 N 条)。
            # 不用最新 analysis 工件——多次调度时最新实例只有本轮的 findings,
            # 会丢前几轮已产出候选(ADR-0003 的 N 条候选 = 聚合全量)。
            src = [f for f in self.all_findings if isinstance(f, dict)]
            ranked = sorted(
                src,
                key=lambda f: (_VERIFY_SEVERITY_RANK.get(
                    str(f.get("severity", "info")).lower(), 9),
                    _VERIFY_CONFIDENCE_RANK.get(
                        str(f.get("confidence", "")).lower(), 9)))
            top = ranked[: _verify_k()]

            # 逐条派独立实例(每条必跑;补跑逻辑整体取消)
            instances = [self._run_verify_one(self._next_seq(), f, upstream,
                                              task, request)
                         for f in top]
            self._verification_instances = instances

            # 聚合:全量 N 条(K 覆盖复核结论,N-K 原样 verified=None + confidence 初值)
            # 锚点=各实例对应的原 analysis finding(按实例序与 top 对齐):复核结果
            # 回填到原槽位——实例返回的 finding 常缺 addr/func,按 dedup_key 会错位
            # 成新条目;以原 finding 的键锚定,verified/rationale/confidence 覆盖,
            # 未进前 K 的条目原样保留(verified=None,confidence 保留 analysis 初值)。
            # 复核结论回填:只覆盖复核权威字段(verified/rationale/confidence),不
            # 重排锚点——实例返回的 finding 可能缺 addr/func 或改 title,一律忽略
            # 身份字段,防"换成别的 finding"混入(VERIFY_SYSTEM 单条必达红线 + 代码兜底)。
            by_key = {self._agg.dedup_key(f): f for f in ranked}
            verified_n = 0
            for anchor, v in zip(top, instances):
                if not v.findings:
                    continue                    # 实例失败/无产出:该条保持未复核
                vf = v.findings[0]
                merged = dict(by_key[self._agg.dedup_key(anchor)])
                merged["verified"] = vf.get("verified")      # True/False/None 照收
                if vf.get("rationale"):
                    merged["rationale"] = vf["rationale"]    # 存疑项可能留空
                if vf.get("confidence"):
                    merged["confidence"] = vf["confidence"]  # 存疑降级;无则留初值
                merged["source_agent"] = "verification"
                merged["instance_seq"] = v.seq
                by_key[self._agg.dedup_key(anchor)] = merged
                if merged["verified"] is not None:
                    verified_n += 1
            phase_findings = list(by_key.values())

            phase_summary = (f"已复核 {verified_n}/{len(ranked)} 条"
                             f"(未进入前 {len(top)} 的 {len(ranked) - len(top)}"
                             " 条未复核,verified=None,confidence 保留 analysis 初值)")
            out_path = self.agent_dir / cfg.output_name
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps({
                "schema": 2, "agent": "verification", "summary": phase_summary,
                "findings": phase_findings,
            }, ensure_ascii=False, indent=2), encoding="utf-8")

            # 阶段终态:全部实例 SUCCESS/SKIPPED → success;任一 FAILED/DEGRADED
            # (仅 .md 降级工件,该条结论不完整)→ 阶段降级/失败,如实上报不冒充
            bad = [v for v in instances
                   if v.status in (DispatchStatus.FAILED, DispatchStatus.DEGRADED)]
            if not bad:
                status = DispatchStatus.SUCCESS
            elif all(v.status == DispatchStatus.DEGRADED for v in bad):
                status = DispatchStatus.DEGRADED
            else:
                status = DispatchStatus.FAILED
            phase = SubAgentResult(
                seq=seq, agent_name="verification", status=status,
                artifact_path=out_path, summary=phase_summary,
                findings=phase_findings,
                error="; ".join(v.error for v in bad),
                request=request,
                duration_ms=int((time.time() - t0) * 1000),
                steps=sum(v.steps for v in instances),
                tool_calls=[c for v in instances for c in v.tool_calls],
                budget_exhausted=any(v.budget_exhausted for v in instances))
            self._register(phase)
            self._verification_done = True
            self._log_finish(rec, status, duration_ms=phase.duration_ms,
                             artifact=str(out_path), summary=phase_summary,
                             error=phase.error,
                             budget_state=self._budget_state("verification"))
            if status == DispatchStatus.SUCCESS:
                return ToolResult(ok=True, text=(
                    f"## verification Agent 结果(每疑点一实例,成功,实例 {seq})\n"
                    f"已复核 {verified_n}/{len(ranked)} 条(共 {len(ranked)} 条;"
                    f"未进入前 {len(top)} 的未复核,verified=None)\n"
                    f"工件: {out_path.name}\n"
                    f"(下一步: 调用 summarize 取报告素材)\n"
                    + self._budget_state_text("verification")))
            return ToolResult(ok=False, text="", error=(
                f"verification 阶段失败(实例 {seq}): {phase.error}"))
        except LLMError:
            self._log_interrupted(rec)
            raise
        except Exception as e:
            self._log_finish(rec, DispatchStatus.FAILED,
                             error=f"{type(e).__name__}: {e}",
                             budget_state=self._budget_state("verification"))
            return ToolResult(ok=False, text="", error=(
                f"verification 阶段失败(实例 {seq}): {type(e).__name__}: {e}"))

    def _run_verify_one(self, vseq: int, finding: dict, upstream: Path,
                        task: str, request: dict) -> SubAgentResult:
        """单条 finding 的独立 verification 实例(ADR-0003)。

        输入=单条 finding + 工件指针(build_verify_single_brief),输出=单条
        verified finding;上下文隔离铁律不破(只从工件读,不传对话历史)。
        """
        cfg = self._sub_cfgs["verification"]
        out_dir = self.agent_dir / f"{vseq}_verification"
        out_path = out_dir / cfg.output_name
        t0 = time.time()
        # 单实例不进主 dispatch_log(ADR-0003:逐实例留痕在其自身 transcript/obs +
        # result.json 的 verification_instances;主 dispatch_log 只记编排调度(阶段))
        try:
            # 断点续跑(单实例):该实例 .json 工件已存在且未 force → skipped
            if out_path.is_file() and not self.force:
                loaded = load_artifact(out_path) or {}
                vfs = [f for f in (loaded.get("findings") or [])
                       if isinstance(f, dict)]
                return SubAgentResult(
                    seq=vseq, agent_name="verification", status=DispatchStatus.SKIPPED,
                    artifact_path=out_path, summary=loaded.get("summary", ""),
                    findings=vfs, request=request,
                    duration_ms=int((time.time() - t0) * 1000))
            ares = run_agent(cfg, self.process_dir, self.base_llm, upstream,
                             output_dir=out_dir,
                             extra_brief=build_verify_single_brief(
                                 self.process_dir, finding))
            elapsed = int((time.time() - t0) * 1000)
            if ares.ok and ares.artifact_path:
                status = DispatchStatus.SUCCESS
            elif ares.artifact_path and ares.artifact_path.suffix == ".md":
                status = DispatchStatus.DEGRADED
            else:
                status = DispatchStatus.FAILED
            loaded_v = (load_artifact(ares.artifact_path)
                        if ares.artifact_path else None)
            vfs = [f for f in (loaded_v or {}).get("findings", []) or []
                   if isinstance(f, dict)]
            for f in vfs:                 # 溯源:该条复核结论产自本实例
                f["source_agent"] = "verification"
                f["instance_seq"] = vseq
            react = ares.react
            budget_exhausted = bool(
                react and (react.steps >= cfg.max_iters or not react.finished))
            return SubAgentResult(
                seq=vseq, agent_name="verification", status=status,
                artifact_path=ares.artifact_path,
                summary=(loaded_v or {}).get("summary", ""),
                findings=vfs, error=ares.error, request=request,
                usage=dict(ares.usage), duration_ms=elapsed,
                steps=react.steps if react else 0,
                tool_calls=[c for c in (react.tool_calls if react else [])],
                budget_exhausted=budget_exhausted)
        except LLMError:
            raise  # 阶段层捕获并回填 interrupted

    # ---- Task6: 动态分配与重合检测(budget_state / pending_focuses / overlap_ratio) ----

    def _pending_focuses(self) -> list[str]:
        """未覆盖疑点清单(Task6.4):recon survey 的 recommended_actions
        (priority=high/medium)∩ 未出现在已聚合 all_findings 的项。

        差分规则(simple contains/normalize):action 文本(含文件名/疑点描述)
        归一化后包含某条 finding 的 file 或 title(均归一化)即视为已覆盖;
        排序按 recon high_risk_areas 中 file 出现顺序(未命中者保序靠后)。
        recon 未产出/工件缺失/无 survey 结构时返回空列表。
        """
        recon = self._agent_results.get("recon")
        if recon is None or recon.artifact_path is None:
            return []
        survey = load_survey(recon.artifact_path)
        if survey is None:
            return []
        actions: list[str] = []
        for a in survey.get("recommended_actions") or []:
            if not isinstance(a, dict):
                continue
            if str(a.get("priority", "")).strip().lower() not in ("high", "medium"):
                continue
            text = str(a.get("action", "")).strip()
            if text:
                actions.append(text)
        if not actions:
            return []
        covered = set()
        for f in self._agg.all_findings:
            if not isinstance(f, dict):
                continue
            for k in ("title", "file"):
                n = self._agg.norm_text(f.get(k, ""))
                if n:
                    covered.add(n)
        pending = [a for a in actions
                   if not any(c in self._agg.norm_text(a) for c in covered)]
        # 排序锚点:high_risk_areas 的 file 出现顺序(去重保序)
        order: list[str] = []
        for h in survey.get("high_risk_areas") or []:
            if isinstance(h, dict):
                f = self._agg.norm_text(h.get("file", ""))
                if f and f not in order:
                    order.append(f)

        def _rank(action: str) -> int:
            n = self._agg.norm_text(action)
            for i, f in enumerate(order):
                if f and f in n:
                    return i
            return len(order)   # 未命中排最后,稳定排序保序

        return sorted(pending, key=_rank)

    def _budget_state(self, agent: str) -> dict:
        """结构化预算状态(Task6.3):该类型最新实例的 exhausted/steps/
        max_iters/pending_count/pending_focuses/overlap_ratio;summarize 与
        dispatch Observation、dispatch_log/result.json 共用此投影。"""
        cfg = self._sub_cfgs.get(agent)
        max_iters = cfg.max_iters if cfg else 0
        sub = self._agent_results.get(agent)
        if sub is None:
            return {"agent": agent, "exhausted": False, "steps": 0,
                    "max_iters": max_iters, "pending_count": 0,
                    "pending_focuses": [], "overlap_ratio": 0.0}
        focuses = self._pending_focuses()
        return {
            "agent": agent,
            "exhausted": bool(sub.budget_exhausted),
            "steps": sub.steps,
            "max_iters": max_iters,
            "pending_count": len(focuses),
            "pending_focuses": focuses[:_BUDGET_FOCUS_LIMIT],
            "overlap_ratio": round(float(sub.overlap_ratio), 4),
        }

    def _budget_state_text(self, agent: str) -> str:
        """budget_state 的 Observation 投影(单行 JSON,LLM 可读)。"""
        return "budget_state: " + json.dumps(
            self._budget_state(agent), ensure_ascii=False)

    def _rerun_suggestion(self, agent: str) -> str:
        """补跑建议段(Task6.6):仅 analysis 预算耗尽、仍有未覆盖疑点且
        调度次数未达上限时给出;其余场景返回空串(Observation 不附)。"""
        state = self._budget_state(agent)
        n_done = sum(1 for d in self._dispatches if d.agent_name == agent)
        if not (agent == "analysis" and state["exhausted"]
                and state["pending_count"] > 0
                and n_done < MAX_DISPATCH_PER_AGENT):
            return ""
        top = state["pending_focuses"][:3]
        lines = [
            "## 补跑建议(结构化)",
            f"可对 analysis 追加第 {n_done + 1} 轮补跑"
            f"(还剩 {MAX_DISPATCH_PER_AGENT - n_done} 次):优先疑点:",
        ]
        lines.extend(f"- {f}" for f in top)
        lines.append("task 必须与已覆盖项差分:聚焦上述未覆盖疑点,"
                     "禁止重复提交已存在标题的 finding。")
        return "\n".join(lines)

    def _build_rerun_brief(self, agent: str, handoff: str,
                           max_findings: int = 30) -> str:
        """补跑简报增补(Task6.7):既有交接块 + 已覆盖清单(all_findings 的
        title/file,前 30 条)+ 差分 task 提示;经 extra_brief 注入子 Agent
        简报尾部(run_agent 透传),配合 ANALYSIS_SYSTEM 补跑红线食用。"""
        round_no = sum(1 for d in self._dispatches
                       if d.agent_name == agent) + 1
        lines = [handoff, "",
                 f"--- 已覆盖清单(前 {max_findings} 条,编排器注入) ---"]
        if self._agg.all_findings:
            for f in self._agg.all_findings[:max_findings]:
                lines.append(f"- {f.get('title', '?')} @ {f.get('file', '')}")
            if len(self._agg.all_findings) > max_findings:
                lines.append(f"...(共 {len(self._agg.all_findings)} 条,余下省略)")
        else:
            lines.append("(暂无已覆盖 findings)")
        lines.append(f"本实例为第 {round_no} 轮补跑,聚焦未覆盖疑点,"
                     "禁止重复提交已存在标题")
        return "\n".join(lines)

    def _order_violation(self, agent: str) -> str | None:
        """顺序门:前段未完成不得调度后段;后段已启动不得回退(严格单向)。"""
        ph = _PHASE[agent]
        for lower, lph in _PHASE.items():
            if lph < ph and not any(
                    d.agent_name == lower and d.status in DispatchStatus.DONE_OK
                    for d in self._dispatches):
                return (f"顺序违规:调度 {agent} 前必须先完成 {lower} 阶段"
                        "(单向工作流 recon→analysis→verification,不得跳序)")
        if any(_PHASE[d.agent_name] > ph for d in self._dispatches):
            return (f"顺序违规:{agent} 所属阶段已被更后段阶段越过,"
                    "不能回头调度(单向工作流 recon→analysis→verification)")
        return None

    def _find_duplicate(self, agent: str, task: str) -> SubAgentResult | None:
        """类型+任务唯一性检查:同 Agent 同任务(忽略大小写/空白)视为重复工作。"""
        key = " ".join(task.split()).lower()
        for d in self._dispatches:
            if d.agent_name == agent and d.status in (
                    DispatchStatus.SUCCESS, DispatchStatus.SKIPPED,
                    DispatchStatus.DEGRADED, DispatchStatus.FAILED):
                prior = " ".join((d.request.get("task") or "").split()).lower()
                if prior == key:
                    return d
        return None

    def _latest_upstream(self, agent: str) -> Path | None:
        """交接上游:最近一次已完成调度的工件(同类型多次调用时即其前次输出)。"""
        if _PHASE[agent] == 0:
            return None
        for d in reversed(self._dispatches):
            if (d.status in DispatchStatus.DONE_OK and d.artifact_path
                    and d.artifact_path.is_file()
                    and d.artifact_path.suffix == ".json"):
                return d.artifact_path
        return None

    @staticmethod
    def _resume_degraded_enabled() -> bool:
        """degraded 复跑开关:默认开启;STEP5_RESUME_DEGRADED=0 显式关闭。"""
        return (os.environ.get("STEP5_RESUME_DEGRADED", "1").strip()
                not in ("0", "false", "False"))

    def _resume_result(self, agent: str, task: str, request: dict, seq: int,
                       path: Path, status: str, t0: float) -> ToolResult:
        """断点续跑统一路径:skipped(.json 存在)/ degraded(仅 .md,ok=False)。"""
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
        self._register(sub)
        self._log_attempt(agent, task, request, status, t0, seq=seq,
                          artifact=str(path), summary=sub.summary,
                          error=sub.error, budget_state=self._budget_state(agent))
        label = _STATUS_LABEL.get(status, status)
        text = (f"## {agent} Agent 结果({label},实例 {seq})\n"
                f"发现数: {len(sub.findings)}")
        if status == DispatchStatus.DEGRADED:
            text += ("\n注意: 该实例仅有降级工件(.md),上一轮 JSON 解析失败,"
                     "findings 可能不完整;建议推进前评估是否需要补调。")
        return ToolResult(ok=(status == DispatchStatus.SKIPPED), text=text)

    def _build_handoff(self, agent: str, task: str, context: str) -> str:
        """交接块(注入子 Agent 简报尾部):任务状态/前次结果/累计发现/上下文。"""
        lines = ["", "--- 交接信息(编排器自动注入) ---"]
        done = [d for d in self._dispatches
                if d.status in DispatchStatus.EXECUTED]
        if done:
            lines.append("前序任务状态:")
            for d in done:
                art = d.artifact_path.name if d.artifact_path else "无"
                t = (d.request.get("task") or "")[:40]
                lines.append(f"  - 实例[{d.seq}] {d.agent_name}「{t}」:"
                             f"{_STATUS_LABEL.get(d.status, d.status)},工件 {art},"
                             f"findings {len(d.findings or [])} 条")
        prev = [d for d in done if d.agent_name == agent]
        if prev:
            last = prev[-1]
            art = last.artifact_path.name if last.artifact_path else "无"
            lines.append(f"本次为 {agent} 的第 {len(prev) + 1} 次调用:上一次输出 {art}"
                         f"({len(last.findings or [])} findings);请在既有结果基础上"
                         "补充推进,不要重复已完成的工作")
        if self._agg.all_findings:
            lines.append(f"全链路累计 findings: {len(self._agg.all_findings)} 条"
                         "(细节可用 read_file 读取上列工件)")
        if context:
            lines.append(f"本次任务补充上下文: {context}")
        lines.append("工件按 agent/<seq>_<type>/ 目录组织,可直接 read_file 读取")
        return "\n".join(lines)

    def _save_handoff_snapshot(self, seq: int, agent: str, task: str,
                               context: str, handoff_text: str) -> None:
        """交接快照:结构化落盘 handoff_<seq>_<type>.json,文本块是其投影。
        交接从此可审计、可程序化消费(与 transcript 互补)。"""
        done = [d for d in self._dispatches
                if d.status in DispatchStatus.EXECUTED]
        snapshot = {
            "seq": seq,
            "to_agent": agent,
            "task": task,
            "context": context,
            "prior_dispatches": [
                {"seq": d.seq, "agent": d.agent_name, "status": d.status,
                 "task": d.request.get("task", ""),
                 "artifact": str(d.artifact_path) if d.artifact_path else None,
                 "findings": len(d.findings or [])}
                for d in done],
            "prior_same_agent": {
                "calls": len([d for d in done if d.agent_name == agent]),
                "last_summary": next(
                    (d.summary for d in reversed(done) if d.agent_name == agent), ""),
            },
            "cumulative_findings": len(self._agg.all_findings),
            "ts": _now(),
        }
        try:
            self.orch_dir.mkdir(parents=True, exist_ok=True)
            (self.orch_dir / f"handoff_{seq}_{agent}.json").write_text(
                json.dumps(snapshot, ensure_ascii=False, indent=2),
                encoding="utf-8")
        except OSError:
            pass  # 快照失败不阻塞调度(handoff 文本块仍会注入)

    # ---- 调度日志(请求/状态变迁/时间戳/错误;拒绝与重复同样留痕) ----

    def _write_dispatch_log(self) -> None:
        self.orch_dir.mkdir(parents=True, exist_ok=True)
        (self.orch_dir / "dispatch_log.json").write_text(
            json.dumps(self._dispatch_log, ensure_ascii=False, indent=2),
            encoding="utf-8")

    def _log_start(self, seq: int, agent: str, task: str, request: dict) -> dict:
        """登记调度开始(running),返回记录引用供终态回填。"""
        rec = {"seq": seq, "agent": agent, "task": task, "status": DispatchStatus.RUNNING,
               "request": request, "started_at": _now(), "finished_at": None,
               "duration_ms": None, "artifact_path": None, "summary": "",
               "error": "", "status_history": [{"status": DispatchStatus.RUNNING, "ts": _now()}]}
        self._dispatch_log.append(rec)
        self._write_dispatch_log()
        return rec

    def _log_finish(self, rec: dict, status: str, *, duration_ms: int | None = None,
                    artifact: str | None = None, summary: str = "",
                    error: str = "", budget_state: dict | None = None) -> None:
        """回填调度终态:状态变迁 running→success/degraded/failed 落痕。

        budget_state(Task6.8)为该实例的结构化预算状态快照(聚合后取,
        含 overlap_ratio/pending 差分),原样写入该条 dispatch_log 记录。"""
        rec["status"] = status
        rec["finished_at"] = _now()
        rec["duration_ms"] = duration_ms
        rec["artifact_path"] = artifact
        rec["summary"] = summary
        rec["error"] = error
        if budget_state is not None:
            rec["budget_state"] = budget_state
        rec["status_history"].append({"status": status, "ts": _now()})
        self._write_dispatch_log()

    def _log_interrupted(self, rec: dict) -> None:
        """执行中断兜底:run_agent 抛异常向上传播时,running 记录回填为
        interrupted(LLMError 终止整个 Step5 的场景),不留悬挂的运行中状态。"""
        if rec.get("status") == DispatchStatus.RUNNING:
            rec["status"] = DispatchStatus.INTERRUPTED
            rec["finished_at"] = _now()
            rec["error"] = rec.get("error") or "子 Agent 执行中断(异常向上传播)"
            rec["status_history"].append(
                {"status": DispatchStatus.INTERRUPTED, "ts": _now()})
            self._write_dispatch_log()

    def _log_attempt(self, agent: str, task: str, request: dict, status: str,
                     t0: float, *, seq: int | None = None,
                     artifact: str | None = None, summary: str = "",
                     error: str = "", duplicate_of: int | None = None,
                     budget_state: dict | None = None) -> None:
        """单次留痕:跳过/降级/拒绝/重复等不经过 running 阶段的调度尝试。

        budget_state 仅在实例已登记(skipped/degraded 复跑等)时有值。"""
        rec = {"seq": seq, "agent": agent, "task": task, "status": status,
               "request": request, "started_at": _now(), "finished_at": _now(),
               "duration_ms": int((time.time() - t0) * 1000),
               "artifact_path": artifact, "summary": summary, "error": error,
               "status_history": [{"status": status, "ts": _now()}]}
        if duplicate_of is not None:
            rec["duplicate_of"] = duplicate_of
        if budget_state is not None:
            rec["budget_state"] = budget_state
        self._dispatch_log.append(rec)
        self._write_dispatch_log()

    def _duplicate_result(self, agent: str, task: str, request: dict,
                          dup: SubAgentResult, t0: float) -> ToolResult:
        """重复调度的 Observation:返回历史结果并指引改用不同任务描述。"""
        art = dup.artifact_path.name if dup.artifact_path else "无"
        if dup.status in DispatchStatus.DONE_OK + (DispatchStatus.DEGRADED,):
            text = (f"## {agent} 重复调度被拒(类型+任务唯一性检查)\n"
                    f"历史实例 [seq={dup.seq}] 已用相同任务执行"
                    f"({_STATUS_LABEL.get(dup.status, dup.status)})。\n"
                    f"结果摘要: {dup.summary or '(无摘要)'}\n"
                    f"工件: {art}(findings {len(dup.findings or [])} 条)\n"
                    "如确需补充工作,请给出**不同的任务描述**再次调度;"
                    "否则请推进下一阶段、summarize 或 finish。")
            self._log_attempt(agent, task, request, DispatchStatus.DUPLICATE, t0,
                              artifact=str(dup.artifact_path) if dup.artifact_path else None,
                              summary=dup.summary, duplicate_of=dup.seq)
            return ToolResult(ok=True, text=text)
        msg = (f"{agent} 相同任务此前已失败(实例 seq={dup.seq}): "
               f"{dup.error or '未知错误'};请改用不同任务描述,或基于已有结果收尾")
        self._log_attempt(agent, task, request, DispatchStatus.DUPLICATE, t0,
                          error=dup.error, duplicate_of=dup.seq)
        return ToolResult(ok=False, text="", error=msg)

    # ---- 对外属性 ----

    @property
    def agent_results(self) -> dict[str, SubAgentResult]:
        return dict(self._agent_results)

    @property
    def dispatches(self) -> list[SubAgentResult]:
        """全部实际执行的调度(含同类型多次调用),时序排列。"""
        return list(self._dispatches)

    @property
    def all_findings(self) -> list[dict]:
        """全链路累计 findings(经聚合器去重合并后的只读视图)。"""
        return list(self._agg.all_findings)

    @property
    def success(self) -> bool:
        return self._success

    @property
    def error(self) -> str:
        return self._error

    def _build_initial_message(self) -> str:
        return (
            "开始对当前固件工作区执行安全审计编排。\n"
            "可调度子 Agent(按序推进): recon → analysis → verification。\n"
            f"recon/analysis 每个子 Agent 最多调度 {MAX_DISPATCH_PER_AGENT} 次:"
            "默认各调度 1 次,结果明显不完整时用不同的任务描述补充调度"
            "(相同任务会返回历史结果)。\n"
            "verification 为**每疑点一实例**(ADR-0003):调度一次即对 analysis "
            f"findings 按 severity+confidence 取前 {_verify_k()} 条(env "
            "STEP5_VERIFY_K 可调)逐条派独立复核实例;每条必被验证,补跑逻辑取消;"
            "复核完成后不得重复调度。\n"
            "每次调度自动交接前序任务状态与中间结果,无需手工搬运。\n"
            "全部阶段完成后: 调用 summarize 取报告素材 → Final Answer 输出"
            "最终 Markdown 审计报告正文(即落盘的 report.md)。"
        )

    def run(self) -> "Orchestrator":
        """执行编排:协调器 ReAct 循环(dispatch/summarize/finish)→ 报告落盘。"""
        self.orch_dir.mkdir(parents=True, exist_ok=True)
        ctx = ToolContext(process_dir=self.process_dir)
        tools = {
            "dispatch_agent": DispatchAgentTool(ctx, self),
            "summarize": SummarizeTool(ctx, self),
            "finish": FinishTool(ctx),
        }
        system_prompt = build_orchestrator_prompt(tools, max_iters=ORCH_MAX_ITERS)
        save_system_prompt(self.orch_dir, system_prompt)  # 编排器系统提示词留档(复现用)
        init = self._build_initial_message()
        transcript = self.orch_dir / "transcript.jsonl"
        transcript.write_text("", encoding="utf-8")

        disp = make_display()
        if disp.enabled:
            disp.stage("orchestrator", "编排", len(tools),
                       getattr(self.base_llm, "model", "?"), ORCH_MAX_ITERS)
        react = run_react_agent(self.base_llm, tools, system_prompt, init,
                                max_iters=ORCH_MAX_ITERS, transcript=transcript,
                                display=disp)

        self._success = react.ok
        self._final_answer = react.final_answer or ""
        if not react.ok:
            self._error = "协调器未产出 Final Answer 或迭代耗尽"
        # 报告落盘:summarize 已调用且 Final Answer 非空 → report.md(主产物);
        # JSON 结构可解析时另存 report.json(可选副产品)
        self._write_report()
        if disp.enabled:
            disp.done("orchestrator", self._report_path.name if self._report_path
                      else "result.json", len(self._agg.all_findings),
                      react.steps, dict(getattr(self.base_llm, "total_usage", {})))
        self._write_result(transcript)
        return self

    def _write_report(self) -> Path | None:
        """Final Answer → report.md(主产物,原样落盘)。

        条件:verification 已完成(素材注入过)+ summarize 已调用 +
        final_answer 非空——三者齐才落盘,防"中途 summarize 决策 + 短结论"
        被误当报告;Final Answer 同时含可解析 JSON 时另存 report.json
        (可选副产品,我方保留字段优先防 LLM 同名覆盖)。
        未满足条件时不出报告(缺失告警由 step5_run 负责),返回 None。
        """
        verification_done = self._agent_results.get("verification") is not None
        if not (verification_done and self._summarize_called
                and self._final_answer.strip()):
            return None
        md = self.orch_dir / "report.md"
        md.write_text(self._final_answer + "\n", encoding="utf-8")
        self._report_path = md
        # 可选 JSON 副产品:宽容解析(剥围栏/找 JSON 对象),失败即不存;
        # 我方保留字段(schema/report_markdown)后写,LLM 同名键不覆盖
        try:
            from .data.artifacts import strip_fence
            s = strip_fence(self._final_answer.strip())
            start, end = s.find("{"), s.rfind("}")
            if start != -1 and end > start:
                obj = json.loads(s[start:end + 1])
                if isinstance(obj, dict):
                    (self.orch_dir / "report.json").write_text(
                        json.dumps({**obj, "schema": 1,
                                    "report_markdown": self._final_answer},
                                   ensure_ascii=False, indent=2),
                        encoding="utf-8")
        except (json.JSONDecodeError, OSError, ValueError):
            pass
        return md

    @property
    def report_path(self) -> Path | None:
        """最终总结报告路径(summarize 产出);未产出时 None。"""
        return self._report_path

    @property
    def summarize_called(self) -> bool:
        return self._summarize_called

    def _write_result(self, transcript: Path) -> Path:
        out = self.orch_dir / "result.json"
        out.write_text(json.dumps({
            "success": self._success,
            "error": self._error,
            "final_answer": self._final_answer,
            "report_path": str(self._report_path) if self._report_path else None,
            "summarize_called": self._summarize_called,
            "steps": self._seq,
            "findings": self.all_findings,
            # Task6.8:各类型最新实例的 budget_state 汇总(动态分配决策留档)
            "budget": {name: self._budget_state(name)
                       for name in self._sub_cfgs},
            "stages": {name: sub.to_dict() for name, sub in self._agent_results.items()},
            "dispatches": [d.to_dict() for d in self._dispatches],
            # ADR-0003:verification 每疑点一实例的逐实例明细(阶段内部,不占调度史)
            "verification_instances": [
                v.to_dict() for v in self._verification_instances],
            "transcript": str(transcript),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return out

    # ---- 公开 API(pipeline 等外部调用方用,不再伸手改私有状态) ----

    def record_failed(self, agent: str, error: str, task: str = "") -> None:
        """登记一个被拒/未执行的阶段为 failed 实例(不占调度史)。

        pipeline 模式被拒阶段用它占位 _agent_results,使调用方可区分
        "未规划"与"被拒"。seq=-1 标记非真实调度。
        """
        self._agent_results[agent] = SubAgentResult(
            seq=-1, agent_name=agent, status=DispatchStatus.FAILED,
            error=error, request={"agent": agent, "task": task})

    def finish(self, success: bool, error: str = "") -> None:
        """设置编排终态(success/error),供 pipeline 等外部路径收敛。"""
        self._success = success
        self._error = error

    def write_result(self) -> Path:
        """落盘编排终态 result.json(transcript 缺省;pipeline 模式无 transcript)。"""
        return self._write_result(None)


__all__ = ["Orchestrator", "SubAgentResult", "DispatchAgentTool",
           "SummarizeTool", "FinishTool", "DispatchStatus"]
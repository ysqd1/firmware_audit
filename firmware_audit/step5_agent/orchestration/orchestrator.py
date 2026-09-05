"""Orchestrator(协调器)——轻量 LLM 驱动的固件审计编排层(子 Agent 多次调用版)。

参考 deepaudit 的 OrchestratorAgent 思想做精简移植;v3(2026-08-28)在 v2 基础上:
- summarize 动作: verification 完成后由 orchestrator LLM 编写最终总结报告,
  主产物 process/agent/orchestrator/report.md(Final Answer 原样落盘);
  同时含可解析 JSON 时另存 report.json(可选结构化副产品)
- 报告对账(ADR-0007,2026-09-03):report.md 落盘后由 reconcile_report 纯函数
  (T2 迁至本包 reconciliation 模块,本类只留读盘/落盘/stderr 告警薄壳)
  解析正文,与 verified_findings.json 逐条比对(severity/confidence/verified
  三枚举 + rationale 关键句包含)→ 差异清单落盘 report_reconciliation.json +
  stderr 警告;仅告警不重生成不阻塞。素材侧由提示词红线收敛(见本模块 _ORCH_TMPL)
- degraded 状态: 断点续跑只认 .json 成功工件;.md 降级工件标记 degraded
  (ok=False),复跑默认重跑该实例(防"失败被跳过"冒充成功)
- handoff 快照: 每次真实调度把交接结构化落盘 handoff_<seq>_<type>.json
- v2 保留: 多次调用(类型+任务唯一性)/严格顺序门/立即留痕 dispatch_log/
  中断回填 interrupted(调度留痕 T3 起由本包 dispatch_log.DispatchLog 承担,
  编排层只经 start/finish/interrupted/attempt 四动词消费)
- 动态分配(2026-08-29,Task6+Task7): 同类型上限 2→3;dispatch/summarize
  Observation 尾部呈现结构化 budget_state(exhausted/steps/pending_focuses/
  overlap_ratio);analysis 预算耗尽且仍有未覆盖疑点时附补跑建议;补跑
  dispatch 的简报追加已覆盖清单(前 30 条)与差分 task 提示
- 模块分工(ADR-0009 T4): 调度守卫与三动作工具类在本包 actions 模块、交接
  块构建/快照落盘在 handoff、共享词汇(状态枚举/标签/结果封装)在 state——
  本模块只剩编排主体: 状态持有与登记、run() 主循环、verification 阶段引擎
  (T5 迁 verify_phase)、budget 集群、报告/对账/终态落盘

目录落盘 (以 process/agent/ 为根):
- orchestrator/  : transcript.jsonl(编排 LLM 输出)、dispatch_log.json(全量
                   调度史,含被拒尝试)、handoff_<seq>_<type>.json(交接快照)、
                   report.md(最终总结报告,summarize 产出)、
                   report_reconciliation.json(ADR-0007 对账差异清单)、
                   result.json(终态)
- <seq>_<type>/  : 每次子 Agent 执行的 transcript.jsonl + obs/ + 产出工件

断点续跑: force=False 且该实例 .json 工件已存在 → status=skipped,加载已有工件;
.md 降级工件 → status=degraded,复跑(默认)。
API 失败(LLMError)不在工具层吞掉,向上传播立即终止(保持既有语义)。
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from .actions import (MAX_DISPATCH_PER_AGENT, _VERIFY_CONFIDENCE_RANK,
                      _VERIFY_SEVERITY_RANK, agent_call_count,
                      DispatchAgentTool, FinishTool, SummarizeTool)
from .dispatch_log import DispatchLog
from .reconciliation import reconcile_report
from .state import DispatchStatus, SubAgentResult
from ..aggregator import FindingAggregator
from ..data.artifacts import load_artifact, load_survey
from ..data.prompts import build_system_prompt, build_verify_single_brief, save_system_prompt
from ..engine.display import make_display
from ..engine.react_loop import run_react_agent
from ..providers.llm_client import LLMError
from ..providers.tools import ToolContext
from ..providers.tools.base import ToolResult
from ..runner import ALL_CONFIGS, resolve_max_iters, run_agent

# 多次调用下编排轮数上限:默认 3 次调度+summarize+收尾,余量留给补充调用
ORCH_MAX_ITERS = 12

# budget_state 里 pending_focuses 的呈现上限(防异常大 survey 撑爆 Observation/
# 日志;pending_count 始终是全量数)
_BUDGET_FOCUS_LIMIT = 8

# ADR-0003:verification 每疑点一实例——K 上限(env STEP5_VERIFY_K,默认 10)
# 与排序 rank(severity 主排序 + confidence 次排序,从高到低;rank 表暂驻
# actions,双消费见该模块 docstring)。
DEFAULT_VERIFY_K = 10


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


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
## 发现清单(按 severity 排列:每条含标题/位置/置信度/复核结论;只含**已复核** finding)
## 未复核疑点(独立区段:⚠ 未经复核——verified=None 的疑点(未进入 verification
前 K 条,或复核实例失败未产出结论),confidence 为 analysis 初值、rationale 为空;
报告明确标注"未经复核,confidence 为 analysis 初值",禁止混入发现清单或标注为已证实)
## 误报剔除(verified=false 的条目与理由)
## 编排判断与后续建议
报告内容必须来自 summarize Observation 提供的素材与各子 Agent 工件,
禁止编造未在素材中出现的 finding/路径/统计。

报告写作纪律(ADR-0007 对账红线,逐条强制执行;系统会用机器对账核对):
- 每条 finding 的 severity/confidence/verified 枚举值**逐字抄写**素材里的原值
  (工件 verified_findings.json 是唯一真值),禁止改写或凭印象补写——素材
  confidence=low 就写 low,不得写 high
- 条目的标题/位置/详情/证据**只来自该条 finding 自己的素材字段**,禁止引用或
  转述其他条目的 rationale(跨条目串条是最严重的失真;理由内容不机器核,但人工核对时会发现)
- 压缩详情时**保留工件 rationale 的核心事实与限定**(如"已过期/仅 tests 目录/
  死代码不可达"),禁止省略会改变风险定性的限定语
- 每条 finding 按下列标签行格式书写(便于对账定位;格式允许微调,枚举值不许):
  - **位置：** <file 相对路径,可带 :: func / @ addr>
  - **severity：** <critical|high|medium|low|info>(照抄工件复核后的值,降级照抄)
  - **置信度：** <high|medium|low> → **复核结论：** ✓ 已证实 | ✗ 误报 | ⚠ 未经复核
  - **详情：** <该条 rationale 的忠实转述/压缩>
  - **证据：** <evidence 引用>
  未复核条目(⚠)的置信度标注"（初值）"(confidence 为 analysis 初值,不是复核值);
  severity 不得只写在详情散文里(如"Severity 为 medium"),必须落在 severity 标签行;
  每条 finding 用**带编号的标题**(如 `### 1. 标题` 或 `#### 2. 标题`,编号连续),
  便于机器按条目定位(标题不带编号会无法对账)

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


def build_orchestrator_prompt(tools: dict, max_iters: int = ORCH_MAX_ITERS) -> str:
    """协调器系统提示词 = 角色/动作/纪律 + 工具清单 + 迭代预算。

    K 值动态注入(_orch_system),与运行时 STEP5_VERIFY_K 一致。
    """
    return build_system_prompt(_orch_system(), tools, max_iters=max_iters)


class Orchestrator:
    """协调器:统一调度三子 Agent(支持同类型多次调用),写编排痕迹并产出终态。

    调度史 _dispatches 记录所有实际执行(success/skipped/degraded/failed)的实例;
    _agent_results 按类型保留最新实例(供 step5_run 阶段统计与 summarize 消费)。
    本类装配三动作工具类(DispatchAgentTool/SummarizeTool/FinishTool,守卫与
    调度前置校验见 actions 模块)并被其回调(host 回调面见 actions 模块
    docstring)——编排主体只剩状态持有与登记 + verification 阶段引擎(T5 迁
    verify_phase)+ budget 集群 + 报告/对账/终态落盘。
    """

    def __init__(self, process_dir: Path, base_llm, force: bool = False):
        self.process_dir = process_dir
        self.base_llm = base_llm
        self.force = force
        self.agent_dir = process_dir / "agent"
        self.orch_dir = self.agent_dir / "orchestrator"
        # 轮次上限 env 覆盖(STEP5_<NAME>_MAX_ITERS):replace 出副本,模块常量不污染
        self.sub_cfgs = {c.name: replace(c, max_iters=resolve_max_iters(c.name, c.max_iters))
                         for c in ALL_CONFIGS}
        self._seq = 0
        self._agent_results: dict[str, SubAgentResult] = {}
        self._dispatches: list[SubAgentResult] = []   # 全部实际执行的调度(时序)
        # 调度留痕(T3 收类):记录管理/status_history/落盘全在 DispatchLog
        self.dispatch_log = DispatchLog(self.orch_dir)
        self._agg = FindingAggregator()               # findings 聚合(去重/合并/重合计分)
        self._success = False
        self._final_answer = ""
        self._error = ""
        self._summarize_called = False
        self._report_path: Path | None = None
        # ADR-0003:verification 每疑点一实例——阶段已跑(防重复调度)与逐实例明细
        self._verification_done = False
        self._verification_instances: list[SubAgentResult] = []

    # ---- 调度辅助(actions 动作类回调;host 回调面见 actions 模块 docstring) ----

    def next_seq(self) -> int:
        n = self._seq
        self._seq += 1
        return n

    def register(self, sub: SubAgentResult) -> None:
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

    def run_verification_phase(self, task: str, upstream: Path,
                               seq: int, request: dict, t0: float) -> ToolResult:
        """verification 阶段(每疑点一实例):一次调度 → K 条独立实例 → 聚合工件。

        流程:读 analysis findings → severity 主排序 + confidence 次排序取前 K 条
        (STEP5_VERIFY_K,默认 10)→ 对每条派一个独立 verification 实例(max_iters=8,
        输入=单条 finding + 工件指针)→ 逐条产单条 verified finding → 聚合回
        verified_findings.json(全量 N 条:K 条带复核结论,N-K 条 verified=None,
        confidence 保留 analysis 初值)。补跑逻辑整体取消(每条必被验证)。
        """
        cfg = self.sub_cfgs["verification"]
        rec = self.dispatch_log.start(seq, "verification", task, request)
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
                self.register(sub)
                self._verification_done = True
                self.dispatch_log.finish(rec, DispatchStatus.SKIPPED,
                                         artifact=str(agg_path), summary=sub.summary,
                                         budget_state=self.budget_state("verification"))
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

            # 逐条派独立实例(每条必跑;补跑逻辑整体取消);每实例启动前标
            # "实例 i/N"(#6):单实例 done 行恒 1 findings,不标序号会误导为
            # 全阶段只复核 1 条(阶段全貌由 phase_done 汇总行兜底)
            disp = make_display()
            instances = []
            for i, f in enumerate(top, 1):
                if disp.enabled:
                    disp.instance_tag(i, len(top))
                instances.append(
                    self._run_verify_one(self.next_seq(), f, upstream,
                                         task, request))
            self._verification_instances = instances

            # 聚合:全量 N 条(K 覆盖复核结论,N-K 原样 verified=None + confidence 初值)
            # 锚点=各实例对应的原 analysis finding(按实例序与 top 对齐):复核结果
            # 回填到原槽位——实例返回的 finding 常缺 addr/func,按 dedup_key 会错位
            # 成新条目;以原 finding 的键锚定,verified/rationale/confidence/severity
            # 覆盖,未进前 K 的条目原样保留(verified=None,confidence 保留 analysis
            # 初值)。
            # 复核结论回填:只覆盖复核权威字段(verified/rationale/confidence/severity),
            # 不重排锚点——实例返回的 finding 可能缺 addr/func 或改 title,一律忽略
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
                if vf.get("severity"):
                    merged["severity"] = vf["severity"]      # 判级降级(2026-09-03:
                    # verification 是判级权威,实例 9 死代码降级 low 曾被丢弃,
                    # 聚合产物 severity=high 与 rationale 自相矛盾;ADR-0003 精神延伸)
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
            self.register(phase)
            self._verification_done = True
            self.dispatch_log.finish(rec, status, duration_ms=phase.duration_ms,
                                     artifact=str(out_path), summary=phase_summary,
                                     error=phase.error,
                                     budget_state=self.budget_state("verification"))
            # 阶段级汇总行(#6,2026-09-03):每实例 done 行是单实例计数(恒
            # 1 findings),阶段真实全貌(实例数/已复核 x/N/合计)在此汇总,
            # 不再误导"只复核了 1 条"
            if disp.enabled:
                usage_sum = {}
                for v in instances:
                    for k, n in (v.usage or {}).items():
                        usage_sum[k] = usage_sum.get(k, 0) + n
                disp.phase_done("verification", out_path.name,
                                len(instances), verified_n, len(ranked),
                                phase.steps, usage_sum,
                                elapsed_s=phase.duration_ms / 1000)
            if status == DispatchStatus.SUCCESS:
                return ToolResult(ok=True, text=(
                    f"## verification Agent 结果(每疑点一实例,成功,实例 {seq})\n"
                    f"已复核 {verified_n}/{len(ranked)} 条(共 {len(ranked)} 条;"
                    f"未进入前 {len(top)} 的未复核,verified=None)\n"
                    f"工件: {out_path.name}\n"
                    f"(下一步: 调用 summarize 取报告素材)\n"
                    + self.budget_state_text("verification")))
            return ToolResult(ok=False, text="", error=(
                f"verification 阶段失败(实例 {seq}): {phase.error}"))
        except LLMError:
            self.dispatch_log.interrupted(rec)
            raise
        except Exception as e:
            self.dispatch_log.finish(rec, DispatchStatus.FAILED,
                                     error=f"{type(e).__name__}: {e}",
                                     budget_state=self.budget_state("verification"))
            return ToolResult(ok=False, text="", error=(
                f"verification 阶段失败(实例 {seq}): {type(e).__name__}: {e}"))

    @staticmethod
    def _lift_verify_verdict(loaded: dict | None, vfs: list) -> None:
        """0/N bug(2026-09-03):模型把复核结论写在实例工件**顶层**
        (verified/rationale),findings[] 只含 identity 字段(verified 空)。
        归一进 findings[0],聚合层才读得到——否则已复核条目被丢进未复核区
        (VERIFY_SYSTEM 虽要求写进 findings[],save_artifact 会保留未知顶层字段)。"""
        if not vfs or not loaded:
            return
        head = vfs[0]
        if head.get("verified") is None and "verified" in loaded:
            head["verified"] = loaded["verified"]
        if not head.get("rationale") and loaded.get("rationale"):
            head["rationale"] = loaded["rationale"]

    def _run_verify_one(self, vseq: int, finding: dict, upstream: Path,
                        task: str, request: dict) -> SubAgentResult:
        """单条 finding 的独立 verification 实例(ADR-0003)。

        输入=单条 finding + 工件指针(build_verify_single_brief),输出=单条
        verified finding;上下文隔离铁律不破(只从工件读,不传对话历史)。
        """
        cfg = self.sub_cfgs["verification"]
        out_dir = self.agent_dir / f"{vseq}_verification"
        out_path = out_dir / cfg.output_name
        t0 = time.time()
        # 单实例不进主 dispatch_log(ADR-0003:逐实例留痕在其自身 transcript/obs +
        # result.json 的 verification_instances;主 dispatch_log 只记编排调度(阶段))
        try:
            # 断点续跑(单实例):该实例 .json 工件已存在且未 force → skipped。
            # 身份校验(2026-09-03 错位 bug):目录名是全局 seq 位置而非 finding
            # 身份,续跑时编排路径变化(如 analysis 补跑次数不同)会让 seq 前移,
            # 本条 finding 可能命中**前一条** finding 的旧工件——只判文件存在
            # 就加载会把别人的复核结论错配进来(target/1 实测 9/10 条整体错位,
            # 新[N].rationale==旧[N-1],无任何告警)。故加载后比对工件 finding
            # 与当前锚点身份:不一致或工件无 findings → 弃用工件真跑(如实上报
            # 不冒充;真跑产物写回同一路径,错位旧工件随之被覆盖)。
            # 匹配键=file+title 归一化(2026-09-03 review 修复):实例工件常缺
            # func/addr(上方锚点回填注释自注),完整 dedup_key 四元组全等会把
            # 合法工件误拒 → 每次续跑全部真跑、静默烧预算;file+title 是必填
            # 身份字段,区分度足够(错位场景里 file/title 必然是别的 finding 的)。
            if out_path.is_file() and not self.force:
                loaded = load_artifact(out_path) or {}
                vfs = [f for f in (loaded.get("findings") or [])
                       if isinstance(f, dict)]
                self._lift_verify_verdict(loaded, vfs)
                if vfs and all(
                        self._agg.norm_text(vfs[0].get(k, ""))
                        == self._agg.norm_text(finding.get(k, ""))
                        for k in ("file", "title")):
                    return SubAgentResult(
                        seq=vseq, agent_name="verification",
                        status=DispatchStatus.SKIPPED,
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
            self._lift_verify_verdict(loaded_v, vfs)
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

    def budget_state(self, agent: str) -> dict:
        """结构化预算状态(Task6.3):该类型最新实例的 exhausted/steps/
        max_iters/pending_count/pending_focuses/overlap_ratio;summarize 与
        dispatch Observation、dispatch_log/result.json 共用此投影。"""
        cfg = self.sub_cfgs.get(agent)
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

    def budget_state_text(self, agent: str) -> str:
        """budget_state 的 Observation 投影(单行 JSON,LLM 可读)。"""
        return "budget_state: " + json.dumps(
            self.budget_state(agent), ensure_ascii=False)

    def rerun_suggestion(self, agent: str) -> str:
        """补跑建议段(Task6.6):仅 analysis 预算耗尽、仍有未覆盖疑点且
        调度次数未达上限时给出;其余场景返回空串(Observation 不附)。"""
        state = self.budget_state(agent)
        n_done = agent_call_count(self.dispatches, agent)
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
        orch_iters = resolve_max_iters("orchestrator", ORCH_MAX_ITERS)
        system_prompt = build_orchestrator_prompt(tools, max_iters=orch_iters)
        save_system_prompt(self.orch_dir, system_prompt)  # 编排器系统提示词留档(复现用)
        init = self._build_initial_message()
        transcript = self.orch_dir / "transcript.jsonl"
        transcript.write_text("", encoding="utf-8")

        disp = make_display()
        if disp.enabled:
            disp.stage("orchestrator", "编排", len(tools),
                       getattr(self.base_llm, "model", "?"), orch_iters)
        react = run_react_agent(self.base_llm, tools, system_prompt, init,
                                max_iters=orch_iters, transcript=transcript,
                                display=disp)

        self._success = react.ok
        self._final_answer = react.final_answer or ""
        if not react.ok:
            self._error = "协调器未产出 Final Answer 或迭代耗尽"
        # 报告落盘:summarize 已调用且 Final Answer 非空 → report.md(主产物);
        # JSON 结构可解析时另存 report.json(可选副产品)
        self._write_report()
        # ADR-0007:报告落盘后立即事后对账(解析正文 vs verified_findings 真值),
        # 差异清单落盘 + stderr 警告;仅告警不重生成不阻塞
        self._reconcile_report()
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
            from ..data.artifacts import strip_fence
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

    def _reconcile_report(self) -> Path | None:
        """ADR-0007 事后对账(报告落盘后):解析 report.md 正文与 verified_findings.json
        逐条比对(reconcile_report 纯函数)→ 差异清单落盘 report_reconciliation.json
        + stderr 警告。

        仅告警:report.md 原样保留,不自动重生成、不阻塞(ADR-0006 精神"明确告警
        不静默降级";自动重生成不保证收敛,修复交给人工复核后的重跑)。未满足
        对账前置(report.md / verified_findings.json 缺失)时返回 None,不落盘。
        """
        if self._report_path is None:
            return None
        vf_path = self.agent_dir / "verified_findings.json"
        if not vf_path.is_file():
            return None
        try:
            report_md = self._report_path.read_text(encoding="utf-8")
            loaded = load_artifact(vf_path) or {}
            result = reconcile_report(report_md, loaded.get("findings", []) or [])
        except OSError:
            return None   # 读盘失败不阻塞:对账是旁路告警,不干扰主流程
        out = self.orch_dir / "report_reconciliation.json"
        payload = {
            "ts": _now(),
            "report_md": str(self._report_path),
            "verified_findings": str(vf_path),
            **result,
        }
        try:
            out.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                           encoding="utf-8")
        except OSError:
            return None
        s = result["summary"]
        if s["mismatch"] or s["unparsed"] or s["unmatched"]:
            print(f"[reconcile] report.md 与 verified_findings 对账发现差异: "
                  f"mismatch={s['mismatch']} unparsed={s['unparsed']} "
                  f"unmatched={s['unmatched']} 详见 {out}",
                  file=sys.stderr)
        return out

    @property
    def summarize_called(self) -> bool:
        return self._summarize_called

    @summarize_called.setter
    def summarize_called(self, v: bool) -> None:
        # 状态写入口(SummarizeTool 动作回调;host 回调面见 actions 模块 docstring)
        self._summarize_called = bool(v)

    @property
    def verification_done(self) -> bool:
        """verification 阶段已跑(每疑点一实例,ADR-0003;防重复调度)。
        DispatchAgentTool 跨类读取(host 回调面见 actions 模块 docstring)。"""
        return self._verification_done

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
            "budget": {name: self.budget_state(name)
                       for name in self.sub_cfgs},
            "stages": {name: sub.to_dict() for name, sub in self._agent_results.items()},
            "dispatches": [d.to_dict() for d in self._dispatches],
            # ADR-0003:verification 每疑点一实例的逐实例明细(阶段内部,不占调度史)
            "verification_instances": [
                v.to_dict() for v in self._verification_instances],
            "transcript": str(transcript),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        return out

__all__ = ["Orchestrator", "build_orchestrator_prompt"]

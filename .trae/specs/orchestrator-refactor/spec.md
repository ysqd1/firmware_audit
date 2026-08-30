# 固件审计 Agent 架构重构：引入 Orchestrator（协调器）Spec

## Why
firm_audit 当前在 `run_step5.py::step5_run` 用 **Python 硬编码串行循环**调度 recon→analysis→verification，缺少统一协调层与标准化的子 Agent 调用/结果/上下文流转。参考 deepaudit 的 `OrchestratorAgent` 思想，本重构以**轻量 LLM 驱动**的 Orchestrator 负责任务分发与流程控制，统一管理三子 Agent，并规范化落盘目录；不引入 deepaudit 的 TaskHandoff 全字段类与多模块分层，保持精简。

## What Changes
- **单文件编排层**：新增 `step5_agent/orchestrator.py`，含 `Orchestrator`、`SubAgentResult`、`DispatchAgentTool`（复用现有 ReAct 引擎，不新增包/多文件）。
- **专用工具类封装子 Agent 调用**：`DispatchAgentTool`（继承 `AgentTool`，标准化 `execute(**kw)->ToolResult`），内部封装对既有 `run_agent` 的调用与链路守卫，供 orchestrator 调度。
- **子 Agent 结果封装类**：`SubAgentResult`（seq/agent/status/artifact_path/summary/error/request/usage/耗时），含 `ok` 判定，供 orchestrator 判断状态、跟踪与传上下文。
- **精简上下文流转**：orchestrator 维护 `_agent_results`/`_all_findings`，dispatch 下游前把前序工件摘要 + findings 组装为 `previous_results` 注入（不引入 TaskHandoff 类）。
- **目录结构规范化**（以 `important/target/1/process/agent/` 为例）：
  - `process/agent/orchestrator/`：orchestrator 完整 LLM 输出（`transcript.jsonl`）、每次子 Agent 调度的请求参数/返回结果/执行状态（`dispatch_log.json`）、编排终态（`result.json`）。
  - `process/agent/<seq>_<type>/`（如 `0_recon`、`1_analysis`、`2_verification`）：该子 Agent 完整 LLM 输出（`transcript.jsonl`）、所有工具调用完整返回结果（`obs/step<N>_<tool>.txt`）、产出工件。
- **执行入口改造**：`step5_run` 由硬编码循环改为「构造 Orchestrator → 执行编排 → 渲染 report」，保留 `--force` 与无 key/API 失败立即终止语义。

## Impact
- Affected specs: `firmware_audit/agents.md`（「runner 硬编码控制流」描述更新为 orchestrator 编排）。
- Affected code:
  - `important/firmware_audit/step5_agent/runner.py`（`run_agent` 增 `output_dir` 参数）
  - `important/firmware_audit/step5_agent/run_step5.py`（`step5_run` 组装 orchestrator）
  - `important/firmware_audit/step5_agent/data/prompts.py`（下游工件路径解析）
  - 新增：`important/firmware_audit/step5_agent/orchestrator.py`
  - 测试：`test/test_step5_pipeline.py`、`test/test_step5_smoke.py` 及新增 `test/test_orchestrator.py`

## ADDED Requirements

### Requirement: Orchestrator 编排层
系统 SHALL 提供轻量 LLM 驱动的 `Orchestrator`，复用现有 `run_react_agent` 跑自己的 ReAct 循环，通过 `dispatch_agent`/`finish` 两动作统一管理 recon、analysis、verification 的执行顺序与协作逻辑。

#### Scenario: 成功编排一轮
- **WHEN** `step5_run` 触发 Orchestrator 执行
- **THEN** Orchestrator 依链路守卫依次调度子 Agent（dispatch_agent → 子 Agent 结果回喂 → 直至 finish），随后进下游、最终收尾并产出编排终态文件

#### Scenario: 上游缺件
- **WHEN** 调度某子 Agent 但其上游工件缺失（analysis 缺 attack_surface / verification 缺 findings）
- **THEN** `DispatchAgentTool` 返回错误 Observation，不执行该子 Agent，提示先完成前序阶段

### Requirement: 专用工具类封装子 Agent 调用
系统 SHALL 提供 `DispatchAgentTool`（继承 `AgentTool`，标准 `execute(**kw)->ToolResult`）封装子 Agent 调用与链路守卫。

#### Scenario: 标准化接口
- **WHEN** Orchestrator 调用 `dispatch_agent`（参数 agent/task/context）
- **THEN** 返回统一 `ToolResult`（ok/text/error/elapsed/raw），异常不崩，Orchestrator 依 `ok` 判断结果

### Requirement: 子 Agent 结果封装类
系统 SHALL 提供 `SubAgentResult`：seq、agent_name、status（running/success/skipped/failed）、artifact_path、summary、error、request 参数、usage、耗时，含 `ok` 属性。

#### Scenario: 状态可判断与可传递
- **WHEN** 任一子 Agent 执行结束
- **THEN** 生成 `SubAgentResult` 存入 `_agent_results`，供 orchestrator 判断是否推进下游，并作为后续 dispatch 的上下文来源

### Requirement: 子 Agent 间上下文流转
系统 SHALL 在 dispatch 下游子 Agent 前，把前序 `SubAgentResult` 的工件摘要 + findings 组装为 `previous_results` 注入下游（精简握手，不引入 TaskHandoff 类）。

#### Scenario: 下游获得前序上下文
- **WHEN** Orchestrator 调度 analysis/verification
- **THEN** dispatcher 用 `artifact_summary` 生成前序工件摘要并附加已收集 findings，随 `run_agent` 传入

### Requirement: 规范化落盘目录
系统 SHALL 把编排与子 Agent 痕迹持久化到 `process/agent/` 规范化目录。

#### Scenario: orchestrator 目录
- **WHEN** 编排执行告一段落
- **THEN** `process/agent/orchestrator/` 生成 `transcript.jsonl`（完整 LLM 输出）、`dispatch_log.json`（每次调度的请求/结果/状态）、`result.json`（终态）

#### Scenario: 子 Agent 目录
- **WHEN** 任一子 Agent 执行完成
- **THEN** 生成 `process/agent/<seq>_<type>/`（seq 递增不重复），内含 `transcript.jsonl`、`obs/step<N>_<tool>.txt`、产出工件

### Requirement: 断点续跑与健壮性保持
系统 SHALL 保留断点续跑（工件存在即跳过）、`--force` 重跑、无 API key/API 失败立即终止（`LLMError` 向上传播）。

#### Scenario: 已有工件跳过
- **WHEN** `force=False` 且某子 Agent 工件已存在
- **THEN** 该子 Agent 生成 `status=skipped` 的 `SubAgentResult`（加载已有工件），orchestrator 继续推进

## MODIFIED Requirements

### Requirement: run_agent 输出目录
`runner.py::run_agent` 增 `output_dir` 参数（默认 `process/agent/<name>/`，兼容测试与旧调用），由 orchestrator 按 `<seq>_<type>` 指定。

### Requirement: render_report 与下游解析
`render_report` 与下游工件解析优先从 orchestrator 记录定位工件路径，无记录时回退读原根目录工件，兼容旧工作区。

## REMOVED Requirements
无（仅新增编排层，不改动既有工具、ReAct 引擎与工件 schema）。
**Reason**: 本次仅新增 orchestrator 并规范化目录。
**Migration**: 旧工件仍在原路径，通过回退解析兼容。
# Checklist

## Orchestrator 编排层
- [x] 新增单文件 `step5_agent/orchestrator.py`（Orchestrator + SubAgentResult + DispatchAgentTool + FinishTool，不新增包/多文件）
- [x] Orchestrator 复用 `run_react_agent`，通过 `dispatch_agent`/`finish` 两个动作统一管理 recon、analysis、verification 的执行顺序与协作逻辑
- [x] 上游链路守卫：analysis 缺 attack_surface / verification 缺 findings 时返回错误 Observation、记 failed，不执行该子 Agent
- [x] 编排终局以 `finish` 收尾（LLM Final Answer 汇总结论），聚合去重各子 Agent findings

## 专用工具类封装子 Agent 调用
- [x] `DispatchAgentTool` 继承 `AgentTool`，以 `execute(**kw)->ToolResult` 标准化接口封装子 Agent 调用；覆盖 `execute` 放行 LLMError（API 失败向上传播终止）
- [x] 参数 agent/task/context；返回统一 ToolResult（ok/text/error/elapsed/raw），异常不崩

## 子 Agent 结果封装类
- [x] `SubAgentResult` 含 seq、agent_name、status、artifact_path、summary、findings、error、request、usage、耗时，含 `ok` 判定
- [x] Orchestrator 依 `SubAgentResult.status`/`ok` 做结果判断、状态跟踪与上下文传递

## 子 Agent 间上下文流转
- [x] Orchestrator 维护 `_agent_results`/`_all_findings`
- [x] dispatch 下游前把前序 `SubAgentResult.artifact_path` 作为 `upstream_path` 传入 `run_agent`，其简报自动注入 `artifact_summary` 摘要 + findings（精简握手，无 TaskHandoff 类）

## 规范化落盘目录
- [x] `process/agent/orchestrator/` 生成 `transcript.jsonl`（完整 LLM 输出）、`dispatch_log.json`（请求/结果/状态/时间戳）、`result.json`（终态）
- [x] 每个子 Agent 生成 `process/agent/<seq>_<type>/`（如 `0_recon`、`1_analysis`、`2_verification`），内含完整 `transcript.jsonl`、所有工具返回 `obs/step<N>_<tool>.txt`、产出工件
- [x] `<seq>` 为调度顺序号且递增不重复；子 Agent 工件可被下游正常读取

## 既有行为保持
- [x] `--force` 重跑与无 key/API 失败立即终止（LLMError 向上传播）语义保留
- [x] `run_agent` 增 `output_dir` 参数（默认兼容旧 `process/agent/<name>/`）
- [x] `render_report`/`_resolve_verified` 优先从 orchestrator result.json 定位工件，旧工作区无记录时回退读原根目录工件
- [x] `python -m pytest test -q` 全绿（147 passed, 10 skipped）
- [x] 新增 `test/test_orchestrator.py` 覆盖 SubAgentResult、DispatchAgentTool（成功/skipped/上游缺失/未知 agent）、Orchestrator 集成（dispatch→finish + 三文件/编号目录生成）；`test/test_step5_pipeline.py`、`test/test_step5_display.py` 已适配新目录/编排流
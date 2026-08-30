# Tasks
- [x] Task 0: 校验既有测试基线
  - [x] 运行 `python -m pytest test/test_step5_pipeline.py test/test_step5_react.py test/test_step5_smoke.py -q`（重构前全绿基线：27 passed）
  - [x] 确认 `test/conftest.py` 与 `test/scripted_llm.py` 可用于驱动 orchestrator 测试

- [x] Task 1: 结果封装类 `step5_agent/orchestrator.py::SubAgentResult`
  - [x] 定义 `SubAgentResult` dataclass：seq/agent_name/status/artifact_path/summary/findings/error/request/usage/duration_ms/steps/tool_calls，含 `ok` 属性
  - [x] 单测 `test/test_orchestrator.py`：默认值、ok 判定、to_dict

- [x] Task 2: `DispatchAgentTool` + 链路守卫（orchestrator.py 内）
  - [x] 实现 `DispatchAgentTool(AgentTool)`：name=`dispatch_agent`，description/params_doc 写明固件三 Agent 与链路守卫；`_run(**kw)` 委托内部调度逻辑调 `run_agent`；覆盖 `execute` 放行 LLMError
  - [x] 链路守卫：`_UPSTREAM={analysis:"recon", verification:"analysis"}` 上游缺件→failed（记 SubAgentResult + dispatch_log）+明确错误（不执行）；`force=False` 且工件已存在→`skipped` 加载已有工件；成功→`success`
  - [x] 精简上下文：dispatch 给 `run_agent` 传上游工件路径（`upstream_path`），下游简报自动注入 `artifact_summary`
  - [x] 单测：成功/skipped/上游缺失/未知 agent 分支

- [x] Task 3: `Orchestrator` 编排层（orchestrator.py 内）
  - [x] `build_orchestrator_prompt`+`_build_initial_message`（三子 Agent 清单/调度纪律）；注册 `dispatch_agent`/`finish` 工具
  - [x] `run()`：复用 `run_react_agent` 跑 orchestrator ReAct 循环，维护 `_agent_results`/`_all_findings`
  - [x] 落盘 `process/agent/orchestrator/`：`transcript.jsonl`（LLM 输出）+ `dispatch_log.json`（每次调度请求/结果/状态）+ `result.json`（终态）
  - [x] 聚合去重各子 Agent findings；`finish` 收尾由 LLM Final Answer 汇总结论
  - [x] 单测 `test/test_orchestrator.py::test_orchestrator_integration_dirs`：dispatch→finish + 三文件/编号目录生成

- [x] Task 4: `run_agent` 输出目录参数
  - [x] `runner.py::run_agent` 增 `output_dir` 参数（None 沿用 `process/agent/<name>/`）；dispatcher 按 `<seq>_<type>` 传入

- [x] Task 5: 接入 `run_step5.py` 并适配既有流程
  - [x] `step5_run`：构造 `Orchestrator` 并执行编排（传 llm/force），替代硬编码 for 循环；保留无 key/`LLMError` 立即终止
  - [x] `render_report`/`_resolve_verified` 优先从 orchestrator result.json 定位工件，无记录回退读根目录
  - [x] 更新 `test/test_step5_pipeline.py`、`test/test_step5_display.py` 断言适配新目录/或编排流；新增 `test/test_orchestrator.py`
  - [x] `python -m pytest test -q` 全绿（147 passed, 10 skipped）

# Task Dependencies
- [Task 1] 无依赖
- [Task 2] 依赖 [Task 1]（SubAgentResult）
- [Task 3] 依赖 [Task 1][Task 2][Task 4]
- [Task 4] 依赖既有 `runner.py`（可与 [Task 2] 并行）
- [Task 5] 依赖 [Task 3][Task 4]
- [Task 0] 前置基准，可与 [Task 1] 并行
# 0001-Step5 采用 LLM orchestrator 编排三子 Agent

Step5 最初(2026-08-16)设计为三个 ReAct Agent 串行、无 orchestrator、控制流由 Python 硬编码(`requirements.md`、`rules.md:8`、`agents.md` 开头仍残留此说法)。2026-08-28 改为:一个 LLM 驱动的 `Orchestrator`(orchestrator.py)用 `dispatch_agent`/`summarize`/`finish` 三个动作调度 recon→analysis→verification,自身跑 ReAct 循环。各阶段是严格单向顺序门,同类型最多调度 3 次(默认 1 次 + 至多 2 次补跑),验证完成后由 orchestrator 经 summarize 取素材产出最终报告 `report.md`。

选择 LLM 编排而非硬编码,是因为子 Agent 的取舍(何时补跑、何时收尾、优先级)需要跨阶段动态决策,而当时的简单流水线已经暴露出分析遗漏高危疑点无法补救的问题。代价是引入了一个额外的 LLM 层:无 key 时无法跑编排(见 ADR-0002),`planner="pipeline"` 提供了跳过编排 LLM 的确定性快速模式。

旧的"无 orchestrator"表述是三份文档的历史残留,应以本 ADR 与 orchestrator.py 为准。

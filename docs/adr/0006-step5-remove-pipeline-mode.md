# 0006-Step5 删除 planner="pipeline" 确定性快速模式

`planner="pipeline"` 是 2026-08-28 与 LLM 编排一起引入的确定性快速模式:Python 按固定序列调度 recon→analysis→verification,不跑 orchestrator LLM 循环、不产 LLM 报告。原意是"省编排 LLM 轮次"。

删除它。step5_run 只剩 LLM 编排一条路径(planner 参数移除),pipeline 分支(`_run_pipeline`)、分支分叉、`record_failed` 的非 run 用法、`planner` 参数均清理。

## 决策理由

- **价值被压缩**:编排 LLM 既然保留(ADR-0001),pipeline 的"省编排 LLM 轮次"收益小于维护两条分支的代码成本。
- **双分支成本高**:`_run_pipeline`(run_step5.py:95-128)与 auto 分支写同一份调度逻辑两遍,`step5_run` 按 planner 分叉,交接/落盘逻辑双份。
- **不产报告是缺陷**:pipeline 模式 `report=None`,需打警告;若用户跑 pipeline 却期待报告,会困惑。
- **确定性价值不真实**:pipeline 的"确定性"只是省了编排 LLM 的自适应(补跑/优先级),而编排自适应正是保留 LLM 编排的理由。要快速跑完整链路,auto 模式 + 断点续跑已够。

## 代价

删除后,`planner` 参数、`_run_pipeline`、`run_step5` 分支逻辑移除;相关测试(若有 pipeline 专项)更新。纯删代码,无新增逻辑。

## 状态

已定,待实现(2026-09-01)。实现见 to-spec 生成的 spec / tickets。

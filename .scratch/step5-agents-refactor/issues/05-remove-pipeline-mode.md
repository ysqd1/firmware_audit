# 05: 删除 pipeline 模式

**What to build:** 移除 `planner="pipeline"` 确定性快速模式:`planner` 参数、pipeline 分支逻辑、`record_failed` 的非 run 用法全部清理,step5_run 只剩 LLM 编排一条路径。不再有"不产报告"的快速模式,所有 Step5 运行都产出报告、无告警歧义。

**Blocked by:** None(可立即开始)

**Status:** ready-for-agent

- [ ] 移除 `planner` 参数,step5_run 只剩 LLM 编排一条路径
- [ ] 清理 pipeline 分支逻辑与 `record_failed` 的非 run 用法
- [ ] 不再有"不产报告"的快速模式,所有 Step5 运行产出报告
- [ ] 流程级测试:断言 `step5_run` 不再接受 planner 参数,无 pipeline 分支

"""orchestration:Step5 编排层包(LLM Orchestrator 所在地)。

调度决策 + 留痕 + 报告:顺序门/唯一性/次数上限守卫、dispatch_agent/
summarize/finish 三动作、每疑点一实例复核调度、budget_state 动态分配、
report.md 生成与对账(ADR-0007)。本包只做编排,单实例执行在 runner,
findings 聚合纯逻辑在 aggregator,ReAct 引擎与数据契约在 engine/data/providers。

T1(ADR-0009)整体迁入为单模块 orchestration/orchestrator.py;后续票
按单一职责解体为 state/orchestrator/actions/handoff/dispatch_log/
verify_phase/reconciliation——其中 reconciliation(报告对账纯函数群)
已落地(T2),dispatch_log(调度留痕小类,start/finish/interrupted/attempt
四动词)已落地(T3),state(共享词汇:状态枚举/标签/结果封装)、
actions(三动作工具类+调度守卫纯函数)、handoff(交接块构建+快照落盘)
已落地(T4;包内依赖单向 orchestrator → actions → handoff → state,
环由 state 切断),verify_phase(每疑点一实例复核引擎:排序取 K/续跑
身份校验/锚点回填/阶段终态,编排主体只剩调用点与结果登记)已落地(T5;
单向 orchestrator → actions/verify_phase → …)。包内导入一律相对;
依赖只准向下(orchestration → runner/aggregator/engine/data/providers,
守护测试 test_step5_layer_guard.py 机器强制)。
"""

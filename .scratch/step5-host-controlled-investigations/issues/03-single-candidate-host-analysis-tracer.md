# 03: 跑通单 Candidate 的 Host Analysis tracer

**What to build:** 给定一个合法 Candidate，由 Host 驱动一个独立 Investigation 完成“请求模型—校验 Proposal—执行工具—保存 Evidence—回传 Observation View—结束调查”的最小纵向路径。Host 是这条路径唯一真实循环。

**Blocked by:** 01/建立逐步 Agent Session 协议；02/建立工具角色权限与重放契约。

**Status:** ready-for-agent

- [x] Candidate 获得运行内稳定递增 ID，并一一创建独立 Investigation。
- [x] Host 只有在完整 Proposal 校验通过后才应用 state delta 或执行 next action。
- [x] 每个逻辑工具调用获得独立 Evidence ID，保存规范化参数、完整且有界的原始 ToolResult、摘要、位置、digest、归属与顺序。
- [x] 相同输出不合并 Evidence；digest 只用于完整性验证。
- [x] Observation View 可截断但保留原始字面值，并能供下一次 Session 请求使用。
- [x] Analysis 可主动 close，产生明确 finished disposition 和 stop reason，但不产生 verification verdict 或 Finding。
- [x] Fake Session 与 fake tool 的 Host Action Loop 测试证明非法 Proposal 零副作用、不同 Candidate 状态互不污染。

## Comments

2026-09-13：实现与验收完成。代码提交为 b4988e0、b972102、298077b、694ceec、d09c2de。
`pytest -q firmware_audit/test` 最终结果为 386 passed、21 skipped；Host tracer 专项 25 passed；compileall 与 git diff --check 通过。
code-review 双轴复核：Standards 0 剩余发现，Spec 0 剩余发现。评审中发现的 Proposal JSON 无损校验、Session parser 兼容、失败 Observation 状态及循环/非有限工具数据留证问题均已补回归并修复。
本票仍为 expand 阶段：持久化恢复、重放、队列、Claim 策略、verification 与预算继续由后续工单实现，公开 Step5 入口尚未切换。

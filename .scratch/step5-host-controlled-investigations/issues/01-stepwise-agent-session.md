# 01: 建立逐步 Agent Session 协议

**What to build:** 在不改变现有公开 Step5 行为的前提下，增加一次模型请求只产生一个结构化 Proposal 的 Agent Session。它在返回 Proposal 后暂停，不执行工具、不推进阶段，为 Host 接管唯一控制循环建立可验证入口。

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] 合法回复只包含简短 decision summary、state delta 和唯一 next，并解析为 ActionProposal 或 FinalProposal。
- [ ] next kind 按 recon、analysis、verification 角色限制；Related Candidate 位于 state delta。
- [ ] 非 JSON、截断 JSON、未知字段、错误类型和非法枚举返回包含字段路径、期望类型与允许值的结构化错误。
- [ ] Session 本身不调用工具，也不拥有 while 循环或阶段完成权。
- [ ] 现有模型配置、上下文管理和 Transcript 能被复用，且旧公开流程在 expand 阶段继续通过既有测试。
- [ ] 使用 Scripted LLM 覆盖合法 proposal、角色限制和各类无效回复。


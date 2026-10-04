# Ticket 05 Implementation Plan

**Goal:** 按 ADR-0012 安全恢复中断调用，保持 call/Evidence 身份及成本统计。

**Architecture:** Host 以已持久化的逻辑调用记录恢复，先检查不可变 Evidence，再按 registry replay policy 决定重试或 interrupted。Ghidra 自己封装完整缓存验证，Host 不理解其文件布局。

**Tech Stack:** Python 标准库、pytest、现有 InvestigationStore / AgentSession / ToolResult。

基准：用户确认 c84d314；按用户指定 implement/tdd 在当前分支实现。
使用已批准 spec 的 Host Action Loop、Store、工具执行契约 seams。按纵向切片逐个 RED → GREEN，不预写全部测试或实现。

- [x] Host 只读中断恢复：在 test_step5_tool_recovery.py 从 fake tool 注入中断，经新 Host 恢复，断言同 call ID / Evidence ID、attempt=2、logical=1。修改 host/analysis.py 与必要的调用状态模块。
- [x] NEVER 中断：失败 Observation 回馈 Agent，后续替代动作可继续，原工具不重放；覆盖 Observation 与 finished 两个持久化边界。
- [x] Ghidra 完整缓存：在工具执行 seam 用 fake Docker 生成三件套；校验输入及产物 digest，缺失或损坏拒绝接纳。实现 providers/tools 下的专属缓存记录。
- [x] Ghidra Host 恢复：有效缓存零新增 attempt；无效缓存幂等重试且不再走弱缓存；失败仍进入 Evidence。
- [x] 校验持久化调用记录，重复中断与多 Candidate 稳定身份；更新 04 中临时暂停的测试预期。
- [x] 每切片运行单文件 pytest；检查类型工具可用性并定期 compileall。最后运行 pytest -q firmware_audit/test 与 git diff --check。
- [x] 使用 code-review 两个独立只读子 agent，gpt-5.6-terra / medium，分别检查 Standards 与 Spec；核验并修复真实问题。
- [x] 更新 ticket 05 验收记录，提交本票文件到当前分支，保留用户原有改动。

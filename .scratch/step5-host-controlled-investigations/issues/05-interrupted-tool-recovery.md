# 05: 恢复中断的工具调用

**What to build:** Host 能辨认工具调用在中断时所处的边界，并依据工具声明的 replay policy 安全恢复，同时保持逻辑调用、Evidence 和实际成本的身份一致。

**Blocked by:** 02/建立工具角色权限与重放契约；04/让 Investigation 可持久化并精确恢复。

**Status:** ready-for-agent

- [x] 执行前记录带 call ID 的 tool started，原始 Observation 持久化后才记录 tool finished。
- [x] 只有 started 的只读幂等调用使用同一 call ID 重试。
- [x] Ghidra 调用先校验缓存完整性与 digest；有效则接纳，无效或缺失才幂等重试。
- [x] 不可自动重放的中断调用明确标记 interrupted，不静默执行第二次。
- [x] Evidence ID 对应逻辑调用；重试只增加 attempt，不产生新 Evidence ID 或 logical tool call。
- [x] tool attempts 和 logical tool calls 分开统计，失败 Observation 仍可被 Agent 用于选择替代动作。
- [x] 故障注入测试覆盖中断发生在 started 后、Observation 写入后和 finished 后三个边界。

## Comments

2026-09-14：实现完成并提交 `b9ba783`，评审基准由用户确认为 `c84d314`。按 implement/tdd 逐切片实现，使用已批准的 Host Action Loop、Store 与工具执行契约 seams。

验证：`pytest -q firmware_audit/test` 为 **434 passed、21 skipped**；compileall、git diff --check 与 staged diff 检查通过。mypy/pyright 均未安装，未声称完成静态类型检查。故障注入覆盖 started/Observation/finished，以及连续中断、跨 Candidate 身份、损坏调用投影、NEVER 失败后替代取证、Ghidra 缺件/digest/输入变化/半代边车/硬链接重试隔离。

双轴 code-review 使用用户指定的 **gpt-5.6-terra / medium**，两位 agent 只读检查。首次因用量限制未完成；用户要求继续后重试成功。

- **Standards**：无硬性违规；重复 SHA256 helper 已合并并复查。保留一项明确非阻塞的调用记录类型化建议：当前私有 JSON runtime 与 04 一致，集中恢复校验及测试已覆盖，暂不增加抽象。
- **Spec**：无缺失验收项、错误实现或范围扩张。

Ghidra 普通 execute 保留 ADR-0010 的旧缓存兼容；只有恢复 probe 接纳具备输入 digest 与完整三件套 digest 的缓存。恢复重试不会回到弱缓存路径，且原子替换边车不会改写其他去重路径共享的 inode。调用 attempt 在执行前持久化边界记账；有效恢复缓存不增加 attempt，不可重放调用保留结果未知的 interrupted Observation。预算上限/运行锁/公开入口切换仍由后续工单完成。

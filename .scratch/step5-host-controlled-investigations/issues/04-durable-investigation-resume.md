# 04: 让 Investigation 可持久化并精确恢复

**What to build:** 把单 Candidate tracer 变成崩溃后可从确定边界恢复的持久化调查；事件是权威历史，状态文件只是可重建投影。

**Blocked by:** 03/跑通单 Candidate 的 Host Analysis tracer。

**Status:** ready-for-agent

- [x] 事件带连续 seq，快照记录 last event seq，恢复只重放快照后的完整事件。
- [x] 原始 Observation 和事件先落盘，状态快照随后通过原子替换更新。
- [x] 模拟事件已写而快照未更新时，重启能得到与不中断执行相同的 Investigation State。
- [x] 最后一行不完整时保留或隔离异常尾部、记录告警并从最后完整事件继续。
- [x] 中间事件损坏时拒绝自动恢复，不静默跳过。
- [x] 顶层 JSON 与逐行事件分别校验 schema version 和 event version；不兼容版本引导创建新运行世代。
- [x] 恢复上下文只由固定提示、当前状态、相关 Evidence 摘要、最近动作及 Observation View 和剩余预算重建，不重放完整 Transcript。
- [x] 已持久化的合法模型回复不重复请求；未持久化回复从同一状态快照重新请求。

## Comments

2026-09-14：实现完成并提交 `c84d314`。最终验证：`pytest -q firmware_audit/test` 为 402 passed、21 skipped；compileall 与 git diff --check 通过。未安装 mypy/pyright，未执行静态类型检查。

code-review：Standards / Spec 均由 gpt-5.6-terra、medium 只读评审，最终无剩余需修复项。已修复损坏投影的恢复指引与 Evidence 半写入边界，回归覆盖事件/快照/Observation 中断及真实 Session 上下文重建。

工具已执行但 Observation 尚未持久化的 pending/in-flight 状态会明确暂停，自动重放交由工单 05。预算字段由调用方提供并持久化；预算计算与扣减属于工单 10。运行世代/锁与公开入口切换仍按后续工单推进。

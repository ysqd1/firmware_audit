# 0003-Step5 verification 改为每疑点一实例

verification 原为单实例多疑点:一个 verification Agent 接收全部 findings.json,在 24 轮内逐条复核。问题是轮次摊薄——每条 finding 复核约需 3-6 轮(find_decompiled_function 看代码 + xref 看引用 + checksec 看保护 + read_file 看细节),13 条 findings 需要约 52 轮 >> 24 上限,长尾疑点复核不完。e2e 中 verification 未完整跑,API 307 是主因,但轮次摊薄是结构缺陷。

改为**每疑点一个 verification 实例**:

- analysis 产出 findings(N 条候选)后,按 severity(critical>high>medium>low>info)主排序 + confidence 次排序,取前 K 条(默认 10,用户可配置)。
- 对每条取中的 finding 派一个独立 verification 实例:输入=单条 finding + 相关工件指针,`max_iters` 降到 8(远低于原 24)。
- 每实例产单条 verified finding(verified/rationale 结构一致),聚合回 verified_findings.json。
- 未进入前 K 的疑点**不丢弃**:进报告独立区段(⚠ 未复核),`verified=None`(schema 原注释"None=未复核"即此语义),confidence 保留 analysis 初值,报告明确标注"未经复核"。
- verification 可修改 confidence(存疑项降级保留),不新增 verified_scale 枚举——verified=None + 报告标注已足够表达未复核。

## 连带简化

- **补跑逻辑取消**:B 方案下每条 finding 必派实例,"预算耗尽仍有 pending 疑点"的场景被"每条必跑"覆盖,补跑决策(原 orchestrator LLM 判断 / 或拟加的代码规则兜底)不再需要,整个移除。
- **统计不落盘维持**:verification 逐实例的 tool_calls 仍只进各实例 transcript/obs 与内存返回,dispatch_log/result.json 不加 tool_calls 字段(transcript+obs 已留痕,结构化聚合非必需)。

## 决策理由

选择每疑点一实例而非"单实例多疑点"或"按 chunk 分组":

- **强聚焦**:上下文只装一条 finding + 相关证据,判定质量最高(可信度优先的正解)。
- **轮次匹配**:每条给足 8 轮,不摊薄。
- **失败隔离**:一条卡住不影响其他,补跑天然按 finding 粒度。
- **证据链清晰**:每实例 transcript 专注一条,可追溯性更强(evidence discipline 更好落实)。
- **上下文隔离铁律不破**:每实例只从工件读,不传对话历史,与"Agent 间只通过工件文件交接"一致。

被否的方案:chunk 分组(多疑点一实例)存在"最后一两疑点上下文如何传给下一组"的死结——跨组传对话历史打破上下文隔离铁律,上下文跨组累积导致窗口失控。每疑点一实例无此问题。

## 代价

API 调用量上升:K=10 × 8 轮 ≈ 80 次 vs 原 1 × 24 = 24 次,约 3-4 倍(每次调用重复装载系统提示词/brief)。对"审计可信度优先"的优先级是合理代价;K 与轮次均可配置,可下调。

## 状态

已定,待实现(2026-09-01)。实现见 to-spec 生成的 spec / tickets。

# 12: 生成 severity、事实报告并封存运行

**What to build:** Host 从冻结的结构化机器结果生成可重算 severity、固定事实报告和 manifest；只有调查与复核责任全部收束后才封存运行。

**Blocked by:** 09/跑通独立 Verification 与 Finding 聚合；10/落实协议失败、预算与停止规则；11/建立运行世代、活动锁和队列级恢复。

**Status:** ready-for-agent

- [x] Severity 按四档影响范围与三档触发条件矩阵生成，已证实缓解左移一档，完全阻断则反驳决定性 Claim，关键信息缺失不得 critical。
- [x] 报告按固定顺序生成运行与配置、Confirmed、Rejected、Inconclusive、not started、Coverage Gaps、Evidence Index、资源与停止原因。
- [x] 报告默认只呈现敏感值类型、位置、长度与 digest 前缀，不改写权威 Evidence 或发给 Session 的原始字面值。
- [x] Analyst Notes 可选、明确标注且不能覆盖事实；生成失败不阻止封存。
- [x] 仅当所有 proposal 入库、入选调查有 disposition、未选项 not started、全部 ready 案卷已复核且报告与 manifest digest 已生成后才 completed。
- [x] 报告或 manifest 失败保持 finalizing，恢复后可继续；sealed machine artifacts 不可修改。
- [x] 确定性快照测试证明相同结构化输入生成相同事实与 digest，故障注入测试覆盖 finalizing 恢复。


## Comments

**实现（2026-09-18，commit eed1878）**：新增 `host/severity.py`（矩阵 + facet 规则声明）与 `host/reporting.py`（事实报告/Evidence Index/完成门/`seal_run`），driver 内联封存阶段;测试 `test_step5_host_severity.py`（42 项）+ `test_step5_host_reporting.py`（23 项），全套件 1129 passed + 21 skipped。

- **Severity 输入契约（ADR-0012 L47"Verifier 给出结构化影响和前置条件"）**：Claim Result 扩展三个结构化 facet——`actual_impact.impact_scope`（hardening/local/component/system）、`preconditions.trigger_condition`（special/limited/loose）、`mitigations.mitigation_effect`（partial/blocking）；**supported 时必填**（评审修复：省略会让"已证实缓解左移"被静默绕过），not_applicable 的 preconditions 隐含宽松触发。提交与恢复路径共用同一校验；Finding 载荷带 `severity` + `severity_basis`，`SEVERITY_LEVELS` 单一出处移入 severity.py（review overlay 反向引用，兑现票 13 移交①）。
- **矩阵与规则（AC1）**：16 格矩阵逐值对表 ADR L59；partial 缓解左移一档（special 为地板）；blocking 缓解反驳 actual_impact——聚合层落 rejected 不生成 Finding（判定与 severity 重算共用 `severity_assessment` 单一出处），`build_finding_payload` 对 blocking 防御性拒绝；关键信息缺失按最重档代入（system/loose）但 critical 封顶 high。**注**：最重档代入与 not_applicable→loose 是 ADR 未定义处的自加规则（方向保守），建议后续回写 ADR。
- **事实报告（AC2/AC3）**：固定八节（ADR L57 顺序）markdown；只读冻结工件、字节确定（相同结构化输入 → 相同报告与 digest，跨副本快照测试）；**run_state 不进报告**——它是可变投影，封存后复算会与封存时不一致，digest 不可校验（实现中发现的坑）。Evidence Index 只呈现 tool/位置/长度/digest 前 12 字符，不展开 Observation/Summary 原文（有"报告不含密钥原文"测试）。closed/unresolved 调查以明确标注子段挂在第 4 节内——ADR 八节契约外的有意取舍，保可见性。
- **Analyst Notes（AC4）**：驱动封存期一次 LLM 调用（固定提示词，`ANALYST_NOTES_SYSTEM_PROMPT`），catch-all 失败只告警跳过；注记段在八节之后、明确标注非机器事实；**事实 digest 不含注记**。
- **完成门与封存（AC5/AC6）**：`completion_gate` 检查 proposal 入库/入选 disposition/未选 not_started/ready 案卷全复核;`seal_run` = report.md（atomic_text）→ manifest `seal` 块（sealed_at + report_sha256（事实部分）+ 机器工件逐文件 sha256，两棵树全量）→ run_state=completed;失败不触碰 run_state（保持 finalizing 可恢复，故障注入测试覆盖 report 写失败与 manifest 写失败）;completed 幂等返回既有 seal 不重写。**双 digest 口径**：`report_sha256` 覆盖事实部分（可按注记分隔符从盘上 report.md 复算），`artifact_digests["report.md"]` 是含注记全文——为确定性有意为之。
- **Driver**：处理收束（accounting→finalizing）后内联封存;finalizing 世代恢复**只续封存不重跑处理**（爆炸 Session 测试守护）;封存失败回写 `seal_failed:*` 保持 finalizing;封存后 completed 世代不被恢复（后续 run 开新世代），机器工件字节不变有测试。跨票回归：封存写入 completed 后票 13 overlay 即对真实运行生效，且追加 review 不改 manifest seal。
- **给票 14 的移交**：公开入口切换时直接复用 `RunDriver.run()`（现已产 sealed run + report.md + manifest seal）; Analyst Notes 默认开启（llm 可用即尝试），如需关闭应在入口层显式参数化。

**双轴子代理评审**（Standards：0 硬违规 + 6 判断项;Spec：AC 全有落点，1 漏洞 + 2 自加 + 2 偏差）：

- 已修：①**左移绕过漏洞**——supported 省略 facet 被静默忽略 → 协议层必填（回归 S9）;②blocking 规则双编码 → `aggregate_verdict` 复用 `severity_assessment`;③reporting 快照读取与 candidates 装载重复 → 提取共享;④`atomic_json`/`atomic_text` 发布序列重复 → `_atomic_publish`;⑤无效 noqa 清理。记录取舍：①最重档代入/not_applicable→loose 自加规则（建议回写 ADR）;②closed/unresolved 挂第 4 节子段;③双 digest 口径;④severity_assessment 返回裸 dict（盘上 JSON 契约即 dict,不引入转换层）。

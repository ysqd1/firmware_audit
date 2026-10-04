# 08: 完成 Analysis Claim 与 Verification Case 提交

**What to build:** Analysis 对一个入选 Candidate 维护可审计的假设与 Claim 状态；Host 依据固定 Profile 和 Evidence 门槛决定是否允许提交冻结 Verification Case。

**Blocked by:** 03/跑通单 Candidate 的 Host Analysis tracer；07/完成 Candidate 去重、评分和双队列选取。

**Status:** ready-for-agent

- [x] Investigation 同时最多一个 working hypothesis，旧假设以 supported/refuted/replaced 保存简短历史。
- [x] 支持数据传播、配置、凭据处理、内存处理和受限 generic Profile，并实现共同及各 Profile 的必填 Claim。
- [x] Claim 状态只允许 unassessed、supported、refuted、not applicable；supported 必须引用存在的 Evidence ID。
- [x] lifecycle status、disposition 与 stop reason 独立，并拒绝所有非法转换。
- [x] Ready gate 要求必填项有状态、反证已处理且无 blocking gap；决定性 Claim refuted 可正确结束为 rejected。
- [x] 未达 ready gate 的高优先级调查可按 evidence gap 生成冻结案卷，明确保留已有 Evidence 和缺失项，不伪装为 ready。
- [x] 连续五个无新 Evidence、Claim/假设/路径/gap 变化的已完成语义动作触发 no progress；非语义失败不计入。
- [x] Host Policy 表驱动测试覆盖全部 Profile、门槛、关闭路径和非法状态转换。

## Comments

**验收记录(2026-09-14,commit `aa6a7cd`,初始实现 `2e2ee79` 后并入评审修复)**

- 实现:`host/claims.py` 新模块(纯策略,零 IO)——五类 Claim Profile 必填项与决定性(common 4 decisive + preconditions/mitigations 非决定性可 not_applicable + 各 Profile 额外决定性项;generic 只用共同项)、两阶段 state_delta(`validate_analysis_delta` 整份校验成 DeltaPlan → `apply_delta_plan` 免校验幂等应用,受管 state 键 hypothesis/claims/path_nodes/evidence_gaps 直写拒绝,其余未知键按 ticket 03 笔记本语义透传)、lifecycle/disposition/stop_reason 三轴守卫(5×5 转换矩阵 + finished 才许 disposition/stop_reason 且双必填)、ready gate(unassessed/decisive_refuted/unsupported/invalid/open_blocking_gaps 五桶)、冻结案卷 payload(schema_version=1,全量必填 Claim 快照 + 完整 Evidence Reference + pending_claims + blocking_gaps)、no-progress 进展信号。接线 `analysis.py`:submit_case 分支(trial 深拷贝过 gate,拒绝路径零状态突变零 pending 残留;`verifications/<cand>/case.json` 内容确定性可重放)、close 派生 disposition(决定性 refuted → rejected/decisive_refutation,否则 closed/agent_closed,替代 ticket 03 占位)、动作增量副作用前整份校验(用 `peek_next_evidence_id()` 预测本次证据 ID,不提前消耗序列)、连续 5 无进展强制 `finished/unresolved/no_progress`(计数持久化随快照恢复)。恢复:claim_profile 缺失时从 candidate proposal 回填(票 04/05 旧快照保真);apply 对恢复出的畸形受管结构经宽容读取器规整防 mid-loop 崩溃。
- 测试:`test_step5_host_claims.py` 新增(纯策略表驱动:Profile 名单/两阶段 delta 幂等/转换矩阵/gate 五桶/案卷冻结/进展信号),`test_step5_host_analysis.py` 新增 tracer 集成段(submit ready/gap/伪装双向拒绝、close 派生、no-progress 触发/复位/恢复/非语义失败不计、案卷恢复幂等、旧快像回填),`test_step5_host_resume.py` 裸 `hypothesis` 键改结构化。全量 **780 passed, 21 skipped**;compileall 干净。
- code-review(Standards 轴):修 3 硬伤——测试内局部导入提升、死常量 `DELTA_DOMAIN_KEYS` 删除、`apply_analysis_delta` 文档串改为如实描述"无中段调用方的便捷路径"。Duplicated Code 两条判读为刻意保留(delta 拒绝新输入带字段路径 vs gate 容忍恢复态畸形分桶,检查语义不同),记录不改。
- code-review(Spec 轴):修 1 处——gate 分流顺序,决定性 refuted 的归类不再依赖引用合法性(引用失实时同时进 decisive_refuted 与 unsupported 桶,指引仍是"结束为 rejected")。三条记录在案的决定:①AC6"高优先级"过滤属队列层,延期到票 11/12(tracer 只做案卷一致性校验);②evidence_gap 案卷 lifecycle 与 ready 同取 `ready_for_verification`(进度语义;ADR"不伪装成 ready_for_verification"落在案卷内容 admission_reason/pending_claims/blocking_gaps 上,生命周期不新增第六值——**此重解读请用户过目**,不认可则改回时需同步调整票 09 的案卷选取入口);③hypothesis_outcome 重复提交与恢复重放不可区分(no-op),为恢复幂等刻意接受。


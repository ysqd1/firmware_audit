# Ticket 08 实现计划:Analysis Claim 与 Verification Case 提交

新模块 `host/claims.py`(纯策略,IO 零依赖,表驱动测试)+ `host/analysis.py` 接线。
测试文件 `test/test_step5_host_claims.py`;`test_step5_host_analysis.py`/`test_step5_host_resume.py` 少量语义更新。

## 设计决定(依 ADR-0012 + spec 推导)

1. **Claim 模式**(ADR L31):共同 decisive `target_exists/root_cause/trigger_or_exposure/actual_impact`;
   共同非决定性 `preconditions/mitigations`(可 not_applicable);四类 Profile 额外项全部 decisive;
   `generic` 只用共同项。`not_applicable` 仅允许非决定性(决定性"不适用"应走 close_investigation)。
   Profile 名单复用 `candidates.CLAIM_PROFILES`(completeness 测试锁定两个来源一致)。
2. **Claim 状态**:`unassessed/supported/refuted/not_applicable`;delta 只能设置为后三种。
   `supported` 必须引用 ≥1 个本 Investigation 已有 Evidence ID(含本次 action 将产生的
   预留 ID——副作用前整份校验,用 `EvidenceRecorder.peek_next_evidence_id()` 预测,不提前消耗序列);
   `refuted` 的 evidence_ids 可选但若给出必须存在。
3. **working hypothesis**:单一槽位。`state_delta.hypothesis={"statement",...}` 设新假设
   (旧假设自动以 `replaced` 入史);`state_delta.hypothesis_outcome={"outcome": supported|refuted}`
   退役当前假设。历史条目 `{statement, outcome, note?}`,outcome ∈ supported/refuted/replaced。
   同 statement 重复设置 = no-op(幂等 + 不算进展)。
4. **受管 state 键**:`hypothesis/claims/path_nodes/evidence_gaps` 由策略拥有,只能经
   对应 delta 键(`hypothesis`/`hypothesis_outcome`/`claims`/`path_nodes`/`gaps_opened`/`gaps_resolved`)
   结构化写入;直写受管键(如 `{"claims": "junk"}`)→ ProposalRejectedError。
   其余未知键按既有 dict.update 语义透传(ticket 03 起的 agent 笔记本语义保留)。
5. **两阶段 delta**(spec 故事 8:副作用前校验整份回复):`validate_analysis_delta(state, delta,
   evidence_ids, profile) -> DeltaPlan`(无副作用,可抛 ProposalRejectedError)+
   `apply_delta_plan(state, plan) -> AppliedEffects`(免校验,按构造幂等:同值跳过/append 去重/
   已 resolved 不再变)。幂等性服务于 pending 恢复重放(close/submit 在 proposal_accepted 与
   终态 checkpoint 之间崩溃后按同一 delta 重应用)。
6. **lifecycle 守卫**:`queued→{investigating,finished}`、`investigating→{ready_for_verification,
   finished}`、`ready_for_verification→{verifying,finished}`、`verifying→{finished}`、`finished→∅`;
   同值赋值视为 no-op 放行。`disposition/stop_reason` 仅在 finished 时允许且必须齐全(非 finished
   时必须双 None);枚举 `DISPOSITIONS=confirmed/rejected/inconclusive/closed/unresolved/not_started`、
   `STOP_REASONS=completed/decisive_refutation/no_progress/budget_exhausted/input_failure/protocol_error/
   agent_closed`(可随 10/11 扩)。违例抛 `PolicyError`。
7. **ready gate**(ADR L37):必填项全部有合法状态(缺记/未评估=unassessed)、supported 引用真实
   Evidence、**决定性 Claim 无 refuted**(=「反证已处理」:决定性反驳的正确出路是 close 成
   rejected,而非送复核)、无 open blocking gap。非决定性 refuted/not_applicable 不拦 ready。
   GateResult{ok, unassessed, decisive_refuted, unsupported, invalid, open_blocking_gaps, failures[]}。
8. **关闭派生**(替代 ticket 03 占位):close_investigation 时若任一决定性 Claim refuted →
   `(rejected, decisive_refutation)`,否则 `(closed, agent_closed)`(自愿关闭不制造 verdict,故事 50)。
9. **submit_case**:state_delta 弹出 `admission_reason∈{ready,evidence_gap}` 后走域校验;
   在**trial 深拷贝状态**上应用+评估 gate(拒绝路径零状态突变、零 pending 残留),
   通过才落 pending/checkpoint → 应用 → 冻结案卷 → `investigating→ready_for_verification`。
   - ready:gate 必须全绿;决定性 refuted 时拒绝并指引 close(rejected 路线)。
   - evidence_gap:gate 必须未过且非决定性反驳,且确有缺失项(open blocking gap 或 unassessed
     必填)可冻结;gate 已过时提交 gap → 拒绝(伪装降级也是伪装)。
   - 「高优先级才允许 gap 送复核」的优先级过滤属队列层(票 11/12),tracer 只做一致性校验。
   - 案卷落 `run_dir/verifications/<cand>/case.json`(atomic_json,内容确定性→重放同字节);
     payload 含 schema_version=1、claim_profile、admission_reason、全量必填 Claim 快照
     (缺失记为 unassessed)、完整 Evidence Reference 列表(定位材料用)、blocking_gaps、
     pending_claims。lifecycle 取 `ready_for_verification`(进度语义;是否伪装成 ready 由
     案卷 admission_reason 区分——ADR「不伪装」约束落在案卷内容上)。
10. **no-progress**(ADR L37/L73):只计**已完成语义动作**(action_completed,工具成败不论——
    失败 Observation 也是 Evidence);协议无效/服务失败根本不产生完成动作,天然不计。
    进展信号:新 Evidence digest 未见于既往 digest ∨ Claim **状态**迁移(含 unassessed→X;
    同状态改备注不算,防刷)∨ 假设实质变化(statement 变化或退役)∨ 新增 path node ∨
    消解 open gap。连续 5 次无进展 → 强制 `finished/unresolved/no_progress` 并返回。
    计数持久化于 `Investigation.no_progress_count`(恢复续算);seen digests 从 evidence 派生,不另存。

## Investigation/恢复改动

- `Investigation` 新增 `claim_profile="generic"`、`no_progress_count=0`;`add_candidate` 从
  proposal.claim_profile 读取(枚举校验,非法 → ValueError)。
- 恢复校验:claim_profile 缺失时从既有 candidate.proposal 回填(票 04/05 旧快照保真),
  类型/枚举校验;no_progress_count int≥0。
- `_candidate_context` payload 增 `claim_profile` 与 `claim_schema`(profile_claim_document)。

## 波及的既有测试更新(语义变化所致)

- close 后 stop_reason 不再恒为 decisive_refutation → `agent_closed`(无决定性反驳时);
  `test_host_runs_one_candidate_and_preserves_distinct_evidence` 断言更新。
- 裸字符串 `working_hypothesis`/`hypothesis` 键改为结构化 hypothesis delta;
  `test_step5_host_resume.py` 的 `{"hypothesis": "saved"}` → `{"hypothesis": {"statement": "saved"}}`
  及 state 断言更新为 `{working, history}` 形态。

## 切片(逐片 TDD)

- [x] S1 Profile/Claim 名单 + 状态枚举 + completeness(表驱动)
- [x] S2 delta 校验/应用(两阶段 + 幂等 + 受管键)全表
- [x] S3 lifecycle/disposition/stop_reason 守卫矩阵
- [x] S4 ready gate 表(含各 Profile、反驳分流、缺口)
- [x] S5 案卷冻结 payload(ready/gap)
- [x] S6 tracer 接线:submit_case 两分支、close 派生、no-progress 触发/复位/持久化、
      副作用前校验、恢复保真、e2e(真实 parse_proposal JSON)
- [x] S7 全量测试 + compileall + code-review(Standards/Spec 双轴)+ 修复 + 提交

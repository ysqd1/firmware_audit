# Ticket 09 实现计划:跑通独立 Verification 与 Finding 聚合

## 边界(与后续票的切分)

- 票 10:协议重生成×3、三角色协议失败收束(verification→inconclusive/protocol_error)、
  服务中断保存、LLM/token/tool 预算记账、配置解析。→ 本票:协议无效回复沿既有先例
  直接抛 `ProposalRejectedError`(与 analysis tracer/submit_case 同款),轮次耗尽给
  `budget_exhausted` 的最小收束(聚合既有结果,缺项按未支持→inconclusive)。
- 票 11:运行世代/活动锁/队列级恢复;票 12:severity 矩阵、事实报告、封存。
  → 本票:related candidates 校验+落盘到 results/finding(带 origin 关系),不回写
  Candidate Store 队列;不生成 severity。
- 工单 AC8 的"公开级集成测试"待票 14 公开切换后补;本票以 Action Loop seam
  (真 Host 循环 + Fake Session/Fake tools,走 tracer submit → verification 全链)覆盖
  confirmed/rejected/inconclusive/evidence-gap 四路。

## 设计决定

1. **新模块 `host/verification.py`**(纯策略 + runner 同文件,镜像 recon.py 先例):
   - 纯策略:`CLAIM_RESULT_JUDGMENTS=("supported","refuted","not_applicable","unresolved")`、
     `VERDICTS`、`RESULTS_SCHEMA_VERSION=FINDING_SCHEMA_VERSION=1`、
     `DEFAULT_VERIFICATION_MAX_ROUNDS=15` + `resolve_verification_max_rounds()`
     (env `STEP5_VERIFICATION_MAX_ITERS`,ADR-0012 L39 同名覆盖)、
     `validate_verification_delta`(两段式,镜像 claims.py)、`apply_verification_delta_plan`、
     `aggregate_verdict`、`plan_verification_queue`、`build_case_brief`、`build_finding_payload`、
     `load_cases`、`HostVerificationRunner`。
2. **Claim Result schema**(AC3):`state_delta.claim_results = {name: {judgment, observed,
   evidence_ids, method, limitations?}}`;observed/method 必填非空;limitations 可省略;
   supported **与 refuted** 都必须引用本次复核会话的 Evidence(refuted 是积极反驳断言,
   无证据的反驳足以误杀案卷,必须落证据);not_applicable/unresolved 允许空引用;
   决定性 Claim 不允许 not_applicable(与 analysis 同规);未知 Claim 名拒绝
   (Profile 之外禁止扩张)。同轮 action 引用 `peek_next_evidence_id()` 预留 ID
   (复用票 08 手法)。重复提交 last-write-wins(与 analysis claims 同款,幂等重放安全)。
3. **verdict 聚合(AC4/AC5,纯函数)**:任一决定性 refuted → rejected;全部必填项
   (supported 带本次引用 或 非决定性 not_applicable)→ confirmed;其余(缺项/unresolved/
   非决定性 refuted/防御性脏记录)→ inconclusive。工具不可用=unresolved,只阻断
   confirmed 不构成反证。ready 与 evidence_gap 同一规则(故事 68)。
4. **独立上下文(AC1)**:`build_case_brief` 纯函数产出简报:candidate proposal
   (target/signal/next_action/source/sink)、claim schema(名/标签/决定性)、
   claims_to_verify、**冻结案卷的 evidence_references 仅作重定位指针**
   (evidence_id/tool/arguments/location/summary/digest + 明示"不可作为支持证据")、
   pending_claims/blocking_gaps(gap 案卷任务)、本次会话已得 Evidence 与已交 Claim
   Results、last_action/observation_view/剩余轮次。**不含**冻结案卷 claims 的
   status/note(analysis 判定与说服性 rationale 不进复核上下文)——测试以
   inputs[0] 断言不泄漏。
5. **队列(AC6,纯函数)**:`plan_verification_queue`:ready 全量在前(按 candidate_id
   = 提交序),evidence_gap 按 (-priority.total, candidate_id) 其后,`max_gap_cases`
   截断(剩余预算语义,默认不设限);ready 永不截断(故事 65)。priority 取自
   CandidateStore 记录(缺记录按 0)。
6. **Evidence 命名空间**:`EvidenceRecorder` 加 `namespace="investigations"` 构造参数
   (reserve/restore_slot 的 location 前缀),复核用 namespace="verifications" →
   `verifications/<cand>/evidence/ev-*.json`(ADR-0012 L47"每个复核目录保存…
   Evidence References");`seed_sequence_from_files` 扫两棵树,保证运行内 Evidence ID
   全局唯一不重号。EvidenceReference.candidate_id 仍是 cand-xxxx(recover 的
   parts[1] 校验天然兼容),investigation_id 用 `verify-inv-xxxx` 区分来源。
7. **复核会话持久化**:`InvestigationStore` 加 `root="investigations"` 参数 → 复核事件
   与快照落 `verifications/<cand>/{events.jsonl,state.json}`;快照结构
   `{case, session{claim_results,related_candidates,passthrough}, evidence, runtime}`。
   runner 恢复路径镜像 tracer:pending proposal 重放、tool_started/interrupted/
   cache 恢复、results.json 已存在则短路收尾(幂等)。checkpoint kinds:
   proposal_accepted/tool_started/tool_attempt/tool_interrupted/tool_finished/
   action_completed/case_finished。
8. **生命周期归属**:Investigation 快照唯一写者仍是 tracer——新增公共方法
   `begin_verification`(ready_for_verification→verifying;已在 verifying 幂等 no-op)、
   `finish_verification(candidate_id, disposition, stop_reason)`(verifying→finished;
   已 finished 且 (disposition,stop_reason) 一致 → 幂等 no-op,不一致 → ValueError)。
   落账顺序:聚合 → finding 追加(幂等,按 candidate_id 去重)→ results.json →
   finish_verification → checkpoint,崩溃重放不产生重复 Finding。
9. **Finding(AC7)**:仅 confirmed;`findings.json`(run 根)读-追加-原子写,
   finding_id=f-xxxx 按追加序;载荷含 candidate/investigation/claim_profile/verdict/
   claim_results(独立判定全文)/evidence_references(本次)/related_candidates/origin。
   related candidates 结构校验:`normalize_intake(source="verification:<cand>")` +
   必须引用本次会话 Evidence + 必须带独立 fingerprint 输入(signal: anchor/mechanism
   至少其一;coverage: component_or_entry/check_goal 至少其一,"独立入口、位置或
   机制"的结构代理),origin 回填 from_candidate/from_investigation/evidence_ids。
10. **inconclusive 不回 analysis(AC5)**:lifecycle finished 后 `run_analysis` 被
    `_current_investigation` 结构性拒绝——测试断言之。

## 切片

- [x] S1 纯策略 + 表驱动测试(判定枚举/证据落地/聚合矩阵/队列/简报防锚定/Finding 载荷)
- [x] S2 基建:EvidenceRecorder namespace、InvestigationStore root、tracer
      begin/finish_verification(+共享 validate_saved_tool_call 抽取到 tooling.py)
- [x] S3 HostVerificationRunner 动作循环 + Action Loop 测试(四 verdict、防锚定、
      引用拒绝、related、轮次)
- [x] S4 断点续跑/finding 幂等/findings.json + 全量测试(852 passed/21 skipped)
- [x] 双轴 code-review、修复 amend、工单勾选与 Comments 验收记录
      (Spec 8 AC 全 PASS;Standards 4 中 5 低全处理,最终 commit `8eeaefb`,
      全量 859 passed/21 skipped;related 回写认领提醒已追加到票 11 Comments)

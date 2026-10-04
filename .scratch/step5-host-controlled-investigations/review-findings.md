# Step5 Host 控制层 票 01-10 累积评审 findings(接缝评审)

范围:`git diff e9abefa...1bc0b0c`(30 文件 +12207/−58),只查跨票接缝,不重验各票 AC。
阅读范围按 brief §1(host/ 10 文件当前完整实现 + 该范围 diff)。

## Standards · 2026-09-16 · HEAD 1bc0b0c

说明:范围内 `host/` 全部文件均为**新增**(diff 只有 `+` 行),"diff 原文"即所引代码行。
标准来源:AGENTS.md(分层规则/工具契约)、ADR-0012(L 行号)、CONTEXT.md 术语表。
brief §2 的七条"已定取舍"逐条套用,命中处未重复报(见文末归档区)。

### 判断题(10)

1. **Verifier 的 Related Candidate 契约只存在于校验器,提示词未列必填字段** —
   `verification.py:1147-1151` 提示词只写「只有出现独立入口、处理位置或问题机制(signal 带
   anchor/mechanism,coverage 带 component_or_entry/check_goal)时才在
   state_delta.related_candidates 提出」;同一入口 `candidates.py:39` 却要求
   `_INTAKE_REQUIRED_TEXT = ("kind", "target", "signal", "evidence_id", "next_action")`,
   `candidates.py:176-178` 另要求 `proposal_id`,由 `verification.py:207`
   `normalize_intake(entry, source=...)` 整份拒绝。对照 recon 侧 `recon.py:669-679`
   把同一批必填字段写全——**同一份 Candidate 契约在两处提示词里说明不一致**,字段清单散在
   三处(两个提示词 + `_INTAKE_REQUIRED_TEXT`)。测试 fixture 自己补了 `proposal_id`
   (`test_step5_host_verification.py:234`),印证缺口只在提示词侧。
   **能否写失败测试:能**(按 §5 提示词构造最小合法 related candidate → 断言不被拒,现必失败)。
   **影响面:跨票共享契约**(票 06/07/09/10 共用),代价是合法回复被整份拒绝并烧 strike。

2. **Host 路径没有上下文压缩触发点** — `session.py:445-467`(step)只 `append`,从不调压缩;
   全仓唯一调用点是 legacy `engine/react_loop.py:110  cm.maybe_compact(llm)`,而
   `engine/context.py:94-98` 的压缩是显式调用式。ADR-0012 L73「每次模型请求都计入
   llm_calls,包括…**上下文压缩**和中断后的重新请求」在新控制层成为死条款,600k 阈值护栏
   在 host 路径事实失效(当前单调查 ≤30 轮 ×16000 字符 ≈24 万 est tokens,尚未触发,属隐患)。
   **能否写失败测试:能**(构造超阈值 session 上下文 → 断言循环内发生压缩且计入 llm_calls)。
   **影响面:跨票**(票 01 session / 票 03 tracer / 票 10 budget),并涉及 legacy 共存面。

3. **同一统计量在 analysis 与 verification 归位不同** — analysis 挂在 `Investigation`
   (`analysis.py:107-108  tool_attempts/logical_tool_calls`),verification 挂在 runtime dict
   (`verification.py:1017`)。共享校验函数 `validate_saved_tool_call` 因此要同时接受两种取数
   路径:`analysis.py:216-219  logical_tool_calls=data["logical_tool_calls"]` vs
   `verification.py:666-667  logical_tool_calls=runtime["logical_tool_calls"]`。runtime 本身是
   无类型七字段 dict(`analysis.py:244-249`、`verification.py:1013-1019`),恢复期靠手写
   isinstance 链把关(`analysis.py:164-181` 与 `verification.py:616-631` 把同一组字段契约各写
   一遍)——Data Clumps + Primitive Obsession,`Investigation` 是 dataclass、runtime 是 dict,
   同文件内两种建模并存。**能否写失败测试:能**(等价重构,现有恢复测试即护栏)。
   **影响面:跨票共享契约**(03/05/09)。

4. **`claims.py` 与 `verification.py` 的四个私有校验 helper 逐字重复** —
   `_reject`/`_nonempty_string`/`_optional_string`/`_known_keys`:`claims.py:167-189` 与
   `verification.py:91-113` 唯一差异是 `_known_keys(value: Mapping…)` vs
   `def _known_keys(value: dict…)`(标注已漂移,正是复制的证据)。票 09 评审把同类的
   `_recover_cached_tool/_json_clone/_execute_tool` 收敛进 `tooling.py`,这四条漏网。
   **能否写失败测试:需要新 fixture**(行为等价,无测试可红;可仿 `test_step5_layer_guard.py`
   加 AST 守护"同包私有 helper 不得重名重体")。**影响面:跨票**(08/09 及后续所有 delta 校验)。

5. **JSON 类型名两个实现** — `session.py:196-211 _actual` 与 `recon.py:267-280 _json_type`
   函数体逐字相同(仅 session 多 `missing` 分支),把"字段实际类型"这一协议反馈词汇写了两份。
   **能否写失败测试:需要新 fixture**(同上 AST 守护)。**影响面:跨票**(01/06)。

6. **盘上 Candidate 记录损坏的错误类型取决于坏在哪个字段** — `candidates.py:373-375` 先调
   `normalize_intake(...)`(内部投影非法即抛 `CandidateIntakeError`),`candidates.py:380-384`
   才对同一类盘上损坏抛 `StoreError`;`record["source"]`/`proposal_id` 非法会走前者。票 07
   评审记录已把"损坏记录改抛 StoreError"列为修过项,此处是漏网字段。
   **能否写失败测试:能**(造 v2 记录把 source 置为非法值 → 断言 `StoreError`,现得
   `CandidateIntakeError`)。**影响面:跨票**(07/08/11 读取面)。

7. **`evidence.py` 自捕获的 StoreError** — `evidence.py:148-149` 在 `try` 内
   `raise StoreError("Evidence schema 不兼容；请创建新运行世代")`,而 `:160` 的
   `except (ValueError, KeyError, TypeError)` 会把它重新包一层,导引文案被嵌进第二层消息。
   仅文案冗余,不改变拒绝行为。**能否写失败测试:能**。**影响面:仅本文件**。

8. **`candidates.py:38` 注释指向不存在的符号** — 「recon survey 门按同一字段清单做上游类型
   把关(见 recon._gate 字段常量)」;recon 侧实际的 survey 门是 `_survey_issues`(`recon.py:367`)
   与 `_candidate_issues`(`recon.py:318`),`_gate` 不存在(票 07 注释未随票 06 重命名更新)。
   **能否写失败测试:需要新 fixture**(文档漂移,无测试可红)。**影响面:仅本文件**。

9. **`candidates.py:207` 冗余并集** — `known = _KNOWN_KEYS | {"proposal_id"}`,而
   `_KNOWN_KEYS`(`:43-46`)首项已是 `"proposal_id", *_INTAKE_REQUIRED_TEXT`。
   **能否写失败测试:能**(行为无差异,属清理)。**影响面:仅本文件**。

10. **同一包内注释语言分裂** — 英文单行 docstring:`store.py:1,24,47,57,79`、
    `evidence.py:115,142`、`json_values.py:1,10,55`、`tooling.py:92`;其余模块
    (recon/analysis/claims/candidates/verification/budget)全中文。brief §3 把"中文注释习惯"
    列为 AGENTS.md 的文档化标准,但 `grep 中文注释/注释一律/docs 语言约定` 在 AGENTS.md 与
    `docs/agents/*.md` 无命中——**标准实际不存在,只有既成惯例**(故记为判断题而非硬违规)。
    **能否写失败测试:需要新 fixture**(可加"host 模块 docstring 须含中文"的 AST 守护)。
    **影响面:全包风格**,票 03-05 英文 / 票 06-10 中文的分批漂移。

### 已认领 / 已移交(不重复报)

- `STEP5_*_MAX_ITERS`(含 `max_candidates`/`STEP5_CANDIDATE_SLOTS`)双解析、config.json 快照
  的 profile 层值与 runner 实际生效值背离、三 runner 各自 `RunBudget.load(run_dir)` 靠构造顺序
  共享台账 —— 票 11 Comments 已认领(brief §2 条 6 ① ②)。
- `apply_analysis_delta`(`claims.py:480`)无生产调用方 —— 票 08 评审已判读保留
  ("无中段调用方的便捷路径")。
- dedup/scoring 的 LLM 请求未过 `RunBudget`(`candidates.py:295,631`,只进 candidates.json 的
  `llm_calls` 字段)—— `candidates.py:12` 自注"完整预算语义归后续工单",但票 11 AC 未列此项,
  与 ADR-0012 L25「比较请求…计入 LLM 预算」相关,**建议跟进时补票号,否则落空**。
- ADR-0012 L47 复核目录的"独立检查计划/Transcript 落盘"、`plan_verification_queue` 生产消费方
  —— 票 09 Comments 已移交。

### 已核过、判定不成立(避免下轮重复劳动)

- `_append_finding`(`verification.py:983-987`)先写 findings.json 再写 results.json 的崩溃窗口
  **不是缺陷**:`_finalize` 之前 `runtime.update(pending=None, …)` 已把动作落成事件,续跑走
  显式 pending proposal 重放、零模型请求、verdict 可复算,
  `test_crash_between_finding_and_results_resumes_pending_proposal` 已钉住该组合。
- 命中 brief §2 已定取舍故未报:`analysis.py:441-468` 与 `verification.py:444-471` 动作块逐行平行、
  `getattr(session, "last_usage", None)` 鸭子读用量、protocol_error 三连后无条件 inconclusive、
  宽口径"无效回复"、局部轮次计模型请求。

**汇总:硬违规 0 条 / 判断题 10 条。**
最严重一条:Verifier 的 Related Candidate 契约只写在 `candidates.py` 校验器里,
`VERIFICATION_SESSION_SYSTEM` §5(`verification.py:1147-1151`)未列 `proposal_id`/`target`/
`signal`/`next_action` 等必填字段 —— 按提示词产出的合法回复会被整份拒绝并烧掉一次 strike,
三次即 `protocol_error` → 该案卷 `inconclusive`,复核结论丢失。
(唯一硬违规候选是 ADR L73 的"压缩计入 llm_calls",但该条款只约束**已发生**的请求,故归判断题 2。)

## Spec · 2026-09-16 · HEAD 1bc0b0c

范围 `git diff e9abefa...1bc0b0c`(票 01-10),只读。按 brief §1 阅读范围读 `host/` 当前完整实现 + 该范围这些文件的 diff;
规格来源:ADR-0012、`spec.md`、issues 01-10 的 AC 与 Comments、ticket05..10-plan。未重验逐票 AC。

### §4 六项跨票不变量逐项结论

1. **三轴闭合:通过**(一条恢复期加固项见 C2)。三个轴的全部写入点只有
   `_advance_lifecycle`/`_finish_investigation`(analysis.py:745-761),`disposition`/`stop_reason`
   只在后者赋值且必经 `assert_terminal`(claims.py:144-158)——无旁路。各终结组合都有测试:
   rejected/decisive_refutation(test_step5_host_analysis.py:706)、closed/agent_closed(:728)、
   unresolved/no_progress(:805)、unresolved/protocol_error(:440)、unresolved/budget_exhausted
   (test_step5_host_budget.py:281)、not_started/budget_exhausted(:535)、confirmed|rejected|inconclusive
   × completed/budget_exhausted/protocol_error(test_step5_host_verification.py:675/764/784/922/341)。
   `ready_for_verification→finished`(claims.py:121)虽在转移表内但无调用方,属票 11/12 封存所需,不算缺陷。
2. **Evidence ID 唯一:通过**(一处纪律性弱口见 C3)。两棵树(`investigations/`、`verifications/`)
   + 三处会话前抬水位(analysis.py:364、verification.py:700、recon.py:464)+ 恢复路径 `restore_sequence`,
   在票 01-10 的串行顺序(recon 最先)下无重号窗口;`seed_sequence_from_files`(evidence.py:118-133)扫两棵树,
   `recover`(evidence.py:141-161)按 evidence_id/sequence/location/candidate_id/digest 复核身份。
3. **恢复矩阵:通过**。四条边界都能续:(a) `prepared` → 未执行,按 `tool_started` 首次执行(analysis.py:449-457);
   (b) `executing`+只读幂等 → 同 call_id 重试、attempt+1、Evidence ID 不变(analysis.py:448-457);
   (c) NEVER → 标记 `interrupted` 且**不重放**(analysis.py:437-444,verification.py:777-784);
   (d) CACHE_VALIDATED → `recover_cached_result` 先验 receipt(input digest + 三件套 digest,
   ghidra_decompile.py:129-145、ghidra_cache.py:44-56)可接纳则零 attempt;
   (e) Observation 已落盘而 finished 未写 → `recover` 接纳、不重复执行(analysis.py:432-471)。
   `results.json` 短路(verification.py:693-696 → `_replay_finished_case`)在 `finish_verification` 前后都能续;
   预算悬挂活动段在加载时弃置(budget.py:195-204)。唯一边角:recon 侧无续跑(见 A4/C4)。
4. **只有 confirmed 产 Finding:通过**(一条加固项见 C2)。`findings.json` 唯一写入者是
   `_append_finding`(verification.py:960-997),唯一调用点是 `_finalize` 的 confirmed 分支(:873-875);
   protocol_error 无条件强制 inconclusive(:857-867,有测试钉住);Claim Result 的 supported/refuted 必引
   **本次会话**Evidence(verification.py:169-177);`complete_verification` 不接受未落盘的 upcoming ID
   (`_validate_final` 只传已有集合,:1100-1110);evidence-gap 与 ready 同一 `aggregate_verdict`,不看
   admission_reason(:326-373)→「admission reason 不会降低 confirmed 门槛」(spec 故事 68)。
5. **预算口径三阶段一致:通过**。先计后执三处同口径(analysis.py:450-457、verification.py:790-797、
   recon.py:504-509);重生成只 `record_llm_call`、回复被应用才 `record_validated_round`(analysis.py:405/488);
   服务中断在 `session.step` 抛出时零记账(budget.py:240-250,test_step5_host_budget.py:566);
   active 段由各循环 `finally: stop_active()` 封段。brief §2.6 的三条票 11 债务未重复报。
6. **边界:通过**(除 B1 一处越界)。公开入口切换、运行世代/锁、severity/报告/封存、Benchmark 均未见实现;
   `host/` 只在 layer guard 加了一行层级声明(test_step5_layer_guard.py:40)。

### (a) 缺失/不完整

- **A1(中)analysis 没有 Host 时代的角色系统提示词。** `host/` 只有 recon.py:644 `RECON_SESSION_SYSTEM` 与
  verification.py:1119 `VERIFICATION_SESSION_SYSTEM`,全仓无 `ANALYSIS_SESSION_SYSTEM`。若按票 03
  「现有模型配置…复用」接 legacy `data/prompts.py:197 ANALYSIS_SYSTEM`,该提示词会指示
  `cve_bin_tool_scan`/`cve_lookup`(prompts.py:216)、`web_search`(:218)——ADR L63「cve_bin_tool_scan/cve_lookup/
  web_search 对全部三个角色禁用」——并要求 ReAct 与`Final Answer 的 JSON 结构`(:222),与 ADR L41
  「每轮使用纯 JSON 文本协议」矛盾。**影响面:跨票共享契约**(03/08/10/14)。
  **能否写出失败测试:能**(断言 host 导出 analysis 角色提示词,且其工具清单 ⊆ `tool_names_for_role("analysis")`)。
- **A2(中)analysis 侧 Related Candidate 无主。** `state_delta.related_candidates` 由 session.py:189-191 定为
  协议固定位置,但 analysis 把它当自由笔记本键**原样透传**(claims.py:394-395),既不校验 Candidate 契约、
  也不盖 origin、也不进 Candidate Store;对照 verification 侧有完整校验(`_validate_related_candidates`,
  verification.py:192-233)。ADR L89「Related Candidate 只继承相关 Investigation State、Evidence References
  与来源关系」在 analysis 侧无实现;票 07「将 Recon 和 **Related Candidate proposals** 可靠归一为稳定 Candidate」
  的 intake 入口(`CandidateStore.build(extra_intake=…)`,candidates.py:811)至今无调用方。brief §2.6③
  只认领了 verification 侧回写。**影响面:跨票**(07/09/11)。**能否写测试:能**(analysis state_delta 带
  related_candidates → 断言被拒或被校验入册;现状是静默进 state)。
- **A3(低)ADR L47 的「独立检查计划」与 Transcript 未落地。** ADR L47「每个复核目录保存冻结案卷、独立检查计划、
  Claim Results、Evidence References、Transcript、verdict 与限制说明」;`verifications/<cand>/` 实际只有
  case/results/events/state/evidence(verification.py:1010-1027、798-802),无计划工件;`AgentSession` 支持
  transcript 但三个 runner 都不构造也不传(session.py:418-422)。票 09 Comments ② 已移交票 10/14,票 10 未落实。
  **影响面:跨票**(09/10/14)。**能否写测试:需要新 fixture**(断言复核目录存在 transcript)。
- **A4(低)recon 终态不落任何工件。** `ReconRunResult.status`(recon.py:190-208)只在内存返回值里,
  `input_failure`/`incomplete` 不写盘;`STOP_REASONS` 含 `input_failure`(claims.py:115)却在 Investigation 层
  永无产出,ADR L43「recon 以 input_failure 结束本次运行」目前不可持久审计。recon.py:196-199 自述移交票 10/11,
  票 10 未做。**影响面:跨票**(06/11)。**能否写测试:能**(三次协议失败后断言落盘工件含 input_failure)。

### (b) scope creep

- **B1(中)对尚未切换的 legacy 公开入口删掉了 CVE 缓存预检告警。** diff 删除 `run_step5.py` 的
  `cve_cache_preflight_warning` 导入、调用与返回值键 `cve_cache_warning`,并把
  `test_preflight_warning_printed_at_startup` 反转成 `test_blind_discovery_startup_skips_cve_preflight`。
  ADR 要求的是 **Blind Discovery**(新 Host)不预检(ADR L63「Blind Discovery 启动不做 CVE 缓存预检」),
  而 `step5_run` 现在仍是 legacy orchestrator 的入口(`from .orchestration.orchestrator import Orchestrator` 保留),
  legacy 工具集仍含 `cve_bin_tool_scan`(runner.py:68)与 `cve_lookup`/`web_search`(runner.py:79/83)——
  正是 2026-09-11 票01 加告警要盖住的「无 CVE 数据且无人知晓」故障。ADR L13「公开入口一次切换…不保留 shim」,
  此改动等于提前切换并回收了在役告警。**影响面:跨票**(14 接线时须把预检语义搬到 Host 或确认 legacy 退役)。
  **能否写测试:能**(断言 legacy 路径在空库时仍告警)。

### (c) 看似实现但可能实现错了

- **C1(高)`find_decompiled_function` 对三角色全禁,而 ADR 与工具文案都要求模型用它。**
  providers/tools/__init__.py:72 `ToolContract(FindDecompiledFunctionTool, _NO_ROLES, …)`;但 ADR L37 要求
  「二进制分析优先复用已有边车;没有边车时先以低成本工具收窄目标」,观测文本也反复指引调用它:
  ghidra_decompile.py:238「读函数用 find_decompiled_function,读边车用 strings_query/imports_query」、
  r2_disassemble_function.py:26「想看反编译 C 用 find_decompiled_function(读缓存)」、semgrep_scan.py:145。
  analysis/verification 读到这些 Observation 后调用 → `authorize_tool` 抛 ToolAuthorizationError →
  `ProposalRejectedError` 整份重生成并计 strike(analysis.py:630-634),连续 3 次即 unresolved/protocol_error。
  **影响面:跨票共享契约**(02 契约 / 06-10 循环 / 14 接线)。**能否写测试:能**(断言
  `"find_decompiled_function" in tool_names_for_role("analysis")`;现 test_step5_tool_contract.py:295-299 把
  「不含它」钉死。全表 18 件里只有这件既不在 ADR 禁用名单、又不在任何角色的授权名单,需确认是审计结论还是遗漏)。
- **C2(中)恢复路径不重验领域不变量。** analysis `_restore_investigation` 校验结构/身份但**不验三轴组合合法性**
  (analysis.py:164-182),`assert_terminal` 只在写入时调用(claims.py:144);verification `_restore_case_session`
  (verification.py:616-632)不核验 `claim_results[*].evidence_ids` 是否属于本次复核 Evidence,而 `aggregate_verdict`
  只要求 `refs` 非空(verification.py:361-364)→ 与事件历史一致的伪造/旧版投影可产出引用不存在证据的 confirmed
  Finding。规格原文:ADR L45「全部必填 Claim 被 Verifier 以本次独立取得的证据支持才 confirmed」。
  **影响面:本文件 + 聚合规则**(09/11)。**能否写测试:能**(伪造事件写入引用 `ev-999999` 的 claim_result →
  断言恢复被拒;现仅改快照会被 store 拦截,需连事件一起伪造)。
- **C3(低)`reserve` 的碰撞检测是路径粒度,发现不了跨目录重号。** evidence.py:98-112 以
  `namespace/candidate_id/evidence/ev-NNNNNN.json` 为唯一性判据,跨 candidate 的同号不会被
  `FileExistsError` 拦住;唯一保障是「每段会话开始前抬水位」的调用纪律——analysis.py:364 与 verification.py:700
  每次会话都抬,而 recon 只在 `__init__` 抬(recon.py:464),`run()` 不再抬(recon.py:470-491)。当前串行顺序下
  recon 最先故不触发,一旦 recon 在已有 Evidence 之后运行即重号。**影响面:跨票**(02/06/11)。
  **能否写测试:能**。
- **C4(中)重跑 recon 会静默覆盖已升级的 Candidate Store。** `_persist_store` 无条件
  `atomic_json(store_path, payload)` 写 `schema_version=1`(recon.py:633-641),而 `CandidateStore._load` 接受 v1
  并当「去重未做」重新 `deduplicate`(candidates.py:801-804、830-834)→ 已分配的 `cand-xxxx` 按新顺序重排、
  评分与 disposition 丢失,而 `investigations/cand-*/` 下的调查仍在 → ID 与调查错配且无告警。票 06 Comments
  虽把「Recon 断点续跑」移交票 11,但未点名这条数据销毁路径。**影响面:跨票**(06/07/11)。
  **能否写测试:能**(v2 store + 已有 investigation → 重跑 recon → 断言 ID 不变或被拒)。

### 待确认(引文不足或需用户定夺,不算 finding)

- verification 局部轮次耗尽走 `_finalize(stop_reason="budget_exhausted")`(verification.py:735),此时若必填
  Claim Result 已齐且全 supported,会聚合出 confirmed 并产 Finding——**未经 `complete_verification`**。
  ADR L45 字面条件满足,票 09 Comments ② 只说了「缺项按未支持」。请确认是否要求必须经 complete_verification 才 confirmed。
- `STEP5_EXCLUDE_TOOLS`(tools/__init__.py:159-176)排除的工具仍在契约授权集内,模型照契约调用会被判
  `ProposalRejectedError`「已授权但未由 Host 配置」(analysis.py:648-652)→ 计 3-strike,一次环境配置可能把调查
  推成 protocol_error 终态。与 §2.4「宽口径无效回复」部分重叠,故列待确认。
- recon 守卫拒绝(越权/参数失约)走整份重生成(recon.py:501-502、550-559):票 06 Comments 记为刻意(结构化反馈
  轮内自纠),票 10 又把守卫拒绝纳入 3-strike 计数——两票交界处的口径请用户确认。
- A3 的「独立检查计划」是否可由 `build_case_brief` 的产出代替(verification.py:455-506),取决于是否要求它落盘。

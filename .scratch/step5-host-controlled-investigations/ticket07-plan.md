# Ticket 07 Implementation Plan

**Goal:** 将 Recon 与 Related Candidate proposals 可靠归一为稳定 Candidate(`cand-xxxx`),以 signal/coverage 两类精确 fingerprint 去重(精确确定性合并 + 受控语义比较),LLM 只交 0/1/2 分项与 Evidence 依据、Host 按公式算分,双队列(signal/coverage)选取默认 8 个处理名额,未入选者明确 not_started。

**Architecture:** 新增 `host/candidates.py` 内聚"Candidate 接收与去重、队列与优先级"(spec Implementation Decisions 指定的 Host 模块职责):归一化 intake → fingerprint → 去重引擎(精确合并零 LLM;受门控的语义比较一次)→ ID 分配 → 评分(Host 公式)→ 双队列选取 → Candidate Store v2 落盘。comparator/scorer 是注入的 LLM adapter(鸭子类型 `.chat(messages)`),与 AgentSession 无关的一次性纯 JSON 请求;请求/结果进 dedup_log 与 llm_calls 记账(完整预算归票 10)。

**Tech Stack:** Python 标准库、pytest、现有 `atomic_json`/`clone_json_value`/`LLMError`、ScriptedLLM。

基准:master @ 5f5d9fc(ticket 06 已合入)。按 implement/tdd 在当前分支实现,逐切片 RED → GREEN。

**关键设计决策(ADR-0012/CONTEXT.md 未细粒度指定处):**

- **Candidate Store 升级 v1→v2 就地重写**:recon 落的 v1(proposals 原文)读入→去重→写回 v2(幸存 candidates + aliases + merged_proposals + dedup_log + priority + queue + disposition);v2 再入队只处理新增 proposal(已处理 proposal_id 幂等跳过),**已有 Candidate ID 绝不改号**。同文件两版本兼作断点语义:v1=去重未做,v2=已完成(ticket 11 消费)。
- **fingerprint 明文拼接不哈希**(`signal:<target>|<anchor>|<profile>|<mechanism>` / `coverage:<target>|<component_or_entry>|<check_goal>`):CONTEXT.md 定义其组成即身份,明文可读可解释可 diff;target 规范化 = 反斜杠→斜杠、折叠重复分隔符、剥尾 `/`(不 lower,大小写敏感文件系统)。
- **coverage 也带 claim_profile(缺省 generic)**:语义比较门"target 与 Profile 相同"对两类统一成立;fingerprint 本身按 ADR 只对 signal 含 Profile。
- **一次语义比较 = 对最早创建的同 target+同 Profile 且 fingerprint 不同的幸存者比较一次**,不做逐个试探(去重成本受控;different/uncertain 不再比,宁可不合并不吞线索)。
- **比较回复协议**:`{"verdict": "same|different|uncertain", "rationale": "..."}` 纯 JSON;解析失败/枚举外 = invalid_reply;`llm.chat` 抛异常(含 LLMError 重试耗尽)= service_error。两者与 different/uncertain 同样保留独立 Candidate,全部进 dedup_log。
- **评分分项命名**(signal):external_reachability / input_control / high_impact_operation / path_progress / material_strength / estimated_cost;(coverage):component_value / external_exposure / unchecked_extent / estimated_cost。分项计入条件 = score∈{0,1,2} 整数 ∧ evidence_id 非空 ∧ ∈盘上 Evidence ID 全集,否则该分项 0("缺依据为 0");总分 = 正项和 − estimated_cost(计入后);signal 范围 −2..10,coverage −2..6。评分协议无效/服务失败 → 全分项 0 + log 记 status,不阻塞流水。
- **选取语义**:coverage 队列非空 → 保留 1 名额给最高分 coverage,signal 取前 slots−1;**signal 不满时余量按分数续取 coverage(不闲置名额)**;coverage 为空 → 名额归还 signal(全 8)。队内排序 (−total, candidate_id 升序=创建顺序);处理顺序 = signal 入选在前、coverage 入选在后(ADR 未指定跨队交错,票 11 可调)。slots 默认 8,`STEP5_CANDIDATE_SLOTS` 覆盖(缺失/非法回落,下限 1)。
- **not_started 落在 Candidate 记录的 disposition 字段**(未入选者;入选者 disposition=null,Investigation 级 disposition 归票 08)——"超出处理上限者最终可明确标记"由 store 直接可读。
- **recon 侧小改(上游归一质量口)**:`_candidate_issues` 增加可选字段校验(claim_profile ∈ 5 枚举;anchor/mechanism/component_or_entry/check_goal string-or-absent),提示词补一段引导(signal 建议带 mechanism/anchor,coverage 带 component_or_entry/check_goal)。字段经 ticket 06 的 extras 透传链保留,intake 归一时从顶层或 extras 取。
- **Claim Profile 枚举**:`data_propagation / config / credentials / memory / generic`(票 08 实现 Profile 内容,本票只用作 fingerprint 输入与比较门)。

**切片(RED → GREEN):**

- [x] S1 `normalize_target_path` / `signal_fingerprint` / `coverage_fingerprint` / `normalize_intake`(纯函数,表驱动)
- [x] S2 去重引擎:精确合并(零 LLM)、语义门控表、same/different/uncertain/invalid/service 五路、ID 延迟分配与 alias 保留(fake comparator)
- [x] S3 Candidate Store 集成:v1→v2 build 落盘重读、v2 增量不重号、重复 proposal_id 幂等跳过、survey/session_state 保留
- [x] S4 评分:分项有效值表、公式表、PriorityScorer adapter(ok/invalid/service)
- [x] S5 选取:保留名额/归还/续取/同分创建序/slots env,not_started 标记与读取
- [x] S6 recon 可选字段门 + 提示词补充
- [x] S7 端到端:HostReconRunner 真实产物 → CandidateStore.build(ScriptedLLM comparator/scorer)→ 可读 v2;全量 `pytest -q firmware_audit/test` + compileall + git diff --check
- [x] code-review 双轴只读评审(Standards/Spec),修复真实问题
- [x] 更新工单 07 验收记录;提交代码(.scratch 本地不提交)

**Out of scope(后续工单)**:Claim/ready gate(08)、Verification(09)、协议重生成与预算总账(10)、运行世代/恢复/真实选取消费方(11)、报告 not_started 区段(12)。

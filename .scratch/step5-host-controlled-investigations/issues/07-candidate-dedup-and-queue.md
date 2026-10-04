# 07: 完成 Candidate 去重、评分和双队列选取

**What to build:** 将 Recon 和 Related Candidate proposals 可靠归一为稳定 Candidate,并以确定、可解释的 signal/coverage 双队列选择实际 Investigation。

**Blocked by:** 06/从 Recon survey 建立 Candidate Store。

**Status:** ready-for-agent

- [x] Signal 与 coverage 使用 ADR 定义的不同精确 fingerprint,精确重复确定性合并。
- [x] 仅 target 与 Claim Profile 相同且 fingerprint 不同的候选进入一次 same/different/uncertain 语义比较。
- [x] 只有 same 合并;different、uncertain、协议无效和服务失败都保留独立 Candidate。
- [x] 去重完成后才分配递增 Candidate ID;合并保留 alias、请求、结果和依据,已有 ID 不随信息补充改变。
- [x] LLM 只给 0/1/2 分项与 Evidence 依据,Host 按 signal/coverage 公式计算;缺依据为 0,同分按创建顺序。
- [x] 默认八个处理名额为最高 coverage Candidate 保留一个;无 coverage 时名额归还 signal。
- [x] 所有 proposal 均入库,超出处理上限者最终可明确标记 not started。
- [x] 表驱动 Policy 测试和 Candidate Store 集成测试覆盖排序、保留名额及去重失败。

## Comments

2026-09-14:实现完成并提交 `b81befa`(评审基准 `5f5d9fc`,评审修复已 amend 入同一提交)。按 implement/tdd 逐切片 RED→GREEN,计划见 `../ticket07-plan.md`。

验证:`pytest -q firmware_audit/test` 为 **555 passed、21 skipped**(新增 85 项 Candidate 去重/评分/队列测试 + 5 项 recon 门测试);compileall 与 git diff --check 通过。mypy/pyright 未安装,未声称完成静态类型检查。

实现要点:
- 新模块 `host/candidates.py`(Candidate 接收与去重、队列与优先级的 Host 内聚模块):`normalize_intake` 归一 recon/related proposal(claim_profile 枚举缺省 generic,fingerprint 输入字段顶层或 extras 取值)、`signal_fingerprint`(规范化 target+anchor+profile+mechanism)/`coverage_fingerprint`(target+component_or_entry+check_goal)明文拼接不哈希、`deduplicate` 去重引擎、`PriorityScorer`/`SemanticComparator` 一次性纯 JSON LLM 请求、`select_for_processing` 双队列选取、`CandidateStore` 门面。
- 去重三分:精确 fingerprint 重复确定性合并(零 LLM);门控(同规范化 target+同 Profile+不同 fingerprint)与其中**最早创建**幸存者做一次语义比较;same 合并(different/uncertain/invalid_reply/service_error 保留独立)。每次比较的请求/verdict/rationale(失败含 raw_reply)都进 dedup_log 并计入 `llm_calls.dedup`;比较不是 Investigation Evidence。
- ID 分配严格在去重完成后按首次出现顺序 `cand-0001..N`;合并保留主 proposal 字段+alias+merged_proposals 全量(merged_via + comparison),增量重入队不改既有 ID/评分;已知 proposal_id 幂等跳过、同 ID 异内容拒绝。
- 评分:LLM 只交 {score 0|1|2, evidence_id, note};计入条件 = 分值合法 ∧ evidence_id 非空 ∧ ∈盘上 Evidence 全集,否则该分项 0;signal=5 正项−成本,coverage=3 正项−成本;协议无效/服务失败全 0 分且 status 落盘,不阻塞。
- 选取:默认 8 名额(`STEP5_CANDIDATE_SLOTS` 覆盖),coverage 队列非空保留 1 名额给最高分 coverage,无 coverage 归还 signal;signal 不满时余量按分数续取 coverage(计划内决策,防名额闲置);队内 (−total, cand-ID) 排序;未入选者 `disposition="not_started"`,所有 proposal 均入库。
- Candidate Store 就地升级 v1(recon 原始 proposals)→v2(权威集合:survey/session_state 保留+candidates+dedup_log+llm_calls);文件版本兼作断点语义(v1=去重未做/v2=已完成,票 11 消费)。
- recon 侧上游质量口:survey 门复用 `FINGERPRINT_INPUT_FIELDS` 单一来源清单做类型把关 + claim_profile 枚举校验,提示词引导补 fingerprint 输入字段。

code-review 双轴只读评审(Standards/Spec)后修复:Spec 真 bug——已合并 proposal 幂等重入误判"内容不同"崩溃(processed 改记 own 内容,补 exact/semantic 两路回归);kept_independent 分支补齐 ADR 要求的请求/结果/依据日志。Standards——测试 import 全部上提(含函数内 import)、死键 material、恒等映射 _KIND_LABELS、effective_factor_score/_grounded_factor 合一为 grounded_factor、fingerprint 字段清单单一来源化、build 改用 DedupResult.intakes 消除序列化-再归一往返、comparator 先验类型再取键、损坏记录改抛 StoreError、注释漂移修正。刻意保留(已注记):信号名额不满时向 coverage 续取(票文只写了反向归还,计划内防闲置决策)、queue/rank/not_started_ids 读取面为票 11/12 预留。

仍为 expand 阶段:Claim/ready gate/案卷(08)、独立复核(09)、协议重生成与预算总账(10,本票 llm_calls 记账为其输入)、运行世代与选取消费方(11)、报告 not_started 区段(12)由后续工单完成。

# 13: 增加不可变机器结果上的 Review Overlay

**What to build:** 人工或 Codex 能在不修改 sealed machine artifacts 的情况下追加复核决定，并让报告和后续评估清楚区分机器结果与复核结果。

**Blocked by:** 12/生成 severity、事实报告并封存运行。

**Status:** ready-for-agent

- [x] Review 采用追加式记录，包含 reviewer、时间、目标字段、旧值、新值、理由和 Evidence Reference。
- [x] 对未封存运行、未知目标字段、错误旧值或不存在 Evidence 的修改被明确拒绝。
- [x] 追加 review 不改变机器 Finding、Verification Result、manifest digest 或原始报告事实。
- [x] 报告视图可并列展示 machine result 和 reviewed result，并保留多次 review 历史。
- [x] Severity 人工调整必须提供理由并通过 overlay 表达。
- [x] Benchmark 默认仍使用 machine result，reviewed result 可单独统计。
- [x] Store 测试覆盖只追加、重放、冲突 review、sealed immutability 和报告投影。


## Comments

**实现（2026-09-18，commit bb19205）**：新增 `host/review.py`（`ReviewOverlay` + `project_review_report`/`load_review_projection`），测试 `test/test_step5_host_review.py` 33 项，全套件 1064 passed + 21 skipped。

- **封存判据**：`run_state.status == "completed"`（词汇票 11 已定，写入者是票 12）。票 12 落地前真实运行一律拒绝追加；测试直接构造 completed 世代。附注：票 12 的 force 分支已把 finalizing 世代当作"机器工件一律不动"，与本票的 completed-only 判据衔接一致。
- **追加式语义**：`reviews.json` 单一 JSON 文档，`reviews` 数组只增不改，经 `atomic_json` 原子重发布（与 findings/candidates 工件同构）——崩溃不留撕裂现场，覆盖层损坏（版本/seq 断档/字段缺失/坏 JSON）按 StoreError 拒绝重放。
- **并发安全（评审后修复）**：初版行追加存在 TOCTOU——两个写者同窗通过旧值校验会写出重复 seq 毒化整份覆盖层。改为原子重发布 + 写后复读"本记录仍在其 seq 槽位"：同窗输家明确 ReviewError（重读重提），基于本记录之后的合法追加不误拒；两条注入式测试分别覆盖输家拒绝不毒化、合法后继不误拒。
- **拒绝矩阵**：未封存（running/finalizing/abandoned/缺 run_state）、未知字段（注册表 v1 只开放 `finding.severity`）、未知 Finding、机器字段缺失、旧值失真（乐观并发，含跨实例盘上重读）、Evidence 缺失/格式非法（investigations 与 verifications 两棵树都认）、severity 档位越界、新旧同值、空理由/空 reviewer——全部明确拒绝且不留部分状态。
- **报告投影**：`project_review_report` 纯函数并列 machine/reviewed（reviewed 仅在有覆盖记录时给出），逐 Finding 保留完整多次 review 历史；summary 分列 machine/reviewed severity 完整分布（未调整者沿用机器值，无 review 时 reviewed 侧为 None）——Benchmark 默认 machine 侧的接缝。
- **给票 12 的移交**：① severity 矩阵落地时与 `review.py` 的 `SEVERITY_LEVELS` 共享同一出处（当前词汇两处定义：legacy `data/artifacts.py` 与本模块）；② 事实报告生成时消费 `load_review_projection` 实现"并列展示"的最终呈现；③ 封存写入 `status=completed` 后本票 overlay 即对真实运行生效。

**双轴子代理评审**（Standards：0 硬违规 + 6 判断项；Spec：AC 全满足、2 项前瞻留白）：

- 已修：①findings 装载块重复 → 提取 `_load_findings_document`；②并发毒化（见上）；③`__all__` 排序；④未用 `json` 导入。记录在案：evidence_ids 形状谓词读写双验（刻意）、`field == "severity"` 单点校验（注册表扩展时收拢为 validator 映射）、`load_review_projection` 不校验封存（纯读取，未封存世代无可追加覆盖层，投影自然 machine-only）。

**跨票修复(2026-09-19,随票 15 评审落地)**:`project_review_report` 的 reviewed severity 分布存在惰性初始化缺陷——被调整 Finding 排在未调整项之后时,排在它前面的未调整项不进入"完整分布"(与其注释承诺矛盾);单 Finding 的既有测试没有暴露。改为先建 entries 再统一计数,回归测试 `test_reviewed_severities_complete_when_adjusted_finding_is_not_first`。修复由票 15 的 machine/reviewed 并列指标消费暴露。

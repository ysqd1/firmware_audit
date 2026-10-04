# 15: 建立封存后的 Benchmark Evaluator

**What to build:** 在 Agent 运行完全封存后，以隔离 Ground Truth 对机器结果做可审计的候选匹配和用户显式启动的 Codex 语义裁定，不把字符串完全相等当作问题等价。

**Blocked by:** 12/生成 severity、事实报告并封存运行；13/增加不可变机器结果上的 Review Overlay。

**Status:** ready-for-agent

- [x] 公开案例输入只含固件、profile 和无答案元数据；Ground Truth 根不进入 Step5 参数、提示、快照或 Agent 工作区。
- [x] Evaluator 拒绝未 sealed 运行，并在封存后才同时接收运行结果与 Ground Truth。
- [x] 确定性阶段只规范化路径、地址、组件和函数别名并生成候选映射，不输出最终 full/partial/miss。
- [x] Codex reviewer 可读取 Ground Truth、Findings、inconclusive/closed Investigations、Cases、Evidence References 和 Candidates。
- [x] 字段级量表覆盖根因或机制、输入或触发、关键关系、实际影响和 machine disposition。
- [x] 每项 Ground Truth 仅一个 primary；正确实现 full/partial/miss，重复对应不重复得分。
- [x] Unmatched confirmed Finding 分类为 novel valid、unsupported 或 uncertain；uncertain 不进入确定指标。
- [x] 评审工件保存字段决定、双方引用、理由、模型版本、固定提示和输入 digest，并分别呈现 machine/reviewed 指标。
- [x] Fixture 测试证明 Ground Truth 隔离、语义措辞不同仍可对应及评审结果可重放审计。

## Comments

**实现(2026-09-19)**:新增 `host/evaluation.py`(Ground Truth 加载/四类规范化/确定性候选映射/语义裁定/指标/重放审计)与 `test/test_step5_host_evaluation.py` 19 项;顺带修复票 13 `project_review_projection` 的 reviewed 分布惰性初始化缺陷(回归测试入 review 套件)。全套件 1048 passed + 16 skipped。

- **双根隔离(AC1)**:结构上成立——`RunDriver`/Session/工具层没有任何 Ground Truth 入参,`evaluate_run` 是封存后的独立入口。边界测试用真驱动全链路(票 14 的 fake session 基建)跑出 sealed run,GT 根放工作区外 `gt-root/`,内容带 marker,逐字节扫描世代目录证明运行产物零泄漏;评估工件也只落 GT 文件名 + sha256 + case_id,不落宿主路径。公开案例根布局(固件 + profile + 无答案元数据)是数据约定,由票 16 首批案例落物化。
- **封存门(AC2)**:`require_sealed_run` 只认 `run_state.status == "completed"`(与票 13 同判据);`generate_candidate_map` 与 `evaluate_run` 都过门。评审工件已存在时拒绝重跑(覆盖会摧毁审计链);模型版本取显式参数或 `llm.model`,取不到在写任何工件之前拒绝。
- **确定性阶段(AC3)**:路径(剥工具根/binwalk 嵌套前缀 + 小写折叠,与 `normalize_target_path` 的差别已注明——这是召回键不是 ADR-0008 工具路径口径)、地址(0x/前导零)、组件(lib/.so/版本后缀)、函数别名(限定名/参数表/下划线折叠,`do_overflow` ≡ `DoOverflow`)四类规范化键求交,输出 `evaluation/candidates.json`(字节确定、无时间戳、可重算比对);match 结构只有 kind/id/signals,测试断言全文不含语义标签。信号源:候选记录字段 + Evidence Reference 的 arguments/summary + claims observed;prose 只回收路径与地址,符号只来自结构化字段防英文文档词泛洪。
- **语义裁定(AC4/AC5)**:材料包七节全量(ground_truth/candidates/findings/investigations 未确认侧/verification_cases/evidence Reference 清单/candidate_map);固定系统提示词声明"评审模型只交字段判断,不输出结果标签"。**full/partial/miss 由 Host 确定性派生**(与 severity 矩阵同款分工):miss ⟺ 无 primary;full ⟺ primary 是 confirmed Finding 且 root_cause/key_relations/impact 三字段 consistent(ADR-0012 L67 严格读法,触发/入口与 disposition 不参与 full);其余 partial。ADR 未定义处的自加规则:**inconclusive 调查才能作 primary**(L148 只点名 inconclusive;rejected/closed/unresolved 都表达"机器已下相反结论或缺证据",计入 partial 会给错误结论记分),建议回写 ADR。
- **计分与分类(AC6/AC7)**:每 GT 至多一个 primary;未任 primary 的 confirmed Finding 必须恰好在 duplicates/unmatched 出现一次(完整性双向校验,重复引用/重叠/缺漏全拒绝);duplicates 永不计分。指标 `definitive` 块只含 full/partial/miss + novel_valid/unsupported,uncertain 两侧(match 侧不存在、unmatched 侧)都不进;完整分布另行保留供审计。
- **评审工件与 machine/reviewed(AC8)**:`evaluation/evaluation_review.json` 保存字段决定(gt_quote/machine_quote 双方引用 + rationale)、派生结果、理由、model、固定提示原文与 digest、GT sha256、manifest seal 全量 machine digests、candidate_map digest、usage。指标 machine/reviewed 并列:经票 13 投影取两侧 severity 分布(覆盖层当前只能调 severity,两投影仅此处可分异)。
- **重放审计(AC9)**:`load_evaluation_review(gen_dir, gt_path=None)` 校验链:固定提示与当前代码一致(漂移即拒绝)且自 digest 相符 → 工件 machine digest 与 manifest seal 一致 → **逐文件复算封存 digest**(只比两份记录挡不住"记录一起改";封存文件被动过/缺失直接失败)→ candidate_map digest 可复算 → 决策合法性对当前机器工件重放(引用存在性/资格/完整性)→ 存储结果标签与字段派生一致(单改标签不被复算静默覆盖)→ 指标复算一致;提供 gt_path 时额外校验 GT 文件 digest/case_id。
- **跨票修复**:票 13 `project_review_report` 的 reviewed 分布在"被调整 Finding 排未调整项之后"时漏计未调整项(计数器惰性初始化缺陷,与其"完整分布"注释矛盾);改为先建 entries 再统一计数,回归测试入 `test_step5_host_review.py`。
- **给票 16 的移交**:`evaluate_run(gen_dir, gt_path, llm, model=None, now=None)` 即端到端评估入口;CLI 包装、公开案例根目录物化与首批三案例对接由票 16 承接。评审失败(服务/回复非法)不写评审工件、`evaluation/candidates.json` 保留,可直接重跑 `evaluate_run`。

**双轴子代理评审(Standards:1 硬违规 + 1 硬缺陷;Spec:2 实缺陷 + 1 ADR 缺口)已修**:

- Standards:①`_known_keys` 三份拷贝违反 rules.md"同一逻辑禁止第三个拷贝" → 提取 `store.unknown_keys` 共享纯检测(错误通道各模块保留),claims/verification 同步委托;②`__init__.__all__` 重复导出 `GateResult` 笔误 → 删除;③`_object_texts` 条件表达式当语句、`canonical_json` 缺 `allow_nan=False` 且未声明与 `clone_json_value` 的分工 → 均修。
- Spec:①**miss 条目可携带 duplicates**(判 miss 即无可信对应,重复对应无从谈起,还能借 duplicates 豁免 unmatched 三分类)→ 校验拒绝 + 测试;②**重放审计时点锚错**——reviewed 指标对"当前"投影复算,评审后合法追加 overlay 会被误判篡改 → machine 侧严格复算(封存锚定),reviewed 块只做内部一致性校验(severity 快照锚定评审时刻),回归测试;③提示词材料名单与 ADR L65 措辞对齐(rejected/unresolved 显式化)。
- ADR L61"统计重发现、路径完整度、证据可复查性、错误结论、未决调查和资源消耗":路径完整度/证据可复查性由字段级 agreement + 双方引用承载(定性),未决调查与资源消耗补为工件 `run` 块(disposition 分布 + 预算台账),可审计复算;full/partial/miss 聚合已有。ADR 层聚合口径若需定量化,建议随首批案例实测回写 ADR。
- 自加规则补登记(建议回写 ADR):①inconclusive-only primary;②非 primary confirmed Finding 与 duplicates/unmatched 严格一一对应(重复引用/重叠/缺漏/miss 带 duplicates 全拒绝——比 L67"重复不重复计分"更硬,是完整性校验的实现口径);③closed 调查作为 primary 的拒绝(L148 只点名 inconclusive)。
- 记录在案:跨测试模块 import 驱动测试私有夹具(仓库既有惯例);evaluation.py 体量与同包 candidates/verification 相当属常态。

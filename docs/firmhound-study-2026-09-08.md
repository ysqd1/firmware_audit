# FirmHound-CLI 对标研究:可吸取清单(2026-09-08)

> 对象:`FirmHound-CLI-main/`(挑战杯「揭榜挂帅」参赛作品,第一队,IoT 固件漏洞挖掘流水线)。
> 本文是**研究文档,不是工单**——每项给出"他们怎么做(带文件证据)→ 我们的现状与痛点 → 落点建议 → 与现有纪律的冲突检查 → 讨论点"。
> 真要落地时,按工作流走 brainstorming/to-spec → to-tickets,再逐票实现。

---

## 0. 一句话结论与根本分歧

**FirmHound 是"确定性规则流水线为主体,LLM 只是可选配件";我们的 fw 是"LLM Agent 审计为主体,确定性工具是供血器官"。**

- 它默认 `offline` 运行时(纯规则、零 LLM 调用),LLM 是 `openai_compatible` 可选开关(`config/models.yaml`);模型不可用时"只返回明确 degraded 状态,不生成替代模型结论"。
- 我们是无 API key 或调用失败即 `LLMError` 终止,**绝不产降级工件**(铁律,AGENTS.md"终止策略")。

这个分歧决定了评判标准:它的规则判定可解释、可测试、零成本,但上限被它自己的盲测证明(见 §L1"诚实版");我们的 LLM 判定上限更高,但任意性、成本、不可复现是真实代价。**下文每一项都要放在这个透镜下看:学它的"方法论沉淀",不学它的"规则替代 LLM"。**

## 1. FirmHound 概览(读懂后文的最低限度)

- 流程:解包 → 攻击面 → 二进制分诊 → 静态数据流审计 → **十维评分** → **反证验证** → 动态验证(可选) → 证据报告。
- 阶段机:`INIT → BASELINE → UNPACK → SURFACE → BINARY_TRIAGE → DECOMPILE → STATIC_ANALYSIS → RANK → VERIFY_TOP_K → {LOCAL_VALIDATION | REPORT} → DONE`;UNPACK 部分失败降级到 ELF 级分析,required 阶段失败 → ABORTED 可 resume。
- 二进制层:pyelftools + capstone 纯 Python(Windows 直跑),Ghidra 只是可选降级;ARM32 调用链恢复靠 `tools/binary/call_chain.py` 线性扫描(约 3s/830KB)。
- 规模:363 文件,README badge 称 320 passed;四个学术外部分析器(SaTC/FirmRec/KLEE/BOND)作可选双轨。
- 它自己的诚实结论(盲测记录 v3):纯静态无反编译时 verifier 对全部候选 DOWNGRADE("call-chain-not-proven 是纯静态的硬上限"),1239 个候选无法收敛——这正是我们 Ghidra 产物链 + LLM 取证能补的位置。

---

## 2. 可吸取清单

优先级含义:P0 = 直接堵现有痛点;P1 = 结构增强;P2 = 工程卫生;P3 = 工作方式。成本:S ≤ 半天,M ≈ 1-2 天,L = 多天/需拆多票。

### L1(P0,S-M)CVE 金标准回归——守护"检出能力"而不只是"代码不坏"

**他们**:`benchmarks/CVEs/` 下 9 个历史 CVE(CVE-2017-17215、CVE-2018-5767 等),每个 CVE 一套三件 JSON:`attack_surface.json` + `candidate.json` + `verdict.json`。candidate 是完整证据化样本(source.type=soap_arg、sink=system、call_chain、risk_score、conclusion_category),verdict 是该候选的裁决样例。金标准守护的是"零先验检出能力"这个核心资产。

**我们**:`test/` 全套件(176+ passed)守护的是单元行为与工件 schema——AST 分层、ScriptedLLM 协议、聚合纯函数。**没有任何一个测试断言"流水线跑完后,已知漏洞会被检出"**。改 Step5 提示词、换工具截断参数、动 aggregator,检出能力退化不会有任何测试变红。

**落点建议**:
- 新建 `benchmarks/`(或 `test/benchmarks/`),以 target/1、target/3(已知 1 个 critical RCE,见 memory)为首批金标准:fixture 只存**期望检出锚点**(归一化 file + func/addr 或 title 关键词),不存固件本体(体积/版权/保密)。
- 判定断言:对 frozen 的 Step4 工件跑 Step5(`python -m firmware_audit.step5_agent.run_step5`),断言 `verified_findings.json` 中存在覆盖锚点的 finding;可选加负向断言(误报数上限)。
- 两档跑法:**tier A** = Step4 工件冻结、只复跑 Step5(花 LLM token,守护判定能力,日常可跑);**tier B** = 全链 Step0-5(贵,里程碑/发布前跑)。
- conftest 已有工件缺失 SKIP 的门控先例,金标准缺固件时同样 SKIP,不卡 CI。

**冲突检查**:fixture 是纯 JSON,零依赖铁律无冲突;金标准跑 Step5 要花 token——tier A 一次冒烟约 10k token 级,可接受但需用户定预算口径。

**讨论点**:① 金标准判定口径用 file+func 归一化还是 dedup_key?续跑身份校验那次的教训是完整 dedup_key 太脆(实例工件常缺 func/addr),建议归一化 file + title 关键词双通道。② target 固件能否进仓库(版权/保密)→ 锚点式 fixture 规避,但"期望值"由谁背书(目前是我们自己的实测结论)。③ token 预算谁批、跑多少频次。

---

### L2(P0,S-M)反证优先验证:12 条硬规则 + 五分类结论 + 四种裁决动作

**他们**(证据:`skills/05-candidate-verifier/SKILL.md`、`fsa/orchestrator/verifier.py`):
- **哲学**:verifier 的职责不是证明候选是漏洞,而是**系统性地找推翻它的证据**;只有经质证仍无法证伪的才升档。
- **12 条硬判定规则**,全是审计踩坑沉淀,可直接变成我们的提示词纪律:
  1. 危险 API 导入 ≠ 漏洞证据(只能 observation);
  2. 认证豁免 ≠ 未认证可达(需 handler 层+启动证据复核);
  3. **过滤函数存在 ≠ 过滤有效**(必须审绕过:黑名单不完整、截断绕过等);
  4. 源码有调用 ≠ 运行时可达(要调用链/控制流证据);
  5. 配置硬编码 ≠ 用户可控;
  6. 调试/测试函数 ≠ 生产攻击面;
  7. `require_auth` 调用存在 ≠ 真的需要认证(可能是死代码);
  8. UPnP/SOAP 输入 ≠ 公网可达;
  9. **证据不足只能到 high-confidence/observation/unknown,禁止为报告好看升 confirmed**;
  10. **false-positive 必须有击败性证据,仅凭"不确定"不能判误报**;
  11. 矛盾证据势均力敌 → 降级为 unknown 并标记需动态验证;
  12. 结论必须标注 reviewer(rule/model/human)。
- **五分类结论**:`confirmed-issue` / `high-confidence-candidate` / `false-positive` / `unknown` / `observation`。后两档专门兜"证据不足"和"只有危险痕迹缺链路",**不逼判定者硬选是/非**。
- **四种裁决动作**:ACCEPT / DOWNGRADE / REJECT / NEED_DYNAMIC——降级是显式动作且带 original_score→revised_score 对照。
- verdict 样例(`benchmarks/CVEs/CVE-2018-5767/verdict.json`):每条带 `reasons[]`、`supporting_evidence[]`、`counterevidence[]`、`reviewer: "rule"`。

**我们**:verification 每疑点一独立实例(ADR-0003,上限 8 轮),产物是 `verified` 布尔语义 + rationale 自由文本。痛点有实据:2026-09-03 被迫在 orchestrator 锚点回填与 aggregator `_OVERRIDE_KEYS` 两处打 severity 覆盖补丁,根因是**判级/结论靠 LLM 自由裁量,工件与理由自相矛盾没有结构约束**;"verified=None 未复核区段"也只解决了"没复核",没解决"复核了但证据不足"的表达。

**落点建议**:
- **第一步(纯提示词,半天)**:12 条硬规则译入 `data/prompts.py` 的 VERIFICATION_SYSTEM 纪律区(与"read_file 报文件不存在 → 必判 false_positive"既有硬规定并列)。零代码风险。
- **第二步(schema 扩展,M)**:finding 增加 `conclusion_category`(五分类)+ `action`(四动作)+ `reviewer` 溯源;`verified` 布尔改为派生字段保持兼容(`category ∈ {confirmed-issue, high-confidence-candidate}` → true)。aggregator 的 severity 覆盖集机制保留,但矛盾面大幅收窄。
- 报告分区随之升级:已复核区段内再分 ACCEPT / DOWNGRADE / unknown / observation,NEED_DYNAMIC 对接未来动态验证。

**冲突检查**:规则进提示词不破上下文隔离铁律(不是新依赖、不是新工具);schema 加字段对旧工件向后兼容(缺字段给默认,`from_json` 宽容解析现成)。

**讨论点**:① `unknown`/`observation` 两档与现有"未复核区段(verified=None)"如何共处——建议三区:已复核-ACCEPT / 已复核-降级与存疑 / 未复核。② 十二条是否全量进提示词,还是取我们实测最痛的 3/4/6/10 四条先试(提示词膨胀会挤 8 轮预算)。③ 是否把反证问题清单(10 问)作为 verification 实例的输出模板强制逐条作答——结构化收益大,但单条 finding 的 8 轮预算装不装得下。

---

### L3(P1,S-M)判级从"印象"变"证据驱动分解"

**他们**:`tools/analysis/risk_score.py`,十维评分 P-I-U-D-C-S-W-K-V-T(每维 0-3,满分 30,≥24 CRITICAL / 18-23 HIGH / 12-17 MEDIUM)。关键设计:**每一维打分必须引用证据 ID,无证据记 0 分并写明 note**(如"认证状态未知,保守记 1")。维度是显式枚举:预认证可达性、输入来源、用户可控性、危险函数可达、字符串拼接、Shell 上下文、文件写入、配置持久化、输入验证(反向)、可测试性。

**我们**:severity(critical/high/medium/low/info)是 analysis Agent 的整体判断,rationale 里可能给理由但不强制结构化;verification 复核时没有"原判 vs 复核判"的对照锚点。

**落点建议**:
- **不必照搬十维**(那是无反编译器静态规则引擎的产物,我们 Ghidra+LLM 的信息更丰富)。取其"证据驱动"原则:analysis 提示词要求 severity 附 `severity_reasons`(2-4 条,每条引用具体文件/地址/代码片段或边车数据);verification 复核先独立判级再对照原判,不一致必须写明理由(我们已有两处 severity 覆盖集,这个对照让覆盖从"兜底"变"显式裁决")。
- 可选做轻量五维(P 预认证 / I 输入来源 / U 可控性 / D sink 可达 / V 缓解反向)作为 analysis 输出模板——讨论后再定。

**冲突检查**:增加输出字段会占 token;五分类( L2)与 severity 分解有重叠,两者一起上要合并设计,避免双重判级口径。

**讨论点**:轻量五维值不值得上,还是只做 severity_reasons?我倾向**先只做 reasons**,维度化等金标准(L1)能量化误报后再说。

---

### L4(P1,S-M)证据账本 + explain——报告结论可回溯

**他们**:`fsa/reporting/evidence_store.py` + `schemas/evidence.schema.json`:每条证据有 `evidence_id`、`fact_status`(confirmed/inferred/unknown/external-reference)、**`supports[]`/`contradicts[]` 指针网络**;`tools/report/explain.py` 的 `build_evidence_ledger` + `render_ledger_markdown` 提供 `fsa explain <run-id>`——候选从哪来、为何可疑、有什么反证,事后可查询。

**我们**:report.md 是 orchestrator `summarize` 一次性生成(64k 护栏素材),**报告生成完就没有任何事后回溯入口**。证据散落在 findings 的 evidence 字段(自由文本)、`obs/` 全文落盘、transcript.jsonl 三处,彼此没有索引。

**落点建议**:
- 零 LLM、纯聚合层:`orchestration/reconciliation.py`(已是"报告对账纯函数群"的家)新增 ledger 构建——每条 verified finding → 指向支撑它的工具调用(obs/ 路径、transcript 事件、边车文件)与反证(复核 rationale);落 `orchestrator/evidence_ledger.json`。
- 入口做成 `python -m firmware_audit.step5_agent.run_step5 explain <target-dir> [finding-key]`(或独立子模块),渲染 md。我们 `obs/` 落盘与 transcript 忠实化(2026-09-06 票02)基建全在,只差索引层。

**冲突检查**:无;这是纯读侧增强,不碰写路径。

**讨论点**:fact_status(confirmed/inferred)要不要引入?它要求 Agent 区分"工具原文证实"与"推理得出"——对报告可信度很有价值,但给 LLM 又添一类要守的口径,可以后置。

---

### L5(P1,S)工具层 status 三态契约(ok / degraded / failed)

**他们**:协作纪律(其 AGENTS.md 规则 6):**每个工具必须输出 `status` 字段,主链路遇 degraded 可继续,failed 必须恢复或降级**。这是全项目统一的工具健康契约,doctor、报告、回归都消费同一口径。

**我们**:工具失败只有一条路——Observation 返回错误文本让 Agent 自行换路(铁律"失败不崩")。Agent 级有 `post_run_status` 三岔,但**工具级没有统一健康视图**:dispatch_log 记了调度史,却看不出"本次运行里 cve_bin_tool 是因为没预热缓存而 degraded"这类信息;排查要翻 transcript。

**落点建议**:`ToolResult` 增加 `status`(ok/degraded/failed)语义层——ok 不变;**可预期的能力缺失**(可选工具被 exclude、CVE 库未预热、外网不可达、镜像缺失)记 degraded;**意外崩溃**(异常、退出码非 0 且非预期)记 failed。消费点:dispatch_log.json 逐条带 status、result.json 的 budget 汇总加各工具健康合计、Observation 文本在 degraded 时附一句"已降级"提示。判定规则收敛在基类一处。

**冲突检查**:不改变"失败不终止"行为,只是让失败**可分类、可统计**;注意别让 LLM 把 degraded 当"工具坏了全弃"——Observation 措辞要说清"结果可能不完整,可继续或换路"。

**讨论点**:degraded/failed 边界由谁定——基类按异常类型自动分,还是各工具子类 `_run` 自己声明?倾向后者(工具最懂自己的可选性),基类只定枚举。

---

### L6(P2,M)路径策略集中化(PolicyEngine 思路)

**他们**:`fsa/safety/policy_engine.py` + `config/safety.yaml` 单一出处:路径白名单/黑名单、命令黑名单、网络白名单,统一 `SafetyViolation` 异常;纪律明文"安全红线不可绕过"。所有读写过同一道闸。

**我们**:路径治理分散在至少四处,且**每一处都单独踩过坑**:`resolve_within` 盘符前缀契约(1537b28,WSL 迁移暴露)、`search_code._resolve_scope` 三类范围守卫(.cve_cache 10.7 万文件卡死事故)、read_file 路径白名单、`cli_base.extracted_tool_path` 工具路径口径(ADR-0008 上游修复)。守卫测试有,但规则本体散——下一个新工具接入还要重新踩一遍"该用哪个 resolve"。

**落点建议**:收一个 `path_policy` 模块(工具层内):路径白名单、树范围语义(extracted/analysis 并集)、盘符/前缀规则、拒绝原因文案,单一出处;现有四处改为消费方;AST/单元守护测试禁止绕过(仿 `test_step5_layer_guard.py` 先例)。

**冲突检查**:迁移本身有回归风险(M 的主因),需要 ADR-0008 系列回归测试全程护航;好处是新工具接入只改一处。

**讨论点**:值得在连续两次路径事故后做,但优先级让位于 L1/L2;可等下一个路径类需求出现时顺路重构。

---

### L7(P2,S)doctor 式环境自检

**他们**:`fsa doctor`(cli.py:265)一条命令体检:本机路径、Schema、运行时、外部工具可用性,缺什么给降级说明。

**我们**:环境健康检查藏在 test conftest 的门控里(工件缺失 SKIP、Docker 门控、smoke 的 STEP5_SMOKE+key 门控)——**跑测试才知道环境缺什么,而且 SKIP 是静默的**。换机器、Docker 集成失效(WSL 老毛病,见 memory)时要靠踩坑发现。

**落点建议**:`python -m firmware_audit.doctor`(或 run_step5 子命令):检查 Docker 可用与两个镜像(firm_audit/sandbox、binwalk)、CVE 缓存卷与预热状态、Ghidra 容器实跑能力(可选,慢)、LLM key 与 base_url 连通性、Step4 工件链完整性。纯只读检查,每项输出 ok/degraded/failed(与 L5 口径一致)。

**冲突检查**:无;注意 Ghidra 实跑检查要显式 opt-in,别让 doctor 默认跑 5 分钟。

**讨论点**:是否与 L5 合并成一张"环境+运行健康"表。倾向合并,同一套枚举两个消费场景。

---

### L8(P2,S)先验隔离:已知 CVE 佐证与零先验发现分开计分

**他们**:外部分析器双轨里,FirmRec(已知漏洞复发扫描)被**代码强制隔离**:旁路结果独立保存(`recurrence_findings.json`)、不计入零先验指标;主轨与外部**双轨互证**命中才提级 `high-confidence-candidate` 并追加证据(汇聚层 `fuse()` 产 `unified_candidates.json`)。

**我们**:cve_bin_tool_scan 的已知 CVE 命中和 Agent 的零先验发现混在同一份 verified_findings/报告里,报告读者分不清"独立发现 N 个新疑点"和"N 个里有 M 个是已知 CVE 佐证"——这两个数字含金量完全不同。

**落点建议**:最小落地(S):reconciliation/报告层把 findings 按溯源拆两组计数展示(cve_bin_tool 命中关联 vs 无 CVE 佐证),report 模板加两行。进一步(后置):CVE 命中作为 finding 的**佐证提级信号**(互证提级),但不改变 finding 本体归属。

**冲突检查**:无;纯报告口径。

**讨论点**:互证提级要不要做——它会让"已知 CVE"影响判级,和"零先验"叙事有张力;我倾向先只做统计隔离,提级不动。

---

### L9(P2,S-M)关键工件轻量机器校验

**他们**:9 个 JSON Schema + 每个配 example,工件落盘前 `validate()`;纪律"改 Schema 必须同步 examples"。schema 拒绝过他们自己的 bug(盲测记录:证据 type 用了枚举外值被 schema 拒,当场暴露)。

**我们**:`data/artifacts.py` 是 dataclass 宽容解析 + 解析失败降级 `.md`——**宽容是读侧美德,但写侧没有校验意味着坏工件静默落盘**,等下游(Agent/报告/人)踩到才暴露。reconciliation 已经在做"报告对账",校验是它的自然延伸。

**落点建议**:不引 jsonschema(零新依赖铁律),在 `data/artifacts.py` 落盘函数处加**手写必填键/类型校验**(`save_aggregate`/`rewrite_artifact`):survey 必须无 findings/判级键(recon v3 守护现有语义,已有解析层先例)、verified_findings 每条必须有 file+title+severity、conclusion_category(若上 L2)必须在枚举内。校验失败 = 显式告警 + 拒绝落盘或带缺陷标记,不静默。

**冲突检查**:与"只降级不崩溃"的铁律要对齐口径——**写侧严格、读侧宽容**,两者不矛盾(落盘时拦住,比下游 Agent 消化坏工件再错一轮便宜得多)。

**讨论点**:校验失败是拒落盘(硬)还是带 `schema_violation` 标记照落(软)?我倾向硬拒——工件是唯一交接契约,坏的比没有更危险。

---

### L10(P3,S)盲测迭代记录文体(工作方式,零代码)

**他们**:`docs/盲测迭代记录_AC15_OpenWrt_2026-09-02.md`:同一未知固件 v1→v4 横向量化(攻击面 207→167、候选 1239→849、verdict 翻转),每代列"发现的自身缺陷 + 铁证 + 修复 + 效果",专设"当前盲测结论(诚实版)"章节,并维护 rolling backlog(如"handler 名还原是榜首")。

**我们**:target/1、target/3 的实测与事故记录质量很高(路径口径事故、续跑错配、卡死根因都在 AGENTS.md/ADR 里),但都是**单点事故复盘**,没有"同固件、多版本、可对比指标"的纵向迭代记录;检出率/误报率没有基线数字。

**落点建议**:给 target/3(Go2 NX,已知 1 critical RCE)写第一份 `docs/盲测迭代记录_target3_*.md`:固定字段(版本 / findings 数 / verified 分布 / 已知洞是否命中 / 误报观察 / 本版改动),配合 L1 金标准跑出第一组基线。这份文档同时是 L1 的验收载体。

**讨论点**:文档放 docs/ 还是 .scratch;频率(每轮 Step5 大改后必跑必记?)。

---

### L11(P3,S)文档产品化(视交付需求)

**他们**:README 面向陌生用户:60 秒快速开始、六步完整流程、判读口诀(分数段/sink 信号/优先审 HIGH)、FAQ、两条安装路线、小白教程与部署指南分册。这是**交付物视角**的文档完整度。

**我们**:AGENTS.md/CONTEXT.md/ADR 是一流的开发者文档,但没有一篇面向"使用者"(三个月后的自己、或要接手的别人):拿到一个新固件从头跑一遍的操作手册不存在,判读 report.md 的口诀也不存在。

**落点建议**:若近期有交付/演示需求,写一篇 `docs/usage-walkthrough.md`:环境自检(依赖 L7 doctor)→ 放固件 → 跑 main.py → 读 report.md(各字段什么意思、verified=None 区段怎么理解)→ 补跑与排查。半天的量。

**讨论点**:现在做还是等 doctor(L7)落地后一起——倾向后者,walkthrough 的第一步就是 doctor。

---

## 3. 明确不吸取的(带理由)

| 项 | 他们的做法 | 不学的理由 |
|---|---|---|
| offline 规则降级运行时 | 无 LLM 时切纯规则跑完整流水线 | 与我们"无降级报告"铁律正面冲突。我们的 Step5 价值主张就是"LLM 证据链审计",规则版报告是负资产。工具链层的 offline 自检价值由 L7 doctor 承接,不需要第二个运行时 |
| 纯 Python 浅层二进制分析替代 Ghidra | pyelftools+capstone,免 Docker 免 Ghidra | 他们自己承认这是 Ghidra 缺席的无奈("纯静态无反编译器是硬上限")。我们的 Ghidra 产物链(.c + 五种边车)是核心壁垒,轻量化是降级不是升级 |
| 规则 verifier 当主判 | 10问+12硬规则由代码引擎执行,LLM 只挂名 | 判定语义(过滤是否可绕过、链是否可达)恰恰是规则最弱、LLM 取证最强的位置;他们盲测全 DOWNGRADE 就是证据。学**规则文本**进提示词(L2),不学**规则引擎**替 LLM |
| 评审前冻结 Schema 再写代码 | "Schema 冻结前不写业务代码" | 适合多人协作交付;我们是单人+Agent 流程,工件 schema 演进靠宽容解析+版本化已够,重流程反而拖慢 |

## 4. 反向清单:我们已领先、讨论时别被带偏的

- **ReAct 引擎深度**:上下文四分区+600k 压缩、transcript 忠实化、Observation 截断+obs 落盘+read_file 回读闭环、循环守卫三件套、token 续写(ADR-0005)、续跑身份校验——他们的 LLM 层只有 mock/openai 两个薄 runtime 文件,以上全没有。
- **验证架构**:每疑点一独立实例、上下文隔离、按 severity×confidence 取前 K(ADR-0003)——比单实例规则跑批信息密度高,且天然并行友好。
- **沙箱基线**:Docker ro 挂载 + `--network none` 全工具统一;他们是进程级策略 + QEMU 本地仿真,隔离边界不同(他们有动态验证 L0-L3 分层,这是我们都没有的另一翼,反向值得未来借鉴,本文不展开)。
- **测试工程**:AST 分层守护、pytest 钩子灭假绿、双模式 fixture——他们的 320 tests 数量更多,但"分层架构机器强制"这类守护我们没有先例可抄他们。

## 5. 建议的落地顺序(草案,供讨论定稿)

1. **L2 第一步**:12 条硬规则进 VERIFICATION 提示词(纯提示词,S,零风险,立刻可做);
2. **L1 tier A**:target/3 金标准 fixture + Step5 复跑断言(建立检出能力基线,此后一切大改有安全网);
3. **L10**:盲测迭代记录 target/3 第一期(以 1、2 的产出为素材);
4. **L2 第二步 + L3**:五分类 schema 扩展 + severity_reasons(合并设计,一次落);
5. **L4**:evidence ledger + explain(读侧增强);
6. **L5 + L7 合并**:status 三态 + doctor;
7. **L8、L9**:报告口径拆分 + 写侧校验;
8. **L6**:路径策略集中化(等下一个路径类需求顺路做);
9. **L11**:usage walkthrough(交付需求明确后)。

每项按工作流:单票直接 implement;L1/L2/L4 这类跨模块的走 to-spec → to-tickets。

## 6. 附:两仓库模块对照索引

| FirmHound-CLI-main | 我们的 fw | 关系 |
|---|---|---|
| `fsa/orchestrator/`(engine/planner/verifier) | `step5_agent/orchestration/`(orchestrator/actions/verify_phase/reconciliation) | 同位;我们的编排是 LLM 驱动,他们是阶段机代码驱动 |
| `tools/analysis/risk_score.py` | 无(判级在 LLM) | L3 对标源 |
| `fsa/orchestrator/verifier.py` + `skills/05-candidate-verifier/` | `data/prompts.py` VERIFICATION + `verify_phase.py` | L2 对标源 |
| `fsa/reporting/evidence_store.py` + `tools/report/explain.py` | 无(obs/、transcript 是散装原料) | L4 对标源 |
| `fsa/safety/policy_engine.py` + `config/safety.yaml` | 路径规则散在 resolve_within/_resolve_scope/read_file/cli_base | L6 对标源 |
| `benchmarks/CVEs/` | 无 | L1 对标源 |
| `fsa/cli.py`(doctor/explain/status/resume) | `run_step5.py` + `python -m` 补跑 | L7 对标源 |
| `docs/盲测迭代记录_AC15_OpenWrt_2026-09-02.md` | AGENTS.md 事故记录(单点式) | L10 对标源 |
| `fsa/runtime/`(offline/openai_compatible/skill_loader) | `providers/llm_client.py`(无降级) | 分歧点,不吸取 |
| `skills/00-08 SKILL.md`(方法论知识库,带验收标准/降级路径表) | 提示词内嵌 + AGENTS.md | 形式差异;他们的"验收标准写进知识文档"值得在改提示词时参考 |

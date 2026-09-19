# 固件安全审计(Firmware Security Audit)

对嵌入式设备(当前为宇树 Unitree)固件做安全审计的流水线:预解压与解包(Step0-1),随后由三个 LLM Agent 按序侦查、取证、复核(Step5,按需调用 r2/Ghidra 工具),产出带证据链的审计报告。产物全部落在 `target/<N>/process/` 工作区下。

## 语言

### 流水线与工件

**固件 (firmware)**:
用户放入 `target/<N>/` 的待审文件(归档/单文件压缩/磁盘镜像三种形态),整条流水线的输入。识别由 `main.py._find_firmware` 按扩展名/大小完成。
_Avoid_: 镜像(仅指磁盘镜像), 包(package)

**工作区 (workspace)**:
`target/<N>/process/` 目录——固件解包产物与全部审计产出的唯一落盘根,也是 Step5 工具(read_file/list_files 等)的白名单根。磁盘镜像场景下每个分区子文件夹自成一个工作区。
_Avoid_: 输出目录(out 是单个分区的子目录)

**解包树 (extracted tree)**:
Step1 把固件解包出的文件目录树(`process/extracted/`),只读,是后续所有分析的原始材料。
_Avoid_: 解包根, extracted

**工件 (artifact)**:
当前指运行世代目录(`process/generations/gen-XXXX/`)下的机器产物:manifest、run_state、config、Candidate Store、Investigation/Verification 目录、findings.json、report.md 与 Evidence。旧版 `process/agent/<seq>_<type>/` 下的 `survey.json`、`findings.json`、`verified_findings.json` 属旧语义工件,新流程不读取也不迁移,旧工作区需显式新建运行世代重跑。
_Avoid_: 产出文件, 中间文件, 把旧三工件当作现行输入

**调查工作区产物 (analysis sidecar)**:
ghidra_decompile 在 `process/analysis/` 下按文件相对路径产出的**边车三件套**(`.c / .strings.json / .imports.json`)——strings_query/imports_query 的边车优先数据源、find_decompiled_function 的读源、semgrep 双扫的 analysis/*.c 路。由 Step5 工具按需产出并幂等缓存(ADR-0010),不再是流水线批量产物;functions.json/meta.json 无工具消费者,不落盘。
_Avoid_: 边车文件(实现细节), 反编译产物

**工具路径 (tool path)**:
相对工作区 `process/` 根的路径(`extracted/unitree/...`、`analysis/...`、`agent/...`)——LLM 工具(read_file/list_files/search_code)**唯一接受的入参形态**,也是 Agent 工件(survey/high_risk_areas、findings/verified_findings)中 file 字段的**唯一规范口径**(ADR-0008)。
_Avoid_: process/ 前缀形态(`process/analysis/...` 没有任何工具能打开), 相对路径(歧义:相对谁)

**逻辑路径 (logical path)**:
相对固件根的路径(`unitree/...`,与 analysis 边车命名同构)——**纯内部键**,只存在于解包侧代码与 CLI 工具(semgrep/gitleaks)的原始容器输出里;进入任何 Agent 工件或工具入参前必须换算成工具路径。
_Avoid_: 固件路径, 物理路径

**文档声明(requirements.md / rules.md / agents.md)**:
`requirements.md` 已删除(2026-09-09,ADR-0011 收尾;旧 Step5 需求快照失去宿主);`rules.md` 是代码规范铁律,`agents.md`(AGENTS.md)是 Agent 架构与工具层设计。这两份里的**部分条款已过时**(尤其 Step1-4 相关章节,见 ADR-0010/0011),与代码现状不一致处以下文术语表、docs/adr/ 和代码为准。
_Avoid_: 把它们当现状说明书

### 阶段与角色

**预处理流水线 (pipeline)**:
固定顺序的规则化处理阶段:Step0 预解压/磁盘镜像分区提取 → Step1 引导式解包。纯代码,不依赖 LLM。原 Step2 过滤/Step3 分类/Step4 反编译已决定删除(ADR-0011),反编译降为 Step5 的按需工具(ADR-0010)。

**Step5 (Agent 审计)**:
面向解包树的 LLM 辅助审计阶段。Host 控制 Candidate 到 Investigation、Verification Case 和 Finding 的状态转换,recon、analysis 与 verification 只承担各自的语义研判角色。

**宿主控制层 (Host)**:
承载 Agent 的确定性控制边界,拥有调查生命周期、预算、工具执行、证据留存与最低证据门槛。LLM 可以提出调查结论,但 Host 会拒绝证据不完整的 confirmed,并在无法继续时保留为 inconclusive。
_Avoid_: orchestrator(当前由 LLM 参与控制的具体角色), Agent, 工具

**子 Agent (sub-agent)**:
Step5 的三个语义研判角色之一,由 Host 在确定性生命周期内调度。三者是不同角色配置,不是各自拥有控制权的独立层级。
_Avoid_: 阶段, 子任务(会与 pipeline 阶段混淆)

**recon(侦查 Agent)**:
第一个子 Agent。对解包固件做广度调查与一跳安全研判,在明确调查目标、可疑依据和起始动作后形成 Candidate;多层调用链证明、最终影响和严重度留给后续调查。
_Avoid_: 侦察, 铺面阶段

**analysis(深度分析 Agent)**:
围绕一个 Candidate 持续推进 Investigation 的推理角色,负责修正假设、选择下一项取证动作并提出待独立复核的 Claim;它不产生最终复核结论。
_Avoid_: 取证 Agent(职责是取证但名是 analysis)

**verification(复核 Agent)**:
独立检查 Investigation 提交的 Claim 与原始工件、Evidence Reference 是否吻合的推理角色,是最终复核结论的唯一产生者。它不继承 analysis 的最终判断、严重度或说服性描述。
_Avoid_: 复核阶段

**旧版 orchestrator (legacy orchestrator)**:
ADR-0012 之前由 LLM 参与阶段推进、结束和报告生成的编排角色。已随票 14 公开切换整体删除(`orchestration/` 包、runner/aggregator 与 top-K/verify-K/LLM 事实报告行为),不保留 shim、双模式或旧行为开关。
_Avoid_: 把 orchestrator 当作目标架构的控制层, 迁移期兼容入口(已不存在)

**独立复核 (independent verification)**:
verification 根据待验证 Claim、目标工件和 Evidence Reference 重新取得关键事实,不继承 analysis 的 verdict、severity、confidence 或说服性描述。
_Avoid_: 二次阅读 finding, 完全盲扫

**旧版实例 (legacy instance)**:
一次真实执行的子 Agent 运行,落盘在 `process/agent/<seq>_<type>/`(如 `0_recon`),带递增序号 seq 与独立 transcript/obs/工件。
_Avoid_: 用它表达目标模型的 Agent Session 或 Investigation

### 发现链

**调查候选 (Candidate)**:
足以启动一次独立调查的可证伪疑点,主要由 recon 形成;Investigation 或 verification 发现独立问题时提交候选建议,由 Host 去重并正式创建。它必须包含明确 target、攻击面信号、初始证据与下一步动作,possible source/sink 可以暂时为空,尚不是 finding。
_Avoid_: 候选漏洞(暗示已经构成漏洞), candidate finding(指 analysis 的旧工件条目)

**信号 Candidate (signal Candidate)**:
由具体配置、代码、字符串、导入或输入路径信号触发的 Candidate,必须引用形成该信号的初始证据。
_Avoid_: confirmed issue, finding

**覆盖 Candidate (coverage Candidate)**:
缺少具体问题信号时,为高价值攻击面建立的深度检查目标。它必须说明目标的入口或安全相关角色,但不声称已经存在缺陷。
_Avoid_: 弱信号 Candidate, 强制 finding

**攻击面调查 (survey)**:
单个 recon 对解包树形成的广度记录,包含已检查范围、coverage gaps 与 Candidate proposals。它描述调查覆盖和后续入口,不是 Candidate 的权威存储。
_Avoid_: inventory(已被 ADR-0011 否决的独立流水线产物), finding

**Candidate Store**:
Host 校验、去重并分配稳定身份后的 Candidate 权威集合。signal Candidate 的确定性 fingerprint 由目标路径、位置锚点、Claim Profile 与问题机制组成;coverage Candidate 则由目标路径、组件或入口与检查目标组成。只有目标与 Profile 相同但 fingerprint 不同时才做一次语义比较;结果为 same / different / uncertain,只有 same 合并并保留原 proposal 作为 alias。
_Avoid_: survey.json 内嵌列表, Agent 私有队列

**Candidate ID**:
Candidate 在单个运行世代内的递增稳定身份,如 `cand-0001`。它不由可变内容或 fingerprint 生成,候选信息补充或 proposal 合并后也不改变。
_Avoid_: fingerprint(只用于去重), 全局跨运行 ID

**调查 (Investigation)**:
围绕一个 Candidate 持续追踪假设、证据、反证与待补证据的完整生命周期。一次 Investigation 只负责一个 Candidate,直到确认、排除、证据不足或预算耗尽。
_Avoid_: analysis 实例(当前实现一次可处理多个疑点), 调度

**工作假设 (working hypothesis)**:
Investigation 对当前问题机制的可证伪解释,可以为空,同一时刻只保留一个活跃项;被支持、反驳或替换的旧解释进入简短历史。它指导下一项调查动作,不属于最终 Claim。
_Avoid_: Candidate(调查对象), Claim(待正式证明的主张), 多 Agent 辩论

**调查生命周期 (Investigation Lifecycle)**:
一个 Investigation 的处理进度,值域为 queued / investigating / ready_for_verification / verifying / finished。它只表达进度,不承担最终 disposition 或 stop reason;高优先级未决调查可从 investigating 经 evidence_gap 案卷直接进入 verifying。
_Avoid_: Agent 轮次, Candidate Queue

**调查处置 (Investigation Disposition)**:
Investigation 结束时的结果分类:confirmed / rejected / inconclusive / closed / unresolved / not_started。服务临时中断不产生 disposition,未完成 Investigation 保留原生命周期状态等待恢复;案例总预算耗尽是例外——进行中的 Investigation 以 unresolved 收束,运行随后正常封存(2026-09-19 确认)。
_Avoid_: lifecycle status, stop reason

**停止原因 (stop reason)**:
说明 Investigation 为什么停止的独立字段,如 completed / decisive_refutation / budget_exhausted / no_progress / input_failure。它不替代 disposition 或 verification verdict。
_Avoid_: 最终结果, 生命周期状态

**关联调查候选 (related Candidate)**:
调查中发现的独立入口、独立 sink 或独立影响所形成的新 Candidate,保留其来源 Investigation;同一根因或同一攻击路径继续留在原 Investigation。
_Avoid_: 子 Investigation, 新 finding

**复核案卷 (Verification Case)**:
Investigation 提交给 verification 的冻结待审对象,由 Candidate 身份、admission reason、待验证 Claim、Evidence Reference、已探索路径、前置条件与预期影响组成。admission reason 区分已满足门槛的 ready 与需补齐材料的 evidence_gap;Verifier 不修改原案卷。
_Avoid_: 裸 Candidate(证据不足以复核), candidate finding

**补证复核案卷 (evidence-gap case)**:
高优先级未决调查在正常完整度门槛之外进入独立复核的 Verification Case,必须显式列出缺失 Claim 与已知限制。Verifier 如用本次独立取得的 Evidence Reference 支持全部必填 Claim,仍可得到 confirmed;否则为 inconclusive。
_Avoid_: 普通 ready 案卷, 自动降级结论

**调查状态 (Investigation State)**:
跨 LLM 对话保存的结构化调查记忆,包含工作假设、Claim、Evidence Reference、已探索路径、缺失证据与下一项动作。Related Candidate 只继承相关状态、证据和来源关系,不复制旧聊天记录。
_Avoid_: Transcript(完整留痕但不作为工作记忆), 对话上下文

**Investigation Store**:
每个 Investigation 的追加事件历史与当前状态投影。追加事件是权威历史,状态快照记录 last_event_seq 并可由后续事件重建;二者不并列充当相互冲突的真值。
_Avoid_: 数据库(第一版不需要), 只保存最终结果

**运行世代 (run generation)**:
同一工作区内一次完整审计的独立结果边界。未完成世代默认恢复,已完成世代保持不变;重新审计必须显式创建新世代。
_Avoid_: 覆盖重跑, 把运行标识当作 Candidate 身份

**封存运行 (sealed run)**:
所有 Candidate 均有处理记录、必需复核已完成、事实报告与工件 digest 已生成的已完成运行世代。封存后机器工件不可修改,后续人工或 Codex 复核只能通过独立覆盖层表达。
_Avoid_: 仅 Agent 执行结束, 可原地修改的结果

**复核覆盖层 (review overlay)**:
对封存运行中的 machine result 追加的独立复核记录,保存复核者、时间、目标字段、原值、新值、理由与 Evidence Reference。它不改写原始机器结果。
_Avoid_: 直接编辑封存 JSON, machine result

**主张 (Claim)**:
Investigation 中需要由 Evidence Reference 支持或反驳的可证伪陈述,状态为 unassessed / supported / refuted / not_applicable。所有调查使用通用 Claim,并按问题类型选择额外的 Claim Profile。
_Avoid_: hypothesis(指导当前调查方向), finding(复核后的最终问题)

**主张结果 (Claim Result)**:
Verifier 对单项 Claim 的独立复核记录,包含 supported/refuted/unresolved/not_applicable 评价、实际观察、复核证据、验证方法与限制。Host 由全部必填 Claim Results 聚合最终 verdict。
_Avoid_: finding, 自由文本 rationale

**主张模板 (Claim Profile)**:
Host 用来检查 Investigation 完整度的固定 Claim 集合。第一版只有数据传播、配置、凭据处理、内存处理四类与受限 `generic`;目标、根因、触发或暴露关系及实际影响是共同决定性 Claim,前置条件与缓解因素是非决定性必填 Claim。
_Avoid_: 固定 source/sink 表, LLM 自由字段

**证据引用 (Evidence Reference)**:
指向某次真实工具 Observation 及其原始工件的运行内递增稳定标识,如 `ev-000001`。每次工具调用都有独立身份,即使返回内容相同也不合并;原文 SHA-256 用于完整性校验,不作为身份。原始 Observation 与摘要分离且写入后不可修改,摘要和 Claim 关联可以更新。
_Avoid_: evidence 文本(当前 finding 中的自由文本摘要), 文件路径

**发现 (finding)**:
verification 确认复核案卷成立后形成的最终安全问题。已排除和未决调查分别留在调查记录中,不属于 finding。
_Avoid_: candidate finding(旧 analysis 工件条目), verified finding(在新模型中重复表达)

**旧版候选漏洞 (legacy candidate finding)**:
当前实现中 analysis 产出的未经复核条目,集中在 `findings.json`;目标模型将其拆为复核案卷、已关闭调查或未决调查。
_Avoid_: 作为新模型的正式术语

**旧版已验证发现 (legacy verified finding)**:
当前实现中 verification 复核后的 finding 容器条目;目标模型中 finding 本身已表示确认成立,不再需要 verified 前缀。
_Avoid_: 作为新模型的正式术语

**调查关闭 (investigation closure)**:
Investigator 因决定性反证而停止某个 Candidate 的处理,必须保留关闭原因与 Evidence Reference。它不是 verification 产生的 rejected verdict。
_Avoid_: reject_candidate(会与独立复核的 rejected 混淆), 误报

**未决调查 (unresolved investigation)**:
因预算、环境或关键材料不足而无法满足普通复核门槛的 Investigation。高优先级项可以补证复核案卷进入 verification;因案例总预算耗尽而未决的 Investigation 是终态记录(随运行封存,不再恢复),且不作为 Benchmark 评估的 partial primary(2026-09-19 确认)。
_Avoid_: finding, 已排除调查

**已确认问题 (confirmed issue)**:
输入来源、传播路径、敏感操作、可达条件、限制条件与实际影响均有可追溯证据支持的调查结论。仅证明敏感函数或危险配置存在时仍属于证据不足。
_Avoid_: verified=true(当前字段可能只表示局部静态事实成立), 高置信度 finding

**误报 (false positive)**:
Verification Case 因决定性 Claim 被独立反驳而得到 rejected verdict 的评估分类。它必须保留 Claim Result、Evidence Reference 与限制说明,不许静默丢弃。

**疑点 (suspicion / lead)**:
有待查证的线索:recon 的 `high_risk_areas`(观察点,无判级)、analysis 的候选、被引用的函数/导入/字符串命中。与 finding 不同,疑点是"待查",finding 是"有结论"。
_Avoid_: 线索(lead 英文可,中文不用"线索"以免歧义)

**观察点 (observation point)**:
recon 的 `high_risk_areas` 数组里的条目——一个"高危区域标记,非判定",只记录 file+metric+detail,不判级、不展开证据链。判级与证据链移交 analysis。
_Avoid_: 发现, 判断(它有判级含义)

**Observation(A 大写,保留英文)**:
一次真实工具执行产生的有界原始结果,是 Evidence Reference 的来源。Host 在上下文截断前保存其完整文本和结构化数据;大型或二进制产物单独落盘,引用只记路径、大小与 digest。
_Avoid_: 上下文截断版, 无界容器输出

**Observation View**:
从原始 Observation 派生、送入 Agent 上下文的有界文本视图。它可以截断并附回读指针,但保留原始字面值,且不是权威证据存储。
_Avoid_: 原始 Observation, 证据原文

**报告 (report)**:
Host 从 Finding、复核案卷、未决调查、coverage gaps、Evidence Reference 与运行统计确定性生成的事实文档。固定事实章节后可有独立标注的 Analyst Notes;LLM 说明不能改变结构化结论,缺失时也不影响报告完成。
_Avoid_: LLM Final Answer 原样落盘, 自由生成的事实表

### Agent 交互与状态

**ReAct 循环 (ReAct loop)**:
子 Agent 的逐步协议:decision summary → Action Proposal → Observation View → 下一步。Agent Session 每次产生一个动作建议后暂停,Host 负责校验、执行、持久化原始 Observation,再将视图送回会话。
_Avoid_: 对话循环, Agent 循环

**Agent Session**:
一个可逐步驱动的 Agent 语义会话,每次以结构化文本产生 state delta 和唯一 next proposal,不自行执行工具或推进 Investigation Lifecycle。Host 完整校验后才应用该回复,不接受部分状态更新。
_Avoid_: 完整自主运行器, Host

**轮 (round/step)**:
ReAct 循环的一次 LLM 调用迭代,记入 transcript 并编号(step 1..max_iters)。
_Avoid_: 步(step 已用于索引)

**Transcript**:
一次 Agent Session 的完整留痕,包含输入输出、动作建议、耗时与用量。它用于追溯,不是 Investigation State 也不作为恢复时的工作记忆。
_Avoid_: Investigation State, 恢复快照

**工具 (tool)**:
Agent 在 Action 里调用的能力,统一 `AgentTool.execute(**kw) → ToolResult` 接口,返回 `{ok, text, data, error, elapsed, raw}`。按数据来源分三类:读盘类(读工作区/边车,毫秒级)、CLI 类(subprocess 调容器内 CLI)、API 类(urllib 调 HTTP);另有唯一的**产物生产工具** ghidra_decompile(调容器并把边车落盘,ADR-0010)。
_Avoid_: 函数(与 Ghidra 函数混淆), 命令

**接口契约 (interface contract)**:
工具对 LLM 暴露的参数约定——`params_doc` 是结构化规格(声明侧:参数名→类型/必选/默认/枚举),`base.execute` 按声明校验(执行侧:未知键/类型/缺失必选)。两侧同步闭合。ADR-0004。旧态(散文 + 无校验)已废除。
_Avoid_: 参数说明(params_doc 只是声明侧), 工具签名(那是 execute 执行侧)

**读盘类工具 (read-disk tool)**:
直接读工作区文件与边车、不调容器的工具:`list_files`/`read_file`/`search_code`/`strings_query`/`imports_query`/`find_decompiled_function`。廉价、毫秒级。其中 strings_query/imports_query 是**边车优先 + r2 兜底的混合型**:缺边车时降级为 CLI 通道现算(ADR-0010),不再报"未找到"。
_Avoid_: 本地工具, 便宜工具

**CLI 类工具 (CLI tool)**:
经 `run_docker` 调容器内 CLI 的工具:`checksec`/`r2_list_functions`/`r2_disassemble_function`/`r2_xref_query`/`cve_bin_tool_scan`/`semgrep_scan`/`gitleaks_scan`/`binwalk_rescan`/`sandbox_verify`。贵、走网络隔离;strings_query/imports_query 的 r2 兜底路也走此类通道(ADR-0010)。

**API 类工具 (API tool)**:
宿主 Python 用 urllib 调外部 HTTP API 的工具:`cve_lookup`/`web_search`。带节流/缓存/降级。

**TaskResult(ToolResult 专用名)**:
工具的通用返回结构,ReAct 循环只消费它,不感知数据来源。字段 `ok/text/data/error/elapsed/raw`(`providers/tools/base.py`)。
_Avoid_: 工具返回, 结果(太泛)

#### 旧版编排术语(仅用于解释迁移前代码)

**上游工件 (upstream artifact)**:
交接给某子 Agent 的前序阶段工件:analysis 的上游是 survey.json,verification 的上游是 findings.json。orchestrator 用 `latest_upstream`(orchestration/actions.py 守卫函数)取最近一次已完成调度的工件。缺件时下游调度被拒。

**交接 (handoff)**:
orchestrator 注入子 Agent 简报尾部的上下文块:前序任务状态、同类型前次结果、累计发现、任务上下文;补跑时追加已覆盖清单与差分提示。结构化快照落盘 `handoff_<seq>_<type>.json`。
_Avoid_: 上下文注入(太泛), 传参

**简报 (brief)**:
每次子 Agent 执行的初始化用户消息(`build_*_brief`),含工作区锚点、上游工件摘要、任务说明。交接块经 `extra_brief` 追加到简报尾部。
_Avoid_: 系统提示(system prompt 是另一回事), 初始消息

**系统提示 (system prompt)**:
Agent 的系统提示词(`RECON_SYSTEM`/`ANALYSIS_SYSTEM`/`VERIFY_SYSTEM`/编排 ORCH_SYSTEM),含角色、工具清单、输出协议、纪律。留档在实例目录下供复现。
_Avoid_: 提示词(太泛), 任务描述

**调度 (dispatch)**:
orchestrator 对某个子 Agent 的一次安排,由 `dispatch_agent` 动作发起,经过守卫(未知 agent/顺序门/任务唯一性/次数上限)后执行。全程记入 `dispatch_log.json`(含被拒与重复尝试)。
_Avoid_: 调用(与工具调用混淆), 安排

**调度状态 (dispatch status)**:
一次调度的落盘状态枚举(`DispatchStatus`):running / success / skipped / degraded / failed / interrupted / rejected / duplicate。其中 `skipped`=.json 工件已存在;`degraded`=仅 .md 降级工件,默认复跑。
_Avoid_: 状态, 执行状态

**预算状态 (budget state)**:
某类型子 Agent 最新实例的迭代预算快照 `{agent, exhausted, steps, max_iters, pending_count, pending_focuses, overlap_ratio}`,注入 dispatch/summarize 的 Observation 与 dispatch_log/result.json,供 orchestrator 做是否补跑的动态决策。
_Avoid_: 预算, 剩余轮次(仅含 steps/max_iters)

#### Host 调查术语

**调查预算 (Investigation Budget)**:
分配给单个 Investigation 的资源边界。模型请求、工具实际尝试、token 与活动执行时间按真实消耗计数,同时单独记录 validated rounds 与 logical tool calls 便于解释。第一版各 Candidate 使用相同固定额度,同时受案例级总额度限制。
_Avoid_: budget state(当前按 Agent 类型统计), LLM 自定轮数

**调查优先级 (Investigation Priority)**:
有限预算下安排 Candidate 处理顺序的值,不是问题严重度。signal 与 coverage Candidate 分队排序;前者按外部可达性、输入可控性、高影响操作、路径进展、材料强度减预计成本计分,后者按组件价值、外部暴露程度、尚未检查程度减预计成本计分。各项只取 0/1/2,LLM 提供分项判断与依据,Host 计算总分。
_Avoid_: severity(仅适用于确认后的问题), LLM 直接输出 high/medium/low

#### 旧版补跑术语(仅用于解释迁移前代码)

**补跑 (re-run / supplementary dispatch)**:
同一类型子 Agent 的第 2/3 次调度,仅当结果明显不完整(如 analysis 预算耗尽仍有未覆盖疑点)时用**不同的任务描述**发起;简报追加已覆盖清单(前 30 条)与差分任务提示,禁止重复提交已存在标题的 finding。

**降级 (degraded)**:
两处含义,均在术语表内不冲突:① 工件解析失败(JSON → `.md`),调度状态记为 degraded;② 工具失败降级兜底("失败不崩"原则)——返回 ok=False 并记录失败原因,不中断整体流程。

#### Host 恢复术语

**断点续跑 (resume / checkpoint)**:
从未完成运行世代的权威状态快照和追加事件继续执行。恢复不以“某个最终 JSON 是否存在”为判据,也不覆盖已完成运行世代。
_Avoid_: 跳过已有阶段工件, force 覆盖

### 审计判定

**Benchmark**:
由公开案例输入、与 Agent 隔离的 Ground Truth、固定运行配置和评价指标组成的研究测试集。公开案例不含参考答案;Evaluator 只在运行结果冻结后读取独立 Ground Truth 根目录。
_Avoid_: 固件集合(缺少答案与评价规则), CVE 扫描

**Ground Truth**:
Benchmark 案例的隐藏参考答案,包含公开编号、根因位置、输入入口、关键处理关系、前置条件与影响。它位于 Agent 工具访问边界之外的独立根目录,路径不进入 Step5 参数、简报或运行快照,只由结果冻结后的 Evaluator 读取。
_Avoid_: Recon 输入, 公开文章全文

**盲发现 (blind discovery)**:
发现阶段与已知 CVE 编号、问题描述、版本匹配结果及 Benchmark Ground Truth 隔离的审计模式。通用文件、代码、二进制与受控验证工具继续可用;CVE 扫描、公开问题查询和外部检索不进入 Agent 权限,调查结果冻结后才允许对照评估。
_Avoid_: 未知漏洞扫描(盲发现也可以重发现公开问题), 无先验分析

**已知问题辅助 (known-issue assist)**:
允许把公开缺陷资料作为分析先验的审计模式,其结果必须标记外部知识来源,并与盲发现结果分开评价。
_Avoid_: benchmark 模式, 盲发现

**对照评估 (ground-truth evaluation)**:
在盲发现结果封存后,先由确定性程序生成候选对应,再由 Codex 对 Ground Truth 与 Finding/Investigation 做字段级语义裁定并计算研究指标的过程。它不要求路径、函数名或描述文本完全相同。
_Avoid_: CVE 扫描, 发现阶段

**语义裁定 (semantic adjudication)**:
Codex 在封存运行之后,按固定量表比较 Ground Truth 与机器输出的根因、入口或触发条件、关键处理关系、实际影响和 disposition。裁定必须保存字段级结果、双方引用、理由、评审模型与输入 digest。
_Avoid_: 字符串相等匹配, 无依据的自动分类

**未匹配 Finding (unmatched Finding)**:
无法与 Benchmark Ground Truth 自动对应的 confirmed Finding,需要人工判断是新增有效结果还是错误结论,不能自动计入 false positive。
_Avoid_: false positive, 自动忽略

**重发现 (rediscovery)**:
在不读取 Ground Truth 的条件下重建参考问题的 Benchmark 结果。根因、关键处理关系与影响语义对应且形成 confirmed Finding 为 full;可确认在调查同一问题但链路、影响或最终确认仍有缺口为 partial;没有可信对应 Investigation 为 miss。
_Avoid_: 输出相同公开编号, 版本匹配

**严重度 (severity)**:
confirmed Finding 的影响等级,由 Host 将结构化影响范围与触发条件代入固定二维矩阵生成 `info / low / medium / high / critical`。缓解因素只能下调,关键字段缺失时不得给出 critical;人工调整必须保留理由。
_Avoid_: 等级, 风险等级(风险有可利用性含义)

**旧版置信度 (legacy confidence)**:
旧 finding 模型的 high / medium / low 证据概括值。目标模型用 Claim Result、verdict 与 evidence completeness 分别表达事实,不再用 confidence 承担最终结论。
_Avoid_: 用 confidence 替代 verdict 或证据完整度

**复核结论 (verdict / rationale)**:
verification 对待复核 Claim 的最终判定,值域为 confirmed / rejected / inconclusive;进入复核前为空值。结论与验证方法、证据完备度分开表达。
_Avoid_: verified 布尔值(无法表达存疑), status(还可能指生命周期状态)

**验证方法 (verification method)**:
复核结论所采用的方法类别:static_analysis / behavior_model / target_execution。方法只说明如何检查,不暗示检查结果成立或被排除。
_Avoid_: reproduced(暗含成功复现), proof level

**证据完备度 (evidence completeness)**:
某项 Claim 当前证据覆盖程度:observation_only / partial_chain / complete_chain;尚无证据时为空值。它描述材料是否闭合,不替代复核结论。
_Avoid_: confidence(是另一种概括性估计), 验证方法

**可利用性 (exploitability)**:
基于二进制保护属性的漏洞被利用的难易程度,由 checksec 的 NX/PIE/RELRO/Canary/Fortify 等属性评估。NX 关闭 + 无 PIE → 可利用性上调。是 LLM 的评估输入,不是 finding 的字段。
_Avoid_: 风险, 严重度(severity 是另一个维度)

**证据链 (evidence chain)**:
一条 finding 从疑点(HIT)到结论的支撑材料:工具 Observation 原文(file/line/code 片段)、交叉引用、CVE 详情。要求逐字可溯源,禁止编造。
_Avoid_: 证据(单条是 evidence,整条链是 evidence chain)

### 工具与数据(分析工具与边车)

**升级调用 (escalation)**:
两级二进制分析模型(ADR-0010):r2 廉价层(r2_list_functions / r2_disassemble_function / r2_xref_query,及 strings_query/imports_query 的 r2 兜底——秒级、不落盘、不反编译)先行,LLM 判断信息不够才升级调用 ghidra_decompile(分钟级、落盘边车三件套、幂等缓存)。升级规则写在提示词与缺件报错文案里;verification 红线按升级链改写:缺 `.c` → r2 层查证 → 信息不够 → 反编译 → 仍缺失/零产出 → 才判 false_positive。
_Avoid_: fallback(中英混排), 反编译升级

**ghidra_decompile**:
Step5 唯一的 Ghidra 入口:对单个 ELF 反编译并落盘边车三件套(`.c/.strings.json/.imports.json`),幂等缓存(`extractinfo_version` 匹配即跳过 + sha256 去重)。带 `-analysisTimeoutPerFile 300` 截断防止大型共享库陷入无限循环。原 Step4 批量反编译已退役(ADR-0010/0011)。
_Avoid_: 反编译(单独用会与 find_decompiled_function 混淆), 批量反编译

**危险函数表 (dangerous function table)**:
imports_query 使用的导入风险分级表,值域 high(命令执行/内存不安全)/ medium(权限/动态加载)/ low(网络/随机),集中配置。与硬编码文本模式是两套独立的东西。
_Avoid_: 黑名单(与已退役的 step2 过滤名单混淆), 危险模式表(会与 _TEXT_PATTERNS 撞名)

**硬编码文本模式 (hardcoded-text patterns)**:
`_TEXT_PATTERNS` 正则模式集(URL/IP/密钥/口令),现由 strings_query 的 `pattern` 参数在**查询时过滤**边车或 r2 兜底的字符串(原 Step4 预产 .text.json 已退役,ADR-0011)。命中只标记"检出",不代表有问题,需人工确认(如 paho-mqtt 的 token 误报)。与 imports_query 的危险函数表是两套独立的东西,勿混。
_Avoid_: 危险模式表, 文本正则(太泛)

**系统信任库 (system trust store)**:
固件里位于标准系统信任目录(`etc/ssl/certs` 等)下的证书,表示"非厂商硬编码凭证"。原 Step3 的 `is_system_trust` 标记随 Step2-4 退役(ADR-0011);"系统 CA 不作可疑点上报"降为 Agent 提示词纪律。
_Avoid_: 信任文件, 系统证书

**敏感配置 (sensitive config)**:
`etc/` 下需要审计的配置文件,与发行版标准配置相对。原白名单强制保留机制(WHITELIST_ETC)随 Step2 退役(ADR-0011);现在所有解包文件对 Agent 可见,该区分只是审计常识。

**SDK 系统库目录 (SDK/system library dir)**:
`usr/lib`、`usr/local/lib`、`usr/share`、`lib`、`opt` 等目录。Step5 的 list_files/search_code/semgrep 按 profile 的 `SEARCH_EXCLUDE_DIRS` 自动跳过(SDK 噪音;原 Step2 过滤黑名单已退役)。与厂商自研目录(`home/unitree/`)相对。

**逻辑路径 (logical path)**:
剥掉 binwalk 解包嵌套前缀(`<name>.extracted/<N>/`、`<fstype>-root/`)后的固件内相对路径,analysis 边车按它命名。例:`foo.tar.xz.extracted/0/etc/passwd → etc/passwd`。
_Avoid_: 相对路径(带嵌套前缀的是物理相对路径)

**镜像分区 (disk-image partition)**:
磁盘镜像(GPT/MBR)解析出的分区(APP/rootfs/bootloader/recovery 等),Step0 按名字+大小推断 kind,每个分区独立子工作区跑完整流水线。分区字段含 offset/size/type/kind/crc_ok 等(`step0_split_img.py`)。
_Avoid_: 分区表(那是解析对象不是产物), 镜像文件

### 执行语义

**失败不崩 (fail-soft)**:
项目铁律:任何步骤失败降级兜底、继续往下跑、记录失败原因,不中断整体流程。在 Agent 层体现为工具返回 ok=False 与工具级降级。
_Avoid_: 容错(太泛), 优雅降级(只有工具级,Agent 层无规则降级)

**无 key 立即终止 (no-key hard stop)**:
Step5 在无 API key 或 API 调用失败时抛 `LLMError` 立即终止,不产出降级工件、不执行规则模式。注意:这与 tools_summary 部分旧文档"降级纯规则"的表述**不一致**——以代码为准。
_Avoid_: 降级, 规则模式(Step5 已无规则模式)

**同参空转 (same-call spin)**:
ReAct 循环里同一工具+完全相同参数被调用超过 `MAX_REPEAT_CALLS`(3)次,循环守卫拦截不再执行,注入干预 Observation(改参数/换工具/收尾)。
_Avoid_: 卡死, 死循环(系统会拦截)

**零工具 Final 拒绝 (no-tool final reject)**:
ReAct 循环从未调用任何工具就输出 Final Answer → 拒绝退回,要求先用至少一个工具查证(上限 `MAX_NO_TOOL_REJECTS`=1,强制收尾轮不设此门槛)。
_Avoid_: 强制收尾(那是另一码事)

**强制收尾 (forced final)**:
ReAct 循环到迭代上限仍未给 Final Answer 时,注入强制收尾指令,给最后一次机会输出含执行总结的 Final Answer;收尾仍失败则截取最后 2000 字符当 best-effort 答案。
_Avoid_: 收尾, 强制结束

**证据纪律 (evidence discipline)**:
Agent 判定规则:每条 finding 的 evidence/addr/cve 必须逐字来自某次工具 Observation,禁止编造、拼凑或凭记忆补写;引用未在 Observation 出现过的路径/函数/地址/CVE 视为违规。
_Avoid_: 证据要求, 引用规范

### 边界与约束

**路径白名单 (path whitelist)**:
Step5 工具(read_file/list_files/读盘类)只能访问 `process/` 工作区之内,越界/`..`/绝对盘符 → ok=False。防 Agent(或被污染的 file_ref)借工具读任意宿主文件。
_Avoid_: 沙箱(那是 sandbox_verify), 权限

**网络隔离 (network isolation)**:
CLI 类工具一律 `--network none` 跑容器;唯一例外是 API 类(cve_lookup/web_search)需要出网。binwalk_rescan 也走 none。

**Docker 容器 (container)**:
Step0-1 的 binwalk 与 Step5 的 CLI 类工具、ghidra_decompile 在容器内执行,宿主机只跑 Python。统一经 `docker_utils.run_docker` 调用(returncode/stdout/stderr,不抛异常,超时返回 124)。唯一例外:Step0 ext4 直读的 debugfs/mount 后端在宿主原生执行(debugfs 用户态读镜像,不进内核;见 ext4 直读)。
_Avoid_: 沙箱(指具体镜像 firm_audit/sandbox), Docker 命令

**沙箱 (sandbox)**:
具体镜像 `firm_audit/sandbox`,ENTRYPOINT 是 Ghidra analyzeHeadless,内置 checksec/r2/cve-bin-tool/semgrep/gitleaks/解释器;调非 Ghidra CLI 必须覆盖 entrypoint。

**引导解包 (guided extraction)**:
Step1 主路径——按文件魔数决策逐层解包(替代 binwalk -Me 盲解,避免 fdt 分解成数十万节点),manifest 落盘支持断点续解。binwalk -Me 仅是兜底。解包路由与 binwalk 签名库的可解集对齐(对齐表 + 漂移守护测试防表落后于镜像能力);binwalk 也解不了的厂商魔数明确终止报"解不了"。大体积无签名文件 finalize 前做一次守卫全偏移复扫(binwalk -e -M,副本递容器原件永存;内核藏 initramfs 型 rootfs 物化,票04)。
_Avoid_: 解包(特指 binwalk -Me), 魔数解包

**预解压 (preprocess)**:
Step0 在 binwalk 之前用宿主标准库解外层压缩/归档/磁盘镜像,避开 binwalk 解压偶发 bug,提升确定性。产物按分流规则决定是否仍需 binwalk。
_Avoid_: 预处理(太泛), 解压

**ext4 直读 (ext4 direct-read)**:
Step0 对磁盘镜像中 ext4 分区(超级块魔数命中)的原生文件树读取——不经 dd+binwalk,直接产出该分区的解包树与 Step1 完成标记,下游零改动。双后端:debugfs(默认,用户态零特权)/ mount(快路,需 root)。取代 2026-09-06 的手工旁路。
_Avoid_: 旁路(指当年手工方案), 挂载(特指 mount 后端)

**不透明固件 (opaque firmware)**:
file 识别不出类型的二进制(unknown/裸 blob)。审计路径结构性存在:无过滤的 list_files 天然看见、strings_query 的 r2 兜底(izz 任意文件)可提取字符串线索、binwalk_rescan 出签名表("无签名"本身是可引用 Observation)。原规则分诊随 Step4 退役(ADR-0011),分诊七类与魔数知识留 git 历史。
_Avoid_: 垃圾文件, 未知格式

**profile**:
固件机型名单文件(`profiles/<name>.yaml`)。ADR-0011 后只剩 `SEARCH_EXCLUDE_DIRS` 一段——Step5 工具(list_files/search_code/semgrep)与简报现场概览消费的 SDK 搜索排除名单;`main.run_pipeline` 经 `file_rules.configure(--profile)` 切换。换机型只需改 profile 不改代码。当前默认 `nano-ubuntu`。
_Avoid_: 配置(与固件 config 文件混淆), 机型

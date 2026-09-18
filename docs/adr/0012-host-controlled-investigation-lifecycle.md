---
status: accepted
---

# 0012-由 Host 控制逐 Candidate 调查生命周期

当前 analysis 把多条疑点放入一次有固定轮数的 Agent 执行,中间假设与缺失证据没有独立生命周期;LLM orchestrator 同时参与阶段结束判断。为支持可恢复的长链调查并降低结论语义混杂,由 Host 接管状态转换、预算、证据引用和最低证据门槛,LLM 只负责语义研判与下一项分析动作。

本 ADR 明确替代 ADR-0001 中由 LLM orchestrator 决定阶段推进、`finish` 和报告事实的条款,ADR-0003 中前 K 项复核、默认 8 轮与 `STEP5_VERIFY_K` 的条款,以及 ADR-0007 中由 LLM 原样生成报告事实的条款。`STEP5_ORCHESTRATOR_MAX_ITERS` 与 `STEP5_VERIFY_K` 随迁移退役;现有 Step5 命令入口和工具层保留,不设旧控制流开关。

目标实现新建 `step5_agent/host/` 作为单一控制边界,内聚调查生命周期、持久化、排队、复核聚合与报告事实生成,并复用现有协议解析、上下文管理、Agent 配置与 tools。现有 `run_agent`/`run_react_agent` 把完整循环和工具执行藏在 engine 内,不能原样复用:它们将被拆成逐步 Agent Session,每次产生 `ActionProposal` 或 `FinalProposal` 后暂停,Host 校验、执行、保存 Evidence 并回传 Observation View。唯一真实 while 循环属于 Host。

实现期可以在分支内先构建新包,但公开入口不暴露双模式;Host 准备完成后,`run_step5` 一次切换并删除旧 `orchestration/`,不保留 shim。

每个 Candidate 对应一个 Investigation。第一版由单个 recon 产生包含覆盖缺口与 Candidate proposals 的攻击面 survey,Host 负责校验、去重并写入统一 Candidate Store;analysis 将成熟调查提交为 Verification Case;verification 独立复核案卷,只有 confirmed 才形成 Finding。Investigator 的主动关闭不产生 verification verdict,未决调查按优先级决定是否送复核。

第一版使用串行 Candidate Queue 和每 Candidate 固定预算,并行与动态追加预算后置。新的 Agent 工件不读取或迁移旧版 `survey.json` / `findings.json` / `verified_findings.json`;旧工作区需要显式重新执行,但现有命令入口与仍适用的环境配置不因此废弃。

第一版 recon 单实例运行,最多 30 轮并允许通过 `STEP5_RECON_MAX_ITERS` 覆盖。Host 为其提供增强的现场概览;recon 使用读盘、元数据、字符串、导入、保护属性与规则扫描等浅层能力,不调用 Ghidra,需要反编译时把动作写入 Candidate proposal 交给 analysis。Host 仅在 survey 明确记录攻击面、Candidate proposals、已检查范围与 coverage gaps 后接受其完成。

Candidate 不要求 recon 已经同时确定 source 与 sink;它可以带空的 possible source/sink,但必须具备明确 target、攻击面信号、初始证据和下一步调查动作。Recon 使用现有现场概览的增强版减少目录枚举轮次,不恢复 ADR-0011 已否决的持久化 Inventory 阶段。

Candidate ID 是运行世代内的递增稳定标识(`cand-0001` 形式),不从可变内容或 fingerprint 派生。signal Candidate 的精确 fingerprint 使用规范化目标路径、位置锚点、Claim Profile 和问题机制;coverage Candidate 使用目标路径、组件或入口和检查目标。目标与 Profile 相同但 fingerprint 不同时才允许一次语义比较;合并后保留 proposal alias,ID 不变。

语义去重的回复值固定为 same / different / uncertain,只有 same 合并;uncertain、无效回复或模型服务失败都保留为独立 Candidate。比较请求与结果进入决策日志并计入 LLM 预算,但不是 Investigation Evidence;新 proposal 在去重完成后才分配 Candidate ID。

有效解包树必须产生至少一个 Candidate。存在具体观察信号时建立 signal Candidate;没有具体信号时从网络解析器、升级处理器、管理接口或其他高价值攻击面中建立 coverage Candidate。coverage Candidate 只要求深度覆盖,不暗示问题成立;解包失败、空树或无有效目标属于输入失败,不强制生成 Candidate。

Investigation 使用共同 Claim 加按问题类型选择的 Claim Profile,不强迫配置、凭据等问题套用 source/sink 模型。Host 在工具返回后立即保存原始 Observation 与 Evidence Reference;下一次正常 LLM 响应同时提交 state delta 和 next action,不增加专门的总结调用。第一版每个 Analysis Investigation 最多 30 轮并允许通过 `STEP5_ANALYSIS_MAX_ITERS` 覆盖,满足完成门槛或触发无进展规则时提前停止。

第一版 Claim Profile 固定为数据传播、配置、凭据处理与内存处理四类,另提供只能组合预定义 Claim 的受限 `generic` Profile。共同 Claim 中,目标存在、根因成立、触发或暴露关系成立及确有实际影响是决定性必填项;前置条件与缓解因素是非决定性必填项,可以 `not_applicable`。数据传播型额外要求输入来源、关键处理关系与到达高影响操作;配置型要求配置值真实生效及作用范围;凭据处理型要求材料有效、访问边界与实际使用关系;内存处理型要求输入或索引可控、边界条件缺失与相关操作可达。各 Profile 的上述额外项均是决定性 Claim;`generic` 只使用共同 Claim。决定性 Claim 被反驳则 rejected,非决定性 Claim 变化只修正条件或 severity。不允许 LLM 自由增加 schema 字段;新增 Profile 需显式升级 schema。

Investigation 同一时刻最多保存一个可为空的 working hypothesis,用于说明当前解释和下一项动作的理由;旧假设以 supported/refuted/replaced 结果进入简短历史。它不增加 Agent,也不替代 Candidate 或最终 Claim。

Investigation 的 `lifecycle_status` 仅表示 queued / investigating / ready_for_verification / verifying / finished 进度;`disposition` 仅在结束时表示 confirmed / rejected / inconclusive / closed / unresolved / not_started;`stop_reason` 独立记录 completed / decisive_refutation / budget_exhausted / no_progress / input_failure 等原因。服务临时中断不产生终态,保留当前 lifecycle_status 恢复;案例总预算耗尽时,尚未处理项可从 queued 直接到 finished,且 disposition=not_started。

Claim 状态为 unassessed/supported/refuted/not_applicable。Host 仅在所选 Claim Profile 的必填项都有状态、支撑项引用真实证据、反证已处理且没有 blocking missing evidence 时接受 ready_for_verification。未达到该门槛的高优先级未决调查可以 admission reason=`evidence_gap` 单独进入补证复核,案卷必须冻结待验证 Claim、已有引用和缺失项;它不伪装成 ready_for_verification。二进制分析优先复用已有边车;没有边车时先以低成本工具收窄目标,语义仍不足再按需调用 Ghidra。连续 5 个已完成动作没有新增非重复证据、Claim/工作假设变化、路径节点或缺失证据消解时,以 no_progress 停止。

每个 Verification Case 使用独立上下文,默认最多 15 轮并允许通过 `STEP5_VERIFICATION_MAX_ITERS` 覆盖。Verifier 可独立使用与 analysis 同类的读盘、搜索、r2 和按需 Ghidra 工具,但不接收 analysis 的 verdict/severity/confidence/结论性 rationale;已有 Evidence Reference 只作为重新取得原始材料的入口。工具不可用使相关 Claim unresolved,不能作为反证;behavior model 只作辅助。

Agent Session 每轮使用纯 JSON 文本协议,不依赖供应商 function calling:顶层字段是简短 `decision_summary`、`state_delta` 和唯一 `next`;`next.kind` 只允许 tool_action / complete_survey / submit_case / close_investigation / complete_verification。Related Candidate proposal 位于 state_delta。Host 对完整回复校验通过后才执行任何动作或状态变化,不应用局部有效字段,也不要求模型输出完整思维过程。

协议回复无法解析或 schema 校验失败时,Host 将字段路径、期望类型与允许值回馈给同一 Agent Session,要求从头生成整份 JSON,不接受局部补丁。首次无效后最多重新生成两次,每次计入 LLM 轮次与 token 总额,但不计入工具调用或 no_progress;无效回复只进 Transcript,不改变 Investigation State。三次均无效时:recon 以 input_failure 结束本次运行;analysis 将当前 Investigation 标记为 unresolved/protocol_error 并继续下一项;verification 将当前案卷标记为 inconclusive/protocol_error,不生成 Finding。模型服务中断不属于无效回复,按运行恢复规则处理。

Verification Case 在提交时冻结。Verifier 逐项输出 Claim Result 与本次取得的证据,不修改原案卷;同一案卷内的问题反映在 Claim Result,只有独立入口、处理位置或问题机制才提出 Related Candidate。Host 对 ready 与 evidence_gap 两类案卷使用同一聚合规则:全部必填 Claim 被 Verifier 以本次独立取得的证据支持才 confirmed,任一决定性 Claim refuted 则 rejected,其余为 inconclusive;工具不可用只能得到 unresolved,不能作为反证。所有 ready_for_verification 案卷均复核,剩余预算再用于高优先级未决调查;复核后仍 inconclusive 的案卷第一版不自动返回 analysis。

每个复核目录保存冻结案卷、独立检查计划、Claim Results、Evidence References、Transcript、verdict 与限制说明。confirmed 后由 Verifier 给出结构化影响和前置条件,Host 以固定规则生成初始 severity。

Investigation Store 同时保存追加式 `events.jsonl` 与最新 `state.json` 投影。事件是权威历史,每条含连续 seq;快照记录 last_event_seq,恢复时重放其后事件。日志最后一行若因中断而不完整,先保存异常尾部并记录恢复告警,再从最后一条完整事件继续;中间事件损坏则不得自动跳过。

每次工具调用分配独立的运行内递增 Evidence ID(`ev-000001` 形式),即使返回内容相同也不合并;原文 SHA-256 只用于完整性校验。Evidence Reference 至少记录工具名、规范化参数、原文位置、摘要、digest、所属 Investigation 与产生顺序;Claim 只保存 Evidence ID。Host 保存上下文截断前的完整 `ToolResult` 文本与结构化数据;原文写入后不可修改。大型或二进制产物由工具单独落盘,Evidence Reference 只保存路径、大小与 digest;不自动收集无界容器输出。送入 Agent 的 Observation View 可以截断但保留原始字面值,不是权威证据存储。报告默认只展示敏感值的类型、位置、长度与 digest 前缀,不展开原值。

工具逻辑调用在执行前先追加带 `call_id` 的 tool_started,原始 Observation 完整落盘后再追加 tool_finished。恢复时遇到只有 started 的调用:只读幂等工具使用同一 call_id 重试;ghidra_decompile 先校验完整缓存与 digest,可接纳则不再执行,否则幂等重试;不可自动重放的工具标记 interrupted。工具注册元数据必须声明 replay_policy。Evidence ID 对应逻辑调用,重试只增加 attempt 事件,不分配新 Evidence ID。

新运行世代的工件根为工作区下 `generations/gen-XXXX/`(票 11 定稿:世代目录即 run_dir,与 process_dir 解耦,机器工件布局零改动;`generations/` 相对公开入口挂载点的定位归票 14 接线),包含 `manifest.json`、`run_state.json`、`candidates.json`、`investigations/<candidate-id>/{state.json,events.jsonl,evidence/}`、`verifications/<candidate-id>/{case.json,results.json}`、`findings.json` 与 `report.md`。每个顶层 JSON 带 `schema_version`,`events.jsonl` 每行带 `event_version`;不兼容版本拒绝静默恢复并引导创建新运行世代。

最终报告的事实部分由 Host 从结构化 Finding、复核案卷、未决调查、coverage gaps、证据引用与运行统计生成。固定章节顺序为:运行摘要与有效配置、Confirmed Findings、Rejected Verification Cases、Inconclusive Cases、未开始 Candidate、Coverage Gaps、Evidence Index、资源使用与停止原因,最后才是可选且明确标注的 Analyst Notes。前八节全由 Host 生成;LLM 说明缺失时不影响报告完成,也不能覆盖结构化事实。

第一版 severity 的触发条件轴为特殊条件/有限条件/宽松条件,影响范围轴为仅加固建议/局部对象或单一功能/完整组件或关键服务/系统级或信任边界。对应矩阵依次为:`info/info/low`,`low/low/medium`,`medium/medium/high`,`high/high/critical`。已证实的缓解因素使触发条件左移一档;若完全阻断实际影响,则反驳决定性 Claim,而不是只降 severity。关键字段缺失时不得给出 critical,人工调整必须保留理由;标准化评分后置。

第一版审计流程只支持 blind discovery:Agent 不使用 cve-bin-tool、公开问题查询、版本到问题映射或 Benchmark Ground Truth;现有通用文件、代码、二进制与受控验证工具继续复用。Benchmark 使用双根目录:公开案例根只含输入、运行 profile 与无答案元数据;独立 Ground Truth 根位于 Agent 工具访问边界之外,其路径不进入 Step5 启动参数、简报、环境快照或 Agent 工作区。Evaluator 在运行结果冻结后单独接收两个根目录,统计重发现、路径完整度、证据可复查性、错误结论、未决调查和资源消耗。首批选择 5–10 个标注完整案例,可先以 3 个完成端到端验证。

Blind Discovery 工具权限固定为:recon 可用 list_files/read_file/search_code/strings_query/imports_query/checksec/semgrep_scan/gitleaks_scan/binwalk_rescan;analysis 和 verification 在此基础上增加 find_decompiled_function、r2 工具族、ghidra_decompile 与 sandbox_verify,且 verification 使用独立上下文。cve_bin_tool_scan/cve_lookup/web_search 对全部三个角色禁用,Blind Discovery 启动不做 CVE 缓存预检。recon 不直接调用 r2 工具族或 Ghidra;strings_query/imports_query 内部的低成本读取不改变其广度职责。

Benchmark 不要求 Agent 输出公开编号,也不以路径、函数名或描述文本完全相同作为判据。Evaluator 先规范化路径、地址、组件和函数别名,只生成 Ground Truth 到 Finding/Investigation 的候选对应,不在此阶段判断 full/partial/miss。运行封存后,由用户启动 Codex 读取 Ground Truth、Finding、inconclusive/closed Investigation、Verification Case、Evidence Reference 与候选对应,按固定量表做字段级语义裁定。

Codex 分别判断根因或问题机制、输入入口或触发条件、关键处理关系、实际影响与机器结论。根因和关键处理关系语义一致、影响对应且有 confirmed Finding 为 full;能确认调查同一问题,但链路、影响或最终确认仍有缺口为 partial,inconclusive Investigation 可进入该类;无可信对应 Investigation 为 miss。每个 Ground Truth 只选一个 primary match,重复报告不重复计分。

Ground Truth 未覆盖的 confirmed Finding 标为 unmatched,由 Codex 进一步分为 novel_valid / unsupported / uncertain。无法确定的对应可输出 uncertain,暂不进入确定指标,不强制猜测。Codex 产出结构化 `evaluation_review.json`,保存字段级判断、Ground Truth 字段引用、Finding/Investigation ID、理由、模型版本、固定评审提示与输入 digest。每个案例同时受 Agent 级与案例级总预算约束;具体预算值来自运行配置并写入结果快照。

正式实验预算保存在版本化 Benchmark profile,`.env` 只作本机覆盖,Host 将最终生效配置写入每次运行的配置快照。第一版暂定单案例最多 8 个 Candidate、400 次 LLM 轮次、320 次工具调用和 7200 秒;这些是实现与前三例试运行的初始上限,不是已经完成的 Benchmark 结果。

预算按真实消耗计数:每次模型请求都计入 llm_calls,包括协议重新生成、上下文压缩和中断后的重新请求;另记 validated_rounds。工具每次真实执行均计入 tool_attempts,另记 logical_tool_calls。token 全量累计,7200 秒只计活动执行时间,不包含关机或等待恢复的间隔;no_progress 只计成功完成的语义动作。

配置优先级为显式运行参数、`.env` 本机覆盖、版本化 profile、代码默认值,最终生效值必须进入运行快照。案例总预算耗尽时保存当前 Investigation,尚未开始的 Candidate 标为 not_started,不得计作已检查。单个工具失败作为 Observation 留存并允许 Agent 选择替代方法;模型服务中断则保存运行现场并结束本次执行,恢复后继续,不生成替代结论。

Candidate Queue 分为 signal 与 coverage 两队。单案例默认 8 个处理名额中为最高优先级 coverage Candidate 保留 1 个,没有 coverage Candidate 时该名额自动归还 signal 队列。signal 分数=外部可达性+输入可控性+高影响操作+路径进展+材料强度-预计成本;coverage 分数=组件价值+外部暴露程度+尚未检查程度-预计成本。各项只取 0/1/2,缺少依据时取 0;LLM 只提交分项判断与依据,Host 计算总分,同分按创建顺序。本次 Candidate 上限只限制实际处理数量,所有 proposal 仍进入 Candidate Store,超出上限者标为 not_started。

每个工作区同一时刻只有一个活动运行。重新启动时,Host 默认从 `run_state` 恢复正在处理的 Investigation,随后继续 Candidate Queue;已完成的运行世代保持只读,开始新审计需显式创建新运行世代。现有 `--force` 作为“创建新运行世代”的兼容入口,不再就地覆盖已有记录。

运行仅在所有 proposal 已进入 Candidate Store、已选 Investigation 均有 disposition、未选项均标记 not_started、所有 ready 案卷已复核、Host 事实报告与 manifest 工件 digest 已生成后才封存为 completed。确定性报告或 manifest 生成失败时保持 finalizing,下次恢复继续;Analyst Notes 失败不阻止封存。封存后机器工件不可修改。

人工或 Codex 复核不直接编辑封存工件,而是追加独立 `review.jsonl` 覆盖层,记录 reviewer、时间、目标字段、原值、新值、理由与 Evidence Reference。报告展示 machine result 与 reviewed result;Benchmark 默认统计原始 machine result,复核后结果单独统计。

事件与原始 Observation 先持久化,再用临时文件原子替换状态快照,使恢复时最多重放已存在事件,不会引用未落盘证据。活动运行锁记录进程身份与开始时间;只有确认原持有进程已不活动时才能接管遗留锁。

恢复 Agent Session 时不重放完整 Transcript。Host 仅从固定系统提示、当前 Investigation State、相关 Evidence 摘要与引用、最近一个已完成动作及 Observation View、剩余预算重建上下文。模型请求已发出但回复未持久化时,从同一快照重新请求;回复已持久化且校验通过时,按事件继续,不重复决策。

Related Candidate 只继承相关 Investigation State、Evidence References 与来源关系,不复制旧 LLM 聊天记录。Candidate Store 先以确定性 fingerprint 合并精确重复,模糊项再做一次语义比较,且已分配的 Candidate ID 不随信息补充而改变。Claim Result 逐项保存评价、实际观察、复核证据、验证方法与限制。Verification 默认沿用主模型,允许用 `STEP5_VERIFICATION_MODEL` 单独覆盖。

## 2026-09-16 接缝评审后的确认

用户确认以下四项决定；实施与公开接线验收由票 14 承接，票 02/09/10 保留来源记录。

1. **边车读取权限**：`find_decompiled_function` 授权给 analysis 和 verification，Recon 权限保持原清单。该工具读取已有反编译边车，不发起 Ghidra；工具描述、Observation 指引与实际角色权限保持一致。
2. **预算耗尽与复核结论**：Verification 因预算耗尽收束时仍按已持久化 Claim Result 聚合；必填 Claim 满足本次独立证据支持门槛时允许 `confirmed`，并记录 `stop_reason=budget_exhausted`，不要求额外收到 `complete_verification`。决定性反证仍为 rejected，其余未满足门槛者为 inconclusive；`protocol_error` 保持无条件 inconclusive，不生成 Finding。结论与停止原因分别表达证据判断和执行过程。
3. **上下文压缩**：由 Host 显式检查并触发上下文压缩，压缩请求进入运行预算、token/活动时间统计与 Transcript；Agent Session 的 `step` 保持一次模型请求的契约。压缩只能改变模型上下文，不改写权威 Investigation State、原始 Evidence 或已保存 Transcript。公开入口切换前完成接线，不能把额外 LLM 请求隐藏在 Session 内。
4. **独立检查计划**：Host 根据冻结 Verification Case 形成并持久化逐 Claim 检查清单和证据入口，Verifier 在正常响应中表达并执行下一步检查，不增加专门规划 LLM 轮次。计划继承案卷的上下文隔离要求，原 Evidence 只用于重新定位；恢复时能读取既有计划。只有案卷摘要的 brief 不视为已交付检查计划。

## 2026-09-18 实现期语义确认（票 12）

用户确认 severity 矩阵在 ADR 未定义处的两条补白规则；实现为 `host/severity.py`，工单 12 保留来源记录。

1. **关键信息缺失按最重档代入**：结构化 facet 缺失时，影响范围按"系统级或信任边界"、触发条件按"宽松"代入矩阵计算，计算后仍封顶不得 critical——未知信息不降低严重度，但最高档必须建立在完整事实之上（承接 L59 的"关键字段缺失时不得给出 critical"）。
2. **前置条件不适用即宽松触发**：`preconditions` 判 `not_applicable` 视为"无前置条件"，按宽松触发计且属完整信息，不算缺失。

## 代价与影响

- 当前 LLM orchestrator 在迁移期间只作为兼容入口,不再拥有 finish、阶段跳转或 confirmed 接受权。
- `finding` 从“analysis 候选容器条目”收窄为 verification 确认后的最终安全问题。
- 结果模型分别表达生命周期、停止原因、verification verdict、验证方法和证据完备度。
- 串行实现先验证调查语义;并行只能在 Investigation 隔离、证据写入和工具缓存具备并发安全后单独引入。

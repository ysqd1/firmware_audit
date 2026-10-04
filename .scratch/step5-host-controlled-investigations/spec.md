# Spec: Step5 Host 控制的逐 Candidate 调查生命周期

Status: ready-for-agent
日期: 2026-09-12
规则出处: ADR-0012（由 Host 控制逐 Candidate 调查生命周期）是本 spec 的单一架构规则出处；若本文与 ADR 冲突，以 ADR 为准。术语口径见 CONTEXT.md。

## Problem Statement

当前 Step5 把侦察、分析、复核和事实报告的大量控制权放在 LLM orchestrator 内：一次 Agent 循环同时承载多条疑点，固定轮数和 top-K 决定调查深度，工具执行藏在 ReAct engine 内，中间假设、Claim、证据缺口和停止原因没有独立而稳定的生命周期。结果是 Host 无法可靠判断“调查到了哪一步、为什么停止、哪些结论有独立证据”，也难以在模型回复无效、工具进程中断或宿主进程重启后从精确边界恢复。

现有 `survey.json`、`findings.json`、`verified_findings.json` 还混用了 Candidate、待复核结论和最终 Finding 的语义。analysis 的措辞可能提前变成事实，verification 只复核前 K 项，报告事实又由 LLM 自由生成，因此审计结果、覆盖缺口、资源消耗和机器结论不能由确定性状态完整重建。这个问题无法通过继续增加提示词或提高循环上限解决，需要把控制面、持久化和结论聚合整体移回 Host。

## Solution

将 Step5 重构为由 Host 驱动的串行调查系统。Recon 只负责形成攻击面 survey、Candidate proposals、检查范围和 coverage gaps；Host 校验并去重 Candidate，为每个入选 Candidate 建立独立 Investigation；Analysis Agent Session 每轮只提交结构化状态增量和一个下一动作；Host 完整校验后才执行工具、持久化 Evidence、推进状态和预算；成熟案卷被冻结为 Verification Case，由独立 Verification Agent Session 重新取证。只有 Host 按固定 Claim 聚合规则判为 confirmed 的案卷才成为 Finding。

Host 同时负责 Candidate 排队、生命周期合法性、Evidence 身份、工具重放策略、事件与快照事务、恢复、预算、no-progress、severity、事实报告、运行封存和复核覆盖层。LLM 保留语义研判、工作假设、分项依据和下一动作提议，但不再拥有阶段跳转、工具执行、最终事实或 confirmed 接受权。

迁移采用一次公开切换：内部完成 Host 后，将现有 Step5 入口直接接到新控制流并删除旧 orchestration，不提供双模式、兼容 shim 或旧行为开关。旧版三种结果工件不迁移也不读取；需要新语义的旧工作区显式创建新运行世代重新执行。

## User Stories

1. As an 审计运行者, I want 继续使用现有 Step5 命令入口, so that 架构重构不迫使我学习另一套启动方式。
2. As an 审计运行者, I want 每次执行有独立且递增的运行世代, so that 新审计不会覆盖旧结果。
3. As an 审计运行者, I want 默认恢复未完成运行, so that 宿主或模型服务中断后可以继续而不是重跑全部工作。
4. As an 审计运行者, I want 已完成运行保持只读, so that 可复查结果不会被后续执行悄悄改变。
5. As an 审计运行者, I want `--force` 创建新运行世代而非原地覆盖, so that 兼容现有操作习惯同时保留审计历史。
6. As an 审计工程师, I want Host 成为唯一真实控制循环, so that 生命周期、预算、工具副作用和完成条件都由可测试代码决定。
7. As an 审计工程师, I want LLM 每轮只提出状态增量和一个下一动作, so that 模型不能绕过 Host 连续执行或隐式推进阶段。
8. As an 审计工程师, I want Host 在任何副作用前校验完整模型回复, so that 局部有效的无效 JSON 不会污染状态。
9. As an 审计工程师, I want Candidate、Investigation、Verification Case 和 Finding 各自有单一含义, so that “线索”“调查”“案卷”和“已确认问题”不再混用。
10. As a recon Agent, I want 获得增强的现场概览和浅层审计工具, so that 我能在有限轮次内铺开攻击面。
11. As a recon Agent, I want 不被授权直接调用 r2 或 Ghidra, so that 广度侦察不会滑向高成本深挖。
12. As a recon Agent, I want 提交已检查范围和 coverage gaps, so that 没发现具体信号也能留下可量化覆盖信息。
13. As a Host, I want 只接受包含攻击面、Candidate proposals、检查范围和 coverage gaps 的完整 survey, so that recon 完成不是一句没有结构的总结。
14. As a Host, I want 有效解包树至少产生一个 Candidate, so that 高价值但未深入的入口不会静默消失。
15. As a Host, I want 在观察到具体信号时创建 signal Candidate, so that 可疑线索进入基于证据的调查队列。
16. As a Host, I want 在没有具体信号时从高价值未检查面创建 coverage Candidate, so that 深度覆盖需求不会被误写成漏洞结论。
17. As an 审计运行者, I want 解包失败、空树或没有有效目标明确成为 input failure, so that 无效输入不会被强行包装成 Candidate。
18. As a recon Agent, I want Candidate 可以暂时缺少 source 或 sink, so that 早期线索不因信息尚不完整而丢失。
19. As a Host, I want 每个 Candidate 至少包含明确 target、攻击面信号、初始 Evidence 和下一步动作, so that Investigation 有可执行起点。
20. As a Host, I want signal 与 coverage Candidate 使用不同的确定性 fingerprint, so that 精确重复可按各自语义可靠合并。
21. As a Host, I want 只对相同 target 和 Claim Profile 的模糊重复请求一次语义比较, so that 去重成本受控且不跨问题类型误合并。
22. As a Host, I want 语义去重只接受 same、different 或 uncertain, so that 合并决策没有模糊自由文本。
23. As a Host, I want 只有 same 才合并 Candidate, so that uncertain、协议无效或模型故障不会吞掉真实线索。
24. As an 审计复查者, I want 被合并 proposal 的 alias 和去重决定保留下来, so that 我能追溯 Candidate 的所有来源。
25. As a Host, I want 在去重完成后才分配递增的 `cand-xxxx` 标识, so that ID 在运行世代内稳定且不依赖可变内容。
26. As an 审计运行者, I want signal 和 coverage 使用独立队列, so that 明确信号与覆盖责任都能得到处理。
27. As an 审计运行者, I want 默认处理名额为八个并为最高优先级 coverage Candidate 保留一个名额, so that 线索密集时仍不会完全放弃攻击面覆盖。
28. As an 审计运行者, I want 没有 coverage Candidate 时保留名额自动归还 signal 队列, so that 处理能力不会闲置。
29. As a Host, I want LLM 只提交优先级分项和依据而由 Host 算总分, so that 排序结果确定且可重放。
30. As an 审计复查者, I want 每个优先级因子只取 0、1、2 且缺证据为 0, so that 分数有统一且可解释的尺度。
31. As a Host, I want signal 分数反映可达性、可控输入、高影响操作、路径进展、证据强度和成本, so that 最值得深挖的信号先处理。
32. As a Host, I want coverage 分数反映组件价值、暴露程度、未检查程度和成本, so that 覆盖名额用于最有价值的未知面。
33. As a Host, I want 同分 Candidate 按创建顺序处理, so that 相同输入得到稳定队列顺序。
34. As an 审计复查者, I want 所有 proposal 都进入 Candidate Store, so that 超出上限的 Candidate 仍可见并明确标为 not_started。
35. As an analysis Agent, I want 每个 Candidate 拥有独立 Investigation 和上下文, so that 不同问题的假设、证据和预算不会互相污染。
36. As an analysis Agent, I want Investigation 同时最多保存一个 working hypothesis, so that 当前解释和下一动作理由保持聚焦。
37. As an 审计复查者, I want 旧假设以 supported、refuted 或 replaced 进入简短历史, so that 推理变化可以追溯而无需保存完整思维过程。
38. As an analysis Agent, I want 选择数据传播、配置、凭据处理、内存处理或受限 generic Claim Profile, so that 不同问题类型使用合适的证据门槛。
39. As a Host, I want generic Profile 只能组合预定义共同 Claim, so that 模型不能自由扩张 schema。
40. As a Host, I want 新增 Claim Profile 必须显式升级 schema, so that 已封存运行的含义保持稳定。
41. As an 审计复查者, I want 每个 Investigation 都判断目标存在、根因、触发或暴露关系和实际影响, so that 决定性结论具备共同最小链条。
42. As an 审计复查者, I want 前置条件和缓解因素也被明确检查且允许 not_applicable, so that severity 和适用范围有证据依据。
43. As an 审计复查者, I want 数据传播问题额外覆盖输入来源、关键处理关系和高影响操作可达性, so that source-to-sink 链条不是一句结论。
44. As an 审计复查者, I want 配置问题额外覆盖有效值和作用范围, so that 静态配置文本不会被误认为运行时事实。
45. As an 审计复查者, I want 凭据问题额外覆盖材料有效性、访问边界和实际使用, so that 仅出现疑似字符串不会直接成为 Finding。
46. As an 审计复查者, I want 内存问题额外覆盖输入或索引可控、边界缺失和相关操作可达, so that 危险函数名本身不等于可触发问题。
47. As a Host, I want Claim 状态限定为 unassessed、supported、refuted 和 not_applicable, so that 聚合规则无需解释任意措辞。
48. As a Host, I want supported Claim 必须引用真实 Evidence ID, so that 结论不能只由 LLM 自述支撑。
49. As a Host, I want ready gate 检查必填 Claim、反证处理和 blocking gap, so that 不完整调查不能伪装成成熟案卷。
50. As an analysis Agent, I want 可以主动 close Investigation 而不制造 verification verdict, so that 无法继续的调查与“已证伪”保持区别。
51. As a Host, I want 高优先级未决 Investigation 可以用 evidence_gap 原因进入复核, so that 独立验证者有机会补足关键材料。
52. As an 审计复查者, I want evidence-gap 案卷冻结待验证 Claim、已有引用和缺失项, so that 它不会被误写成 ready 案卷。
53. As a Host, I want 连续五个已完成语义动作无任何有效进展时停止当前调查, so that Agent 不会在同一死路上耗尽案例预算。
54. As an analysis Agent, I want 新的非重复 Evidence、Claim 变化、假设变化、路径节点或 gap 消解都算进展, so that no-progress 不会惩罚真实推进。
55. As a Host, I want 协议重生成和失败请求不计 no-progress, so that 格式纠错不会被误认为调查停滞。
56. As an 审计复查者, I want lifecycle_status、disposition 和 stop_reason 分开记录, so that “进行到哪一步”“最终怎样”“为何停止”不会混成一个枚举。
57. As a Host, I want lifecycle_status 只使用 queued、investigating、ready_for_verification、verifying 和 finished, so that 生命周期转换可以完整验证。
58. As a Host, I want disposition 只在结束时表达 confirmed、rejected、inconclusive、closed、unresolved 或 not_started, so that 中间状态不会提前承诺结果。
59. As an 审计运行者, I want 服务临时中断不产生终态, so that 恢复后能从原 lifecycle_status 继续。
60. As an 审计运行者, I want 案例总预算耗尽时未处理 Candidate 明确成为 not_started, so that 它们不会被误计为已经检查。
61. As a verification Agent, I want 每个 Verification Case 使用独立上下文和独立预算, so that 复核不是 analysis 对话的延续。
62. As a verification Agent, I want 可使用 analysis 同类的读盘、搜索、r2、按需 Ghidra 和受控验证工具, so that 我能独立重新取得事实。
63. As a verification Agent, I want 不接收 analysis 的 verdict、severity、confidence 或说服性结论, so that 复核不会被原判断锚定。
64. As a verification Agent, I want Evidence Reference 只作为重新定位原始材料的入口, so that 我必须用自己的工具调用形成 Verification Evidence。
65. As a Host, I want 所有 ready 案卷均进入 verification, so that 不再由 top-K 丢弃成熟问题。
66. As a Host, I want 仅在 ready 案卷处理后用剩余预算复核高优先级 evidence-gap 案卷, so that 成熟结论优先得到确认。
67. As a verification Agent, I want 逐项输出 Claim Result、实际观察、验证方法、限制和独立 Evidence, so that verdict 可以由 Host 重算。
68. As a Host, I want ready 与 evidence-gap 使用同一聚合规则, so that admission reason 不会降低 confirmed 门槛。
69. As a Host, I want 只有所有必填 Claim 被独立证据支持才 confirmed, so that Finding 始终来自完整复核。
70. As a Host, I want 任一决定性 Claim 被反驳时判 rejected, so that 根因链条断裂不会留下可疑 Finding。
71. As a Host, I want 其余不完整结果判 inconclusive, so that 缺证与证伪保持区别。
72. As a Host, I want 工具不可用只产生 unresolved Claim 而不算反证, so that 环境限制不会制造错误 rejected。
73. As an 审计运行者, I want inconclusive 案卷第一版不自动返回 analysis, so that 控制流和预算保持可预测。
74. As a verification Agent, I want 只在独立入口、处理位置或问题机制出现时提出 Related Candidate, so that 同一案卷内的分支观察不会制造重复 Candidate。
75. As a Host, I want Related Candidate 只继承相关状态、Evidence References 和来源关系, so that 新调查不会复制旧 LLM Transcript。
76. As a Host, I want Agent Session 使用供应商无关的纯 JSON 文本协议, so that 控制面不依赖某一家 function calling 实现。
77. As a Host, I want 每轮回复顶层只含简短 decision_summary、state_delta 和唯一 next, so that 协议既保留语义依据又不要求完整思维过程。
78. As a Host, I want next.kind 限定为 tool_action、complete_survey、submit_case、close_investigation 或 complete_verification, so that 每轮只发生一种受控动作。
79. As a Host, I want 无效回复收到精确字段路径、期望类型和允许枚举提示, so that Agent 能重新生成一份完整合法 JSON。
80. As a Host, I want 首次无效后最多再请求两次, so that 协议纠错有机会成功但不会无限循环。
81. As an 审计复查者, I want 无效回复只留在 Transcript 且没有局部状态效果, so that 可恢复状态始终来自合法事件。
82. As a 预算分析者, I want 每次协议重生成计入 LLM 调用和 token, so that 资源统计反映真实开销。
83. As a Host, I want recon 三次协议失败结束为 input_failure, so that 没有合法 survey 时不会继续虚构后续阶段。
84. As a Host, I want analysis 三次协议失败结束当前 Investigation 为 unresolved/protocol_error 并继续队列, so that 单一坏回复不会阻断整个案例。
85. As a Host, I want verification 三次协议失败形成 inconclusive/protocol_error 且不生成 Finding, so that 协议故障不会被误判为确认。
86. As an 审计运行者, I want 模型服务中断与协议无效分开处理, so that 临时不可用保留可恢复现场而不是消耗语义终态。
87. As an 审计复查者, I want 每个逻辑工具调用获得独立递增 Evidence ID, so that 即使输出相同也保留不同调查动作的身份。
88. As an 审计复查者, I want SHA-256 只用于完整性而不用于 Evidence 去重, so that digest 相同不会抹掉调用历史。
89. As an 审计复查者, I want Evidence Reference 记录工具、规范化参数、原文位置、摘要、digest、所属 Investigation 和顺序, so that 任何 Claim 都能定位到可校验材料。
90. As a Host, I want 在上下文截断前保存完整且有界的 ToolResult 文本与结构化数据, so that Observation View 的压缩不会损害权威证据。
91. As a Host, I want 大型或二进制产物由工具独立落盘并只引用路径、大小和 digest, so that Evidence Store 不会无界复制容器输出。
92. As an Agent Session, I want Observation View 可以截断但保留原始字面值, so that 后续语义判断看到的值没有被擅自改写。
93. As a 报告读者, I want 报告默认只显示敏感值类型、位置、长度和 digest 前缀, so that 事实可定位但正文不展开原始值。
94. As a Host, I want 工具执行前先持久化带 call_id 的 tool_started, so that 中断后能识别副作用是否可能已经开始。
95. As a Host, I want 原始 Observation 落盘后再写 tool_finished, so that 完成事件永远不会引用不存在的证据。
96. As a Host, I want 只读幂等工具用同一 call_id 恢复重试, so that 重启不会制造新的逻辑调用身份。
97. As a Host, I want Ghidra 恢复时先校验缓存与 digest 再决定接纳或重试, so that 昂贵分析不被无条件重复执行。
98. As a Host, I want 不可重放工具在中断后明确标记 interrupted, so that 未知副作用不会被静默再次执行。
99. As a 工具维护者, I want 每个工具在注册元数据中声明 replay_policy, so that Host 不靠工具名猜测恢复策略。
100. As a 预算分析者, I want 重试增加 tool_attempts 但不增加 logical_tool_calls 或 Evidence ID, so that 逻辑工作量与实际执行成本都可见。
101. As an 审计复查者, I want 每个 Investigation 有追加式权威事件和最新状态投影, so that 历史可审计且当前状态可快速读取。
102. As a Host, I want 事件序号连续且快照记录 last_event_seq, so that 恢复时可以从快照后精确重放。
103. As a Host, I want 先写事件和 Observation 再原子替换快照, so that 崩溃最多导致重放而不会产生悬空引用。
104. As an 审计运行者, I want 末尾不完整事件被隔离并产生恢复告警后继续, so that 常见断电写入不会毁掉整个运行。
105. As an 审计运行者, I want 中间事件损坏阻止自动恢复, so that Host 不会跳过历史空洞后继续产生不可信状态。
106. As an 审计运行者, I want 所有顶层 JSON 和事件带版本, so that 不兼容数据不会被旧或新代码静默误读。
107. As an 审计运行者, I want 不兼容恢复明确引导创建新运行世代, so that schema 升级不需要危险的猜测迁移。
108. As an 审计运行者, I want 同一工作区同时只有一个活动运行, so that 两个 Host 不会交错写入同一审计历史。
109. As a Host, I want 活动锁记录进程身份和开始时间且仅在原进程已不活动时接管, so that 正常长任务不会被误判为 stale。
110. As an Agent Session, I want 恢复时只接收固定系统提示、当前状态、相关证据摘要、最近动作与 Observation View 和剩余预算, so that 不必重放易膨胀且不稳定的完整 Transcript。
111. As a Host, I want 未持久化的模型回复从同一状态快照重新请求, so that 恢复不会假装知道丢失的决策。
112. As a Host, I want 已持久化且校验通过的回复按事件继续而不重复请求, so that 恢复不会重复决策或副作用。
113. As a 预算分析者, I want 每次真实模型请求都计入 llm_calls 并另记 validated_rounds, so that 无效回复、压缩和恢复重请求成本可见。
114. As a 预算分析者, I want 每次真实工具执行都计入 tool_attempts 并另记 logical_tool_calls, so that 重试成本与调查动作数可以区分。
115. As a 预算分析者, I want 累计全部 token 且 active time 排除停机等待, so that 跨日恢复的运行不会被错误计为持续占用执行时间。
116. As an 审计运行者, I want 正式预算来自版本化 Benchmark profile, so that 实验上限可复现而不是只藏在本机环境中。
117. As an 审计运行者, I want 配置按显式参数、本机环境覆盖、版本化 profile、代码默认值依次解析, so that 优先级明确且可预测。
118. As an 审计复查者, I want 最终生效配置完整写入运行快照, so that 结果可以按实际预算和模型配置解释。
119. As an 实验维护者, I want 初始单案例上限为 8 Candidate、400 LLM 请求、320 tool attempts 和 7200 active seconds, so that 前三例端到端试运行有一致起点。
120. As a Host, I want recon、analysis 和 verification 分别有默认 30、30 和 15 轮上限并允许对应配置覆盖, so that 各角色局部预算可控。
121. As a Host, I want 事实报告完全由结构化状态确定生成, so that LLM 文风不能改变机器结论。
122. As a 报告读者, I want 依次看到运行配置、confirmed、rejected、inconclusive、not_started、coverage gaps、Evidence Index 和资源与停止原因, so that 完整结果和未覆盖部分同样显眼。
123. As a 报告读者, I want Analyst Notes 只能作为最后的可选标注段, so that 说明文字不能覆盖前八节机器事实。
124. As a Host, I want Analyst Notes 生成失败不阻止运行封存, so that 可选说明不会让确定性结果处于半完成状态。
125. As a Host, I want severity 由影响范围和触发条件固定矩阵生成, so that confirmed Finding 的初始严重度可重算。
126. As an 审计复查者, I want 已证实缓解因素使触发条件左移一档, so that severity 调整有统一规则。
127. As an 审计复查者, I want 完全阻断实际影响的缓解因素反驳决定性 Claim, so that 被阻断问题不会只靠降级继续成为 Finding。
128. As a Host, I want 关键字段缺失时禁止 critical, so that 最高等级必须建立在完整事实之上。
129. As an 人工复核者, I want severity 人工调整保留理由, so that reviewed result 不会覆盖机器规则而无痕迹。
130. As an 审计运行者, I want 只有所有 proposal 入库、入选调查有 disposition、未选项为 not_started、ready 案卷已复核且报告与 manifest digest 已生成后才能 completed, so that 封存代表真正完整的机器运行。
131. As an 审计运行者, I want 报告或 manifest 生成失败时停留 finalizing 并可恢复, so that 半成品不会被标记 completed。
132. As an 审计复查者, I want 封存后的机器工件不可修改, so that Benchmark 和复核始终有稳定基线。
133. As an 人工或 Codex 复核者, I want 通过追加 review overlay 修正字段而非编辑机器工件, so that 原结果和复核结果可以同时追溯。
134. As an 审计复查者, I want review 记录 reviewer、时间、字段、旧值、新值、理由和 Evidence Reference, so that 每项改动都有责任与依据。
135. As a 报告读者, I want 同时看到 machine result 与 reviewed result, so that 人工判断不会伪装成原始 Agent 输出。
136. As a Benchmark 维护者, I want 默认指标使用 machine result 并单列 reviewed result, so that 自动系统能力和后续复核价值不会混算。
137. As a Benchmark 维护者, I want Blind Discovery 的公开案例根只含输入、profile 和无答案元数据, so that Agent 无法从案例目录读取答案。
138. As a Benchmark 维护者, I want Ground Truth 根位于 Agent 工具边界之外且不进入参数、提示、快照或工作区, so that 评测不存在答案泄漏。
139. As a Benchmark 维护者, I want recon、analysis、verification 均禁用 CVE 扫描、公开问题查询和 web search, so that Benchmark 测量的是盲发现能力。
140. As a Benchmark 维护者, I want Blind Discovery 启动不做 CVE 缓存预检, so that 禁用的知识源不会通过前置步骤侧漏。
141. As an analysis or verification Agent, I want 保留通用文件、代码、二进制和受控验证工具, so that 盲发现仍能完成实质性取证。
142. As a Benchmark Evaluator, I want 在运行封存后才同时读取结果和 Ground Truth, so that 评估不会影响 Agent 决策。
143. As a Benchmark Evaluator, I want 确定性程序只规范化路径、地址、组件和函数别名并生成候选映射, so that 最终语义标签不会被脆弱字符串相等决定。
144. As a Benchmark 维护者, I want 用户显式启动 Codex 完成语义裁定, so that 人工可控的评审步骤处理不可完全相同的表述。
145. As a Codex reviewer, I want 同时读取 Ground Truth、Findings、inconclusive/closed Investigations、Verification Cases、Evidence References 和 Candidates, so that partial 与 miss 的判断不只看最终报告。
146. As a Codex reviewer, I want 分别判断根因或机制、输入或触发、关键关系、实际影响和机器 disposition, so that 语义对应有字段级依据。
147. As a Benchmark 维护者, I want full 要求语义一致的根因、关键关系和影响且存在 confirmed Finding, so that 完整重发现具有严格含义。
148. As a Benchmark 维护者, I want 同一问题但链路、影响或最终确认缺失时可判 partial, so that 有价值的未决调查不会一律算 miss。
149. As a Benchmark 维护者, I want 没有可信 Investigation 对应时判 miss, so that 仅靠含糊关键词不能获得发现分。
150. As a Benchmark 维护者, I want 每个 Ground Truth 只选择一个 primary match, so that 重复报告不会重复计分。
151. As a Benchmark 维护者, I want Ground Truth 外的 confirmed Finding 被分为 novel_valid、unsupported 或 uncertain, so that 新发现与错误结论可以区分。
152. As a Benchmark 维护者, I want uncertain 暂不进入确定指标, so that 评审者无需在证据不足时强制猜测。
153. As an 实验复查者, I want 评估产物保存字段判断、双方引用、理由、模型版本、固定提示和输入 digest, so that Codex 语义评审可审计和重跑。
154. As a Benchmark 维护者, I want 首批从 5–10 个标注完整案例中先用 3 个跑通端到端, so that 架构和评估闭环能在扩大实验前得到验证。
155. As a 维护者, I want 旧 LLM orchestrator、top-K、旧轮数变量和 LLM 事实报告一次性退役, so that 系统不会长期维护两套互相矛盾的控制语义。
156. As a 维护者, I want 旧三种结果工件既不迁移也不读取, so that 新 Host 不必猜测旧数据缺失的生命周期和证据语义。
157. As a 维护者, I want 新 Host 可在内部逐步构建但公开入口只切换一次, so that 开发可分阶段而用户不会遇到双模式。
158. As a 维护者, I want 切换后删除旧 orchestration 且不留 shim, so that 后续修改只有一个控制边界。

## Implementation Decisions

- ADR-0012 是实现规则的单一来源；本 spec 负责把已确认设计转成验收范围，不重新定义与 ADR 冲突的替代语义。
- 建立内聚的 Host 模块，统一承载 Candidate 接收与去重、队列与优先级、Investigation 生命周期、Claim 门槛、Verification 聚合、预算、恢复、severity、事实报告和运行封存。公开 Step5 入口只调用该 Host。
- 将现有隐藏完整循环与工具执行的 Agent engine 拆为逐步 Agent Session。每次调用只返回 ActionProposal 或 FinalProposal；Host 是唯一调用工具并决定后续迭代的组件。
- Agent Session 采用纯 JSON 文本协议。顶层为简短 `decision_summary`、`state_delta` 与唯一 `next`；相关 Candidate proposal 属于状态增量；协议不要求、存储或展示完整思维过程。
- `next.kind` 按角色限制为 tool action、survey completion、case submission、investigation close 或 verification completion。Host 先校验整份回复，再应用任何状态变化或副作用。
- 无效回复要求整份重新生成，Host 返回字段路径、类型和枚举错误；首次失败后最多再请求两次。无效文本只进入 Transcript。三次失败按 recon input failure、analysis unresolved protocol error、verification inconclusive protocol error 分别收束。模型服务中断保留可恢复状态，不走协议失败分支。
- Recon 保持单实例、默认最多 30 轮，只使用文件读取、搜索、字符串、导入、保护属性、规则扫描和重新解包等浅层工具。它必须产出攻击面、Candidate proposals、已检查范围和 coverage gaps，且不能直接调用 r2 或 Ghidra。
- 有效解包树至少形成一个 Candidate：具体观察形成 signal Candidate，无具体信号时从高价值攻击面形成 coverage Candidate；输入解包失败、空树或无有效目标则记录 input failure。
- Candidate ID 在单一运行世代内按创建顺序递增且稳定。精确 fingerprint 按 signal/coverage 两类分别定义；只有 target 与 Claim Profile 相同而 fingerprint 不同的候选才进入一次语义比较。仅 same 合并，其他结果保留独立 Candidate，并保存 alias 和决策日志。
- Candidate Queue 采用 signal 与 coverage 两队，默认八个实际处理名额并为最高优先级 coverage Candidate 保留一个；不存在 coverage 时归还名额。所有 proposal 均入库，未获名额者在结束时成为 not_started。
- 优先级各因子只取 0/1/2，模型给出分项及 Evidence 依据，Host 计算分数。signal 使用可达性、输入可控性、高影响操作、路径进展、材料强度与预计成本；coverage 使用组件价值、外部暴露、未检查程度与预计成本；同分按创建顺序。
- 每个 Candidate 一一对应独立 Investigation。第一版串行执行，每个 Candidate 使用固定局部预算，不实现并行或动态追加预算。
- Investigation 最多有一个当前 working hypothesis，旧假设以 supported/refuted/replaced 进入简短历史。它是调查状态的一部分，不是独立 Agent，也不替代 Claim。
- Claim 使用共同字段加一个 Profile。Profile 固定为数据传播、配置、凭据处理、内存处理和受限 generic；新增 Profile 必须升级 schema。共同决定性字段为目标、根因、触发或暴露关系和实际影响；前置条件与缓解因素为非决定性必填字段并可 not applicable。各专用 Profile 使用 ADR-0012 定义的额外决定性字段。
- Claim 状态固定为 unassessed、supported、refuted 和 not applicable。supported 必须引用 Evidence ID。ready gate 要求所有必填项有状态、支撑引用存在、反证已处理且不存在 blocking gap。
- 生命周期、结果和停止原因分别建模。生命周期只描述 queued、investigating、ready for verification、verifying 和 finished；disposition 只在结束时表达 confirmed、rejected、inconclusive、closed、unresolved 或 not started；stop reason 独立表达完成、决定性反驳、预算耗尽、无进展、输入或协议失败等原因。
- 连续五个已完成语义动作均未新增非重复 Evidence、Claim/假设变化、路径节点或 gap 消解时触发 no-progress。协议重生成、服务失败等非语义完成动作不进入该计数。
- Analysis 默认每 Investigation 最多 30 轮。未满足 ready gate 的高优先级调查可按 `evidence_gap` admission reason 生成独立冻结案卷，明确记录 Claim、已有 Evidence 和 blocking gaps，不改变其为 ready 状态。
- Verification Case 在提交时冻结。Verifier 使用独立上下文和默认 15 轮预算，可使用 analysis 同类工具重新取证，但不接收 analysis 的 verdict、severity、confidence 或说服性结论。原 Evidence Reference 只帮助定位材料，不算 Verifier 独立支持。
- 全部 ready 案卷必须复核，剩余案例预算再按优先级用于 evidence-gap 案卷。两类案卷使用相同聚合：全部必填 Claim 由本次独立 Evidence 支持才 confirmed，任一决定性 Claim refuted 则 rejected，其余为 inconclusive。工具不可用只产生 unresolved，不是反证。
- Verified Claim Result 逐项保存评价、实际观察、验证方法、限制和新 Evidence。Verifier 不修改冻结案卷；只有出现独立入口、位置或机制时才提出 Related Candidate。第一版 inconclusive 不自动返回 analysis。
- 每个逻辑工具调用分配一个运行内递增 Evidence ID；相同输出仍是不同 Evidence。SHA-256 只校验完整性。Evidence Reference 保存工具、规范化参数、原文位置、摘要、digest、所属 Investigation 和产生顺序；Claim 仅引用 Evidence ID。
- Host 在任何 Observation View 截断前保存完整且有界的 ToolResult 文本与结构化数据。大型或二进制产物由工具管理，Evidence 只引用其位置、大小和 digest。Observation View 可以截断，但提交给 LLM 的值保持原始字面值。事实报告默认只展示敏感值的类型、位置、长度和 digest 前缀。
- 工具逻辑调用按 `tool_started`、原始 Observation 持久化、`tool_finished` 的顺序记录。工具注册契约新增 replay policy。只读幂等工具用同一 call ID 重试；Ghidra 先验证缓存与 digest 后接纳或重试；不可重放调用标记 interrupted。重试增加实际 attempt，不创建新逻辑调用或 Evidence ID。
- Investigation Store 使用追加式事件作为权威历史、状态快照作为物化投影。事件带连续序号，快照带最后事件序号；恢复只重放快照之后的事件。写入顺序为事件和 Observation 优先，再原子替换快照。
- 日志末尾不完整记录要保留或隔离并发出恢复告警，然后从最后完整事件继续；中间损坏禁止自动跳过。顶层 JSON 与逐行事件分别带 schema version 和 event version；不兼容版本拒绝恢复并引导新建运行世代。
- 每个运行世代保存 manifest、运行状态、Candidate Store、按 Candidate 隔离的 Investigation 状态/事件/Evidence、冻结 Verification Case/Results、Findings 和事实报告。运行目录及机器工件在封存后不可修改。
- 一个工作区同一时刻只允许一个活动运行。锁记录进程身份和启动时间；只有确认原持有进程不活动时才接管。默认恢复未完成世代，完成世代只读，显式强制执行创建新世代。
- 恢复 Agent Session 时不重放完整 Transcript，而是从固定系统提示、当前 Investigation State、相关 Evidence 摘要与引用、最近完成动作及 Observation View、剩余预算重建。请求已发出但回复未持久化时从同一快照重请求；合法回复已持久化则按事件继续。
- 预算配置优先级固定为显式运行参数、本机环境覆盖、版本化 Benchmark profile、代码默认值，并把最终生效值写入运行快照。初始单案例上限为 8 个实际处理 Candidate、400 个 LLM 请求、320 个工具 attempts 和 7200 秒 active time。
- 预算按真实消耗计量：所有模型请求、协议重生成、压缩和恢复重请求都进入 llm calls，并另记 validated rounds；每次真实工具执行进入 tool attempts，并另记 logical tool calls；累计全部 token；active time 排除停机和等待恢复。
- 事实报告由 Host 按固定顺序生成运行配置、Confirmed Findings、Rejected Cases、Inconclusive Cases、not-started Candidates、Coverage Gaps、Evidence Index、资源与停止原因。Analyst Notes 可选且位于事实段之后，不能覆盖结构化事实。
- Severity 由影响范围和触发条件矩阵确定：仅加固为 info/info/low，局部对象或单一功能为 low/low/medium，完整组件或关键服务为 medium/medium/high，系统或信任边界为 high/high/critical，三列对应特殊、有限、宽松条件。已验证缓解使触发条件左移一档；完全阻断影响则反驳决定性 Claim；关键字段缺失不得 critical；人工调整写入 review overlay。
- 运行只有在全部 proposal 入库、入选 Investigation 都有 disposition、未选 Candidate 为 not started、全部 ready 案卷已复核、事实报告和 manifest digest 均生成后才能 completed。报告或 manifest 失败保持 finalizing 并可恢复；Analyst Notes 失败不阻塞封存。
- 人工或 Codex 复核通过追加式 review overlay 保存 reviewer、时间、目标字段、旧值、新值、理由和 Evidence Reference，不修改封存机器工件。报告并列 machine 与 reviewed result；Benchmark 默认统计 machine result，reviewed result 单独统计。
- Blind Discovery 固定工具权限：recon 仅使用浅层工具；analysis 和 verification 在此基础上使用 find_decompiled_function 读取已有边车，并使用 r2、按需 Ghidra 与受控验证；三个角色均禁用 CVE 扫描、公开问题查询和 web search，启动时不做 CVE 缓存预检。
- Benchmark 使用互相隔离的公开案例输入根和 Ground Truth 根。Ground Truth 路径不得进入 Step5 参数、提示、环境快照或 Agent 工作区；Evaluator 只在运行封存后接收两侧输入。
- 确定性评估只做路径、地址、组件与函数别名规范化并生成候选映射，不做最终语义标签。用户显式启动 Codex 读取完整结构化运行材料和 Ground Truth，按固定字段量表裁定 full、partial、miss 以及 unmatched finding 的 novel valid、unsupported、uncertain。
- 每个 Ground Truth 只能有一个 primary match，重复报告不重复得分；uncertain 暂不进入确定指标。评审产物保存字段级决定、双方引用、理由、模型版本、固定评审提示和输入 digest。
- 首批 Benchmark 目标为 5–10 个标注完整案例，先用 3 个跑通完整 Agent、封存和 Codex 复核链路。预算上限是实现与试运行初值，不代表已取得 Benchmark 成绩。
- 旧 orchestrator 对阶段推进、finish、top-K 和事实报告的控制全部退役；旧迭代与复核数量配置退役。内部可以先完成新 Host，但公开 Step5 入口一次切换，随后删除旧 orchestration，不保留 shim、双模式或旧行为开关。
- 新控制流不读取或迁移旧 survey、findings 和 verified findings 工件。旧工作区需要显式创建新运行世代重跑；仍适用的命令入口、模型设置和工具实现继续复用。

## 2026-09-16 已确认补充验收范围

以 ADR-0012「2026-09-16 接缝评审后的确认」为语义依据，由票 14 在公开切换前验收：

- 工具授权测试证明 analysis/verification 可读反编译函数、Recon 仍被拒绝；模型可见工具描述与调用指引符合有效权限。
- Verification 最后一轮已取得完整独立支持、未提交 complete_verification 时，预算耗尽可产 confirmed Finding 且保留 budget_exhausted；缺项和 protocol_error 不产 confirmed，决定性反证仍按 rejected 聚合。
- 真 AgentSession + ScriptedLLM 的低阈值上下文测试验证 Host 发起压缩、预算与 Transcript 留痕、后续动作继续；预算不足时不发起额外请求，恢复遵守既有状态重建规则，权威 Evidence 不受压缩影响。
- 每个复核目录具有持久化的逐 Claim 检查清单与证据入口；恢复可读取，隔离 analysis 结论，原证据只作定位；计划生成不增加模型请求，Verifier 沿普通响应检查。

## Testing Decisions

好测试以可观察契约为中心：给定状态、事件、模型 proposal、工具结果、预算或运行工件，断言 Host 输出、持久化顺序、恢复结果和最终报告；不锁定私有辅助函数、内部类拆分或无意义调用次数。由于这是控制面大重构，不能只依赖一条端到端 happy path；测试应在最高可控 seam 验证整体行为，同时用少量纯状态与存储测试覆盖故障组合和非法转换。

1. **Host Policy 纯逻辑 seam（新增核心 seam）**：以状态、事件或配置为输入，断言新状态或明确错误，不接触文件系统、LLM 或真实工具。覆盖合法与非法 lifecycle 转换、disposition/stop reason 分离、ready gate、evidence-gap admission、Claim Profile 必填项、verification 聚合、Candidate fingerprint/优先级/保留名额、no-progress、severity 矩阵和各层预算边界。该 seam 用表驱动测试穷举状态机和聚合规则，防止只能通过昂贵端到端场景发现控制错误。
2. **Host Store 持久化 seam（新增核心 seam）**：在临时工作区通过公开 Store 操作写事件、Observation、Evidence 和快照，再以新 Store 实例恢复，断言外部可见状态。覆盖事件先于快照、last event sequence 重放、末尾断行隔离与告警、中间损坏拒绝、schema/event version 不兼容、digest 校验、原始 ToolResult 保真、原子快照失败恢复、active/stale lock、completed 工件不可变和 review overlay 仅追加。
3. **Host Action Loop seam（新增主要编排 seam）**：用 fake Agent Session 与 fake tools 驱动真实 Host 循环，不模拟 Host 内部方法。覆盖整份 proposal 校验通过前零副作用、state delta 与唯一 next、协议最多三次、各角色失败收束、`tool_started → Observation → tool_finished → snapshot` 顺序、同 call ID 重试、replay policy、Evidence ID 与 attempt 计数、Observation View、预算/no-progress、单 Candidate 隔离、ready/evidence-gap 提交、Verification 独立取证和 Finding 聚合。
4. **公开 Step5 入口端到端 seam（复用现有最高 seam）**：沿用现有 pipeline 测试中的 public Step5 runner、临时工作区和 Scripted LLM 先例，跑通 recon → Candidate Store → Investigation → Verification → deterministic report → manifest → sealed run。断言运行世代目录和关键工件、默认 resume、finalizing 恢复、completed 只读、强制新世代、未处理 Candidate 为 not_started，并证明公开入口已切到 Host、旧 orchestrator/旧三工件/双模式不再参与。
5. **Agent Session 协议 seam（保留小而专的协议测试）**：沿用现有 ReAct parser 与 Scripted LLM 的先例，测试合法 `state_delta + next`、角色允许的 next kind、未知字段、错误类型/枚举、截断或非 JSON 文本、整份重生成提示和无效回复仅进 Transcript。这里不重复测试 Host 生命周期，只保证模型文本到 proposal 的边界稳定。
6. **工具注册与执行契约 seam（复用现有工具测试）**：扩展现有 registry/parameter contract 测试，断言 recon、analysis、verification 的 Blind Discovery 权限矩阵，所有工具具有合法 replay policy，Host 传入规范化参数，既有工具 execute 行为继续由原测试负责。网络查询和 CVE 工具在三个角色中均不可见，recon 不可见 r2/Ghidra。
7. **Benchmark Evaluator seam（新增封存后评估 seam）**：用最小 sealed-run fixture、独立 Ground Truth fixture 和可控 Codex reviewer response，断言确定性规范化只生成候选映射、Ground Truth 每项唯一 primary、full/partial/miss 字段规则、unmatched 的三种标签、uncertain 不进确定指标以及结构化 evaluation review 的引用、提示、模型和 digest。另加边界测试证明 Agent 运行输入和快照不包含 Ground Truth 路径或内容。

验收顺序以 Host Policy、Store 和 Action Loop 为重构安全网，再由公开 Step5 端到端测试证明接线与一次切换成立。既有 orchestrator 测试中只描述退役行为的部分随旧模块删除；仍有价值的 parser、Scripted LLM、工具契约、context 和 display 测试迁移到新公开 seam，不以保留旧实现为目的。

前三个 Benchmark 案例的端到端试运行属于系统验收：每例必须能从公开输入启动、在预算内形成 sealed run，再由用户显式启动 Codex 产出可审计 evaluation review。它们验证完整工作流，但不代替上述确定性自动化测试。

## Out of Scope

- Investigation 并行执行、并行 Verification、动态追加 Candidate 预算或跨 Candidate 借用局部预算。
- 迁移、转换或继续读取旧版 survey/findings/verified findings 工件；保留旧 orchestrator、兼容 shim、双公开模式或旧行为 feature flag。
- 恢复 ADR-0011 已否决的持久化 Inventory 阶段，或让 recon 直接使用 r2/Ghidra 做深度分析。
- Known-issue-assisted discovery、CVE 数据库/缓存、公开问题查询、版本到漏洞映射和 Agent web search；这些能力若需要，应使用与 Blind Discovery 分离的运行模式另行设计。
- 引入标准化漏洞评分体系。第一版只实现 ADR-0012 的确定性 severity 矩阵。
- Verification inconclusive 后自动返回 analysis 的循环，以及跨 Investigation 的自动合并或重新分配预算。
- 使用供应商 function calling 取代纯 JSON 协议，或要求/存储模型完整思维过程。
- 为状态存储引入数据库、事件总线、向量数据库、RAG 系统或新的 Agent 框架；除非实现中出现经证据证明且 ADR 未覆盖的必要性，应另行决策。
- 自动判定所有语义等价。确定性 Evaluator 只做规范化和候选映射，最终字段级对应由用户显式启动 Codex 复核。
- 把 uncertain 强制归入正确或错误指标，或把 reviewed result 覆盖 machine result。
- 声称已经取得 Benchmark 成绩。5–10 例与前三例是数据选择和验收目标，预算值是初始限制。
- 自动删除旧运行、旧工件或用户数据。新运行只是不读取旧语义工件。

## Further Notes

- 这是控制面重构，不是提示词调整。实现拆票时应优先建立 Host Policy、Store 与 Action Loop 的契约和测试，再完成公开入口切换；不能先让新 Host 调用旧 orchestrator 的完整循环并把它称为迁移完成。
- 当前 engine 把 while 循环和工具执行内藏，因此只能复用协议解析、上下文管理、模型配置与工具实现，不能原样作为 Host 下的 Agent Session。
- 旧术语在 CONTEXT.md 中已标为 legacy。实现、测试和报告应使用 Candidate、Investigation、Verification Case、Claim Result、Finding、Evidence Reference、Observation View、lifecycle status、disposition、stop reason、sealed run 和 review overlay。
- Observation View 向 LLM 发送原始字面值是已确认决定；“报告默认不展开敏感原值”是单独的呈现规则，两者不得混为数据脱敏或证据改写。
- Benchmark 的语义匹配不要求路径、函数名或描述文本完全一致。Codex 评审按问题机制、触发、关键关系和影响做字段级判断，并为每项决定引用双方材料。
- 本 spec 只发布设计与验收范围，没有开始实现代码。下一步应由票据拆分把状态模型、存储、会话协议、控制循环、报告/封存、评估和一次切换组织成可独立验证的实现单元。

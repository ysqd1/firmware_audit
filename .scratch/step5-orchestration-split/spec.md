# Spec: step5 编排层包化(orchestration/ 解体 orchestrator.py)

Status: ready-for-agent

## Problem Statement

维护者视角:Step5 的文件与文件夹分工不清晰。最痛的一点是编排器模块——1675 行,是全库第二大文件的 2.4 倍,一个模块同时佩戴五顶职责帽子(调度守卫、调度日志、verification 每疑点一实例引擎、报告对账、预算状态),30+ 个成员摊在类表面,而生产代码真正使用的接口只有 5 个点。顶层平级文件还混了三个层次(编排决策/单实例执行/纯逻辑/CLI 入口/演示脚本),依赖规则("engine/data/providers 互不 import、只准向下")只写在文档里靠自觉。后果:读懂一个概念要在 1675 行里跳,改一处要人肉找齐散落各处的同源知识,新读者(含 Agent)导航成本高,改大了怕出 bug。

## Solution

把编排层收进一个独立的 orchestration/ 包,原编排器模块解体为七个单一职责模块(共享词汇/编排主体/动作与守卫/交接/调度日志/复核引擎/报告对账);engine/data/providers 三包名字与位置不动;依赖规则从文档升级为 AST 守护测试(机器强制);demo 脚本挪出主包。全程**零行为变更**:分 6 张严格线性票迁移,每票全套件跑绿 + 票内新增测试,master 上一票一 commit,任一绿点可停可回滚。

## User Stories

1. 作为 Step5 维护者,我想让编排器模块只做"调度决策 + 留痕 + 出报告"这一件事,这样改编排逻辑时不用在五顶帽子之间跳。
2. 作为 Step5 维护者,我想让每个对账/日志/复核引擎的改动集中在一个单一职责模块里,这样修 bug 时定位与验证都在一处(locality)。
3. 作为 Step5 维护者,我想让新读者打开 orchestration/ 包就能从模块名读懂分工(state/orchestrator/actions/handoff/dispatch_log/verify_phase/reconciliation),这样不需要先读 1600 行代码。
4. 作为 Step5 维护者,我想让"三个包互不 import、依赖只准向下"的规则由测试守护,这样未来任何人(含 Agent)违规时 CI 直接红,而不是靠 code review 肉眼抓。
5. 作为 Step5 维护者,我想让迁移分 6 张互相独立、严格线性、各自可回滚的小票执行,这样不会"一次改太多出 bug"。
6. 作为 Step5 维护者,我想让每张票的验收标准是客观的(全套件绿 + 该票新增测试),这样不需要人肉判断"改没改坏"。
7. 作为 Step5 维护者,我想让"纯搬家"成为迁移纪律(顺手发现的问题记票不修),这样每张票的 diff 可以用"逻辑零改动"快速审阅。
8. 作为实现票的 Agent,我想让每张票自包含(上下文不依赖其他票的对话历史),这样每张票可以 /clear 后从票文冷启动。
9. 作为实现票的 Agent,我想让测试 import 一次性更新到新路径、不留兼容 shim,这样我不会看到两套并存的可 import 路径而困惑。
10. 作为 Step5 测试编写者,我想让每个新模块(DispatchLog/verify_phase)有自己的小接口可直测,这样不必为测一个日志类构造整个 Orchestrator。
11. 作为 Step5 测试编写者,我想让报告对账继续以纯函数形式直测,这样对账规则的回归测试零 IO 零 LLM。
12. 作为审计流水线用户,我想让迁移前后 step5_run 的行为与产物(dispatch_log.json、report.md、result.json 的结构)完全一致,这样迁移对我不可见。
13. 作为审计流水线用户,我想让 CLI 入口(python -m firmware_audit.step5_agent.run_step5)与 step5_run 签名不变,这样我的调用脚本和文档不用改。
14. 作为未来贡献者,我想让这次结构决策有 ADR 记录(包结构 + 依赖分层 + 守护测试),这样未来架构勘察不会重新提议已被否掉的方案(平铺/全量改名)。
15. 作为未来贡献者,我想让 AGENTS.md 的目录树随迁移同步更新,这样文档与代码不漂移。
16. 作为未来贡献者,我想让迁移途中发现的可疑点有去处(issue tracker),这样它们不会被顺手修进搬家 commit 里,也不会丢。

## Implementation Decisions

- 新建编排层包 `orchestration/`,原 1675 行编排器模块解体为七个模块,职责各一:
  - **state**:编排共享词汇——调度状态枚举、单次执行结果封装、状态中文标签。标签转正为公开名(去掉下划线前缀,它是测试唯一还在 import 的私有符号)。**只放共享词汇**;小格式化 helper 留在各自消费者旁,state 不变成杂物抽屉。
  - **orchestrator**:Orchestrator 类本体——run() 主循环、报告落盘、终态落盘、对外属性。预计 ~380 行。
  - **actions**:三个编排动作工具类(dispatch_agent/summarize/finish)+ 调度守卫(顺序门/任务唯一性/次数上限/断点续跑判断/重复调度应答)。
  - **handoff**:交接块构建 + 交接快照落盘。
  - **dispatch_log**:调度留痕小类,接口四个动词(start/finish/interrupted/attempt),拥有调度日志 list 与 dispatch_log.json 落盘的全部知识。
  - **verify_phase**:verification 每疑点一实例引擎——排序取 K、单实例续跑身份校验、锚点回填聚合、阶段终态判定。
  - **reconciliation**:报告对账纯函数群(零 IO 零 LLM),照聚合器模块"纯逻辑下沉"的先例。
- state 单独成模块的动机:actions 与 orchestrator 互相需要对方的类,共享词汇单独放一个 ~120 行小文件,包内依赖无环。
- 包内依赖方向:orchestrator → 各模块;actions/handoff/verify_phase → state/dispatch_log;禁止反向。
- 顶层其余文件不动:CLI 入口、单实例执行(runner)、聚合器(aggregator)保持原位原名;engine/data/providers 三包**不改名不挪动**(全量改名是大手术换零清晰度,已否)。
- demo 脚本挪入包内 demos/ 子目录,演示命令同步更新为 `python -m firmware_audit.step5_agent.demos.demo_display`。
- 依赖分层(守护测试的规则来源):
  - 入口 → orchestration → runner/aggregator/engine/data/providers
  - runner → engine/data/providers(runner 永不 import orchestration)
  - engine、data、providers 互不 import,也不向上 import(既有规则,不变)
- 测试 import 策略:全部直接更新到新路径,**不留兼容 shim**——旧模块路径不保留再导出,避免双接口。
- 迁移纪律:**纯搬家**。一张票里"移动"与"修改"不混合;途中发现的可疑点(无效 lazy import、硬编码工件名等已知项除外,那些本身是 T6 的票内内容)记入 issue tracker,不顺手修。
- 迁移顺序:6 张严格线性票 T1→T6,全碰同一文件故不并行;master 上一票一 commit(仓库现行习惯,不开分支)。
  - T1 建包迁移 + ADR-0009 + 依赖守护测试(逻辑零改动的整体搬家)
  - T2 报告对账出走
  - T3 调度日志收类
  - T4 守卫+交接进 actions
  - T5 复核引擎下沉
  - T6 小刀群(收编散落的同源知识:宽容 JSON 解析复用、工件写盘走 data 层、硬编码工件文件名走配置、severity 排序表单一出处、执行后状态判定去重、transcript 清空去重)+ demo 迁移 + AGENTS.md 目录树定稿
- ADR-0009 内容:包结构决策 + 依赖分层规则 + 守护测试 + 被否备选(顶层平铺不加包/按层次全量改名/runner 并入编排包)及否因。T1 票内落地。
- CONTEXT.md 中指向旧模块文件的既有词条(orchestrator 条目等)随 T1 落地时同步更正。

## Testing Decisions

- 好测试只测外部行为,不测实现细节;本重构的行为面完全由**既有 seam** 承载,不新增行为 seam:
  - 最高 seam:step5_run 端到端(ScriptedLLM 打桩 base_llm,既有 pipeline 测试)——迁移前后必须同样跑绿。
  - 编排器公开类直驱:Orchestrator.run()、DispatchAgentTool/SummarizeTool 的 execute(既有 orchestrator 测试 20 项 + 守卫测试 16 处直驱)。
  - 报告对账纯函数直测(既有 4 处,随 T2 改 import 路径)。
- 新增测试面(每个新模块自己的小接口,数量刻意少):
  - DispatchLog:四动词接口直测(状态变迁、status_history、落盘内容),不为它构造 Orchestrator。
  - verify_phase:排序取 K/续跑身份校验/锚点回填三块的聚焦单测;编排行为仍走 dispatch_agent.execute 公开路径。
  - 依赖守护测试:AST 扫描 step5_agent 全部 import 边,断言分层规则(见实现决策);先例是工具权限守护测试(tool_permissions_and_threshold)的"规则机器化"模式。
- 验收闸门(每票统一):现有全套件(176 passed + 2 skipped)跑绿 + 该票新增测试绿。不引入字节级产物对比(dispatch_log 含时间戳/耗时,天然不可比,只会产噪)。
- 测试 import 更新(约 24 处 + 1 处 patch 字符串路径)随各票机械完成,不集中到最后。

## Out of Scope

- 预算状态簇(budget)独立成模块——勘察标为 Speculative,现无第二消费者,候选 1-5 落地后重看。
- data/prompts.py 拆分(纯文本模板堆,同质不混乱,保留)。
- engine/data/providers 三包改名或重组。
- 任何行为变更:提示词文案、工具语义、工件 schema、状态枚举值域、调度规则,一律不动。
- 迁移途中发现的 bug 修复(记票,后续独立处理)。
- CLI 入口路径与 step5_run 签名变更(保持不变)。
- 测试 import 兼容 shim(明确不留)。

## Further Notes

- 勘察依据:全库行数统计 + orchestrator.py 全文精读 + 周边模块/测试耦合子代理走查;候选清单与前后对照图见临时报告(会话产物,未入库)。
- 已知待收编的重复知识清单(T6 票的输入):手写宽容 JSON 解析(与 data 层提取函数重复)、裸写工件 schema 落盘 ×2、硬编码 verified_findings.json 文件名(第三处同源)、severity 排序表两处、执行后状态三岔判定两处、transcript 跑前清空两处。
- 迁移途中新发现的可疑点,记入本 feature 的 issue tracker(追加 issue 文件),不顺手修。
- 六张票落满后:原 1675 行模块变为 8 个平均 ~200 行的单一职责模块(7 模块 + 包导出),Orchestrator 类从 30+ 成员缩到 ~12 个。

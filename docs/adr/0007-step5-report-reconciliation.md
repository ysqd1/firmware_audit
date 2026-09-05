# 0007-Step5 报告呈现失真治理:素材收敛 + 事后对账双保险

**2026-09-03 现场实证**(target/1 process/agent):report.md(orchestrator LLM 的 Final Answer 原样落盘,ADR-0006)与 verified\_findings.json(判级/置信度/复核结论唯一真值)存在三处失真:

- **失真 1(置信度错报)**:pet\_go 条目报告写"置信度: high",工件该条 `confidence="low"`(复核实例 8 降级);JWT 条目报告写 high、工件为 medium。severity 降级被正确转述,confidence 没有。

- **失真 2(限定被吞)**:JWT 条目工件 rationale 明确"token 已于 2025-01-29 过期,泄露的是凭据模式/认证机制/内部 API 结构",报告只写"可用于冒充用户身份访问云服务 API",风险定性被夸大。

- **失真 3(复核理由被编造,最严重)**:pet\_go 工件 rationale="死代码,pet\_go 目录无任何文件导入或调用 perform\_cmd,不可达、无攻击面";报告详情却写"调用点当前均为硬编码命令常量拼接"——该句逐字是 net\_switcher 条目(#10)的复核理由,属**跨条目串条**而非改写,且与同条"无远程可达输入源"自相矛盾。违反铁律"证据链逐字可溯源,禁止编造"。

## 关键事实(取证,改变方案评估前提)

- **素材并非缺失**:`SummarizeTool._run`(orchestrator.py)已逐字段结构化喂入——已复核区每条含 severity/三态标记/位置行/confidence+verified/**rationale 全文**/evidence 前 600 字,已复核/未复核拆独立区段。方向 a"把素材逐字段喂"已实现大半,失真的根因在**转写环节**(LLM 把长文本 Observation 转写成 markdown 时出错),不在素材。

- 失真 3 是**跨条目串条**:LLM 把 A 条的理由嫁接到 B 条。长文本 Observation 越喂越长,这种污染越易发生,提示词红线约束"写作纪律",约束不了"大脑串线"。

- report.md 结构是 LLM 的实际输出非契约(本轮恰好用 `### CRITICAL + #### N. + 置信度:` 格式,下轮可能换样)。

## 决策

报告生成主体仍是 orchestrator LLM(Final Answer 原样落盘,不复活 render\_report)。在此基础上:

1. **方向 = c:素材收敛 + 事后对账双保险**。素材侧加提示词红线;对账侧加机器校验,保证失真必被抓住。
2. **对账输入 = 解析 report.md 正文**,不要求 LLM 另附机器清单。按分区标题定位 finding 条目,提取"置信度/复核结论"等标签行的枚举值与 buried 比对;**提取不到的条目显式报出**(本身即告警信号,不静默)。
3. **对账粒度 = 确定性事实(2026-09-03 用户决策修订)**:file(位置)一致 + `severity/confidence/verified` 三枚举值逐条比对。**rationale 关键句包含已移除**——语义判断规则化必有偏差(12 字符连续重合把合理压缩转述误报为 warning,target/1 wangyi 实锤:"复核确认证据与源码完全吻合" vs 长段 rationale 最长公共片段仅 9 字符),理由溯源回归人工检查。
4. **对账不符动作 = 仅告警**:report.md 原样保留,旁落盘 `report_reconciliation.json` 差异清单(title/字段/工件值/报告值)+ stderr 警告,**不自动重生成、不阻塞**。

## 决策理由

- **纯 a(素材加固)不保真**:素材已结构化,增量只剩提示词红线;失真 3 是跨条目污染,红线约束不了。若无机器校验,`/tdd` 期失真 3 类问题无法自动回归锁定,验收只能靠人工检视。

- **纯 b(纯对账)契约脆弱**:markdown 自由文本无稳定结构,无素材收敛时对账逐条提取命中率低;若要 LLM 在报告末尾附机器清单,等于多一个靠 LLM 自觉才能成立的点——治理 LLM 不可靠的同时又给 LLM 加一个"记得抄清单"的依赖。

- **对账读正文而非锚点**:对账应当检查读者真正看到的东西;LLM 背后再抄一份清单,抄的那份同样可能错。甲的"提取失败 → 明确报出 N 条未比对"已实现不静默;且零新依赖、最小净增代码(纯函数 + 轻提示词约定)。

- **仅告警不重生成**:ADR-0006 精神即"明确告警不静默降级",告警落盘 + stderr 已是"不静默"。自动重生成是收敛性问题(LLM 可能改 A 错引 B 错),不该由流水线猜;修复交给人工复核后的重跑(断点续跑体系已支撑)。

- **中粒度而非逐字**:rationale 逐字比对过严——LLM 合理缩句会被误报,淹没真信号;"关键句包含"抓的是"理由被换/被编造"(失真 3),放行"同义缩句",平衡可读性与溯源纪律。

## 被否决的方案

| 方案                          | 否决理由                                                                              |
| --------------------------- | --------------------------------------------------------------------------------- |
| a 单独(素材加固)                  | 素材已逐字段喂全(事实),增量只剩提示词红线;降概率不保真,失真 3 无法自动锁定                                         |
| b 单独(纯对账)                   | report.md 无稳定契约,纯启发式脆弱;锚点方案给 LLM 加"抄清单"依赖,与治理目标相悖                                 |
| 告警+自动重生成                    | 不保证收敛,可能引入新失真;违背"Final Answer 原样落盘",修复应交给人工决定的重跑                                  |
| 复活 render\_report(代码渲染发现清单) | 红线禁止:生成主体必须是 orchestrator LLM(ADR-0006)                                           |
| rationale 逐字比对(细粒度)         | 合理缩句误报,淹没真信号;对账目标是抓"串条/编造"而非禁止压缩                                                  |
| ~~rationale 关键句包含(已实现后移除)~~ | 语义判断规则化必有偏差:12 字符连续重合把合理压缩转述误报为 warning(target/1 wangyi 实锤),用户决策:证据内容不检查,理由溯源回归人工 |

## 代价

- summarize 提示词加红线段;orchestrator 侧新增一个对账纯函数(report.md 解析 + 工件比对 + 差异落盘),共净增代码量小,集中在 orchestrator.py(对账函数 + `_ORCH_TMPL` 报告写作纪律红线段)。

- 对账是启发式(2026-09-03 起只核确定性事实):file/severity/confidence/verified 提取依赖标签行格式基本稳定,提取失败条目显式报出为"未比对"(不静默,可人工看);rationale 内容不自动检查(语义判断规则化必有偏差)。

## 状态

已实现(2026-09-03,/tdd + code-review 缺口修复 + 用户决策修订)。对账纯函数
`reconcile_report`(2026-09-05 T2 迁至 orchestration/reconciliation.py,原
orchestrator.py)解析 report.md 正文与 verified\_findings.json
逐条比对**确定性事实**:file(位置)+ severity/confidence/verified 三枚举值;
Orchestrator.run 落盘 report.md 后自动对账,差异清单写 report\_reconciliation.json

- stderr 警告,report.md 原样保留;summarize 提示词(`_ORCH_TMPL` ## 5)新增
  "报告写作纪律"红线。**review 缺口修复(同日)**:条目标题识别放宽(带编号或 ≥4 个

# 即条目,`### N.` 不再被当分区吞掉)、severity 标签行解析 5 值、提示词红线补

"severity 标签行"与"带编号标题"约定。**rationale 关键句包含已移除(同日,用户
决策:证据内容不检查)**——12 字符连续重合把合理压缩转述误报为 warning(target/1
wangyi 实锤),语义判断规则化必有偏差,理由溯源回归人工。需人工复跑已产出的
报告后重新生成(report\_reconciliation.json 每次 run() 幂等重写)。测试 6 项
(test\_orchestrator.py,44 全绿):纯函数枚举/file 比对/显式报出/边界缺口/集成落盘/
提示词红线;target/1 现场回归 file+confidence+verified 全过、无 rationale 维度。

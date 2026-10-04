# Spec: Step5 Observation 预算修订(全局 16k / summarize 64k 护栏 / transcript 忠实化)

Status: ready-for-agent

## Problem Statement

审计编排者(orchestrator)视角:verification 完成后调用 summarize 取报告写作素材,素材(9 条 finding 全量字段,14,417 字符)被工具 Observation 的 8000 字符上限按"头 75% + 尾 20%"截断——第 2-7 条的 confidence/rationale/evidence 明细正好落在被丢弃的中间段。orchestrator 是唯一没有 read_file 动作的角色,截断提示引导的回读路径走不通(实测撞"未知工具"白烧一轮),最终报告 6 条 finding 缺 confidence 等可解析字段(reconcile unparsed=6;所幸 mismatch=0,判级无损)。排查时还被第二层截断误导:transcript 记录层把每条事件裁到 4000 字符,连截断提示本身都被裁掉,日志里看不出发生过截断。

根因是两处预算取值过时:①8000 字符上限是从"小窗口时代"(原 60k 窗口)继承的保守值,对 1M 窗口的 v4-flash 与 600k est tokens 压缩阈值(本次 run 最大 agent 上下文仅约 4 万 est tokens,15 倍余量)过紧,实测 141 个 Observation 中 12 个超限,集中在 find_decompiled_function(最大 24,542 字符)、summarize(14,417)、read_file(13,263);②summarize 在 ADR-0006 之后成为报告素材的唯一注入点,其素材规模随 findings 数线性增长(每条约 1.5k 字符),"普通工具截断+回读"的兜底设计对它不成立。

## Solution

三层修订,行为模型(头 75%/尾 20%/省略提示/全文落盘 obs/)完全不变,只调数值与补机制:

1. **全局 Observation 上限 8000 → 16000 字符**:覆盖 find_decompiled_function 与 read_file 的全部实测样本,子 Agent 少烧回读轮次(verification 每实例仅 8 轮,一轮很贵)。
2. **per-tool 覆盖机制 + summarize 护栏 64,000 字符**:AgentTool 基类加可选覆盖属性,None 用全局默认;SummarizeTool 声明 64k——报告素材是唯一必须完整的 Observation,64k ≈ 40+ 条全字段素材(本次 run 的 4.4 倍),护栏只防 findings 规模失控,不碍正常审计。
3. **transcript 记录忠实化**:删除记录层 4000 字符截断,transcript.jsonl 变成"LLM 实际看到了什么"的精确存证(与 obs/ 互补:obs/ 存截断前原文,中间段只有 obs/ 有)。上游自限(observation ≤16k/64k、assistant 受 max_tokens 约束)使记录尺寸天然有界。

配套:summarize 素材文案修正(不再向 orchestrator 承诺它没有的 read_file)、AGENTS.md 与 CONTEXT.md 的 8KB 口径同步、现有测试断言同步。

## User Stories

1. 作为 orchestrator 报告生成者,我想 summarize 报告素材 Observation 不受全局默认截断约束,这样全部 finding 的 confidence/rationale/evidence 完整进入上下文,报告不再缺明细字段。
2. 作为 orchestrator,我想在 findings 规模失控(素材超 64k)时仍有护栏截断兜底,这样异常 run 不会把无界素材灌进上下文。
3. 作为 analysis 子 Agent,我想工具 Observation 上限上调到 16k,这样大型反编译函数(实测最大 24.5k 字符)更容易整段命中,不用为省略的中间段额外烧轮次。
4. 作为 verification 实例(每实例仅 8 轮),我想少花轮次回读被截断的 obs 全文,这样轮次预算留给取证与判定本身。
5. 作为排查工程师,我想 transcript.jsonl 忠实记录进上下文的文本(含截断提示),这样从日志直接看出"发生过截断、LLM 看到了哪段",不再被记录层裁剪误导。
6. 作为排查工程师,我想 transcript 与 obs/ 语义分工保持清晰(transcript=实际所见,obs/=截断前原文),这样两份材料互补且各有唯一用途。
7. 作为 orchestrator,我想 summarize 素材文案不再出现"read_file 可查"的空头承诺,这样不会按提示调用不存在的动作白烧一轮(本次 run 实测撞过)。
8. 作为 Step5 维护者,我想全局默认与单工具覆盖是单一机制(工具基类可选属性),这样未来调整某工具上限只改一处声明,不动截断调用点。
9. 作为 Step5 维护者,我想 AGENTS.md 与 CONTEXT.md 的 8KB 口径同步为新值,这样文档与代码不再互相矛盾,新读者不会被误导。
10. 作为 Step5 维护者,我想现有测试断言同步到新口径并守卫新值,这样全套件继续绿,回归有人管。
11. 作为审计报告读者,我想报告每条 finding 带完整 confidence 等字段,这样报告可独立判读,不必回查工件。
12. 作为 Step5 维护者,我想截断行为模型保持不变(头尾保留比例、省略提示、obs 全文落盘、回读路径),这样改动只是调参,行为心智模型零学习成本。

## Implementation Decisions

1. **全局上限**:Observation 入上下文文本上限 8000 → 16000 字符;截断算法(头 75% + 尾 20% + 省略提示含全文总量与 obs 回读路径)不变。16k 覆盖实测全部超限样本中除 summarize 外的所有情况(find_decompiled_function 最大 24.5k 中 4/5 个 ≤17.5k,残余靠既有回读闭环;read_file 最大 13.3k 全覆盖)。
2. **per-tool 覆盖机制**:工具基类新增可选类属性(整型字符数或 None,None=用全局默认),工具统一入口在截断时消费该属性。SummarizeTool 声明 64000。护栏值依据:每条全字段素材约 1.5k 字符,64k ≈ 40+ 条,为本次 run 的 4.4 倍;64k 字符 ≈ 32k est tokens,对 600k 压缩阈值是零头;超出护栏的场景(finding 数失控)本属异常 run,截断兜底优于无界注入。
3. **transcript 忠实化**:记录层删除 4000 字符截断,三种事件(assistant/tool/observation)一律记全文;不新增记录结构、不改事件类型。尺寸上界:observation 受新上限约束(≤16k/64k),assistant 回复受 max_tokens(32768)约束,单文件预计 1-1.5MB 量级,可接受。
4. **文案修正**:summarize 报告素材区段中"工件路径(read_file 可查)"改为不误导表述(素材已完整注入;全文已落盘 obs/)。不给 orchestrator 加回查动作。
5. **文档口径同步**:AGENTS.md 全部 8KB/8000 相关描述(上下文管理、工具层、实测踩坑等处)与 CONTEXT.md 的 Observation 词条同步为 16k/64k 口径;演示脚本与终端显示注释里的过时 8KB 字样一并修正。
6. **数值依据留痕**:上述取值全部来自 target/1 全 run 实测(141 个 Observation、12 个超限的分布,见 Further Notes)。

## Testing Decisions

- **只测外部行为**:截断后文本的形态(恰在阈值不截/超长头尾保留/省略提示在场/总长上界)、transcript 记录的忠实性(记录与进上下文文本一致、截断提示不被裁)、护栏触发与否(素材 ≤64k 全量、>64k 截断)、文案断言(素材不含"read_file 可查");不断言内部调用次数等实现细节。
- **三个现有缝,零新增**:
  1. 纯函数缝(现有 truncate_text 参数化用例):边界值 8000 → 16000 同步(恰 16000 不截、超长截断、头尾保留)。
  2. ReAct 端到端缝(ScriptedLLM 驱动的现有超限素材用例):MIDDLE_LOST 定位断言改 16k 口径;**新增** transcript 忠实化断言(记录不再被 4000 裁剪、截断提示完整出现在记录中)。
  3. 编排层缝(现有 summarize 用例):素材 ≤64k 全量进 Observation;>64k 触发护栏截断;素材文案不再含"read_file 可查"。
- **先行参考**:纯函数参数化表(test_step5_parsing)、ScriptedLLM 全链路用例(test_step5_react)、orchestrator summarize 用例(test_orchestrator)。
- **回归口径**:全套件绿(基线 176 passed + 2 skipped)。

## Out of Scope

- 不给 orchestrator 加 read_file 或任何回查动作(文案修正后需求消失;未来如需,单独立项)。
- 不动 binwalk_rescan 的 data 字段自限、search_code 的二进制嗅探阈值、obs 文件软折行宽度(均为不同关注点的独立常量)。
- 不动上下文压缩阈值(600k est tokens)与 LLM max_tokens(32768)。
- 不改截断算法本身(头 75%/尾 20%、提示格式、obs 落盘与回读路径机制)。
- 不把报告素材落盘为独立工件(verified_findings.json 已是单一出处,ADR-0007 对账兜底报告一致性)。
- 不改 transcript 的 JSONL 结构与事件类型。

## Further Notes

- **事故溯源**:2026-09-05 target/1 run——summarize 素材 14,417 字符被 8000 上限截断(头 6000/尾 1600,精确命中第 1 条完整、第 8-9 条完整、第 2-7 条明细丢失);orchestrator 调 read_file 被拒("未知工具");第二次 summarize 确定性复现同样截断;最终报告 reconcile unparsed=6(第 2-7 条缺 confidence)、mismatch=0。排查中 transcript 4000 记录线把截断提示(位于上下文文本 ~6000 字符处)裁掉,二次误导排查。
- **实测数据**:全 run 141 个 Observation,超 8000 字符 12 个:find_decompiled_function ×5(9,422-24,542)、summarize ×2(14,399/14,417)、read_file ×3(8,097-13,263)。全 run obs 原文合计约 400KB,最大 agent 上下文约 4 万 est tokens(压缩阈值 600k)——"防爆文件/省窗口"均非当前真实约束。
- **兼容性**:纯运行时参数与记录层变更,不产生工件 schema 变化,无断点续跑失效问题(与 extractinfo_version 失效机制无关)。
- **无新 ADR**:参数级修订、易回退,决策依据以本 spec 与文档同步承载,不满足 ADR 三条件。

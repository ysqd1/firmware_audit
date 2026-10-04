# Step5 Host 控制层 票 01-10 累积评审 brief(自包含)

本文件是给**另一个 harness/模型**(DeepSeek v4.1 via ZCode)执行的评审说明。
执行者不需要本仓库的历史上下文,只按本文件读 diff、跑命令、产出 findings。

## 0. 铁律(先读)

- **只读**:不修改、不 `git add`、不 `git commit`、不 `git stash`、不切分支。
  工作树里有用户自己的未提交改动(`M CONTEXT.md`、未跟踪的 `dataset/`、`docs/adr/0012-*.md`、
  `docs/firmhound-study-*.md`、`可参考的开源项目/`),任何写操作都可能破坏它们。
- **不跑会改盘的东西**:不要执行 pytest 之外的写入型脚本;跑测试用
  `python -m pytest firmware_audit/test/<file> -q`(只读)。基线:HEAD 全量 `890 passed, 21 skipped`。
- **每条 finding 必须引用 diff 原文**(`file:line` + 引文),禁止凭印象下结论;
  写不出引文的"感觉有问题"归入"待确认"区,不算 finding。
- 输出用中文。

## 1. 范围与固定点(三个批次,各自独立跑)

| 批次 | git 范围 | 规模 | 覆盖的票 |
|---|---|---|---|
| **全量**(唯一一次) | `git diff e9abefa...1bc0b0c` | 30 文件 +12207/−58(源码聚焦后 ~2k) | ①-⑩ |

单批即可,因为**十张票都已逐票做过双轴评审并修复**(用户 2026-09-16 确认)。
逐票评审结构上只能看见那一票的 diff,所以这次唯一还没被覆盖的东西是**跨票接缝**——
单批全量 + 按接缝限定阅读范围,是能一次吃完的量。

工单目录:`/home/dr/fw/.scratch/step5-host-controlled-investigations/issues/`
架构规则单一出处:`/home/dr/fw/docs/adr/0012-host-controlled-investigation-lifecycle.md`
特性规格:`/home/dr/fw/.scratch/step5-host-controlled-investigations/spec.md`
术语表:`/home/dr/fw/CONTEXT.md`(legacy 词与新词 Candidate/Investigation/Verification Case/Claim Result/Finding 的对应关系在此)
工作区约定:`/home/dr/fw/AGENTS.md`

**阅读范围限定**(12k 行里真正要读的):不要通读 diff,按下列接缝读
——`host/` 下的 `analysis.py`、`verification.py`、`recon.py`、`claims.py`、`evidence.py`、
`store.py`、`budget.py`、`tooling.py`、`session.py`、`candidates.py` 的当前完整实现(约 5.6k 行),
加上 `git diff e9abefa...1bc0b0c -- <上述文件>` 看演变;测试只按需抽查(用测试名定位)。

**为什么不分 1-5 / 6-10 两批**:全量源码只有 6162 行 / 16 文件(`host/` 包合计 5881 行),
约 70-90k token,一个窗口放得下且留推理余量——之前"12k 行"的压迫感来自测试文件。
更要紧的是,`b9ba783`(票 05/06 边界)正是**最有价值的接缝**:票 01-05 交付 Agent Session /
Store / 工具重放契约,票 06-10 是消费这些契约的 host 流程;切在那里,前半看不见消费者、
后半判契约又必须回读前半,什么也没省,却恰好把要查的跨票漂移切成两半。

**如果跑出来太浅**(只复述实现、不给判断),下一步按**不变量**拆,不按票号拆:
①生命周期三轴 + 只有 confirmed 产 Finding 链;②Evidence 身份唯一性 + 预算记账口径;
③恢复矩阵(四种中断点组合)。

## 2. 既有评审覆盖与已定取舍(避免重复劳动)

十张票都做过双轴评审并已修复。因此:

- **不要逐条重验工单 AC**,也不要把逐票内部结构再评一遍(已验过)。
  这次的价值只剩三处:①跨票语义漂移(见 §4);②**不同模型**的独立第二意见(DeepSeek 的盲区与 GLM 不同);
  ③已认领债务在 host 层收口前再确认一次归属。
- 下列**已定取舍**不要当新发现报,报了就标注"已定"并跳过:
  1. `analysis.py` 与 `verification.py` 的动作执行块**刻意逐行平行**(票 05 恢复语义安全关键路径,
     代码内有同步注释"修改必须同步另一侧")——Duplicated Code 不报。
  2. `getattr(session, "last_usage", None)` 鸭子类型读用量,无属性则只计次数不计 token
     ——`session.py` 注释声明的刻意的 seam。
  3. verification 三连协议失败**无条件**判 inconclusive(即使 claim_results 已齐也不聚合出 confirmed)
     ——工单 AC2/spec 故事 85 的语义,有 `test_verification_protocol_error_never_confirms_even_with_full_results` 钉住。
  4. "无效回复"取宽口径:协议形状失败**与** Host 守卫拒绝(工具越权/参数失约/门槛不满足)
     都触发整份重生成与 3-strike——ADR L43 "schema 校验失败"含领域 delta 校验。
  5. 局部轮次上限计**模型请求**(含重生成),不是只计生效轮——沿 recon 票 06 先例。
  6. 以下三项**票 11 已认领**,报了只归档:①`STEP5_*_MAX_ITERS` 同名双消费(角色 resolver 与
     `budget.ENV_KEYS` 各解析一次);②三个 runner 默认各自 `RunBudget.load(run_dir)`,靠构造顺序
     经 budget.json 文件共享台账;③verification 提出的 related candidate 尚未回写 Candidate Store 队列。
  7. 公开入口切换、运行世代/活动锁、severity/报告/封存、Benchmark 评估分别属票 11/12/14/15,
     **不在本范围**;"host 包未接公开入口"不是缺陷。

## 3. 提示词 A:Standards 轴(一个 agent)

> 你是代码评审的 Standards 轴审查员。仓库 `/home/dr/fw`(git)。以最高思考强度审阅,输出中文。
>
> 范围:全量 `e9abefa...1bc0b0c`。**不通读 diff**——十票已逐票评过,你只查接缝:
> 按 brief §1 的阅读范围读 `host/` 当前完整实现 + 该范围下这些文件的 diff;测试按名抽查。
> 先 `git -C /home/dr/fw log e9abefa..1bc0b0c --oneline` 建立票序。
>
> 先读文档化标准:`/home/dr/fw/AGENTS.md`(分层规则、工具契约、中文注释习惯)、
> `/home/dr/fw/docs/agents/*.md`(如存在)、`/home/dr/fw/CONTEXT.md` 术语表。
>
> 在此之上始终套用 Fowler 坏味道基线(每条都是判断题;文档化标准优先于基线;工具已强制的跳过):
> Mysterious Name(名字不揭示用途→重命名)、Duplicated Code(同形状逻辑多处→抽共享)、
> Feature Envy(方法过度伸手别的对象的数据→移到数据处)、Data Clumps(同组字段/参数总结伴→捆成类型)、
> Primitive Obsession(原始类型顶替领域概念→建小类型)、Repeated Switches(同类型同型分支反复→多态或共享映射)、
> Shotgun Surgery(一个逻辑变更散落多文件→聚拢)、Divergent Change(一模块因多个不相关原因被改→拆分)、
> Speculative Generality(规格没要的抽象/参数/钩子→删掉内联)、Message Chains(长链式导航→封装一方法)、
> Middle Man(只做转发的类/函数→去掉直连)、Refused Bequest(继承者无视大部分继承→改组合)。
>
> 必须遵守 brief §2 的"已定取舍"清单:命中时标注"已定"并跳过,不重复报。
>
> 汇报格式:按文件列出 (a) 违反文档化标准处(引用标准文件+规则原文;可判硬违规);
> (b) 基线坏味道(命名+引用 hunk;一律判断题)。每条给 `file:line` 与 diff 原文引用,
> 并补两个 triage 字段:**能否用现有测试框架写出一条会失败的测试**(能/不能/需要新 fixture)与
> **影响面**(仅本文件 / 跨票共享契约,后者点名哪些票依赖它)。
> 结尾一行汇总:硬违规 N 条 / 判断题 M 条 / 最严重一条是什么。**不修改任何文件。**
> 800 字以内。

## 4. 提示词 B:Spec 轴(一个 agent)

> 你是代码评审的 Spec 轴审查员。仓库 `/home/dr/fw`(git)。以最高思考强度审阅,输出中文。
>
> 范围:全量 `e9abefa...1bc0b0c`。**不通读 diff**,只查 §4 列出的跨票接缝。
> 先 `git -C /home/dr/fw log e9abefa..1bc0b0c --oneline` 建立票序,再按接缝读代码。
>
> 规格来源(先读):`issues/01..10*.md` 的 AC 勾选状态与 Comments(实现记录、取舍、移交边界)、
> ticket05..10-plan.md、`docs/adr/0012-host-controlled-investigation-lifecycle.md`、`spec.md` 的 User Stories 与
> Implementation Decisions。注意工单 Comments 已记录"实现时的取舍"与"移交给后续票的边界"。
>
> 重点**不是**重验各票 AC(已验过),而是**跨票不变量**。逐项检查并在汇报里明确给出"通过/有问题":
> 1. lifecycle_status / disposition / stop_reason 三轴在 recon→analysis→verification 全链是否闭合
>    (每个终结路径的取值组合都合法、都有测试;`assert_terminal` 的守卫无绕过)。
> 2. Evidence ID 是否全运行唯一:两棵 Evidence 树(investigations/ 与 verifications/)+ 三处水位抬升
>    调用点(recon、analysis run_analysis、verification run_case)+ 恢复路径,拼起来有无重号窗口。
> 3. 恢复语义端到端的组合空档:analysis pending 工具重放、tool_started/interrupted/cache-validated 分流、
>    verification pending 收尾、results.json 短路、预算台账悬挂活动段——四种中断点组合是否都能续。
> 4. "只有 confirmed 产 Finding"链条:冻结案卷→Claim Result 校验→聚合→findings.json 幂等追加,
>    有无路径能产出未经独立证据支持的 Finding。
> 5. 预算记账口径三阶段一致:先计后执(attempt)、重生成只计 llm_calls、失败请求不计账、
>    active time 只计活动段。
> 6. 边界:brief §2 第 6/7 条列出的后续票范围不算缺失。
>
> 汇报格式:(a) 缺失/不完整的规格要求(引用工单或 ADR 行号);
> (b) scope creep(规格没要求但做了的);
> (c) 看似实现但可能实现错了的(引用规格行 + `file:line` + diff 原文);
> (d) §4 六项不变量的逐项结论。每条给 `file:line`,并补两个 triage 字段:
> **能否写出一条会失败的测试**(能/不能/需要新 fixture)与**影响面**(仅本文件 / 跨票共享契约)。**不修改任何文件。** 800 字以内。

## 5. 汇报与后续

- 两条轴**并列汇报、不合并、不重排**;同一问题被两轴同时提到是正常的。
- 建议执行者把结果写成一个文件(见 §6 的产物约定),再由用户带回主会话 triage:
  真问题走 implement 流程带测试修;判断题归档;命中"已定取舍"的直接丢弃。
- 评审 agent **不得自行修代码**:自审自改会丢掉"独立第二双眼睛"的价值。

## 6. 怎么跑(闲时任务不可用,用普通会话)

ZCode 的闲时任务当前有 bug、跑不了(用户 2026-09-16 确认),所以按普通会话执行:

- **一个会话跑一条轴**(Standards 一个会话,Spec 另一个会话),别在一个窗口里跑两条轴
  ——两轴必须不共享上下文,否则一条轴的结论会污染另一条。
- 或者:若该 harness 支持后台子代理/任务,就把 §3/§4 的提示词原样交给两个子代理并行,
  做完各回一份报告。
- 会话开头把只读纪律和 brief 路径一起给出去(见下方模板);两轴**产物分文件**
  (`review-findings-standards.md` / `review-findings-spec.md`,都在 `.scratch/` 下,git 忽略),
  这样两条轴可以**并行跑**而不互相覆盖。唯一禁止的并行是"一条轴读另一条的结论"。
- 每节开头写 `## <轴> · <日期> · HEAD <sha>`。

会话启动提示词模板:

```
只读任务,禁止任何写操作(git add/commit/stash/切分支一律禁止;工作树有用户未提交改动)。
读 /home/dr/fw/.scratch/step5-host-controlled-investigations/review-brief-01-10.md,
按 §1 的阅读范围与 §3(或 §4,二选一,不要两条轴同窗)的提示词执行。
结果写入 .scratch/step5-host-controlled-investigations/review-findings-<轴名>.md
(不要与其他会话共用同一个文件)。
不改任何代码:发现只写成 findings,修复由另一会话按 triage 结果做。
```

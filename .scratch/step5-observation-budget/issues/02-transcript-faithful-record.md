# 02: transcript 记录忠实化——删除 4000 字符记录截断

**What to build:** transcript.jsonl 忠实记录进上下文的事件文本(assistant/tool/observation 三种事件一律记全文),不再有记录层 4000 字符截断。排查者从日志直接看到"LLM 实际看到了什么"——包括截断提示本身(它位于上下文文本 ~6000 字符处,此前恰好被 4000 记录线裁掉,2026-09-05 排查中被它二次误导)。与 obs/ 分工保持互补:transcript=实际所见,obs/=截断前原文(中间段只有 obs/ 有)。记录尺寸天然有界:observation 受新上限约束(≤16k/64k),assistant 回复受 max_tokens 约束,不改 JSONL 结构与事件类型。

**Blocked by:** 01(新增忠实性断言挂在 ReAct 端到端超限素材用例上,该用例先在 01 完成 16k 口径翻新,避免同一用例两次翻新——同文件顺序门)

**Status:** ready-for-human

- [x] ReAct 端到端缝:超限素材场景下,transcript 记录的 observation 与进上下文文本一致,截断提示完整出现在记录中
- [x] assistant/tool 事件长内容(超过 4000 字符)不再被记录层裁剪
- [x] 全套件绿(基线 176 passed + 2 skipped)

## Comments

**2026-09-06 实现完成(agent),待人工复核 → ready-for-human**

- 落点:`engine/transcript.py`(`Transcript.log` 删 `content[:4000]`,docstring 改记忠实性契约与尺寸有界依据)与 `engine/react_loop.py`(tool_call/tool 事件记完整 `raw_input`,删 `[:200]` 回显截断;`user_obs = f"Observation: {obs}"` 同一字符串既进上下文也进 observation 记录——逐字一致由结构保证,不再靠"前缀固定"约定)。编排层零改动:orchestrator 复用 `run_react_agent`(orchestrator.py:458),子 Agent 与编排 transcript 同一落点收口。
- 测试:断言挂在既有端到端超限素材用例 `test_truncate_headtail_and_obs_fulltext` 上(与 spec "三个现有缝,零新增"一致),Action Input 放大到 5000 字符使 assistant/tool_call/tool 事件超 4000;RED 实测 5 条新断言全红(recorded=4000 vs ctx=15371,截断提示缺失——即 2026-09-05 排查被二次误导的形态),实现后转绿;全套件 **270 passed + 11 skipped**(票01 后基线,skip 全为环境门控,零回归;清单末项"176 passed + 2 skipped"是 8 月基线,已过时)。
- 边界保持:obs/ 软折行 width=4000 是行宽不是内容裁剪,不动(spec Out of Scope);"user" 相位系统注记事件(协议错误回喂/同参干预等)不在工单三种事件之列,维持摘要式留痕。
- code-review(双轴)结论:Standards 无硬性违规 / Spec 可放行。落实一条:`f"{name}({raw_input})"` 回显提为 `call_echo` 局部变量(tool_call/tool 两事件同串复用,消除本 diff 放大的重复构造)。两条转出:①observation 事件 content 现带 `Observation: ` 前缀(实现逐字一致的手段),格式语义记入票 03 文档补充项;②"user" 注记事件仅剩 `[同参循环干预] {key[:160]}` 一处截断,key 可由 tool_call 全文重建,残差极小不值得单开工单,如需收敛随票 03 顺带定夺。

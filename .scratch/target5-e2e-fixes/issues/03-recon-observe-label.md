# 票03:recon 显示标签改"观察点"(显示层,非提示词)

Status: ready-for-human
Claimed: 2026-09-11 (agent, /implement)
Date: 2026-09-11
Origin: target/5 e2e 实测 P3(spec: .scratch/target5-e2e-fixes/spec.md)

## 问题(根因已实锤)

recon v3 明令禁止 findings 字段(CONTEXT.md 词汇纪律),但终端完成行显示
`survey.json · 11 findings`。根因:`runner.py:205` recon 分支拿 `high_risk_areas` 数量(11),
却在 `runner.py:214/218` 与 `engine/display.py:175/206` 按 findings 标签渲染——代码违反术语表,
误导运行判读(e2e 时一度被误读为守护被绕过)。

## 需求(grilling Q3 定稿)

recon 分支的完成行与任务简报文案改用"观察点"计数标签(数据源不变,仍是 high_risk_areas 数量);
analysis/verification 的 "findings" 标签不动。纯显示层改动,**提示词一行不动**。

## 改动点

- `runner.py` recon 分支两处文案(约 :205-218)
- `engine/display.py` 完成行标签随调用方传入(或 recon 专属文案),:175/:206 附近

## 验收

- recon done/简报输出含"观察点"、不含 "findings";analysis/verification 输出不变
- 既有 display 守护测试(display_none 零侵入)不回归;新增标签断言

## Comments

**2026-09-11 实现完成(agent),待人工复核 → ready-for-human**(commit 78f8171)

- 落点:①`engine/display.py` `done()` 加 `label` 参数(默认 "findings";参数 `findings` 更名 `count`,三个调用点 runner/orchestrator/demo 全按位置传参零波及;NullDisplay `*a, **k` 万能签名,display_none 零侵入不破);`_final_summary`(结论行,:206)加 `high_risk_areas` 观察点分支,findings 载荷优先——recon survey 载荷报 "N 观察点(详见工件)"。②`runner.py` recon 分支:`is_recon` 一次判定,disp.done 传 `label="观察点"`,回退打印 "N 个观察点"(analysis/verification 回退文案逐字不变)。
- "简报文案"的落点判定:结论行(`_final_summary`)与回退打印各对应工单改动点 :206/:218;handoff.py 交接块的 "findings N 条" **未改且不应改**——它是注入子 Agent 的提示侧文本(非终端显示层,改它违背"提示词一行不动"),数据源是 SubAgentResult.findings(analysis/verification 真 findings),且 spec Out of Scope 明言"显示层之外的词汇清扫"不做。
- 测试:`test_recon_observe_label`(先红:done 不认 label 参数;后绿:recon 完成行/结论行含"观察点"不含 findings,analysis 仍 findings,双键载荷 findings 优先)+ banner 端到端锚定 "recon 完成 · survey.json · 0 观察点";display 套件 13 用例含 display_none 零侵入守护全过。全量 **327 passed + 21 skipped** 零回归;提示词零改动。
- code-review 双轴:Spec 全过无 scope creep;Standards 采纳三条——DISPLAY.md 事件表与示例同步为观察点形态(demo_display 场景1 载荷同步改 v3 survey 形态,文档/示例/实现一致)、runner 同 hunk 三次 recon 判定收敛为 is_recon 一次、banner 断言从裸 "观察点" 加强为锚定 recon 完成行计数片段。

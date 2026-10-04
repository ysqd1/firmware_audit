# 票05:对账假警报双侧修——报告标题逐字复制红线 + 匹配模糊兜底

Status: ready-for-human
Claimed: 2026-09-11 (agent, /implement)
Date: 2026-09-11
Origin: target/5 e2e 实测 P6(spec: .scratch/target5-e2e-fixes/spec.md)

## 问题(根因已实锤,逐字符对照)

对账守卫按归一化标题**精确相等**匹配(`reconciliation.py:148` `findings_by_norm.get(norm_title)`)。
orchestrator 写报告时把 WebDAV 条目标题从 98 字符缩写成 67 字符(路径 `/etc_ro/lighttpd/lighttpd.user`
被删),4/7 条对不上钥匙 → unmatched=4 假警报。内容与 severity 实际零差异,守卫可信度受损。

## 需求(grilling Q6 定稿:方案 A 双侧修)

1. **提示词红线**:编排层系统提示词(报告生成方)新增——报告条目标题必须**逐字复制**
   verified finding 的 title,禁止缩写/改写/删路径。
2. **匹配兜底**:`reconciliation.py` 在归一化精确相等失败后,加模糊匹配——标题前缀一致
   或重合度 ≥0.8(如 difflib 序列重合度)视为同一 finding;仍失败才记 unmatched。
   file/severity/confidence/verified 的确定性比对语义**不变**(取值方仍是工件)。

## 改动点

- `data/prompts.py` 编排层系统提示词(红线一条)
- `orchestration/reconciliation.py` 匹配段(兜底函数保持纯函数、零 IO/零 LLM)

## 验收

- 先红:用 target/5 实测对照(67/98 字符标题)跑 reconcile,现状 4 条 unmatched
- 后绿:同输入 4 条全部 matched 且 checks 比对正常
- 反向用例:真不一致(标题完全不相关/排除条目)仍 unmatched;severity 改动仍 mismatch
- 提示词内容断言(红线文案存在);全量套件无回归

## Comments

**2026-09-11 实现完成(agent),待人工复核 → ready-for-human**(commit 90efd98)

- 落点:①红线在 `orchestration/orchestrator.py` 的 `_ORCH_TMPL` 报告写作纪律首条——工单改动点写的 `data/prompts.py` 是陈旧指针,编排层系统提示词真源在 `_ORCH_TMPL`(`data/prompts.py` 只有三个子 Agent 提示词),红线加在真源处;②匹配兜底在 `orchestration/reconciliation.py`:`_recon_fuzzy_title` 纯函数(前缀一致 ratio=1.0 / difflib 重合度 ≥0.8,多候选取最高,并列取先现),item 新增 `match`(exact/fuzzy/none)、summary 新增 `fuzzy` 计数留痕(标题漂移可见、不告警)。
- **超改动点的必要修复(解析器)**:分区头现会关闭当前打开的条目。真实 target/5 输入上,report.md 误报剔除区 `### ✗ fwupload...`(无编号 3# → 被当分区)的标签行把前一条目 rsstest 的 file/severity/confidence 全部串写污染成假 mismatch——精确匹配时代该污染被 unmatched 掩盖,模糊匹配后必然暴露,不修则验收"同输入 4 条全部 matched 且 checks 比对正常"不成立。fixture 按污染形态加锁断言(条目 6 紧邻 ✗ 分区,checks 逐一验证)。
- 先红后绿:红态实测(缩样 + 真实产物)——现状 4 条缩写全 unmatched(matched=1/unmatched=5);绿态——真实 target/5 产物 7/7 matched 全 ok(unmatched 4→0,fuzzy=4,含真不一致仍 unmatched、severity 错报仍 mismatch 反向用例)。
- 测试:`test_reconcile_fuzzy_title_fallback`(缩样 fixture,标题逐字取自实测产物)+ `test_orchestrator_prompt_reconcile_redlines` 扩四针;全量 **325 passed + 21 skipped** 零回归(skip 全为 Docker/STEP5_SMOKE 环境门控)。
- code-review 双轴结论:Standards 无硬违规(已顺手收敛:补返回注解、docstring 背景段去重);Spec 无实质缺件,`match`/`fuzzy` 留痕与解析修复判为合理必要。遗留提示(不阻塞):极短报告标题的前缀兜底在多 finding 前缀重叠时理论上有歧义,规格明文允许前缀兜底,暂不加长度下限,后续实测再说。

**2026-09-11 agent 只读复核(第二次 /implement 调用,未改代码)**

- 本票在早前会话已实现(90efd98),复核确认验收全绿:①`test_orchestrator.py` 50/50(`test_reconcile_fuzzy_title_fallback` 六项断言 + `test_orchestrator_prompt_reconcile_redlines` 四针红线文案);②真实 target/5 产物现跑 `reconcile_report`:report_items=7 / matched=7(exact 3 + fuzzy 4)/ ok=7 / mismatch=0 / unmatched=0 / unparsed=0;③全量套件 330 passed + 21 skipped(含本会话票04 后基线)。状态维持 ready-for-human,人工验收归用户。

**2026-09-11 端到端重跑验证(target/5 --force)**:对账零假警报——report_reconciliation.json matched=6/6 全 exact,unmatched=0、mismatch=0、fuzzy=0(标题逐字复制红线生效,模糊兜底未需启用);基线同文件 matched=3/**unmatched=4**(标题缩写假警报)。

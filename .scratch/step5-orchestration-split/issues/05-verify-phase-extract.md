# 05: 复核引擎下沉(verify_phase 模块)

Parent: ../spec.md

**What to build:** verification 每疑点一实例引擎(severity+confidence 排序取前 K、单实例断点续跑身份校验、复核结论锚点回填聚合、阶段终态判定与阶段级留痕)从编排主体迁出,成为独立模块 verify_phase——显式收依赖(子 Agent 配置/工作区/LLM/上游工件/聚合器/force)与留痕回调,返回阶段结果。编排主体只剩一处调用。引擎三块核心逻辑获得独立聚焦单测,不再必须构造整个 Orchestrator 才能测。

**Blocked by:** 04

**Status:** ready-for-agent

- [x] verify_phase 模块承接引擎;编排主体只留调用点与结果登记
- [x] 行为不变且被既有测试守护全绿:每疑点一实例调度语义、K 上限(env 可配)、排序规则、断点续跑身份校验(file+title 归一化比对,不一致弃工件真跑)、锚点回填只覆盖复核权威字段(verified/rationale/confidence/severity)、未进前 K 条目 verified=None 原样保留、LLMError 向上传播、interrupted 回填
- [x] 排序取 K / 续跑身份校验 / 锚点回填三块各有不依赖完整编排器的聚焦单测
- [x] 阶段级产物(聚合工件 verified_findings.json 的结构与内容、阶段 display 汇总行、dispatch_log 阶段记录)不变
- [x] 编排主体减约 250 行;全套件绿

## Comments

- 2026-09-05 T5 落地:新建 `orchestration/verify_phase.py`(364 行)——三块核心逻辑纯函数化:`rank_findings`(severity 主+confidence 次排序,rank 表自 actions 迁入并转正公开名 VERIFY_SEVERITY_RANK/VERIFY_CONFIDENCE_RANK,SummarizeTool 改从本模块导入,排序规则单一出处;T4 裁决 2 移交注记兑现)/`resume_identity_matches`(file+title 归一化身份校验,缺 func/addr 容忍)/`merge_verdicts`(锚点回填,只覆盖 verified/rationale/confidence/severity+溯源,未进前 K 原样);`_lift_verify_verdict`/`_run_verify_one` 随迁;阶段主入口 `run_verify_phase(cfg, *, agent_dir, process_dir, base_llm, upstream, findings, agg, force, dispatch_log, next_seq, budget_state, task, request, seq, t0)` 显式收依赖与留痕回调,返回 `VerifyPhaseOutcome(result/done/phase/instances)`;`DEFAULT_VERIFY_K`/`verify_k()`(原 `_verify_k` 转正,T4 STATUS_LABEL 同款)迁入。orchestrator.py 839→593 行(−246):`run_verification_phase` 只剩委托+登记(register/_verification_done/_verification_instances),LLMError 由引擎回填 interrupted 后原样上抛;imports 随迁清 iota(run_agent/build_verify_single_brief/LLMError/time/DispatchStatus 出,run_verify_phase/verify_k 进)。包内依赖单向 orchestrator → actions/verify_phase → …,verify_phase 不 import actions/orchestrator(打破潜在环,排序表因此必须落 verify_phase 而非反向借用);layer guard `test_orchestration_internal_edges` 守护面扩至 verify_phase。测试:新增 `test_step5_verify_phase.py`(3 聚焦单测,零 Orchestrator 零 LLM);`test_orchestrator.py` patch 字符串 `orchestrator.make_display`→`verify_phase.make_display`(spec 预告的 1 处)。全套件 259 passed + 11 skipped(T4 基线 255 + 新增 3 聚焦 + 新文件 test_main 收集项,skip 均为环境门控)。既有编排级测试(K env/排序/续跑错位弃用重跑/宽松匹配/顶层结论归一/severity 降级覆盖/未复核区段/阶段 display 汇总行/verification 只调度一次)照绿即回归锁定。

- 2026-09-05 纯搬家纪律记档(不顺手修,T6 候选):`_run_verify_one` 的 `task` 形参在收编前即无消费者(编排级 `task` 只进 dispatch_log 阶段记录),本次按纪律原样保留签名未删;T6 小刀群可顺手清。

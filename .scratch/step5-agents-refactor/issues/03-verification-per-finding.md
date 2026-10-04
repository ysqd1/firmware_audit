# 03: verification 每疑点一实例

**What to build:** verification 从"单实例多疑点"改为"每疑点一实例":analysis 产出 findings 后,按 severity(critical>high>medium>low>info)主排序 + confidence(high>medium>low)次排序,取前 K 条(默认 10,可配置);对每条取中 finding 派一个独立 verification 实例(输入=单条 finding + 相关工件指针,max_iters=8),逐条产单条 verified finding 聚合回 `verified_findings.json`。每条必被验证,补跑逻辑整体取消。上下文隔离铁律不破(每实例只从工件读,不传对话历史)。调度次数上限语义从"同类型最多 3 次"改为按 finding 计数(K 上限)。

**Blocked by:** 01(工具接口契约——契约稳定保证单条 verified 输出可靠)

**Status:** done

- [x] verification 调度语义改为每 finding 一实例(最多 K 次),输入=单条 finding + 工件指针
- [x] 排序:severity 主排序 + confidence 次排序,截前 K 条(默认 10,可配置)
- [x] 每实例 max_iters=8,输出=单条 verified finding
- [x] 聚合:K 条单实例输出合并为 `verified_findings.json`
- [x] 补跑逻辑取消
- [x] 流程级 `step5_run()` 测试:喂含 N 条 findings 的 fixtures → 断言 `verified_findings.json` 是 K 条、未进入 K 的 `verified=None`

> 实现说明(2026-09-01,ADR-0003):聚合 `verified_findings.json` 保留**全量 N 条**——前 K 条带 verified/rationale,未进前 K 的 `verified=None` + confidence 保留 analysis 初值(报告 04 据此划未复核区段)。verification 阶段由编排 LLM dispatch 触发,内部按 finding 逐实例派发;实例不进主 dispatch_log,明细在 `verification_instances`(result.json)+ 各自 transcript/obs。K=env `STEP5_VERIFY_K`(默认 10)。code-review 修复:confidence 次排序补测、未复核计数修正、degraded 不冒充 success、K 动态注入提示词、复核只回填 verified/rationale/confidence。

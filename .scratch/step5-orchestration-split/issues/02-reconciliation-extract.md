# 02: 报告对账出走(reconciliation 模块)

Parent: ../spec.md

**What to build:** 报告对账(解析 report.md 正文与 verified_findings 逐条比对、产出差异清单)的纯函数群从编排主体迁出,成为包内独立模块 reconciliation——照聚合器模块"纯逻辑下沉"的既有先例。编排主体只留"读盘→调用→落盘+stderr 告警"的薄 IO 壳。对账行为与差异清单结构一字不变。

**Blocked by:** 01

**Status:** ready-for-agent

- [x] reconciliation 模块承接对账纯函数群(报告解析、条目匹配、三枚举比对、状态聚合),零 IO 零 LLM 性质不变
- [x] 编排主体只留薄壳:读 report.md 与 verified_findings → 调用纯函数 → 差异清单落盘 + stderr 告警;对账的前置条件判断与失败旁路语义(缺失/读盘失败返回不阻塞)不变
- [x] 对账纯函数的既有直测(4 处)import 更新到新路径后全绿;差异清单字段结构不变
- [x] 编排主体模块行数显著下降(约 190 行迁出)
- [x] 全套件绿

## Comments

- 2026-09-05 T2 落地:`orchestration/reconciliation.py`(207 行,零 IO 零 LLM,仅 `import re`);编排主体 1675 → 1482 行(净迁出 193)。纯搬家机械验证:HEAD 原块 vs 新模块逐字 diff,唯一差异 1 行注释——`_ORCH_TMPL` 跨模块引用补"见 orchestrator 模块"指引(符号已不在同模块,照抄反而误导;属 T1 同款位置指针更正,已在 commit message 明示)。薄壳 `_reconcile_report` 41 行逐字节不变(评审 diff 复核 METHOD-IDENTICAL);测试 4 处 import 更新(lines 1835/1895/1949/2069),集成测试(Orchestrator.run 落盘+stderr)不改自绿;`reconcile_report` 移出 orchestrator `__all__`,不留 shim,全库 grep 无旧路径残留。ADR-0007 状态段补 T2 迁移注记(同 T1 更正 CONTEXT.md 先例);`orchestration/__init__.py` docstring 标记 T2 进度。全套件 249 passed + 11 skipped(与 T1 基线一致);pyflakes 干净。code-review 双轴:Spec 轴五项验收全过无阻塞;Standards 轴顺带发现编排主体 docstring "三枚举 + rationale 关键句包含" 为 2026-09-03 已过期的旧文案(先于本票存在)——按纪律记票 **issue 08**(建议并入 T6),不顺手修。


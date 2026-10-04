# 03: 调度日志收类(DispatchLog)

Parent: ../spec.md

**What to build:** 调度留痕成为独立小类 DispatchLog:接口只有 start / finish / interrupted / attempt 四个动词,调度日志的记录管理、status_history 变迁、dispatch_log.json 落盘知识全部收进类内;同时把散落在编排层的同类查询重复(已完成调度清单、同类型调度计数,各 3 处)收敛为单一出处。dispatch_log.json 的字段结构与落盘内容完全不变。

**Blocked by:** 02

**Status:** ready-for-agent

- [x] DispatchLog 落地,四动词接口;内部拥有日志记录与落盘(含 mkdir),编排层不再直接拼日志记录 dict
- [x] "已完成/实际执行的调度清单"与"同类型调度计数"两类重复查询收敛为单一出处,各消费点改走它
- [x] dispatch_log.json 结构与字段不变:既有测试对日志内容的断言照绿(running 记录回填终态、拒绝/重复留痕、budget_state 附加)
- [x] 四动词接口直测落地:状态变迁、status_history、落盘内容——不构造 Orchestrator 即可测
- [x] 编排主体减约 5 个方法;全套件绿

## Comments

- 2026-09-05 T3 落地:`orchestration/dispatch_log.py`(新模块,包内叶子)——DispatchLog 四动词接口(start/finish/interrupted/attempt),记录管理、status_history 变迁、dispatch_log.json 落盘(含 mkdir)全部收进类内;编排主体删 5 个日志方法(_write_dispatch_log/_log_start/_log_finish/_log_interrupted/_log_attempt),17 处调用点改走四动词,不再拼记录 dict。方法体原样搬迁(仅内部改名 _records/_flush/_dir),dispatch_log.json 结构与字段逐字不变,既有 orchestrator 测试不改自绿。查询收敛:已完成调度清单(EXECUTED 过滤;summarize/交接块/交接快照 3 处)与同类型调度计数(5 处,票面"各 3 处"为勘察低估)收敛为 `Orchestrator._executed_dispatches()` / `_agent_call_count()` 单一出处,8 个消费点全部改走;剩余 `_dispatches` 直用均属守卫/序列化(归 T4/T6)。直测:`test_step5_dispatch_log.py` 5 项(四动词状态变迁/status_history/落盘内容/budget_state·duplicate_of 条件键,零 Orchestrator)+ 字面量漂移守护。全套件 255 passed + 11 skipped(T2 基线 249+11,增量恰为新测试 6 个收集项);pyflakes 干净。设计取舍:dispatch_log.py 不 import 编排主体(spec 包内方向"orchestrator → 各模块,禁止反向",反向 import 成环),模块内自持 `_RUNNING`/`_INTERRUPTED` 落盘字面量(值即 dispatch_log.json 契约值)+ 漂移守护测试锁值,T4 state 落地时收编(移交注记已追加到票 04);`_now` helper 照 spec"小格式化 helper 留在消费者旁"原地保留一份。"减约 5 个方法"口径:删 5、增 2(增 2 是本票验收 2 的查询收敛要求),类方法 36→33 净 −3。code-review 双轴:Spec 轴四项实质验收全过无阻塞;Standards 轴 3 条 judgement call——修 2(测试重复块合并;docstring 规则引用从 ADR-0009 改指 spec,ADR 原文"包内边不受限",叶子约束出自 spec),留 1(日志区段单行去向注释,迁移期导航用,T4 消化)。


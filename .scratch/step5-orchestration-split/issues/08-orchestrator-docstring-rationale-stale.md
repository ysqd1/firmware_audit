# 08: orchestrator.py 模块 docstring 对账描述过期(rationale 检查早已移除)

Parent: ../spec.md

**What to build:** `orchestration/orchestrator.py` 模块 docstring 的报告对账条目仍写
"逐条比对(severity/confidence/verified 三枚举 **+ rationale 关键句包含**)"——
rationale 关键句检查已于 2026-09-03 移除(commit addd229,对账只核确定性事实,
ADR-0007 用户决策),moved 代码与新模块 reconciliation.py 的注释都已如实陈述
"rationale/evidence 内容不检查",唯独编排主体 docstring 这一句未同步。

**来源:** T2 搬家 code-review(Standards 轴)顺带发现;按纯搬家纪律记票不修
(先于本票存在,非搬家引入)。

**Blocked by:** None

**Status:** done

- [x] 修正该句为"三枚举比对"(去"rationale 关键句包含"),或直接引用
      reconciliation 模块的确定性事实口径
- [x] 建议并入 T6 小刀群(同批文档清扫:AGENTS.md 目录树定稿、tools_summary
      路径漂移 issue 07)一并处理

## Comments

- 2026-09-05 已随票 06 处理(采纳本票"并入 T6"建议):docstring 对账条目改为
  "逐条比对确定性事实(severity/confidence/verified 三枚举;rationale/详情
  内容不检查)",与 reconciliation 模块注释口径一致(commit addd229 后的现行
  语义)。

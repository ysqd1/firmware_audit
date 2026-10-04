# 07: tools_summary.md 编排层模块路径漂移(T1 迁移途中发现)

Parent: ../spec.md

**What to build:** `firmware_audit/docs/tools_summary.md` 是 AGENTS.md 引用的活文档,仍有三处把编排层工具所在地写为旧路径 `step5_agent/orchestrator.py`(L53 归属表、L1072 章节锚点 + 标题、L1142 小节标题;L33 目录锚点随 L1072 标题联动)。T1 已把该模块迁至 `step5_agent/orchestration/orchestrator.py`(ADR-0009),文档未跟进。按 spec 迁移纪律"发现的可疑点记票不顺手修",不在 T1 修。

建议:T6 本就负责"AGENTS.md 目录树定稿"等文档定稿,可把本文件的路径词条并入 T6 一并清扫;或单独小票处理。顺带核对 `firmware_audit/docs/` 下其余活文档是否有同款旧路径引用(BUGFIX-*.md 等带日期的历史快照不改)。

**Blocked by:** None(建议并入 06)

**Status:** done

## Comments

- 2026-09-05 已随票 06 处理(采纳本票"并入 T6"建议):四处落点全部更正——
  L33 目录锚点、L53 归属表(`step5_agent/orchestration/actions.py`,三动作
  工具类 T4 起在此)、L1072 章节标题、L1142 小节标题(`orchestration/` 包 +
  `runner.py`)。顺带清扫:`firmware_audit/docs/` 其余活文档 grep 无同款旧
  路径残留(带日期历史快照未动);DISPLAY.md 三处 demo 命令随 T6 demos/ 迁移
  一并更新。

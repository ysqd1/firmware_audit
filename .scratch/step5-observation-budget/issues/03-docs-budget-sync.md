# 03: 文档口径同步——8KB→16k/64k 与 per-tool 覆盖机制

**What to build:** 文档与代码注释的 Observation 预算口径与新值一致(全局 16000 / summarize 护栏 64000 / per-tool 可选覆盖属性),新读者不再读到"小窗口时代"遗留的 8KB 描述。范围:AGENTS.md 全部 Observation 预算相关描述(上下文管理、工具层、实测踩坑等处)、CONTEXT.md 的 Observation 词条核对、演示脚本与终端显示注释里的过时 8KB 字样。纯文档票,零行为变更。

**Blocked by:** 01(数值定稿后才好同步;02 无文档面,不构成依赖)

**Status:** ready-for-human

- [x] AGENTS.md 全部 Observation 预算描述更新为 16k/64k 口径,并注明 per-tool 覆盖机制(summarize 64k 护栏的依据一句话留痕)
- [x] CONTEXT.md Observation 词条与新口径一致(词条若无数值则确认即可)
- [x] 代码内过时注释修正(演示脚本">8KB"字样、终端显示层注释等)
- [x] 全库 grep 无旧口径残留(历史测试报告、ADR 等历史文档除外)
- [x] 全套件绿(基线 176 passed + 2 skipped)

## Comments

**2026-09-06 票02 评审转来的补充项(agent)**

- AGENTS.md"已定:transcript 落盘与测试"节建议补一行记录忠实化语义(票02 落地后的新契约):transcript=实际所见(记录层零截断;observation 事件 content 含 `Observation: ` 前缀,与进上下文 user 消息逐字一致;assistant 事件含 reasoning+reply),obs/=截断前原文,二者互补。
- 本票第 5 行基线同票01/02:实际以 270 passed + 11 skipped(环境门控 skip)为准。

**2026-09-06 实现完成(agent),待人工复核 → ready-for-human**

- 提交 5914217,7 文件:AGENTS.md(截断 bullet/ToolResult 注释/工具表 read_file 行/不丢证据 bullet 四处 8KB → 16000 字符 + per-tool 覆盖 + summarize 64k 依据一句话留痕;transcript 节补忠实化语义一行);rules.md ToolResult 约定(顺手补上该句缺失的 raw 字段);tools_summary.md 两处;`engine/display.py:149`、`engine/transcript.py` docstring(折行失效阈值脱钩具体数值)、`demos/demo_display.py` 与 `test/test_step5_react.py` 的 BigTool docstring(16KB 字节→16k 字符混用一并消灭)。
- CONTEXT.md Observation 词条确认无数值,按工单口径仅确认;requirements.md(头部明示 2026-08-16 需求快照)、docs/progress-report-*.md、ADR、test-fix-reports 按历史文档排除;二进制嗅探"前 8KB 含 NUL"与分区 4KB 为不同机制,刻意不动。
- code-review 双轴通过后落实三条小修:rules.md 字段表补 raw、工具表"≤16k"统一为"≤16000 字符"、demo/测试 BigTool docstring 字节→字符。全套件 **270 passed + 11 skipped**(提交前后各跑一次)。

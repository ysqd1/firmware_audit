# 01: Observation 预算修订——全局 16k + per-tool 覆盖机制 + summarize 64k 护栏 + 素材文案修正

**What to build:** orchestrator 调 summarize 取报告写作素材时,素材在 64,000 字符以内全量进入 Observation(2026-09-05 target/1 事故的直接修复:9 条 finding 的 confidence/rationale/evidence 不再被截在中间段);其余全部工具的 Observation 上限由 8000 升至 16000 字符(大型反编译函数少烧 read_file 回读轮次);summarize 素材文案不再向 orchestrator 承诺它没有的 read_file 回读。机制与数值同票落地:工具基类新增可选覆盖属性(None=用全局默认,SummarizeTool 声明 64000),截断行为模型(头 75%/尾 20%/省略提示含总量与 obs 回读路径/全文落盘 obs/)完全不变。

**Blocked by:** None (can start immediately)

**Status:** ready-for-human

- [x] 纯函数缝:恰 16000 字符不截断;超长按头 75%/尾 20% 保留,省略提示含全文总量与 obs 回读路径
- [x] 工具基类可选覆盖属性生效:未声明时用全局默认 16000,声明 64000 的 summarize 按 64000 截断
- [x] 编排层缝:summarize 素材 ≤64k 全量进 Observation(现有"素材被截"回归场景翻转)
- [x] 编排层缝:summarize 素材 >64k 触发护栏截断(异常规模兜底)
- [x] 编排层缝:summarize 素材文案不再含"read_file 可查"表述
- [x] ReAct 端到端缝:超限素材用例改 16k 口径(加大素材,MIDDLE_LOST 定位断言随头尾切分点更新)
- [x] 全套件绿(基线 176 passed + 2 skipped)

## Comments

**2026-09-06 实现完成(agent),待人工复核 → ready-for-human**

- 落点:`providers/tools/base.py`(`MAX_TEXT_CHARS=16000` + `AgentTool.max_text_chars` 覆盖属性 + `text_limit` 解析 + `_finalize` 统一收尾)与 `orchestration/actions.py`(`SummarizeTool.max_text_chars=64000`、素材文案改"素材已在本 Observation,无需回读")。
- 测试:+3 新用例(基类覆盖缝 `test_per_tool_truncation_override`、编排层 `test_summarize_material_under_64k_full` / `test_summarize_material_over_64k_guardrail`),既有边界用例与 ReAct 端到端用例(BigTool 素材 8019→17019,obs 回读 offset 1→3、折行 5 行)同步 16k 口径;全套件 **270 passed + 11 skipped**(skip 全为 Docker 镜像 ×9 + STEP5_SMOKE ×2 环境门控,零回归)。清单末项的"176 passed + 2 skipped"是 8 月基线数字,已过时,以本次实测为准。
- code-review(双轴)后顺手落实三条:①两处 execute 收尾三行提取 `AgentTool._finalize` 消除同步点;②64k 依据注释收敛到 SummarizeTool 声明点,基类留引用;③SummarizeTool 64000 钉值断言从 react 引擎层测试移到编排层 guardrail 用例。
- 给票 03 的注记:`demos/demo_display.py` 的">8KB"字样与素材尺寸(8019→17019,否则 16k 下演示不再触发截断)已由本票前置完成,票 03 只需核对剩余文档口径(AGENTS.md 四处 8KB、`engine/display.py:149` 注释等)。

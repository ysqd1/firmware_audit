# 06: 全流程测试补强

**What to build:** 三个测试 seam 覆盖 4 个 ADR 的行为:
- **流程级 `step5_run()`**:verification 每疑点一实例的聚合结果(verified_findings.json 是 K 条)、未复核区段、planner 参数移除。
- **工具级 `execute()`**:对每个工具构造非法参数调用,断言 `ok=False` + 优雅错误文本。
- **LLM 级 `chat()`**:content 空 + reasoning 非空 → 续写触发 + 返回续写 content;续写失败 → 降级重试。

只测外部行为,不测实现细节;prior art 为既有 `test/test_step5_tools.py`(工具契约)、`test/test_step5_llm.py`(llm 打桩)、`test/test_step5_react.py`(流程级)。

**Blocked by:** 01、02、03、04、05(全流程测试覆盖所有 ADR 行为,需实现完成后补)

**Status:** done

- [x] 流程级:verified_findings.json 是 K 条、未复核进独立区段、planner 参数移除
- [x] 工具级:每个工具非法参数 → `ok=False` + 优雅错误文本
- [x] LLM 级:续写触发 + 返回续写 content;续写失败降级重试
- [x] 只测外部行为,不测实现细节

> 实现说明(2026-09-01):三个 seam 的测试在先前 ADR 落库时已基本齐备——
> 工具级 `test_step5_tool_contract.py::test_every_tool_rejects_invalid_params`(15 工具
> 未知/类型/缺失必选 → ok=False + 优雅文本)、LLM 级 `test_step5_llm.py`(续写触发 +
> 返回续写 content + 失败降级)、流程级 `test_step5_pipeline.py` 与 `test_orchestrator.py`
> (K 条聚合/planner 移除)。**措辞澄清(code-review 追认)**:spec 的"verified_findings.json
> 是 K 条"实指"含恰好 K 条**已复核**(其余 verified=None 保留,全量 N 条落盘)"——
> ADR-0003 落地时已如此实现(未复核保留供报告独立区段),prior art 测试一致断言全量 N。
> 本票补齐两个缺口:
> 1. **流程级未复核区段**:新增 `test_step5_pipeline.py::test_unreviewed_section_through_step5_run`
>    ——从公开 `step5_run()` 入口驱动全流程,断言 `verified_findings.json` 全量 N 条、
>    已验证 K 条、未复核 verified=None + confidence 保留初值,且最终 report.md 含
>    独立未复核区段(⚠/未经复核标注),与 Orchestrator-seam 用例互补。
> 2. **窄编码显示降级**:修复 `engine/display.py::_emit`——Windows 默认 GBK 控制台页打
>    ✓/⚠ 会抛 UnicodeEncodeError 中断整条管线(独立测试模式实发),违反"显示失败也不
>    改变 Agent 行为"契约;现按输出流编码替换不可编码字符后重打。回归测试
>    `test_step5_display.py::test_emit_narrow_encoding_degrades` 用真实 GBK 流验证
>    (中和修复后必红,已证)。

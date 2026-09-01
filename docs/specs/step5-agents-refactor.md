# Spec:Step5 Agents 框架与工具设计重构

> 本 spec 由 `grill-with-docs` 访谈产出,4 个 ADR(0003-0006)为决策依据,术语遵循 `CONTEXT.md`。测试 seam 已与用户对齐。

## Problem Statement

Step5 是 LLM 驱动的审计阶段,由一个 orchestrator 编排三个子 Agent(recon→analysis→verification)。当前存在四类问题:

1. **verification 轮次摊薄**:单实例接收全部 findings.json、在 24 轮内逐条复核,每条 finding 约需 3-6 轮,13 条就需要约 52 轮 >> 24 上限,长尾疑点复核不完(e2e 中 verification 未完整跑,API 307 是主因,但轮次摊薄是结构缺陷)。
2. **工具接口契约缺口**:`params_doc` 全是自由散文、无类型/必选/枚举声明;`execute` 侧无统一参数校验,必选参数靠 `TypeError` 兜底、未知参数靠 `**kw` 吞或报异常。recon 曾把 `recursive` 传给 `read_file`,semgrep 收到拼碎的 JSON——工具层兜住了(失败不崩),但 LLM 收到的是 Python 异常文案,§7#2 的畸形调用持续发生。
3. **reasoning 溢出**:推理模型(deepseek-v4-flash/mimo)的思考与正文共享 max_tokens(默认 16384),思考烧满预算时 content 为空、`finish_reason=stop`。08-30 已把正文/思考拆分,但根因未解——靠重试兜底,重试 3 次仍空则抛 LLMError 终止整个 Step5。
4. **双分支维护成本**:`planner="pipeline"` 确定性快速模式与 LLM 编排(auto)写同一份调度逻辑两遍,且不产报告。编排 LLM 既然保留,它的省轮次价值被压缩,双分支纯属负担。

## Solution

从用户视角,重构后的 Step5:

- **verification 每疑点一实例**:analysis 产出 findings 后,按 severity(主)+confidence(次)排序,取前 K 条(默认 10,可配置),对每条派一个独立 verification 实例(轮次上限 8),逐条产 verified finding 聚合回 `verified_findings.json`。未进入前 K 的疑点进报告独立区段(⚠ 未复核),`verified=None`,confidence 保留 analysis 初值。每条必被验证,补跑逻辑整体取消。
- **工具接口契约结构化**:params_doc 从自由散文改为结构化规格(声明侧),`base.execute` 加统一参数校验(执行侧),A+B 闭合根治畸形调用。
- **LLM token 稳健**:max_tokens 16384→32768,content 空 + reasoning 非空时截断续写(把 reasoning 回传 API 接续,不进 ReAct 上下文),跳出"重新想又烧满"循环。
- **删除 pipeline 模式**:`planner` 参数移除,step5_run 只剩 LLM 编排一条路径。

## User Stories

### verification 每疑点一实例(ADR-0003)

1. As an auditor, I want analysis 的 findings 按 severity 排序后取前 K 条进行复核, so that 高危疑点优先被验证。
2. As an auditor, I want confidence 作为次级排序, so that 同 severity 下证据更充分的疑点先被验证。
3. As an auditor, I want K 可配置(默认 10), so that 我可以根据预算调整复核深度。
4. As an auditor, I want 每条 finding 有独立的 verification 实例(轮次上限 8), so that 复核聚焦、不摊薄。
5. As an auditor, I want 每条 finding 产单条 verified finding 聚合回 `verified_findings.json`, so that 结果可追溯、可审计。
6. As an auditor, I want 未进入前 K 的疑点不丢弃、进报告独立区段(⚠ 未复核), so that 报告不掩盖"有疑点未复核"的事实。
7. As an auditor, I want 未复核疑点的 `verified=None`、confidence 保留 analysis 初值, so that 读者知道这不是复核后结论。
8. As an auditor, I want verification 可修改 confidence(存疑项降级保留), so that 复核能反映证据充分度变化。
9. As an auditor, I want 补跑逻辑取消, so that "每条必跑"取代"预算耗尽再补跑"的柔性判断,疑点不漏。

### 工具接口契约(ADR-0004)

10. As an agent, I want params_doc 是结构化规格(参数名→类型/必选/默认/枚举), so that 我看清准确参数规格、少填错。
11. As an agent, I want `execute` 按声明校验参数(未知键/类型/缺失必选), so that 我收到优雅错误而非 Python 异常文案。
12. As an auditor, I want read_file 收到 `recursive` 返回"未知参数已忽略,合法:path/offset/limit", so that 畸形调用被优雅拦截而非 TypeError。
13. As an agent, I want 未知参数被过滤而非抛异常, so that 我能从错误信息自纠、继续流程。

### LLM token 稳健(ADR-0005)

14. As an agent, I want max_tokens 从 16384 提到 32768, so that 思考有翻倍空间、正文必然有位置写。
15. As an agent, I want content 空 + reasoning 非空时截断续写, so that 思考烧满预算时不判空回复硬重试,而是接续上次思路直接给结果。
16. As an agent, I want 续写把 reasoning 回传 API(不进 ReAct 上下文), so that "思考不参与协议"原则不受影响。
17. As an auditor, I want 续写请求失败降级为普通重试, so that 供应商不兼容时不阻塞流程。

### 删除 pipeline 模式(ADR-0006)

18. As a maintainer, I want `planner` 参数移除, so that 只有 LLM 编排一条路径、无双分支维护成本。
19. As a maintainer, I want 不再有"不产报告"的快速模式, so that 所有 Step5 运行都产出报告、无告警歧义。

## Implementation Decisions

### 决策 1:verification 每疑点一实例(ADR-0003)

- verification 由"单实例多疑点"改为"每疑点一实例"。调度语义从"verification 一次调度"变为"verification 最多 K 次调度(每 finding 一次)"。
- 排序:severity(critical>high>medium>low>info)主排序 + confidence(high>medium>low)次排序,从高到低,截前 K 条。
- K 可配置(默认 10),走既有配置机制(环境变量/profile)。
- 每个 verification 实例:`AgentConfig` 实例、跑 `run_react_agent`、max_iters=8、输入=单条 finding + 相关工件指针、输出=单条 verified finding。
- 聚合:新增聚合逻辑,把 K 条单实例输出合并为 `verified_findings.json`。
- 未进入 K 的 finding:保留在 findings.json,`verified=None`;报告生成时进独立区段(⚠ 未复核),confidence 保留 analysis 初值。
- 上下文隔离铁律不破:每实例只从工件读,不传对话历史。
- 调度次数上限语义变更:现"同类型最多 3 次"不再适用,改为按 finding 计数(K 上限)。
- 补跑逻辑整体取消。

### 决策 2:工具接口契约结构化(ADR-0004)

- 每个工具新增参数声明(声明侧):参数名 → 类型/必选/默认/枚举。用 dict 声明,零新依赖(不引 pydantic/JSON Schema 库)。
- `base.execute` 加统一参数校验钩子(执行侧):按声明校验未知键/类型/缺失必选。
- 未知参数 → 优雅返回"未知参数 X 已忽略,合法:...",而非 Python 异常。
- 类型错误 → 明确提示期望类型 vs 收到类型。
- 缺失必选 → 明确列出缺哪些必选参数。
- params_doc 从散文改为结构化声明(与校验共享同一份声明,单一来源)。
- 涉及工具:read_file, list_files, search_code, strings_query, imports_query, find_decompiled_function, checksec, cve_bin_tool_scan, semgrep_scan, gitleaks_scan, sandbox_verify, binwalk_rescan, xref_query, cve_lookup, web_search。

### 决策 3:LLM token 稳健(ADR-0005)

- `DEFAULT_MAX_TOKENS` 16384→32768(env `LLM_MAX_TOKENS` 仍可覆盖)。
- `chat()` 内 content 空 + reasoning 非空 → 截断续写:构造续写请求(assistant 消息带 reasoning_content + "直接给最终答复,别展开思考"的 user 提示),用原 max_tokens 再调一次。
- 续写只回传 API 接续,不进 ReAct 上下文(messages 四分区)/长期记忆,`chat()` 对上层透明。
- 续写请求失败(400 等)→ 降级为普通重试,不阻塞。

### 决策 4:删除 pipeline 模式(ADR-0006)

- 移除 `planner` 参数、pipeline 分支、`record_failed` 的非 run 用法。
- step5_run 只剩 LLM 编排一条路径。
- 相关测试更新(若存在 pipeline 专项)。

## Testing Decisions

测试目标:**只测外部行为,不测实现细节。** 好的测试是:给定可构造的输入(工件 fixtures),断言可观察的输出(工件内容/错误文本),不关心内部循环怎么跑。

### Seam 1:流程级 `step5_run()`(ADR-0003/0006)

- **测什么**:verification 每疑点一实例的聚合结果、未复核区段、planner 参数移除。
- **方法**:喂含 N 条 findings 的 fixtures → 断言 `verified_findings.json` 是 K 条、未进入 K 的进报告独立区段、`verified=None`;断言 `step5_run` 不再接受 planner 参数。
- **prior art**:既有 `test/` 下 `step5_run` 相关测试(双模式测试、conftest 的 process_dir/tools fixture)。

### Seam 2:工具级 `execute()`(ADR-0004)

- **测什么**:参数校验——未知参数/类型错误/缺失必选,断言返回优雅错误文本而非异常。
- **方法**:对每个工具构造"非法参数"调用 → 断言 `ToolResult.ok=False`、`error` 含"未知参数/期望类型/缺失必选"。
- **prior art**:`test/test_step5_tools.py` 既有工具测试(含 read_file None 缺参 guard)。

### Seam 3:LLM 级 `chat()`(ADR-0005)

- **测什么**:content 空 + reasoning 非空 → 触发续写;续写返回 content;`chat()` 对上层透明。
- **方法**:ScriptedLLM 打桩返回"content 空 + reasoning 非空"→ 断言 chat() 发起续写请求并返回续写后的 content;续写请求失败 → 断言降级为重试。
- **prior art**:`test/test_step5_llm.py` 既有打桩 urlopen/sleep 测试。

## Out of Scope

- 不改 recon/analysis 的工具分配(ADR-0006 决定保留现状,双遍扫描是可信度来源)。
- 不改纯文本 ReAct 协议(Q2 决定保持,协议漂移靠 08-30 解析兜底)。
- 不做编排统计落盘(Q3 决定,transcript/obs 已留痕)。
- 不换 function calling(Q2 决定,排除不支持 tools 的推理模型)。
- 不加 verified_scale 枚举(Q9 决定,verified=None + 报告标注已够)。
- 不处理 API 307 等基础设施故障(ADR-0002 已覆盖)。
- 不引入新依赖(铁律:零第三方依赖)。

## Further Notes

- 每个 ADR 是独立决策单元,实现时可按 ADR 拆分 ticket(0003/0004/0005/0006 各自独立)。
- K 值、每实例轮次上限、max_tokens 均可配置,运行时调整不改代码。
- API 调用量上升(K=10 × 8 轮 ≈ 80 vs 原 24)是"可信度优先"的合理代价,用户已知悉。

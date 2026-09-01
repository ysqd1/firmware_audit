# 0004-Step5 工具接口契约结构化

§7#2 的根因:工具 `params_doc` 全是带 JSON 示例的自由散文,无类型/必选/枚举声明;`execute` 侧无统一参数校验,必选参数全靠 Python `TypeError` 兜底、未知参数全靠 `**kw` 静默吞或报异常。recon 曾把 `recursive` 传给 `read_file`(`TypeError: _run() got an unexpected keyword argument 'recursive'`),semgrep 收到拼碎的 JSON。工具层 execute 兜住了(失败不崩),但 LLM 收到的是 Python 异常文案,无参数过滤/忽略机制。

改为**接口契约 A+B 都做**:

- **声明侧(A)**:`params_doc` 从自由散文改为结构化规格(每工具一个 dict 声明参数名→类型/必选/默认/枚举)。不进提示词时拼成清晰文本,LLM 看到准确的参数规格,从源头减少填错。
- **执行侧(B)**:`base.execute` 加统一参数校验钩子,按每工具的参数声明校验未知键/类型/缺失必选。`recursive` → 优雅返回"未知参数 recursive,已忽略;合法参数:path/offset/limit",而不是 Python 异常。

## 决策理由

- A、B 是"同一件事的两半":声明侧让 LLM 少错,执行侧让偶发错误优雅拦截,必须同步才闭合。单做 A 是"契约说清楚了但没强制",单做 B 是"校验器但契约没说清楚"。
- 零新依赖铁律可守住:用 dict 声明参数规格,不引 pydantic/JSON Schema 库。
- 这是对"为协议漂移付过的学习成本"的根治——§7#2 的畸形调用本质是契约没声明清楚 + 没强制,而非 LLM 能力问题。

## 代价

每个工具补一份参数声明(dict)+ base.execute 加校验逻辑。改动集中在工具层与 base,ReAct 循环无感知(execute 接口不变)。

## 状态

已定,待实现(2026-09-01)。实现见 to-spec 生成的 spec / tickets。

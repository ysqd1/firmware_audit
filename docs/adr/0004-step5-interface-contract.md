# 0004-Step5 工具接口契约结构化

§7#2 的根因:工具 `params_doc` 全是带 JSON 示例的自由散文,无类型/必选/枚举声明;`execute` 侧无统一参数校验,必选参数全靠 Python `TypeError` 兜底、未知参数全靠 `**kw` 静默吞或报异常。recon 曾把 `recursive` 传给 `read_file`(`TypeError: _run() got an unexpected keyword argument 'recursive'`),semgrep 收到拼碎的 JSON。工具层 execute 兜住了(失败不崩),但 LLM 收到的是 Python 异常文案,无参数过滤/忽略机制。

改为**接口契约 A+B 都做**:

- **声明侧(A)**:`params_doc` 从自由散文改为结构化规格(每工具一个 dict 声明参数名→类型/必选/默认/枚举)。不进提示词时拼成清晰文本,LLM 看到准确的参数规格,从源头减少填错。
- **执行侧(B)**:`base.execute` 加统一参数校验钩子,按每工具的参数声明校验未知键/类型/缺失必选。`recursive` → 优雅返回"未知参数 recursive;整份调用已拒绝且未执行,不产生任何 Observation 或状态变化。合法参数:path/offset/limit",而不是 Python 异常。(票 27,2026-09-25:反馈措辞从"已忽略"改为明示整份未执行——"已忽略"会让模型误以为参数被丢弃后其余部分仍生效。)

## 决策理由

- A、B 是"同一件事的两半":声明侧让 LLM 少错,执行侧让偶发错误优雅拦截,必须同步才闭合。单做 A 是"契约说清楚了但没强制",单做 B 是"校验器但契约没说清楚"。
- 零新依赖铁律可守住:用 dict 声明参数规格,不引 pydantic/JSON Schema 库。
- 这是对"为协议漂移付过的学习成本"的根治——§7#2 的畸形调用本质是契约没声明清楚 + 没强制,而非 LLM 能力问题。

## 代价

每个工具补一份参数声明(dict)+ base.execute 加校验逻辑。改动集中在工具层与 base,ReAct 循环无感知(execute 接口不变)。

## 状态

已实现(2026-09-25,票 27 闭环):

- **声明侧(A)送达**:`role_tool_contract(role)`(`providers/tools/__init__.py`)从注册表与 `render_params_doc` 渲染各角色已授权工具的名称/用途/参数规格,导入期拼入三角色系统提示词(占位符 `{{TOOL_CONTRACT}}`,与 Related Candidate 契约同一装配模式);未授权工具不出现在对应角色契约中。参数规格与 `validate_params` 执行校验共用同一份 `params` 声明(单一来源)。
- **指纹覆盖**:契约拼入被 `prompt_version_document`(票 24)哈希的提示常量,新世代冻结的提示指纹因此覆盖参数契约内容;恢复既有世代沿用既有漂移告警,不静默换用,已封存世代工件不改写。旧世代快照冻结的是拼入前的指纹,恢复时告警属预期迁移边界。
- **落地动机**:2026-09-25 种子单候选冒烟中,`strings_query` 参数盲猜连续三次协议拒绝触发 `protocol_error`(诊断见 `.scratch/qemu-user-mode-experiments/investigation/real-llm-smoke-2026-09-25-seeded/README.md`);gen-0001/gen-0002 两次真实运行均在该工具上消耗约三次校准,证实"参数规格不在上下文"是系统性缺口而非单次模型失误。
- **已知边界**:`STEP5_EXCLUDE_TOOLS` 运行时排除(骨架不变的运营旋钮)不在契约渲染感知范围内——被排除工具仍出现在提示词契约中,调用在 Host 工具分发处查空拒绝(`ProposalRejectedError` "已授权但未由 Host 配置",计入协议失败计数,连续三次可升级 protocol_error);若要感知 exclude 需把排除集纳入提示指纹语义,另行决策。后续可考虑让分发对"已授权但被排除"给出可自纠反馈(与 validate_params 聚合反馈同批实测后再定)。
- 后续改进(未做,待实测后另立票):`validate_params` 一次报告全部类别错误。

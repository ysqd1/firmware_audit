# 27: 把工具参数契约送入角色上下文

**Category:** bug
**Status:** ready-for-agent
**Priority:** P1（阻塞下一次真实 LLM QEMU 自选冒烟）
**Origin:** 2026-09-25 种子单候选真实 LLM 冒烟；[诊断记录](../../qemu-user-mode-experiments/investigation/real-llm-smoke-2026-09-25-seeded/README.md)。
**Blocked by:** None
**Implementation authorization:** 未授权；本票只完成立项与范围裁定。

## 问题与裁定

ADR-0004 要求声明侧与执行侧共享工具参数契约。现有 `AgentTool.params_doc` 已由结构化 `params` 生成，执行侧也用同一声明校验；但生产角色上下文只列工具名与用途，没有送达参数名、必填项、类型和 `strings_query` 的 `re:<正则>` 约定。模型只能靠拒绝反馈猜参数。种子冒烟中，`strings_query` 连续三次协议拒绝后触发 `protocol_error`，调查在 QEMU 决策点之前结束。

这是 ADR-0004 声明侧交付未闭合，不是 QEMU 后端故障。既有 `.scratch/step5-agents-refactor/issues/01-tool-interface-contract.md` 的“LLM 看到清晰参数规格”验收项尚无生产接线；票 26 处理的是 Analysis 状态读写和 transcript 可重放性，不覆盖工具参数送达。本票独立补齐缺口，完成后才重跑真实模型冒烟。

## 验收标准

- [x] Recon、Analysis、Verification 的生产 Session 实际发给模型的上下文包含各自**已授权**工具的名称、用途、参数规格;规格从工具注册表和现有 `params_doc` 生成,不再靠手工维护一份参数表。未授权工具不得出现在该角色的可用工具规格中。
  - 实现:`role_tool_contract(role)`(`providers/tools/__init__.py`),与 `make_tools`/`authorize_tool` 同一注册表;三角色提示词经 `{{TOOL_CONTRACT}}` 占位符导入期拼入(`host/recon.py`、`host/analysis.py`、`host/verification.py`)。
  - 证据:`test_step5_tool_contract_delivery.py::test_role_tool_contract_covers_authorized_tools`、`::test_role_tool_contract_excludes_unauthorized`、`::test_production_session_delivers_role_contract`(经生产 `_session_factory` + 捕获 LLM 核对实际发送的 system 消息)。
- [x] 规格与 `validate_params` 使用同一份声明;必填/可选、类型、默认值、枚举和参数说明可见。`strings_query` 的 `pattern` 必填与 `re:<正则>` 用法、`search_code` 的 `is_regex` 均可从实际模型输入核对。
  - 证据:同上测试文件中对 `re:<正则>`/`is_regex`/必填标注的锚点断言;`params` 声明为渲染与校验的单一来源。
- [x] 新世代的有效提示内容和提示版本指纹一致;恢复既有世代不静默换用新契约,既有 sealed 工件不被改写。若现有冻结机制无法表达新增内容,明确处理兼容与迁移边界。
  - 处理:契约拼入被 `prompt_version_document` 哈希的提示常量,冻结机制无需扩展即可表达;旧世代快照冻结拼入前指纹,恢复时走既有漂移告警(非静默),迁移边界记入 ADR-0004 状态节。
  - 证据:`::test_prompt_fingerprint_covers_tool_contract`(sha256 逐字节一致 + 发送形态钉子);既有 `test_driver_resume_warns_when_prompts_drifted_from_frozen` 继续覆盖恢复告警;未触碰任何世代工件。
- [x] 对无效参数的反馈准确说明整份调用未执行,避免"未知参数已忽略"造成部分生效的误解;保持严格校验、无效回复零工具/状态副作用以及三次协议重生成上限。
  - 实现:`validate_params` 未知参数文案改为"整份调用已拒绝且未执行,不产生任何 Observation 或状态变化";三次上限与零副作用语义未动(未改 `MAX_PROTOCOL_ATTEMPTS`/校验逻辑)。
  - 证据:`::test_invalid_param_feedback_says_not_executed`;`test_step5_tool_contract.py::test_read_file_recursive_graceful` 更新为新文案锚点。
- [x] 用离线生产 Session/ScriptedLLM 集成测试核对实际发送的角色上下文、权限隔离、参数规格、提示指纹与恢复行为;覆盖 `strings_query` 正则参数的可用示例。测试不调用真实 LLM、不读取 GT。
  - 证据:`firmware_audit/test/test_step5_tool_contract_delivery.py`(5 个测试,捕获 LLM 边界核对 messages[0]);全量回归 1293 passed / 17 skipped / 0 failed(2026-09-25,`pytest -q firmware_audit/test --ignore=firmware_audit/test/test_step5_host_evaluation.py`)。
- [x] 更新 ADR-0004 的落地状态与相关契约文档;执行定向和全量回归,并做 Standards + Spec 双轴复审。修复验收后,另行获批预算与真实 LLM 调用,再在隔离新世代按原定 A/B/C 判据重跑冒烟,单独记录"协议成功率"与"QEMU 自选"结果,不把一次阴性结果自动判为工具故障。
  - ADR-0004 状态节已更新(已实现 + 迁移边界 + 后续改进项)。真实 LLM 重跑待用户另行批准预算,不在本票执行。

## 范围边界

本票不增加协议重试次数，不放宽参数校验，不改 QEMU 后端、模型选择、候选排序或漏洞判定规则。`validate_params` 一次报告全部类别错误可减少纠错轮次，但不是本次阻断的必要修复；先记录为后续改进，待声明侧送达后的实测再决定是否另立票。

## Comments

2026-09-25：按种子冒烟诊断立项；修复优先于原样重跑。正式代码和提示词尚未修改。

## Comments

2026-09-25：按种子冒烟诊断立项；修复优先于原样重跑。正式代码和提示词尚未修改。
2026-09-25（实现）：用户授权后按 TDD 完成。实现面:`role_tool_contract` 渲染 + 三角色提示词占位符拼接 + `validate_params` 反馈措辞;测试面:新增 `test_step5_tool_contract_delivery.py`(5 测试),更新 `test_step5_tool_contract.py` 的文案锚点;文档面:ADR-0004 状态节。定向+全量回归 1293 passed/17 skipped/0 failed(跳过为 Docker/工件门控既有语义);真实 LLM 重跑留待另行批准。范围边界遵守:未加重试、未放宽校验、未做"一次报告全部类别错误"(记入 ADR 后续改进)。
2026-09-25（双轴复审记录）：Standards + Spec 两个并行子代理评审工作树最终改动（固定点 HEAD=提交前；覆盖 providers/tools/__init__.py、base.py、host/{analysis,recon,verification}.py、test_step5_tool_contract.py 及新增 test_step5_tool_contract_delivery.py、ADR-0004；用户既有未提交改动不在范围）。
- **Standards 轴**：无硬违规（分层方向合规、零新依赖、措辞与 ADR 修订一致）。发现 4 项判断题：①STEP5_EXCLUDE_TOOLS 运行时排除与契约渲染不感知（账实分叉）→ 以 role_tool_contract docstring"边界"段 + ADR"已知边界"条目记录（第一版措辞失实写"authorize_tool 拒绝"，复审纠正为实况：Host 工具分发查空 ProposalRejectedError"已授权但未由 Host 配置"、计入协议失败计数、连续三次可升级 protocol_error；ADR 并记后续可自纠反馈候选）；②authorize_tool/role_tool_contract 借异常成语重复 → 提取 `_require_role` 共用；③三处提示词装配注释重复 → 不采纳（延续既有 Related Candidate 装配先例，收口 host helper 超出本票，复审确认可接受）；④测试导入私有 `_session_factory` → 不采纳（即生产接缝，复审确认可接受）。
- **Spec 轴**：AC 六条无实质缺失、无 scope creep、无假绿（conftest fails 列表钩子咬合、断言有负向检查与逐参数核对）；生产路径覆盖核实成立（经 `_session_factory`→`AgentSession._messages` 核对实际发送的 system 消息）。两个无害注意点：深挖工具断言裸子串（假失败方向）→ 已改 `"#### "` 锚；_NO_ROOLS 发送侧无独立断言 → 全契约子串传递覆盖，接受。
- **复审闭环**：修复后两轴复审 + 最终单项确认共三轮；结论"全部闭合、无新发现、无回归"。
- **测试证据**：定向 test_step5_tool_contract_delivery/test_step5_tool_contract 23 passed；提交态（549fb2f）全量回归 `pytest -q firmware_audit/test --ignore=firmware_audit/test/test_step5_host_evaluation.py` → 1293 passed / 17 skipped / 0 failed（skip 为 Docker/工件门控既有语义），无真实 LLM 调用、无 GT 读取、未触碰任何世代工件。评审覆盖的提交：549fb2f。
- **Status 说明**：本跟踪器以 Comments 记录完成与验收（既有 16–26 同例），`ready-for-agent` 为分诊标签不翻转。

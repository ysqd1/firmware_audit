# Step5 Agent 编排升级：summarize 报告 + recon 工具收敛 + list\_files + 衔接修复 Spec

## Why

firmware\_audit 的 Step5 在 v2（2026-08-27 引入 Orchestrator）后仍有四类缺口，本次一并补齐：

1. **最终报告与编排结论脱节**：现在最终报告由 `render_report` 从 `verified_findings.json` **代码确定性渲染**（runner.py），orchestrator LLM 的结论只进 `result.json`，不进用户看到的报告；verification 承担了报告素材的产出，报告"作者"却没有任何 LLM 决策参与。
2. **recon 工具权限过宽**：`RECON_CFG.tool_names` 给了 `strings_query/imports_query/checksec`，recon 本应"只铺面、不深挖"，却可直接下钻二进制细节（危险导入、硬编码串、保护属性），与 analysis 职责重叠，浪费迭代预算。
3. **缺目录/文件枚举抓手**：recon 铺面只能靠 `read_file` 列单层目录（read\_file.py L29-31），无递归/过滤/数量上限的枚举工具；DeepAudit 有 `list_files`（file\_tool.py L457-580）。
4. **v2 遗留衔接缺陷**：① 提示词写死上下游工件路径（prompts.py `ANALYSIS_DIR_DOC` 的"三个工件"、`VERIFY_SYSTEM` 开场 `read_file(path: "agent/findings.json")`），与 `<seq>_<type>/` 实际落盘路径漂移，verification 首轮 read\_file 必失败；② 断点续跑把 JSON 解析失败的降级 `.md` 工件也当作"已完成 -> skipped"（orchestrator.py L246），失败/降级实例被静默当成成功。

## What Changes

* **Orchestrator 新增** **`summarize`** **动作**（参考 DeepAudit `_summarize_findings`）：编排到 verification 完成后，orchestrator 汇总全部已审核 findings 与各阶段统计，由 **orchestrator LLM 编写最终总结报告**（Final Answer 输出 Markdown 报告内容），主产物落盘 `process/agent/orchestrator/report.md`；如 Final Answer 同时含可解析 JSON 结构，另存 `report.json`（可选结构化副产品，非必需）。

* **删除** **`render_report`**：`runner.py::render_report` 不再存在（原确定性 md 渲染与 orchestrator 报告作者重复，且报告缺失时不静默降级，改为明确告警）。

* **verification 角色收敛**：只产出 `verified_findings.json`（含 summary/verified/rationale），不再承担任何报告生成。

* **recon 工具收敛**：移除 `strings_query`/`imports_query`/`checksec`（工具本体保留给 analysis/verification），新增 `list_files`；`max_iters` 保持 20 不变；提示词按 DeepAudit recon 思路重构（枚举铺面 + 防幻觉）。

* **新增** **`list_files`** **工具**（参考 DeepAudit `ListFilesTool` 实现）：递归/模式/数量上限枚举 `process/extracted`（Step2 过滤后视图）与 `process/analysis`，SDK/系统库目录自动排除；**对全部三个 Agent（recon/analysis/verification）开放**。

* **衔接修复**：上游工件路径动态注入提示词；`.md` 降级工件标记 `degraded` 状态，断点续跑只认 `.json`。

* **规范化（承接上轮分析的中低优先级项）**：交接块快照 `handoff_<seq>_<type>.json`、聚合去重升级为合并、状态标识枚举化、工件 schema v2 + finding 溯源字段、确定性 `pipeline` 快速模式。

## Impact

* Affected code（`important/firmware_audit/step5_agent/`）：

  * `orchestrator.py`：新增 `SummarizeTool`；FinishTool 语义衔接；degraded 状态；handoff 快照。

  * `runner.py`：`RECON_CFG` 工具集调整；**删除** **`render_report`**（及 `_resolve_verified` 关联逻辑）。

  * `run_step5.py`：`step5_run` 组装 summarize 收尾与报告缺失告警；`planner` 参数。

  * `providers/tools/__init__.py`：注册 `list_files`（默认全量，不加 exclude）。

  * 新增：`providers/tools/list_files.py`；`data/report_schema.py`（可选，报告 JSON 副产品容器）。

  * `data/prompts.py`：`RECON_SYSTEM` 重构；`VERIFY_SYSTEM`/`ANALYSIS_DIR_DOC` 去硬编码路径；schema 文档增字段。

  * `data/artifacts.py`：schema v2 兼容读；Finding 增 `source_agent/instance_seq`。

* Affected specs：`firmware_audit/agents.md`（recon 工具表、verification 职责、报告生成主体）。

* Affected tests：`test/test_step5_tools.py`（list\_files）、`test/test_step5_pipeline.py`（断点续跑 degraded、报告主体）、`test/test_orchestrator.py`（summarize、recon 工具集、degraded）、`test/test_step5_smoke.py`、`test/conftest.py`（新 fixture）。

## ADDED Requirements

### Requirement: orchestrator summarize 动作（最终报告生成主体为 orchestrator）

系统 SHALL 为 `Orchestrator` 新增第三个动作 `summarize`（AgentTool，name=`summarize`，入参 `{"conclusion": "<可选的编排结论>"}`），由 orchestrator LLM 编写最终总结报告，替代 verification+代码渲染作为报告产出主体。

#### Scenario: 成功编排并出报告

* **WHEN** 三个子 Agent（recon→analysis→verification）均完成后，orchestrator 调用 `summarize`，随后输出含 Markdown 报告内容的 `Final Answer`

* **THEN** summarize 工具收集 verification 阶段工件 findings（`<seq>_verification/verified_findings.json`）+ 各 `SubAgentResult` 统计（status/steps/tool\_calls/usage）组装为 Observation（含明确的 Markdown 报告写作要求）；orchestrator LLM 输出的报告文本**原样落盘** `process/agent/orchestrator/report.md`（主产物）；若 Final Answer 同时含可解析 JSON（`{schema, conclusion, summary, findings, recommendations}`），另存 `report.json`（可选结构化副产品）；`step5_run` 返回的 `report` 优先指向 `report.md`

#### Scenario: summarize 缺失/未产出报告

* **WHEN** orchestrator 未调用 summarize 直接 finish，或 summarize 后未产出 `report.md`

* **THEN** `step5_run` 判定报告缺失：打印/返回明确告警（"编排未产出总结报告，报告生成不完整"），**不静默生成替代报告**；`result.json` 仍完整保留 findings 与各阶段统计（status/steps/tool\_calls/usage），供后续人工补跑或再编排

#### Scenario: 决策可见

* **WHEN** orchestrator 处于调度后的空闲轮次

* **THEN** orchestrator 可通过 `summarize`（或同构的只读 `list_findings`）查看当前累计 findings 标题/severity/file 列表，再决定补调或收尾（对齐 DeepAudit `_summarize_findings` 的决策闭环）

### Requirement: verification 角色收敛

系统 SHALL 使 `verification` 只产出 `verified_findings.json`（含 `summary`/`verified`/`rationale` 字段），不再承担任何报告生成；报告生成唯一归口 orchestrator `summarize`（原 `render_report` 一并删除）。

#### Scenario: 阶段职责清晰

* **WHEN** verification 阶段执行完成

* **THEN** 其唯一产物为 `<seq>_verification/verified_findings.json`；无任何报告产出；`VERIFY_SYSTEM` 提示词中关于"最终报告"的表述移除，改为"你的产出是下游总结报告的唯一素材"

### Requirement: list\_files 工具

系统 SHALL 提供 `list_files` 工具（参考 DeepAudit `ListFilesTool`，file\_tool.py L457-580），用于递归/过滤枚举 `process/` 下的文件与目录。**recon/analysis/verification 三个 Agent 的工具集均包含该工具。**

#### Scenario: 参数与行为

* **WHEN** Agent 调用 `list_files`，参数 `directory`（相对 process/，默认 "."）/ `pattern`（如 `*.py`）/ `recursive`（默认 False）/ `max_files`（默认 100）

* **THEN** 返回相对路径列表（目录项标注）；路径安全检查与 `read_file` 同根（白名单 root=process）；`recursive=True` 时自动排除 SDK/系统库目录（与 Step2 过滤口径一致：`usr/lib`、`usr/local/lib`、`lib/`、`.git`、`__pycache__`、`node_modules` 等）；超出 `max_files` 截断并在末尾提示省略数与可下钻路径

#### Scenario: 越界与不存在

* **WHEN** `directory` 解析后不在 process/ 之下，或目录不存在

* **THEN** 返回 `ok=False` 的错误 Observation（越界/不存在），不抛异常（失败不崩）

#### Scenario: 全 Agent 可用

* **WHEN** recon/analysis/verification 任一 Agent 构建工具集

* **THEN** `list_files` 均在其 `tool_names` 中；recon 提示词要求以 `list_files` 作为首动枚举工具

### Requirement: recon 工具收敛

系统 SHALL 调整 `RECON_CFG.tool_names`：移除 `strings_query`、`imports_query`、`checksec`，加入 `list_files`；新集合为 `("list_files", "read_file", "cve_bin_tool_scan", "semgrep_scan", "gitleaks_scan", "binwalk_rescan")`；`max_iters` 保持 20 不变。被移除工具本体保留在 analysis/verification。

#### Scenario: 权限正确

* **WHEN** recon 阶段执行

* **THEN** 其工具集恰为上述 6 个；调用 `strings_query`/`imports_query`/`checksec` 返回"未知工具"；权限守护测试（仿 `tool_permissions_and_threshold`）断言集合精确匹配且不因 max\_iters 变化而受影响

### Requirement: recon 提示词重构（作用与输出规范参考 DeepAudit）

系统 SHALL 重写 `RECON_SYSTEM`（prompts.py）：职责对齐 DeepAudit recon（agents/recon.py L27-188）——枚举铺面而非二进制下钻，输出保持 `{summary, findings, components}` 容器（下游契约不变）。

#### Scenario: 工作流对齐

* **WHEN** recon 执行

* **THEN** 首动作为 `list_files` 建立文件/目录清单与优先级 → 识别入口点/网络服务/敏感配置（read\_file/list\_files）→ 组件识别（cve\_bin\_tool\_scan）→ 脚本语义扫描（semgrep\_scan/gitleaks\_scan）→ 汇总 findings（疑点级，每文件 ≤1-2 轮工具调用）

#### Scenario: 防幻觉纪律

* **WHEN** recon 产出 findings/components

* **THEN** `file` 字段必须来自 `list_files`/`read_file` 实际返回的路径；禁止猜文件、补行号、凭文件名猜版本；components 的 name/version/CVE 必须来自 `cve_bin_tool_scan` Observation（参考 DeepAudit"只报告实际读过的文件"）；明确禁止用 read\_file 搬运整段反编译 C 上上下文

#### Scenario: 输出结构

* **WHEN** recon 输出 Final Answer

* **THEN** JSON 结构仍为 `{summary, findings, components}`（components 为顶层可选字段，兼容下行读取）；findings 内容规范对齐 DeepAudit `high_risk_areas`/`initial_findings`（`file:line - 描述` 具体文件，禁止纯描述文本）

### Requirement: 上游工件路径动态注入（消除路径漂移）

系统 SHALL 移除提示词中的硬编码工件路径（`agent/attack_surface.json`、`agent/findings.json` 等），由构建器在运行时注入实际 upstream 路径（`agent/<seq>_<type>/<output_name>`）。

#### Scenario: 简报注入

* **WHEN** analysis/verification 构建任务简报

* **THEN** `upstream_path`（orchestrator 传入的最近完成实例工件，`_latest_upstream`）的相对路径被写入简报；`VERIFY_SYSTEM` 开场示例改为占位符渲染的实际路径，不再写死 `agent/findings.json`；`ANALYSIS_DIR_DOC` 移除"仅有三个工件"的固定表述

#### Scenario: 兼容非编排调用

* **WHEN** `run_agent` 以 `upstream_path=None` 直接调用（旧路径/测试）

* **THEN** 简报回退到 `process/agent/<output_name>` 默认路径，行为与旧版一致

### Requirement: 降级工件状态语义（degraded）

系统 SHALL 将断点续跑判定收紧：只有 `.json` 成功工件视为可跳过（status=`skipped`）；`.md` 降级工件标记新状态 `degraded`（`SubAgentResult.ok=False`），复跑默认重跑该实例（环境变量 `STEP5_RESUME_DEGRADED=0` 可显式关闭）。

#### Scenario: 降级不冒充成功

* **WHEN** 某实例最后一次产出为 `.md` 降级工件，且非 force 复跑

* **THEN** 该实例 status=`degraded`，`ok=False`，dispatch\_log 落 degraded 态并附原因；summary 与 findings 按可读部分加载但标记不完整；重跑时进入执行路径而非跳过

#### Scenario: 状态全集

* **WHEN** 编排终止

* **THEN** `_STATUS_LABEL`/dispatch\_log 覆盖 `running/success/skipped/failed/interrupted/degraded/rejected/duplicate` 全集，无悬挂 running；看守测试断言状态值域闭合

### Requirement: 规范性增强（承接上轮分析中低优先级项）

系统 SHALL 落地三项规范化，均向后兼容：

#### Scenario: 交接快照

* **WHEN** 每次真实调度（seq 分配后）

* **THEN** 在 `process/agent/orchestrator/handoff_<seq>_<type>.json` 落盘结构化交接（前序状态表/同类型前次 summary/累计 findings 计数/本次 task+context），文本交接块为其投影；交接可审计、可程序化消费

#### Scenario: 聚合去重升级

* **WHEN** `_ingest` 收到新 finding

* **THEN** 去重键从 `(title, file)` 升级为 `(file, func, addr, title_norm)`；命中重复时**合并**（保留已有 evidence，用新实例补充 confidence/verified/evidence 空位），不丢弃深化版本

#### Scenario: 工件 schema v2 与溯源

* **WHEN** 任一子 Agent 落盘工件

* **THEN** `schema` 升为 `2`（兼容读取 v1：缺字段给默认）；每条 `findings` 增加 `source_agent`/`instance_seq`（来源 Agent 与实例序号），`result.json` 可按实例过滤；状态字符串统一由枚举（`AgentStatus`/`DispatchStatus`）生成

### Requirement: 确定性快速模式（planner）

系统 SHALL 为 `step5_run` 增加 `planner="auto|pipeline"` 开关：`pipeline` 模式跳过 orchestrator LLM 循环，由 Python 按顺序门直接调度三 Agent（v1 语义），保留全部落盘/守卫；默认 `auto` 维持现状。

#### Scenario: 快速模式

* **WHEN** `step5_run(..., planner="pipeline")`

* **THEN** 顺序执行 recon→analysis→verification（沿用断点续跑/上游缺件拒绝语义），无 orchestrator 轮次消耗，仍产出三工件；报告按"未产出总结报告"告警处理（pipeline 下无 LLM 可写报告，与 summarize 缺失语义一致）；`--force` 语义不变

## MODIFIED Requirements

### Requirement: 报告整合编排统计

`step5_run` 的 stages/usage/tool\_calls 统计在 summarize Observation 中一并注入（供 LLM 报告引用），不再只打印不进产物。

## REMOVED Requirements

* **`runner.py::render_report`（原有确定性 md 渲染器）**：删除。**Reason**：报告作者统一为 orchestrator LLM（主产物 report.md）；原确定性 md 渲染与 orchestrator 报告同类重复；报告缺失时按"明确告警、不静默降级"处理，无兜底需求。
  **Migration**：旧工作区已有 `process/agent/report.md` 的，仅作历史产物保留；`step5_run` 在新版产出缺失时明确提示，不读取旧文件冒充新报告。

* **verification 的 report.md 产出职责**：迁移至 orchestrator `summarize`。
  **Reason**：报告作者统一为 orchestrator LLM。
  **Migration**：verification 只产 `verified_findings.json`，其 summary/verified/rationale 字段结构不变，供 summarize 消费。

* **recon 的** **`strings_query`/`imports_query`/`checksec`** **权限**（工具本体保留）。
  **Reason**：recon 只铺面不深挖，深挖归 analysis/verification。
  **Migration**：无存量影响，工具注册表不变，仅 `AgentConfig` 工具集调整。

* **提示词中的硬编码工件路径**。**Reason**：与实际 `agent/<seq>_<type>/` 落盘路径漂移，属 v2 遗留缺陷。

## 参考实现（DeepAudit）

* `list_files`：`backend/app/services/agent/tools/file_tool.py` L457-580 `ListFilesTool`——参数 `directory/pattern/recursive/max_files`、`path` 别名、项目根越界检查、`DEFAULT_EXCLUDE_DIRS`、`max_files` 截断。

* recon 职责与提示词：`backend/app/services/agent/agents/recon.py` L27-188——职责四段（结构/技术栈定位、入口点、敏感区域、初评）、输出结构 `project_structure/tech_stack/recommended_tools/entry_points/high_risk_areas/initial_findings/summary`、防幻觉硬纪律（file 必须来自 list\_files/read\_file、禁模板猜测）；固件场景不照搬 `tech_stack` 等字段，取其"枚举铺面 + 防幻觉"思想。

* summarize 汇总：`backend/app/services/agent/agents/orchestrator.py` L1212-1251 `_summarize_findings`——按 severity 计数 + 明细列表；本 spec 在其上增加了"由 LLM 产出最终报告内容并落盘"的能力。


# recon 与 analysis 差异化输出 & orchestrator 动态分配 Spec

## Why

Step5 现行 v3（2026-08-29）已验证编排链路稳定，但存在四类问题：

1. **recon 与 analysis 输出同构越界**：recon 的 findings 沿用 analysis 的完整 schema（含 `severity/confidence/evidence`），recon 实际在做"判级 + 证据链"——本质是 analysis 的判决动作；同时 recon 直接执行 semgrep/gitleaks 内容级扫描并产出带判级的 finding，与"只铺面不深挖"的使命冲突。DeepAudit 的 recon 只产出 `project_structure / tech_stack / recommended_tools / entry_points / high_risk_areas / initial_findings`（无判级字段）。
2. **工件命名误导**：`attack_surface.json` 的 "attack" 语义使 recon 被误读为攻击视角；recon 实为中立调查（survey），产出应命名为 `survey.json`。
3. **analysis 迭代预算不足**：`ANALYSIS_CFG.max_iters=24`，对疑点逐条取证（search\_code → find\_decompiled\_function → xref 链）常在半程被强制收尾，遗留疑点无续跑机制。
4. **orchestrator 对"预算耗尽"无结构感知**：同类型最多调度次数存在（现 2），但"何时值得对 analysis 追加补跑、补跑哪些未覆盖疑点、如何避免与既有结果重合"完全靠 LLM 撞运气，无系统级信号。

## What Changes

* **工件改名**：`attack_surface.json` → **`survey.json`**（BREAKING：目录/路径、brief、聚合、提示词参考、存量数据迁移）。

* **recon 工件 schema 重构（v2→v3）**：移除 findings 数组；新增固件化的架构/建议结构（对齐 DeepAudit recon 输出语义，见 ADDED）。

* **recon 提示词重构**："判级与证据链移交 analysis"；semgrep/gitleaks 命中只进 high\_risk\_areas（file+line 观察点）；`components` 保留（技术栈/组件识别，cve 只许来自工具 Observation）。

* **analysis 上限提升**：`ANALYSIS_CFG.max_iters` 24→**30**；强制收尾复用 react\_loop 机制；新增 30 轮专项测试。

* **orchestrator 动态分配**：`MAX_DISPATCH_PER_AGENT` 2→3；analysis 实例"预算耗尽"结构化信号 + 未覆盖疑点优先级清单（pending\_focuses）+ **与既有结果的重合检测** + 状态监控字段。

* **上下文流转契约化**：明确"recon 摘要只注入首次 analysis brief；补跑 analysis 经 handoff 拿到前序实例摘要与已覆盖清单；orchestrator 的 task/context 以 extra\_brief 附加进子 Agent 简报，补跑时 task 必须由 pending\_focuses 推导且与已覆盖项差分"（见 ADDED）。

* **聚合层适配**：`Orchestrator._ingest` 不再从 recon 聚合 finding；findings 唯一来源 analysis/verification。

* **集成测试**：recon/analysis 功能边界守卫、30 轮收尾、动态分配与**重合适配**（ScriptedLLM + 真 LLM 冒烟）。

## Impact

* Affected specs: firmware\_audit/AGENTS.md（Step5 章节）、docs/tools\_summary.md。

* Affected code:

  * `step5_agent/data/prompts.py`（RECON\_SYSTEM 结构 & 文件名引用、ANALYSIS\_SYSTEM 起点依赖）

  * `step5_agent/data/artifacts.py`（recon v3 容器 + `parse_survey_artifact`，兼容 v2/旧路径）

  * `step5_agent/runner.py`（RECON\_CFG.output\_name、ANALYSIS\_CFG.max\_iters=30）

  * `step5_agent/orchestrator.py`（\_ingest 去 recon finding、动态分配信号/pending/重合计分、SubAgentResult.budget\_exhausted、MAX\_DISPATCH\_PER\_AGENT=3）

  * `step5_agent/run_step5.py`（pipeline 渲染 survey.json）

  * `test/test_step5_pipeline.py`、`test/test_orchestrator.py`、`test/test_step5_guard.py`

## ADDED Requirements

### Requirement: recon 工件 v3 与改名 survey.json

recon 工件 SHALL 命名 `survey.json` 并使用 v3 结构（无 findings/判级字段）：

```json
{
  "schema_version": 3,
  "arch_snapshot": {                   // 架构分析
    "top_level_dirs": [...],
    "components_grouped": [           // 二进制/模块归组(名称+大小+role 推断)
      {
        "name": "...",
        "size": 1234,
        "role": "web server",
        "role_evidence": [            // role 推断的证据链:工具 Observation 原文
          "binds TCP port 80",
          "contains HTTP-related strings"
        ]
      }
    ],
    "os_or_runtime": "..."             // 可识别时;否则 null,不许猜
  },
  "components": [                       // 技术栈/组件识别(只收工具 Observation 实况)
    {"name": "...", "version": "...", "cve": ["CVE-..."], "source": "cve_bin_tool_scan"}
  ],
  "entry_points": [                     // 如监听服务/web/cgi/守护进程
    {"file": "...", "reason": "..."}
  ],
  "high_risk_areas": [                  // 高危区域标记:观察点,非判定
    {"file": "...", "metric": "弱势二进制保护|硬编码密钥|注入模式命中|危险函数邻近", "detail": "..."}
  ],
  "recommended_actions": [              // 扫描建议:给 analysis 的导向(优先级算法输入)
    {"priority": "high|medium|low", "action": "对 <file> 做 <工具> 取证,关注 <疑点>"}
  ],
  "summary": "..."
}
```

\*- 禁止字段：`findings`（数组）与 `severity/confidence/verified/evidence/rationale`（任意层级）。

* `components_grouped[].role` 若给出 SHALL 附 `role_evidence`（≥1 条工具 Observation 原文/可观测事实），禁止仅凭文件名猜角色。

* 迁移：存量 `attack_surface.json` 兼容读取；recon `--force` 后产出 `survey.json`；旧路径引用统一更新。

#### Scenario: Success case

* **WHEN** recon 完成侦察并落盘

* **THEN** 工件为 `<agent>_recon/survey.json`（schema\_version=3），无判级字段；v2 旧文件仍可被解析

#### Scenario: 防幻觉守护

* **WHEN** recon LLM 输出含 findings/severity 等禁止字段

* **THEN** 解析层降级为 high\_risk\_areas 观察点并在 summary 注明，不进入聚合

### Requirement: analysis 迭代上限 30 轮

`ANALYSIS_CFG.max_iters` SHALL 为 30；react\_loop 第 30 轮注入 LAST\_ROUND\_NOTICE，仍发 Action 由 FORCE\_FINAL 兜底；steps 计数器精确（1..30）。

#### Scenario: 30 轮强制收尾

* **WHEN** analysis 连续执行 30 轮仍不输出 Final Answer

* **THEN** 第 30 轮收到"最后一轮"提示；FORCE\_FINAL 兜底；`SubAgentResult.steps==30`

### Requirement: 上下文流转契约（recon→analysis→补跑 analysis）

* **首次 analysis**：init brief = recon 摘要（entry\_points + high\_risk\_areas + recommended\_actions，`build_analysis_brief` 生成） + orchestrator 的 task/context（extra\_brief）。

* **补跑 analysis（第 2/3 次调度）**：init brief = **同一份 recon 摘要**（保证差分所需的完整上游信息） + handoff（前序同类型实例 summary + `_all_findings` 的 title/file 已覆盖清单） + orchestrator task（必须由 pending\_focuses 推导且与已覆盖项差分）。

* **orchestrator 指令注入**：dispatch 的 `task`/`context` SHALL 以 extra\_brief 形式附加进子 Agent 简报（现状保留）；`task` 允许多实例调度状态下标注"第 N 轮补跑，聚焦未覆盖项"。

* **verification**：init brief = 全部 analysis 实例聚合后的 verified 前 findings + handoff。

#### Scenario: 补跑 analysis 上下文完整

* **WHEN** orchestrator 对 analysis 追加第 2 次调度

* **THEN** 该实例简报包含 recon 摘要、前序实例 summary、已覆盖清单、差分 task——不依赖第一个实例的私有上下文

### Requirement: orchestrator 动态分配机制

* `MAX_DISPATCH_PER_AGENT` SHALL 为 3。

\*- 编排器 SHALL 在分析实例结束后提供结构化 `budget_state`：
`{"agent": "analysis", "exhausted": true|false, "steps": N, "max_iters": 30, "pending_count": M, "pending_focuses": [...], "overlap_ratio": 0..1}`

* `pending_focuses` 优先级算法：(1) recon `recommended_actions` 中 high/medium 且 (2) 未出现在已聚合 findings（title/file 差分）的项；(3) 按 recon high\_risk\_areas 排序。

* **重合计分**：每次 analysis 实例结束后计算 `overlap_ratio` = 新 findings 与既有 findings（title/file 归一化）重复比例；记录到 dispatch\_log。

* 子 Agent 调度 SHALL 满足：同类型 ≤ 3；task 唯一；`SubAgentResult.budget_exhausted`（steps==max\_iters 或 FORCE\_FINAL）。

* 状态监控：每实例 budget\_state 写入 `orchestrator/dispatch_log.json` 与 `result.json`。

#### Scenario: analysis 预算耗尽触发补跑

* **WHEN** analysis 以 exhausted 结束且 pending\_count>0 且同类调度次数<3

* **THEN** dispatch Observation 结构化提示补跑，task 指向 pending\_focuses 未覆盖项；新老 findings 按既有合并去重聚合

#### Scenario: 重合适配

* **WHEN** 补跑后 `overlap_ratio` 超过阈值（默认 0.5）

* **THEN** 触发提示词/交接调整预案（spec 明示）：补跑 task 强制差分措辞、handoff 附完整已覆盖 title 清单、RECON/analysis 提示词增加"只处理未覆盖项"红线；预案执行 e2e 复测

#### Scenario: 其余 Agent 不受影响

* **WHEN** recon/verification 正常完成（未 exhausted）

* **THEN** budget\_state.exhausted=false，不生成补跑建议

## MODIFIED Requirements

### Requirement: 聚合层 findings 唯一来源

`Orchestrator._ingest` SHALL 只从 analysis/verification 聚合 finding；recon 实例 findings 视为不合法输入并忽略（旧数据兼容跳过错）。

### Requirement: 提示词工件引用更新

所有提示词/文档中 `attack_surface.json` 引用 SHALL 改 `survey.json`（含 ANALYSIS\_DIR\_DOC 的"三个工件"描述、brief 路径拼接）。

## REMOVED Requirements

### Requirement: recon 输出 analysis 式 findings 与 attack\_surface.json 命名（v2 行为）

**Reason**: 判级字段与 analysis 判决职责重叠、内容级扫描重复成本高；"attack"命名误导 recon 为攻击视角，实为中立调查。DeepAudit recon 亦不产判级条目。
**Migration**: 存量 `attack_surface.json` 兼容读取，recon `--force` 产出 `survey.json`；analysis/verification/聚合按新结构与路径消费。

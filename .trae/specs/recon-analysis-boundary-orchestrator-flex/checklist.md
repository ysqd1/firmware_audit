# Checklist

## recon 差异化输出（survey.json）
- [x] recon 工件命名为 `survey.json`（RECON_CFG.output_name），schema_version=3
- [x] v3 无 findings/severity/confidence/verified/evidence/rationale 键（任意层级；test_recon_v3_orchestration_boundary 递归键扫描断言）
- [x] components 仅收 cve_bin_tool_scan Observation 实况（版本/CVE 不凭记忆）
- [x] arch_snapshot.components_grouped[].role 附 role_evidence（≥1 条 Observation 原文），无裸 role 推断（SURVEY_SCHEMA_DOC + RECON_SYSTEM 红线）
- [x] high_risk_areas 仅工具 Observation 原文/文件名+行号，无自行补判定
- [x] 存量 attack_surface.json 兼容读取（_resolve_survey_path 回退；真机复用 v2 改名文件跑通），recon `--force` 后产出 survey.json
- [x] 全仓 `attack_surface` 引用清理（代码残留均为 v2 兼容实现/注释；requirements.md 属需求文档范围外，如实记录）
- [x] RECON_SYSTEM 明确"判级与证据链移交 analysis"
- [x] 守护测试通过：recon 解析层拒绝/降级 findings 与判级字段（test_step5_guard.py）

## analysis 30 轮
- [x] ANALYSIS_CFG.max_iters == 30（真机 budget_state max_iters=30 实证）
- [x] 30 轮专项用例通过：第 30 轮 LAST_ROUND_NOTICE、仍发 Action 时 FORCE_FINAL 兜底、steps==30（test_force_final_30_rounds）
- [x] 30 轮下 ContextManager 压缩不越界（无异常/断言失败）

## 上下文流转契约
- [x] 首次 analysis 简报含 recon 摘要（entry_points/high_risk_areas/recommended_actions/components；_survey_lines v3 摘要）
- [x] 补跑 analysis 简报含同一份 recon 摘要 + 前序实例 summary + 已覆盖 title/file 清单（前 30 条） + 差分 task（_build_rerun_brief；test_dynamic_dispatch_full_chain_budget 断言"已覆盖清单"/"第 2 轮补跑"）
- [x] verification 简报含全部 analysis 实例聚合后的 findings + handoff
- [x] orchestrator task/context 以 extra_brief 附加进子 Agent 简报，补跑 task 由 pending_focuses 推导且与已覆盖差分

## orchestrator 动态分配
- [x] MAX_DISPATCH_PER_AGENT == 3（第 4 次同类调度被拒留痕 rejected，test_max_dispatch_limit）
- [x] SubAgentResult.budget_exhausted 正确反映 exhausted（steps>=max_iters 或未 finished）
- [x] budget_state 结构化返回（exhausted/steps/max_iters/pending_count/pending_focuses/overlap_ratio；真机 dispatch_log 实证）
- [x] pending_focuses 优先级算法生效（recommended_actions high/medium ∩ 未覆盖 → 按 high_risk_areas 序；用例 1→0 覆盖）
- [x] overlap_ratio 正确计算（新 findings 与既有 title/file 归一化重复比例），记录到 dispatch_log（真机实证；用例 0.5/0.75）
- [x] analysis exhausted 且 pending_count>0 且同类调度<3 → dispatch Observation 给补跑建议（task 指向 pending、差分措辞）
- [x] 补跑后新老 findings 按既有合并去重聚合
- [x] dispatch_log.json/result.json 记录每实例 budget_state（result.json 顶层 "budget" 汇总，真机实证）
- [x] 协作失效守护测试通过：task 唯一性、同类调度 ≤3、seq 递增、transcript 不覆盖

## 重合适配预案
- [x] overlap_ratio > 0.5 时触发适配信号（test_rerun_high_overlap_adapt：0.75 场景建议/清单仍注入）
- [x] ORCH_SYSTEM 含 budget_state 解读与补跑指导（test_build_orchestrator_prompt 6 关键词断言）
- [x] ANALYSIS/RECON 提示词含"只处理未覆盖疑点"红线措辞（补跑实例 system_prompt.txt 实际携带实证）
- [x] 高重合补跑 e2e 用例通过（overlap 0.75、聚合 3+1=4、红线到达子 Agent）

## 集成与端到端
- [x] 功能边界测试通过：recon v3 无判级字段且 analysis 可消费；聚合只收 analysis/verification
- [x] 动态分配端到端（ScriptedLLM 全链 43 次调用）通过：recon v3 → analysis 30 轮耗尽 → 补跑 → verification → summarize → report 落盘；dispatch_log 含 budget_state/overlap_ratio
- [x] 真 LLM 冒烟通过：编排 10 轮 158s/63k tokens exit 0，report.md 落盘且首行干净，dispatch_log/result.json budget_state 真实呈现（三实例 max_iters 20/30/24）；smoke 门控 3 passed（160s）
- [x] 全量 pytest 通过：192 passed + 10 skipped（基线 176+10 → 净增 16 用例，0 failed 无新增 skip）
- [x] 质量指标采集记录：recon high_risk_areas 条目数=1（用例工件）、pending 覆盖 1→0（100%）、补跑触发率 1/2=0.5、overlap_ratio 分布 [0.0,0.5]（全链）/ [0.0,0.75]（高重合适配）

## 文档
- [x] AGENTS.md Step5 章节与实现一致（survey.json/recon v3/30 轮/动态分配，含轮上限列）
- [x] docs/tools_summary.md 与实现一致（15 工具、权限矩阵 max_iters 列、v3 工件结构段、DISPLAY.md 同步）

## 已知事实（如实记录，非缺陷）
- 真机 skipped 实例 budget_state.steps=0/exhausted=false（断点续跑未执行，无轮次可计）
- verification 实例 overlap_ratio=1.0：复核阶段按设计重报同一批 findings（其语义为"复核确认"而非"重复浪费"）
- 真机编排 [08] 出现一次协议漂移（报告散文无块）被既有守卫兜回，[09] 正确 finish——B1/B3 修复仍生效

## 修订记录（v2 兼容层移除，2026-08-29，用户决策后追加）
- [x] `_resolve_survey_path` 只认 survey.json，不回退 attack_surface.json（返回 None）
- [x] `parse_survey_artifact`：顶层/任意层级 findings 一律按"recon 禁止"拒绝（整段不入 survey），不再宽容转 high_risk_areas 观察点；`_obs_from_v2_finding` / `_SURVEY_OBS_METRIC_V2` 删除，统一 `_obs_from_forbidden` + `_SURVEY_OBS_METRIC_FORBIDDEN`
- [x] `_upstream_summary`/`build_analysis_brief`/`_locate_recon_survey`：删 v2 findings 兼容摘要分支与旧名回退（无 survey 上游即无 recon 摘要，不产出 findings 兼容摘要）
- [x] 测试同步：guard 3 用例改写为"拒绝"语义（findings 不转观察点/旧名不回退）、orchestrator brief 用例改无 survey 场景；**192 passed + 10 skipped 全量回归通过**
- [x] 文档同步：AGENTS.md 工件链/recon v3、tools_summary.md 结构段/工件链表均标注"v2 兼容层已移除"
- [ ] **遗留**：target/1 现 `0_recon/survey.json` 为 v2 内容改名，findings 在新解析下被拒（不再转观察点）；要标准 v3 需对该工作区 `--force` 重跑 recon
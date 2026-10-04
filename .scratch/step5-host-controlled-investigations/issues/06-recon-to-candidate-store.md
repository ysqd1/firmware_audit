# 06: 从 Recon survey 建立 Candidate Store

**What to build:** Host 驱动单实例 Recon，以增强现场概览和受限浅层工具形成完整 survey，并把可执行 proposal 转成统一 Candidate Store。

**Blocked by:** 01/建立逐步 Agent Session 协议；03/跑通单 Candidate 的 Host Analysis tracer。

**Status:** ready-for-agent

- [x] Recon 默认最多 30 轮并支持已确认的配置覆盖。
- [x] complete survey 只有同时包含攻击面、Candidate proposals、已检查范围和 coverage gaps 才被接受。
- [x] Candidate 允许 possible source/sink 为空，但必须具有 target、攻击面信号、初始 Evidence 和下一调查动作。
- [x] 有具体观察时形成 signal Candidate；没有具体信号时从高价值未检查面形成 coverage Candidate。
- [x] 有效解包树至少形成一个 Candidate；解包失败、空树或无有效目标明确结束为 input failure。
- [x] Recon 直接请求 r2/Ghidra 时被角色契约拒绝，并可根据 Observation 改用浅层动作或提交 Candidate。
- [x] 端到端测试从临时解包树和 Scripted LLM 生成可读取的 survey 与 Candidate Store。

## Comments

2026-09-14：实现完成并提交 `5f5d9fc`（评审基准 `b9ba783`，评审修复已 amend 入同一提交）。按 implement/tdd 逐切片 RED→GREEN，计划见 `../ticket06-plan.md`。

验证：`pytest -q firmware_audit/test` 为 **465 passed、21 skipped**（新增 31 项 Host Recon 测试）；compileall 与 git diff --check 通过。mypy/pyright 未安装，未声称完成静态类型检查。

实现要点：
- 新模块 `host/recon.py`：`HostReconRunner`（Recon 阶段唯一真实循环）+ `build_site_overview`（增强现场概览：顶层目录×文件×字节、扩展名分布、最大文件、边车计数，首轮注入）+ `input_failure_reason`（extracted 缺失/空树/全被 SEARCH_EXCLUDE 排除 → input_failure，不发起模型请求）。
- 拒绝语义三分：角色越权（r2/Ghidra）与参数失约 → 结构化反馈回喂 Session 轮内自纠、零副作用；survey 不完整/候选字段缺失/引用未知 Evidence → 整份拒绝回喂问题清单；协议形状失败 → 沿 tracer 先例抛 `ProposalRejectedError`（≤2 次重生成与三次失败收束归工单 10）。
- survey 门：四段齐备且结构合法（attack_surface/candidates/checked_scope 非空、coverage_gaps 可空防编造）；新增结构代理——coverage_gaps 非空时至少一个 kind=coverage 的 Candidate。
- Candidate Store：`run_dir/candidates.json`（schema_version=1，survey 原文 + session_state + 保序 proposals）。**`cand-xxxx` 分配刻意推迟到工单 07**（"去重完成后才分配"），本票以 `proposal-000N` 保序。
- Recon Evidence 落 `investigations/recon/evidence/`；`EvidenceRecorder.seed_sequence_from_files()` 从盘上既有文件抬水位，跨实例/跨运行不重号（不影响 tracer 既有事件驱动恢复）。
- 附带收敛：`ProposalRejectedError` 与 `revalidate_proposal(proposal, role)` 移入 `session.py`（tracer 委托，import 路径不变）；`tooling.py` 抽出 `normalize_tool_arguments`/`execute_tool` 共享实现。

code-review 双轴只读评审（Standards/Spec）后修复：术语纪律（侦察→侦查，CONTEXT.md _Avoid_）、`_GuardedAction` 消除 str|tuple 裸分流、status/kind 用 Literal、`seed_sequence_from_files` 死代码、测试 import 上提、checked_scope 非空与 coverage 结构代理两条门规则及配套提示词。刻意不修（已注记）：与 legacy `build_filtered_overview`/`resolve_max_iters` 的迁移期平行、不校验 candidate target 的 `extracted/` 前缀（semgrep '.' 双扫会合法命中 `analysis/` 树）。

仍为 expand 阶段：去重/评分/双队列/cand-ID（07）、Claim 案卷（08）、独立复核（09）、协议重生成与预算（10）、运行世代与 Recon 断点续跑（11）、公开入口切换（14）由后续工单完成。

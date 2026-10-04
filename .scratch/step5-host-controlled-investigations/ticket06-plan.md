# Ticket 06 Implementation Plan

**Goal:** Host 驱动单实例 Recon：以增强现场概览与受限浅层工具形成完整 survey，并把可执行 proposal 转成统一 Candidate Store（`candidates.json`）。

**Architecture:** 新增 `host/recon.py` 作为 Recon 阶段的 Host 控制循环（与 `HostAnalysisTracer` 对称）。Host 在运行前从解包树确定性构建增强现场概览并做输入分类（解包失败/空树/无有效目标 → input failure，不发起模型请求）；运行中逐轮校验完整 Proposal、按 `authorize_tool("recon", ...)` 执行浅层工具并留存 Evidence；`complete_survey` 只有四段齐备且每个 Candidate 带齐 target/signal/初始 Evidence/下一动作才被接受，接受后把 survey + proposal 序列原子落盘为 Candidate Store。角色契约拒绝（r2/Ghidra 越权）与 survey 不完整都以结构化反馈回喂 Session 在轮次预算内自纠，不产生状态或工具副作用。

**Tech Stack:** Python 标准库、pytest、现有 AgentSession / EvidenceRecorder / authorize_tool / make_tools / ScriptedLLM。

基准：master @ b9ba783（ticket 05 已合入）。按 implement/tdd 在当前分支实现，逐切片 RED → GREEN。

**关键设计决策（ADR-0012 未细粒度指定处）：**

- **Candidate ID 分配推迟到工单 07**（"去重完成后才分配递增 Candidate ID"）。本票 Candidate Store 以运行内递增 `proposal-000N` 序号保序保存合法 proposal，不占用 `cand-xxxx`。
- **Candidate Store = `run_dir/candidates.json`**：`{schema_version, survey(attack_surface/checked_scope/coverage_gaps+extras), session_state(中间轮累计 state_delta), candidates[]}`。survey 与 proposals 同一权威工件，可读、可被工单 07/12 消费。
- **Recon Evidence 落在 `run_dir/investigations/recon/evidence/`**（candidate_id=`recon`, investigation_id=`recon-survey`），与 `cand-*` 目录不冲突（tracer 只 glob `cand-*`）。
- **Evidence 序列跨实例唯一**：EvidenceRecorder 新增 `seed_sequence_from_files()` 扫描 `investigations/*/evidence/ev-*.json` 抬高水位；Recon Runner 构造时调用。不改 tracer 既有事件驱动恢复（孤儿文件仍由 reserve 碰撞暴露）。
- **拒绝语义三分**：①角色越权（r2/Ghidra）→ 结构化反馈 Observation 回喂，零副作用，轮内自纠（验收 6）；②survey 不完整/Candidate 字段缺失/引用未知 Evidence → 整份 complete_survey 拒绝并反馈问题清单，轮内重提（验收 2/3/5 的"才被接受"）；③协议形状/参数契约失败 → 沿 tracer 先例抛 `ProposalRejectedError`（协议重生成与三次失败收束归工单 10）。
- **轮次 = 次模型请求**（含被拒绝的轮）；默认 30，`STEP5_RECON_MAX_ITERS` 覆盖（缺失/非法回落、下限 1），消费点解析。耗尽未接受 survey → `status="incomplete"`（stop reason 语义归工单 10/11）。
- **输入分类**：`extracted/` 缺失 → `extraction_missing`；零文件 → `empty_tree`；文件全被 SEARCH_EXCLUDE 命中 → `no_valid_targets`。三者 → `status="input_failure"`，Session 零调用。
- **`_validated_proposal` 收敛**：tracer 的整份重校验守卫参数化为 `session.revalidate_proposal(proposal, role)`，`ProposalRejectedError` 移至 session.py（analysis.py re-export 保持既有 import 路径）。
- **增强现场概览**：结构化 JSON（顶层目录×文件数×字节、扩展名分布、最大文件、analysis 边车计数、可审文件数），SEARCH_EXCLUDE 口径与 list_files 一致；作为首轮 user 消息注入。
- **Recon 系统提示词**放 `host/recon.py`（迁移期不与 legacy `data/prompts.py` 混放；工单 08/09 再抽 host/prompts）。

**切片（RED → GREEN）：**

- [x] S1 现场概览 + 输入分类纯函数（有效树/缺 extracted/空树/全排除）
- [x] S2 EvidenceRecorder 序列播种（既有 ev 文件抬高水位，跨实例不撞号）
- [x] S3 轮次上限：默认 30、env 覆盖、耗尽 → incomplete
- [x] S4 Recon Action Loop：FakeSession + fake tool，浅层工具执行 → Evidence + Observation View 回喂；越权 r2/Ghidra 反馈后改浅层动作继续
- [x] S5 complete_survey 四段校验、Candidate 必填字段/enum/Evidence 归属校验、接受后 candidates.json 原子落盘；缺段/缺字段/未知 Evidence → 反馈不落盘
- [x] S6 input failure 不发起模型请求
- [x] S7 端到端：临时解包树 + make_tools(role="recon") 真实 list_files/read_file + 真实 AgentSession + ScriptedLLM → 可读 survey 与 Candidate Store
- [x] 全量 `pytest -q firmware_audit/test` + compileall + git diff --check
- [x] code-review 双轴只读评审（Standards/Spec），修复真实问题
- [x] 更新工单 06 验收记录；提交代码（.scratch 本地不提交）

**Out of scope（后续工单）**：fingerprint 去重/评分/双队列（07）、Claim/案卷（08）、Verification（09）、协议重生成与预算记账（10）、运行世代/锁/Recon 断点续跑（11）、报告（12）。

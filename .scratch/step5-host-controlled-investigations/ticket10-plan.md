# Ticket 10 实现计划:落实协议失败、预算与停止规则

## 边界(与后续票的切分)

- 票 11:运行世代/活动锁/队列级恢复/运行级驱动循环。→ 本票只交付**原语**:预算守卫、
  `mark_not_started`、BudgetExhaustedError 的"保存现场不落终态"语义;把守卫接入队列的
  完整 run-loop 与 not_started 批量落账归票 11/14 接线。
- 票 12:severity/事实报告/封存。→ 本票的 config 快照(budget.json/config.json)是运行
  资源工件,不是封存 manifest;报告不生成。
- 票 14:公开切换。→ 端到端(公开入口跑真 LLM)不在本票;本票以 Action Loop seam
  (Fake Session/Fake tools/注入时钟)覆盖每个预算边界、服务中断与三角色协议失败(AC8)。

## 设计决定

1. **无效回复的统一口径:一次"轮"= 一个 episode**。`session.step()` 返回的回复凡被 Host
   拒绝(parse/角色/形状失败,或 state_delta/工具授权/参数/门槛等 Host 守卫失败)都算
   **无效回复**:把拒绝理由结构化回喂同一 Session、整份重生成;**连续 3 次无效**触发
   角色收束(AC1/AC2,ADR L43"schema 校验失败"按宽口径含领域 delta 校验——模型必须
   重新生成一份完整合法 JSON)。episode 内尝试失败零副作用(现状已成立的守卫前置不变)。
   非 ProposalRejectedError 的异常(TypeError/StoreError/LLMError 等 Host/服务侧故障)
   **不**进入重生成,原样传播。
2. **三角色收束**:recon → `ReconRunResult(status="input_failure", reason="protocol_error")`;
   analysis → `finished/unresolved/protocol_error`(经既有 `_finish_investigation`,
   队列可继续下一 Candidate);verification → `_finalize(stop_reason="protocol_error")`
   → 聚合既有 claim_results(通常缺项)→ `inconclusive/protocol_error`,不生成 Finding
   (confirmed 判定不受 stop_reason 影响,但三连无效时必缺必填结果,天然不 confirmed)。
3. **服务中断不消耗终态**:LLMError 等异常从 `session.step` 直接传播,零状态突变
   (守卫前置保证);run 级 try/finally 只负责停掉 active 计时段。协议 strike 计数与
   服务失败互不沾染(异常不是"无效回复")。失败的请求(无回复)不计 llm_calls/token。
4. **记账口径(AC4/AC5)**:新模块 `host/budget.py`:
   - `BudgetLedger`:持久化 `run_dir/budget.json`(schema_version=1,atomic_json),
     字段 llm_calls / prompt_tokens+completion_tokens 全量累计 / validated_rounds /
     tool_attempts / logical_tool_calls / active_seconds(+悬挂 segment_start 加载即弃,
     崩溃停机不计时)。时钟可注入(clock 参数,默认 time.monotonic)。
   - 每次**完成**的模型请求记 llm_call(重生成也是真实请求,计入;token 从
     `session.last_usage` 鸭子类型读取,Fake 可不带);**回复被应用**才记 validated_round;
     每次真实工具执行记 tool_attempt(重放 attempt 也计,ADR L100),逻辑调用另计
     (与 Investigation/复核 runtime 的既有计数并存:单据在单元,汇总在台账)。
   - `RunBudget = ledger + limits + guard`:三 runner 增 `budget: RunBudget | None`
     构造参数,None → `RunBudget.load(run_dir)`(默认配置);守卫 `require_llm()/
     require_tool()` 在每次发请求/执行工具前检查 400/320/7200,超限 raise
     `BudgetExhaustedError`(现场已由既有 checkpoint 保存,当前调查**不落终态**)。
5. **轮次口径(局部上限=该单元的模型请求数)**:沿用 recon 票 06 先例(每次 step 消耗
   一轮,含被拒后重生成),三角色统一——协议风暴既被 3-strike 截停也被局部上限兜底;
   `validated_rounds` 是独立的"生效轮"诚实计数。analysis 新增 `resolve_analysis_max_rounds()`
   (env `STEP5_ANALYSIS_MAX_ITERS`,默认 30)+ runtime `rounds_used/max_rounds`
   (恢复守卫同步收紧);recon/verification 既有上限不动。局部轮次耗尽:analysis →
   `finished/unresolved/budget_exhausted`;verification → 既有 `_finalize(
   budget_exhausted)`;recon → 既有 `incomplete/rounds_exhausted`。
   **运行级**预算耗尽(400/320/7200/8)才是"保存当前调查"的非终态路径。
6. **配置解析与快照(AC6)**:`resolve_effective_config(*, explicit, env, profile) ->
   dict`(纯函数):显式参数 > 本机环境 > 版化 profile(schema_version=1 的 dict,可选) >
   代码默认(recon/analysis/verification 轮次 30/30/15、max_llm_calls=400、
   max_tool_attempts=320、max_active_seconds=7200、max_candidates=8);键级来源记录进
   `sources`;`persist_config_snapshot(run_dir, config)` 原子落 `run_dir/config.json`
   (含 schema_version/resolved/sources)。既有 `resolve_*_max_rounds` 改为该链的薄封装
   (默认层=env+defaults),签名不变,票 14 接线 profile 层。max_candidates(初始案例
   上限 8)沿用 candidates.DEFAULT_PROCESSING_SLOTS(票 07 已有),本票纳入 config 键。
7. **not_started 原语(AC7)**:tracer 公开 `mark_not_started(candidate_id)`:
   仅 queued 可标 → `finished/not_started/budget_exhausted`(queued→finished 合法转换),
   checkpoint `marked_not_started`;非 queued 拒绝(已开始的调查不得用 not_started 收束)。
8. **FakeSession 升级**:两份测试文件的 FakeSession `step` 耗尽后**重复最后一个回复**
   (单条坏回复自然走满 3-strike;可继续型测试在同一 Session 里补好回复),并新增带
   `last_usage` 的子类供 token 记账断言;时钟经 `RunBudget.load(run_dir, clock=...)` 注入。

## 切片(TDD 顺序)

- [x] S1 `host/budget.py` 纯逻辑+持久化:配置解析四层优先级/键级 sources/快照落盘;
      ledger 记账(llm/token/validated/tools/active)/崩溃悬挂段弃置/恢复续记;守卫
      三限+BudgetExhaustedError;表驱动测试 test_step5_host_budget.py。
- [x] S2 seam 准备:session.py 暴露 `last_usage`;tooling.py 增 `regeneration_feedback(
      exc/issue)` 结构化回喂文本(三 runner 共用,消灭三处手搓)。
- [x] S3 analysis.py:episode 重生成循环(3-strike→unresolved/protocol_error)、
      rounds_used/max_rounds+恢复守卫、budget 接线(require_llm/require_tool/
      validated_round 记账/active 段)、mark_not_started;迁移既有 raise 型测试+
      新增协议失败/轮次耗尽/预算中断/恢复测试。
- [x] S4 verification.py:同款 episode 循环与 budget 接线(动作块与 analysis 逐行平行
      纪律不变);迁移 raise 型测试+新增三连无效收束/预算保存现场测试。
- [x] S5 recon.py:协议无效(形状/守卫统一进 episode)3-strike→input_failure/
      protocol_error;budget 接线;rounds 口径不变(每次 step 计轮)。
- [x] S6 全量回归 + 自查(导出清单/文档字符串/新旧语义一致性)。

## 已知迁移点(既有测试的契约变化)

- analysis:L429/L452/L488/L514/L544/L611/L668/L696/L760/L768/L914 等
  `pytest.raises(ProposalRejectedError)` 的**循环级**拒绝 → 改断言"反馈回喂+零残留+
  同 Session 重生成后成功"或"3-strike 终态";纯函数 seam(claims.py 校验器)不动。
- verification:L830/L854 同上迁移;`test_round_exhaustion_*` 口径不变(请求计数在
  全有效流上与旧语义同值)。

## 收尾记录(2026-09-15,commit 1bc0b0c)

- 全量 890 passed + 21 skipped;新增 test_step5_host_budget.py(30 项),
  analysis/verification 循环级拒绝测试 18 处迁移到重生成语义。
- 双轴子代理评审:Spec 8 AC 全 PASS(补 1 项时长耗尽 Loop 级测试);
  Standards 无硬违规,已修 env 越界回落/注入 config 校验/recon 记账次序/
  恒等元组;`STEP5_*_MAX_ITERS` 双消费与台账构造顺序共享移交票 11
  (已在其 Comments 追加提醒)。
- 计划偏差(功能等价):FakeSession 保持严格耗尽即 StopIteration(未做
  "重复最后回复");`resolve_*_max_rounds` 保留独立 env 解析,由
  `test_env_keys_stay_coherent_with_role_resolvers` 钉键名一致。

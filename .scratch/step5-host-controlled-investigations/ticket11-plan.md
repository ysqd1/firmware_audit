# Ticket 11 实现计划:运行世代、活动锁与队列级恢复

依据:[票 11](issues/11-run-generations-locking-and-resume.md)、ADR-0012、
[spec](spec.md) Testing Decisions 1/2/4。范围边界:确定性报告/severity/封存归票 12,
D1–D4 与生产 CLI 接线归票 14;本票交付**串行运行驱动 + 世代 + 锁 + 恢复**。

## 盘上布局(新)

```
<workspace_root>/            # 驱动根(生产接哪里由票 14 决;测试传 tmp_path)
  lock.json                  # 工作区级活动锁(单写者边界)
  generations/
    gen-0001/                # = 既有 run_dir,全部现有工件布局不变
      manifest.json          # 世代身份(创建即写,只读)
      run_state.json         # 驱动元状态(status/phase/stop_reason,原子写)
      config.json            # 既有效能快照(budget.persist_config_snapshot)
      budget.json / candidates.json / findings.json
      investigations/{recon,cand-*}/   verifications/cand-*/
```

现有三 runner 的 run_dir 语义零改动——世代目录就是 run_dir。

## 新模块

### `host/generation.py`
- `MANIFEST_SCHEMA_VERSION=1`、`RUN_STATE_SCHEMA_VERSION=1`、`gen-\d{4,}` 模式。
- `list_generations(root)`、`read_manifest`、`load_run_state`/`save_run_state`(atomic_json)。
- `create_generation(root)` → 下一序号,先写 manifest 后返回;schema 不兼容 → StoreError
  带"请创建新运行世代"指引(票 17 口径)。
- run_state.status:`running`(未完成,可恢复)/ `finalizing`(处理全部收束,等票 12
  报告封存)/ `completed`(票 12 写;驱动只读并拒绝继续)/ `abandoned`(force 被顶替)。
- 缺 manifest 的 gen-\* 目录按损坏拒绝,不静默跳过。

### `host/locking.py`
- `lock.json`:`{schema_version, pid, hostname, started_at, generation}`。
- `acquire_lock(root, *, alive_checker=None)`:
  - 无锁 → 原子独占创建;
  - 有锁且 hostname 不同 → 拒绝(引导人工检查,不自动删——用户规矩"删除先问");
  - hostname 相同且 pid 活着(默认 `os.kill(pid,0)` + `/proc/<pid>/stat` starttime
    比对防 PID 复用)→ 拒绝第二运行;
  - pid 已死 → RuntimeWarning + 接管 stale lock;
  - 锁文件损坏 → 拒绝并引导人工处理。
- `LockHandle.release()` 只删自己的锁(pid+hostname 匹配)。

### `host/driver.py`
```python
RunDriver(root, *, tools, session_factory, llm, process_dir,
          explicit=None, profile=None, env=None, clock=time.monotonic)
run(force=False) -> RunSummary
```
- `env=None` → `os.environ`;测试注入空映射隔离宿主环境。
- 步骤:acquire lock → 选/建世代(force:把 running 世代标 abandoned 再新建;
  默认:0 个未完成→新建,1 个→恢复,多个→显式报错)→ 配置(新建=resolve 一次
  +persist;恢复=load_config_snapshot,不二次解析)→ 单一 `RunBudget` 实例 →
  recon(候选库已存在则跳过)→ store build → 注册 selected → 循环
  {analysis queued → verification queue → related 回队} 至不动点 → 收尾
  (status=finalizing, stop_reason=processing_complete)。
- `BudgetExhaustedError`:剩余 queued 标 not_started,stop_reason=budget_exhausted,
  status 保持 running,正常返回摘要(可解释的停止,不上抛)。
- 其他异常:记 stop_reason=`interrupted:<类型名>`,status 保持 running,**上抛**
  (现场已由既有 checkpoint 保存;StoreError 走票 17 拒绝路径)。
- `_BudgetedLLM(llm, budget)`:comparator/scorer 的模型请求过 `require_llm` +
  `record_llm_call`,独立活动段(需要 `BudgetLedger.is_active` 只读属性);
  失败请求不记账;`BudgetExhaustedError` 原样上抛(见下)。

## 既有模块改动

1. **budget.py**:`BudgetLedger.is_active` 属性(段开/段关判断,driver 的
   `_BudgetedLLM` 用)。
2. **candidates.py**:
   - `SemanticComparator.compare`/`PriorityScorer.score` 先 `except
     BudgetExhaustedError: raise` 再 `except Exception`——预算拒绝不得被误判为
     uncertain/评分失败(AC16);`CandidateStore.build` 内存中抛出 → 盘上
     candidates.json 保持上一版本 = 明确恢复边界。
   - `CandidateStore.build` 增量语义:既有 v2 记录里 `disposition is None`
     (已入选,结局在 Investigation)的保持 queue/disposition 原样(**锁定选取**);
     重建只对新增 survivor 以 `slots - len(locked)` 剩余名额跑
     `select_for_processing`;剩余名额 ≤0 → 新增全部 not_started。
     已分配 ID/alias/评分/merged 全保留(AC9/AC13)。
3. **recon.py**(恢复语义,票面接缝 AC8):
   - checkpoint `investigations/recon/state.json`(atomic_json):
     `{schema_version, status, reason, rounds_used, max_rounds, session_state,
     evidence[], pending{proposal,sequence}|null, survey, overview}`。
   - `run()` 开始时 `seed_sequence_from_files()`(此前只在 `__init__`——
     构造顺序不再决定水位,AC10);每个动作完成/接受/终态都落 checkpoint。
   - resume:completed → 幂等返回;survey_accepted → 无模型请求确定性收尾
     (先 _persist_store 再标 completed,崩溃夹缝可续);input_failure →
     重derive 概览,仍失败则返回记录,不再伪造;running → 从保存边界续
     (rounds/session_state/evidence 恢复,pending 的 Evidence 已在盘上则
     recover 回放,否则按同 sequence 重执行)。
   - `_persist_store` 拒绝覆盖 v2(StoreError"拒绝把已升级 Candidate Store
     降级写回")。
4. **analysis.py**:`add_candidate(proposal, *, candidate_id=None)` 可选显式
   ID(驱动按 store 的已分配 ID 注册,`cand-` 模式校验 + seq 抬水位);
   不传时行为不变(既有测试零影响)。
5. **`host/__init__.py`**:导出 `RunDriver`/`RunSummary`/generation/locking 公开件。

## 驱动与既有件的关键咬合

- **ID 对齐**:store 在去重后分配 `cand-xxxx`;tracer 以显式 ID 注册,顺序按
  candidate_id 升序,恢复时未注册的才补注册。
- **Evidence 水位**:全部在世代目录内;analysis/verification 每次 run 前
  re-seed(既有),recon 补 run 前 re-seed(本票)。跨进程恢复天然由文件水位覆盖。
- **verification 队列**:`load_cases` + `plan_verification_queue(cases,
  priority_of=store priority.total)`(ready 全量优先,gap 按优先级,无硬上限,
  预算是上限);已收尾案卷走 `_replay_finished_case` 幂等。
- **related 回队**:`stored_related_proposals(gen_dir)` → `related_intake` →
  `build(extra_intake=...)`;同源同 ID 同内容幂等跳过、同 ID 异内容
  CandidateIntakeError 上抛(不静默覆盖,AC11);无论来源调查结局如何都按
  持久化 proposal 接收(不只读 Findings,AC12)。
- **旧工件**(AC6):驱动只看 `generations/`,`process/agent/` 的
  survey/findings/verified_findings 结构性不可达;测试钉住"根下有旧命名文件
  也不读不迁"。

## 测试(`test/test_step5_host_driver.py` 新文件 + 少量既有文件补测)

TDD 顺序即实现切片顺序,每片先红后绿:

1. **世代**:创建→manifest;再跑→同代恢复;force→新代+旧代 abandoned;
   completed 代拒绝恢复(只读);manifest schema 不兼容→StoreError 指引;
   缺 manifest 的 gen 目录拒绝。
2. **锁**:活动进程→拒绝第二运行;死 PID→接管+警告;hostname 不同→拒绝;
   损坏锁→拒绝;release 后可再取。
3. **配置单一解析**:profile-only / env 覆盖 / explicit 覆盖三用例,断言
   config.json 快照与 recon/analysis/verification 实际轮次、slots 一致;
   恢复时改 env 不影响(snap 只读);不双消费(resolver 结果=快照值)。
4. **预算**:`_BudgetedLLM` 计数+活动段;comparator/scorer 预算耗尽原样上抛
   (不被当 uncertain/0 分);重建不重复扣账;单实例跨阶段累计正确。
5. **recon 恢复**:中断后续跑不重复已存证据、模型请求从保存轮次续;
   input_failure 可审计且不建 Investigation;incomplete 不重跑;
   survey_accepted 崩溃夹缝确定性收尾;v2 防降级。
6. **驱动循环**:selected 注册 ID 对齐;协议失败单项继续队列;服务中断保留
   queued(可恢复续跑);预算耗尽 queued→not_started;related 回队幂等+
   跨源同名拒绝;锁定选取(名额满时新增 not_started,已处理身份保留)。
7. **组合重启**(AC7/AC19):Fake Session/工具,多次重启跨 recon→store→
   analysis→verification→related 回队;断言 Candidate ID 稳定、Evidence ID
   两棵树含 recon 全程严格递增不重号、预算单调累计、复核队列顺序稳定、
   旧 survey/findings/verified_findings 不被读取、非法投影走票 17 拒绝。

## 明确不做

- 报告/severity/manifest digest/封存(票 12);review overlay(票 13);
  CLI 切换与真 Session 端到端(票 14);并行执行;动态追加预算;
  budget 计费模型扩展。

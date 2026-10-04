# 04: 守卫与交接进 actions/handoff

Parent: ../spec.md

**What to build:** 三个编排动作工具类(dispatch_agent / summarize / finish)与它们独享的调度守卫同住 actions 模块,交接块构建与快照落盘独立为 handoff 模块——"一次调度的前置校验"不再跨类六连跳(顺序门/任务唯一性/次数上限/断点续跑判断/重复调度应答全部内聚在调度动作旁)。编排主体只剩状态持有与登记。守卫行为一字不变。

**Blocked by:** 03

**Status:** ready-for-agent

- [x] 三动作工具类迁入 actions 模块;守卫六件套(未知 agent/顺序门/任务唯一性/次数上限/上游工件/断点续跑含 degraded 开关)与重复调度应答随迁;交接块构建与快照落盘独立为 handoff
- [x] 共享词汇(调度状态枚举/单次执行结果封装/状态标签)落位 state 模块:状态标签转正为公开名(去下划线,测试唯一私有 import 点);state 只放共享词汇,不收编格式化小 helper
- [x] 包内依赖无环:actions/handoff → state/dispatch_log,不反向;编排主体装配三动作、被动作回调,环由 state 切断
- [x] 守卫行为经既有公开路径(execute 直驱 16 处 + orchestrator 全流程测试)全绿;各拒绝/跳过/降级/重复的 Observation 文本不变
- [x] Orchestrator 类成员数明显下降(守卫/交接方法迁出);全套件绿

## Comments

- 2026-09-05 T3 移交:T4 state 模块落地时请收编 `orchestration/dispatch_log.py` 的 `_RUNNING`/`_INTERRUPTED` 落盘字面量(T3 起是与 DispatchStatus 同值的临时重复,原因与取舍见票 03 Comments;有漂移守护 `test_step5_dispatch_log.py::test_status_literals_match_dispatchstatus` 锁值),收编后该守护可删或改指 state。

- 2026-09-05 预设计归档(Codebase Design 会话产出;三条判断题用户已裁决,见文末)。**implement 按本设计执行,与本 Comments 冲突时以票面验收为准。**

  **Seam 决策**:动作类与守卫同住 actions,交接落 handoff,共享词汇落 state;actions 永不 import orchestrator——orchestrator 构造动作类时把自己作为 host 递入,回调面收敛为下述显式成员。环在 import 层不存在(state 为双方共同词汇),对象层合法(orchestrator 装配三动作、被动作回调)。

  **三模块 interface**:
  - `state`(~110 行,包内零依赖叶子):仅三样——`DispatchStatus`(原样迁入,值即落盘契约)、`STATUS_LABEL`(转正去下划线)、`SubAgentResult`(原样迁入,含 ok/to_dict)。不收 `_now`、不收格式化 helper。
  - `handoff`(~120 行,→ state):`build_handoff` / `build_rerun_brief` / `save_handoff_snapshot`,纯数据进、文本/副作用出,**不接 host**(可用 tmpdir 直测;本票不加新测,既有 handoff 快照测试经 run() 全流程锁定)。`_now` 原地保留一份(T3 先例)。
  - `actions`(~600 行,→ state / handoff / 下游三包 / runner):`MAX_DISPATCH_PER_AGENT`、`_PHASE`、`_VERIFY_*_RANK`(暂驻,见裁决 2)随守卫走;**守卫纯函数**(模块级,self._dispatches 改显式 dispatches 参数,逻辑逐字不动):`order_violation` / `find_duplicate` / `agent_call_count` / `latest_upstream` / `resume_degraded_enabled` / **`executed_dispatches`(裁决 3 改案新增)**;三个动作工具类:`DispatchAgentTool`(六件套守卫流程+重复/续跑应答;`_resume_result`/`_duplicate_result` 因需 host 服务保留为其方法)、`SummarizeTool`(`_verified_mark`/`_fmt_loc` 随迁)、`FinishTool`。

  **Host 回调面(actions 模块 docstring 文档化,不上 typing.Protocol——单 adapter,第二个出现再转正)**:数据读 `sub_cfgs`(转正)/`dispatches`/`agent_results`/`all_findings`/`process_dir`/`base_llm`/`agent_dir`/`force`;服务调 `next_seq()`(转正)/`register(sub)`(转正)/`dispatch_log`(T3 四动词对象)/`budget_state(agent)`/`budget_state_text(agent)`(转正;budget 集群不迁)/`run_verification_phase(...)`(转正,见裁决 1);状态写 `summarize_called` property 加 setter。Type 注解不写 `Orchestrator`。

  **包内依赖(无环,反向边为零)**:orchestrator→actions→handoff→state;orchestrator→handoff/state/dispatch_log/reconciliation;dispatch_log→state(收编 T3 移交的 `_RUNNING`/`_INTERRUPTED` 字面量)。layer guard 的 TIER 表不动;`test_step5_layer_guard.py` 新增 ~15 行 `test_orchestration_internal_edges`:AST 断言 actions/handoff/state/dispatch_log 的 import 目标不含 `.orchestrator`(本票唯一新增测试面,防环复活)。

  **不动清单**:verification 引擎整体留 orchestrator(`DEFAULT_VERIFY_K`/`_verify_k` 及相关)——T5 领地;budget 集群留 orchestrator(spec out of scope);`_ORCH_TMPL`/`_orch_system`/`build_orchestrator_prompt`/`ORCH_MAX_ITERS`/`run`/report/result/reconcile 留 orchestrator;dispatch_log.json / handoff_*.json / 各 Observation 文本逐字不变。

  **测试影响(机械更新,无 shim)**:`test_orchestrator.py` import 块拆分(SubAgentResult→state;MAX_DISPATCH_PER_AGENT/DispatchAgentTool/SummarizeTool→actions);私有 import 点消灭(`_STATUS_LABEL`→`state.STATUS_LABEL`);7 处 `orch._register(` 改 `register(`;`test_step5_pipeline.py`、`test_step5_dispatch_log.py` 同步;删除 `test_status_literals_match_dispatchstatus`(字面量收编后守护对象消失,T3 移交注记明示)。基线:全套件绿(T3 后 255 passed + 11 skipped;删 1 收集项 + 加 1 内部边守护,数目应持平)。

  **三条判断题(用户 2026-09-05 裁决)**:
  1. **确认** `_run_verification_phase` 转正 `run_verification_phase`:T4 被 actions 跨模块调用,留 `_` 前缀即本票要消灭的跨类私有;T5 迁 verify_phase 时此公开名退役(一次性改名代价)。
  2. **确认** `_VERIFY_*_RANK` 暂驻 actions:state 只放共享词汇(Q4 决定),排序表是复核引擎知识;T4 中 SummarizeTool 与 orchestrator 的 verify 阶段双消费,orchestrator 自 actions 借表方向合法;**本 Comments 即移交注记——T5 迁 verify_phase 时一并带走**。
  3. **否决原案,采改案**:不删除 `_executed_dispatches` 亦不原样搬方法,提升为 actions 模块级纯函数 `executed_dispatches(dispatches)`(与守卫函数同列),DispatchAgentTool._run 与 SummarizeTool 均调用之——T3"重复查询收敛单一出处"验收不破;handoff 照旧只收 `done` 数据、不接 host。(原案"删方法、_run 内联一次"会使 SummarizeTool 被迫重写过滤,钻 T3 验收的空子;且与 `agent_call_count` 的处理标准不一致。)

  **实施顺序**(单 commit):orchestrator 删旧 → state/handoff/actions 落新 → 测试 import 机械更新 → 全套件绿。

- 2026-09-05 T4 落地:`orchestration/state.py`(89 行,包内零依赖叶子:DispatchStatus 原样迁入、STATUS_LABEL 转正去下划线、SubAgentResult 原样迁入;不收 `_now`/格式化 helper)+ `handoff.py`(109 行:build_handoff/build_rerun_brief/save_handoff_snapshot 纯函数化,executed/all_findings/orch_dir/call_count 显式传参,不接 host,`_now` 原地保留一份)+ `actions.py`(521 行:守卫纯函数六件套模块级化——order_violation/find_duplicate/agent_call_count/latest_upstream/resume_degraded_enabled/executed_dispatches(裁决 3 改案,DispatchAgentTool 与 SummarizeTool 共用),self._dispatches 改显式 dispatches 参数,AST 逐段比对 vs HEAD 逻辑逐字;三动作工具类随迁,_resume_result/_duplicate_result 因需 host 服务保留为 DispatchAgentTool 方法;MAX_DISPATCH_PER_AGENT/_PHASE/_VERIFY_*_RANK(裁决 2 暂驻,T5 带走)/_verified_mark/_fmt_loc 同住)。orchestrator.py 1675→839 行,类方法 33→24(守卫 6 + 交接 3 + 应答 2 迁出,三工具类/SubAgentResult/DispatchStatus/_STATUS_LABEL 出模块);host 回调面转正:register/next_seq/sub_cfgs/dispatch_log/budget_state/budget_state_text/rerun_suggestion/run_verification_phase,summarize_called 加 setter。**两处设计 Comments 未列的 host 面成员**:verification_done(新增只读 property)与 rerun_suggestion——DispatchAgentTool 跨类读取/调用属实,留 `_` 前缀即本票要消灭的跨类私有,按裁决 1 同款逻辑转正并写入 actions docstring host 面;依票面"与本 Comments 冲突时以票面验收为准"处理,code-review Spec 轴复核认定可接受。dispatch_log.py 收编 T3 移交的 _RUNNING/_INTERRUPTED 字面量为 state.DispatchStatus(值不变),漂移守护 test_status_literals_match_dispatchstatus 随之删除。包内依赖单向 orchestrator → actions → handoff → state,dispatch_log→state;layer guard 新增 test_orchestration_internal_edges(AST 断言四模块 import 目标不含 orchestrator,ImportFrom+Import 双覆盖——Standards 轴评审建议加固后采纳)。测试机械更新照票面清单:import 块拆分(state/actions)、_STATUS_LABEL→state.STATUS_LABEL、恰 7 处 orch._register(→register(、orch._sub_cfgs→sub_cfgs 3 处、pipeline import 同步;不留 shim。全套件 255 passed + 11 skipped(T3 基线持平:删 1 收集项 + 加 1 内部边守护)。code-review 双轴通过:Spec 轴五项验收全过、偏差认定可接受;Standards 轴无硬违规,smell 全为搬家前既有或裁决 sanctioned(如 find_duplicate 硬编码四状态未用 EXECUTED、守卫注释 5 在 4 前——T6 同源知识收编候选)。
# 17: 多步会话、预算与中断恢复

**What to build:** 在单次实验入口上，让同一会话后继执行读取前序执行写入的运行文件，同时保证次数和活动时间正确记账；调查结束或中断后由 Host 清理封存，恢复不会复活旧会话或重复执行。

**Blocked by:** 16

**Status:** ready-for-agent

**Replaces:** 07, 08

## 验收

- [x] 真实集成演示同一会话两次执行：第一次写运行目录，第二次可读；同一容器内每次新建 PRoot，执行之间没有目标进程存活，临时桩/后端残留不作为运行状态保留
- [x] 会话台账有序追加每次声明输入、原始输出、digest 和结果，保留重放所需执行序列；新会话干净重建，不继承旧运行文件
- [x] 每会话执行次数为显式参数，临时默认 4，使用既有分层配置与 .env 覆盖、缺失/非法回落并记录生效值和来源；超限拒绝，对照/异常/复现逐次计数，最终默认由 19 校准
- [x] 保持每方独立最多 3 会话及单次 60/180 秒；不另设会话级活动时长上限，执行活动计入案例总预算，空闲不计；耗尽后不得继续执行，失败不自动重试
- [x] 调查正常完成、预算耗尽、中断均由 Host 强制停机封存全部会话，不依赖 Agent 自觉停机
- [x] Host 死亡后恢复可识别并收割遗留容器，记录清理结果；覆盖 PRoot/QEMU、短命/后台/脱离进程组的子孙进程，不能把 Docker 客户端死亡当清理完成
- [x] 中断即会话死亡，旧会话不可继续，运行产物仅留档不进新会话；新会话独立计数，不自动重放，已持久化执行不重复扣名额
- [x] 中断状态与清理结果分开，只有不能确认清理才标清理不确定；确认失败的容器不得复用，临时桩和 bind 残留不进入新会话
- [x] 在开启、执行、输出采集、完成、停机各边界注入中断，验证台账、封存和恢复一致；对未完成状态如实记录，不伪装正常结果
- [x] 离线恢复/预算测试与真实状态连续性、清理测试通过，执行项目要求的回归

## 材料

以 16 的后端和 Evidence 契约为基础；旧 07/08 仅保留历史，本票是现行验收要求。

## 共同边界

依据 [spec](../spec.md) 与 [ADR-0013](../../../docs/adr/0013-qemu-user-mode-experiment-boundary.md)。不修改宿主 binfmt、不替换固件 shell、不修改固件安全逻辑；不调用真实 LLM、不读取 GT、不改既有封存世代。动态成功、崩溃或失败均不是漏洞结论。实现按 implement/tdd 推进并以 Standards + Spec code-review 收口；离线与真实 Docker 测试分开，记录命令、输出和限制，真实验收缺失不得用 skipped 关闭工单。

## Comments

### 2026-09-22 实现记录（票 17 完成；提交 799fb89 → 3049caf）

**A. 交付物**

- `qemu_session.py` 重写为多步会话入口（单发语义保持票 16 兼容）：
  - 不带 `session_id`：开启新会话（干净容器 + 干净运行目录）→ 执行一次 → 默认停机封存（"一次性单发实验是只含一次执行的会话特例"）；`keep_open=true` 保持开启并返回 session_id。
  - 带 `session_id`：同一会话容器内再执行一次；每次执行独立 PRoot 实例与 `/proc` 快照，运行目录内前序执行写入的文件后继可读；逐执行清理验证（llscan count → 组杀 → 复扫），执行之间无目标进程存活。
  - `stop=true`：停机封存；`session_id`+`stop=true` 不带 `file_ref` 为仅停机。归属性质调整：`investigation_ref` 改为 Host 注入（模型值被覆盖），契约不再要求 Agent 填写（Host 预校验在注入前，必填声明会让合法调用被拒——真实缺陷，测试中发现并修复）。
  - 台账 schema 2：会话条目带 `status`（running/sealed/seal_failed/interrupted）、`execution_budget`（limit/source/used）、`executions[]` 有序数组（每执行的声明输入、原始输出 digest、退出码、耗时、结果分类、清理判定、链快照）。执行事实先于观测持久化——观测/落盘异常记缺口不抹掉已发生的执行。schema 1 拒绝续写（不静默升级）。
- `qemu_recovery.py`（新增）：`seal_open_sessions`（调查终态强制封存，seal_kind=host_finalize/host_interrupt）+ `reap_leftover_sessions`（恢复收割，seal_kind=recovery_reap），共享 `_dispose_sessions` 处置骨架。状态机：running →（封存路径）确认即 sealed/未确认留 seal_failed；（恢复路径）一律 interrupted；seal_failed 被确认 → sealed（封存完成，非中断）；interrupted 的清理不确定重试只刷新 cleanup/sealed/sealed_at，死亡判定（status/seal_kind/recovery 记录）不动。
- `driver.py` 三钩子：恢复 running 世代前 `reap_leftover_sessions`（SIGKILL 后遗留容器强制收割，收割行为 RuntimeWarning 留痕）；`_seal` 内 `seal_open_sessions(kind="host_finalize")`（正常完成与预算耗尽收束共同路径，finalizing 恢复重入可重试 seal_failed）；`except BaseException`（扩大自 Exception，捕获 Ctrl+C）中断路径 `seal_open_sessions(kind="host_interrupt")` 后再回写 stop_reason 并原样上抛。SIGKILL 无人可拦，由下次运行的恢复路径收割。
- 预算分层：`qemu_max_session_executions` 并入 `RunBudget` 既有分层解析（显式 > env `STEP5_QEMU_MAX_SESSION_EXECUTIONS` > profile > 默认 4），生效值与键级来源随 `config.json` 快照冻结；`execute_for_scope` 新增 `max_executions` 下发（键名 `QEMU_MAX_SESSION_EXECUTIONS_KEY` 单一出处），旧世代快照缺键时工具回落 env/默认并在台账记录实际来源。超限拒绝（`execution_quota_exhausted`，含 session_id 入 refusals）；对照/异常/复现/超时逐次计数。会话名额（默认 3，只可收紧）与单次 60/180s 不变；执行活动经 runner 活动段计入案例 `active_seconds`，会话空闲不计量。

**B. 清理与恢复语义（AC 落地点）**

- 清理未确认（执行后 leftover 残留未清或观测异常 unknown）→ 立即销毁会话容器并封存（spec"无法确认整次执行清理时销毁会话容器并封存"），该会话不可复用（AC1/AC8；第一轮评审缺口，已修）。
- `docker rm -f` 是唯一清理权威（杀 PRoot/QEMU 与全部派生，含后台/脱离进程组子孙——cgroup 语义）；"No such container" 判 absent（确认无容器，不是不确定）；客户端死亡不作为清理完成依据。中断状态（interrupted + recovery 记录）与清理结果（cleanup.verdict）分列，只有拆除不能确认才标 uncertain（AC8）。
- 中断即会话死亡：interrupted/sealed 会话一律拒绝执行（拒绝文案区分封存/中断/封存失败三种死因）；运行目录产物留档（`qemu_sessions/<session_id>/`），新会话运行目录独立创建，不继承旧文件；新会话独立占会话名额，执行计数从 0 起——已持久化执行不重复扣名额（AC7）。
- 预算在开启后、启动前耗尽：目标未运行不入执行账；本次新开的单发会话立即封存（不留从未执行的活动会话），复用会话保持 running 供重试或 Host 收口。

**C. 测试（TDD；命令与结果）**

离线（零容器，Docker 替身）——`pytest -q firmware_audit/test/test_step5_qemu_session.py firmware_audit/test/test_step5_host_driver.py firmware_audit/test/test_step5_host_budget.py -k "not real"`：**164 passed**。覆盖：多执行复用/仅停机/封存后拒绝、逐执行清理升级时序、执行次数三层解析（host_config 压制 env、env 覆盖、非法回落、来源入台账）、会话名额与角色/归属独立、中断五边界注入（开启 run_detached 抛 KeyboardInterrupt、执行窗口、输出采集 OSError、完成、停机 rm 失败）、恢复语义（收割、absent、台账损坏响亮不致命、seal_failed 重试、不重复扣名额）、旧镜像身份漂移拒绝、残留分类映射、argv/env 形状。driver 级两件：中断路径强制封存（host_interrupt）；monkeypatch 封死封存路径模拟 SIGKILL → 恢复运行收割（`pytest.warns` 验证收割告警）。

真实（门控，Docker 29.6.2 + `firm_audit/qemu-exec:p540q1111` + target/6、target/8）——`pytest -q firmware_audit/test/test_step5_qemu_session.py -k "real"`：**6 passed**（46.5s）。①`test_real_session_state_continuity_cleanup_and_session_death`：同会话两次执行（`echo > /tmp/state.txt` 后 `cat` 读回，宿主侧运行目录真实存在该文件）、逐执行清理干净、仅停机封存、封存即死亡、新会话干净重建（cat 失败且无 marker）；②`test_real_leftover_container_reaped_by_recovery`：keep_open 会话（后台 `sleep 30 &` + 前台探针）在客户端调用返回后容器经 `docker ps` 确认存活（遗留现场），`reap_leftover_sessions` 后容器真实消失、台账 interrupted/container_removed/recovery 记录、复用被拒；③会话内执行名额（env=2，第 3 次拒绝）；④ARM 顶层/原链/注入探针/3+1 名额/host-rootfs 边界拒绝（票 16 验收保持）；⑤超时分类与桩身份；⑥MIPS 非 shell 父直接派生。

全量回归（不读 GT，排除 host_evaluation）——`pytest -q firmware_audit/test --ignore=firmware_audit/test/test_step5_host_evaluation.py`：**1229 passed、16 skipped、1 个既有环境对照失败**（详情见 E；基线 1199 passed、16 skipped、同一失败；新增 30 项通过，无本票新增失败）。该次运行不得称为全量全绿；`python -m compileall -q firmware_audit`、`git diff --check` 通过。

**D. code-review 循环（4 轮至零发现）**

- 第 1 轮（799fb89 → 362c5df）：Standards 硬违反——Observation 渲染"第 None 次执行"（execution 记录缺 seq）；recovery 循环骨架重复/llscan 输出解析失败中断整个收割循环/`_now` 重复；预算键名魔法串。Spec 缺口——清理失败后 keep_open 会话仍可继续执行（补强制封存+拒绝复用）；开启边界中断无注入测试；absent 测试名实不符。
- 第 2 轮（f1c7715）：recovery 块误贴到 seal 路径（名不副实）；interrupted 重试注释与行为不符；台账回写失败双表报告；`_INT_KEYS` 字面量；driver 测试死代码；render 不可达分支。
- 第 3 轮（e1002fb）：sealed_at 注释残留（上轮未修净）；复用会话早退拒绝缺 session_id。Spec 轴 10/10 PASS。
- 第 4 轮（3049caf）：固件根不一致拒绝时 session_id 赋值顺序。**最终判定：Standards pass / Spec pass / FINAL: clean**。

**E. 既有问题与本票新增的区分（用户要求）**

- `test_qemu_exec_image.py::test_binfmt_independence_control` 失败为**既有环境漂移**，与本票无关：该测试属票 03 历史镜像 `firmware_audit/qemu-exec:latest`（QEMU 5.2），断言宿主无 binfmt 时裸跑 ARM 得 rc=126；本机 Docker Desktop 宿主 binfmt 已注册 qemu-arm 转译，裸 ARM ELF 进入 qemu 后因固件缺 `/lib/ld-uClibc.so.0` 得 rc=255。票 16 最终 Comments 已记录同一失败（当时亦存在）；本票 diff 未触碰该镜像、该测试或宿主 binfmt。正式 `qemu-exec-v2` 门控 14 项全过，qemu_execute 显式 PRoot+QEMU 路由不依赖宿主 binfmt。
- 本票新增回归为零：三轮全量回归中除上述既有失败外无任何其他失败。

**F. 已知限制与取舍（诚实声明）**

- 主动脱离进程组（setsid/double-fork）的真实探针未做：target/6 固件 busybox v1.14.1 无 setsid applet（实测 applet 清单在案）。后台子孙探针（`sleep 30 &`）已入真实收割测试；脱离进程组子孙由 `docker rm -f` 的 cgroup 权威覆盖（票 16 N4 已证明杀客户端/单杀 pid 均不足，容器拆除兜底）。
- 台账损坏时恢复只响亮告警（`unreadable`），不做 `fw-qemu-*` 前缀盲扫兜底：同宿主可能存在多工作区的活动会话容器，按前缀误杀的风险大于收益；占位记账先于容器创建保证台账必然先于容器存在，损坏属盘上故障需人工介入。
- 执行前不做残留预扫：进程级异常中断后同容器复用的场景，由下次执行后的 `_reap_and_verify` 事后兜底（残留 → leftover → 强制封存拒绝复用）覆盖。
- `execution_budget.source` 对 Host 下发值统一记 `host_config`，不区分快照内该值来自 env 层还是默认层——细粒度溯源在 `config.json` 的键级 sources 中，台账不重复。
- 票 19 校准前，会话内执行次数默认 4 为临时值（env/config 可覆盖，无方向限制——与会话名额"只可收紧"的防护策略不同，属 ADR-0013"可覆盖的显式预算参数"语义，代码注释已说明）。

**G. 边界遵守**

未触碰：宿主 binfmt、固件原件、既有封存世代、`qemu-exec-v2` 镜像与补丁（amd64 后端 + raw execveat 全拒绝边界原样保留）、CONTEXT.md/AGENTS.md/rules.md（用户有未提交改动）。未调用真实 LLM、未读取 GT、未启动票 18。

### 2026-09-23 binfmt 对照后续处理决定（未实现）

用户选择环境感知处理：保留宿主现有 binfmt 注册，不修改宿主全局状态。旧镜像的裸跑否定对照仅在确认无 ARM binfmt 的环境执行；当前 Docker 内核已注册 ARM binfmt，应明确记录该对照“未验证”及原因，不把 skipped 计为通过，也不接受自动转译后的 rc=255 作为等价成功。正式 PRoot + 容器内 QEMU 链路继续用真实回归验证；无 binfmt 对照以后在独立环境补测，此缺口不阻塞票 18。测试代码尚未修改，修复后须记录实际测试结果并复审最终改动。

### 2026-09-23 binfmt 对照环境感知化（实现记录，承接上条决定）

**实现（`firmware_audit/test/test_qemu_exec_image.py`，只动此文件）**：对照改为环境感知三态判定——
1. 预检：测试进程侧只读 `/proc/sys/fs/binfmt_misc`（无 privileged、不改任何条目），有 enabled 条目按 **magic/mask 匹配 ARM32 小端 ELF**（不依赖条目命名）即判"已注册"，直接标未验证、不跑对照；表不可读（测试进程与容器内核可能不同，如 Docker Desktop 非 WSL2 后端）不预判。
2. 行为探测（权威）：裸跑目标 ELF，`rc=126 + Exec format error`（ENOEXEC）才算对照**验证通过**；被转译（rc=0 或输出带 qemu- 前缀）或其它结果一律明确报告原因并 skip 标"**未验证（非通过）**"——rc=255 不当作通过，skip 不计入验证成功。
3. 解析器偏保守：mask 短于 magic 按 0xff 补齐（内核语义）、offset 超出探测头按"可能匹配"处理——宁可漏报"未注册"，不让对照假通过。
4. 新增 6 项离线解析器单测（本机 `/proc` 实测条目原样作夹具：arm 匹配；aarch64/python3.13 不匹配；全局与单条 disabled；表不可读；mask 补齐与 offset 保守）。解析器对实况表验证结果：`(True, 'binfmt_misc 条目: arm')`。

**本环境实测（2026-09-23，Docker 29.6.2 + `firm_audit/qemu-exec:p540q1111`）**：

| 项 | 通过 | 失败 | 未验证 |
| --- | --- | --- | --- |
| `test_qemu_exec_v2_image.py` + `test_qemu_docker_limits.py`（正式 v2 镜像门控 + 资源限额） | 22 | 0 | 0 |
| `test_step5_qemu_session.py -k real`（正式 PRoot+QEMU 会话链：同会话状态连续、会话内名额、遗留容器收割、超时、ARM 链与 `/host-rootfs` 边界、MIPS 派生） | 6 | 0 | 0 |
| `test_binfmt_independence_control` | 0 | 0 | 1（skip："执行容器所在内核已注册 ARM binfmt 转译（binfmt_misc 条目: arm）；按票 01 边界不改宿主，对照在此环境失效"） |
| binfmt 解析器离线单测 | 6 | 0 | 0 |

**语义声明**：该对照在本环境的"未验证"不构成 binfmt 独立性的验证成功，不计入任何验收通过；显式调用不依赖宿主 binfmt 的证明由 v2 门控真实测试承担（显式 PRoot→qemu-arm-static 11.1.1 路由，28 项全绿）。若宿主未来移除注册，对照自动恢复为实跑断言，无需改代码。未修改宿主 binfmt、未使用 privileged、未调用真实 LLM、未读取 GT；票 18 未启动。

### 2026-09-23 binfmt 对照修改的最终复审结论（补记）

- **第 1 轮（对 `99f9278` 全量）**：Standards + Spec 单评审双轴。需求逐条判定忠实：无任何把 rc=255/转译执行判为通过的路径（pass 唯一条件 = rc=126 且含 "Exec format error"）；skip 均附实测 rc 与输出证据，"已注册/被转译/无法确认"三种文案可区分且都标"未验证（非通过）"；无 privileged、无宿主 binfmt 写入、无 LLM、无 GT；解析器保守方向正确（mask 补齐/offset 保守/异常条目不据此判未注册），对实况表交叉验证 `(True, 'binfmt_misc 条目: arm')`。判定 **pass**，附 2 个可选瑕疵（ValueError 注释与返回值语义不符；skip 文案对"宿主侧表可见但容器内核可能不同"过度声明）。
- **第 2 轮（对 `8978f3a` 限定范围）**：仅 2 处纯文案改动、单文件、无逻辑夹带；新注释与行为探测兜底语义一致，新 skip 文案不再过度声明容器内核状态，保守方向如实表达；`pytest -k binfmt` 6 passed + 1 skipped（环境门控），无行为变化。判定 **FINAL: clean**。
- 复审后无未决 finding；本轮改动收口。未修改宿主 binfmt、未使用 privileged、未调用真实 LLM、未读取 GT。

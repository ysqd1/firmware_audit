# 19: 预算校准与完整交付验收

**What to build:** 将已跑通的真实通路接入角色使用说明、案例配置和报告，校准预算默认值，并展示 Analysis 取证后 Verification 在独立干净会话重放关键序列、生成可追溯报告的完整行为。

**Blocked by:** 18

**Status:** ready-for-agent

**Replaces:** 13, 14

## 验收

- [x] 用实际交付 PRoot/QEMU/镜像/模板和至少一个真实多轮业务通路测量准备、执行、清理耗时及分布，保留命令输出；不能用调查启动探针替代实际负载
- [x] 据实测定稿会话内执行次数默认值并说明依据；复核 60/180 秒余量，不足时提出明确建议，不擅自放宽硬上限或修改重试语义
- [x] .env 示例、配置文档、缺失/非法值回落测试同步定稿值；案例 profile 包含 QEMU 预算，每方最多 3 会话，配置快照如实记录生效值及来源
- [x] 18 的真实业务通路有可检查输入输出、正常对照和第二个干净会话重复结果；跨会话不继承文件，同会话重放可见前序状态
- [x] Verification 独立获得关键材料、按台账重建并重放，不直接复用 Analysis 运行产物作为本次证据；引用 QEMU Evidence 的 Claim 在确定性报告中正确呈现
- [x] 真实通路中原程序自主派生并记录身份与限制；target/6、7 各至少一真实 NVRAM 接口验证通过；MIPS32 大端至少一个样本实际执行且有结果/输出，预检不计入
- [x] 正式工具/模板入口回归执行边界（含 /host-rootfs 别名）、最小挂载、原件只读、进程清理、预算与恢复；不能因 PRoot 可运行就宣称隔离通过
- [x] 角色指令/工具说明明确按证据缺口选用、失败非漏洞反证、崩溃非确认依据；Analysis/Verification 可用，recon 无权限，sandbox_verify 不能绕过预算
- [x] 输出上限/截断、未知配置/缺依赖、信号/超时/中断与清理不确定的结果可追溯；成功或异常不自动产生 confirmed Finding
- [x] 汇总 16–18 与本票的实际证据及缺项，执行项目要求的全量回归；真实集成缺失不以跳过完成交付。Host/独立复核路径可用确定性 LLM 替身验证，真实固件路径须实际运行，审计质量改善另行评估

## 材料

使用 18 的通路与适配材料、16–17 的执行和恢复契约；旧 13/14 留作历史。安装成功、合成测试通过或命中 GT 均不是本票交付标准。

## 共同边界

依据 [spec](../spec.md) 与 [ADR-0013](../../../docs/adr/0013-qemu-user-mode-experiment-boundary.md)。不修改宿主 binfmt、不替换固件 shell、不修改固件安全逻辑；不调用真实 LLM、不读取 GT、不改既有封存世代。动态成功、崩溃或失败均不是漏洞结论。实现按 implement/tdd 推进并以 Standards + Spec code-review 收口；离线与真实 Docker 测试分开，记录命令、输出和限制，真实验收缺失不得用 skipped 关闭工单。

## Comments

### 2026-09-23 实现与真实验证记录（实现 + 真实后端验证 + 双轴评审收口）

**A. 交付物**

- **分相耗时入台账**（AC1 substrate）：`qemu_session._execute_once` 每次执行记录 `phase_seconds`（prepare=声明输入固化 / execute=docker exec 全程 / cleanup_verify=残留扫描与击杀 / chain_snapshot=快照读回），会话记录 `open_seconds`（设施核查+适配固化+容器创建）与 `seal_seconds`（容器权威拆除）；观测异常时记截止异常点的实测值。离线测试 `test_phase_timings_recorded_for_calibration`。
- **会话名额入分层配置**（AC3）：`budget.py` 新增 `qemu_max_sessions`（默认 3，env `STEP5_QEMU_MAX_SESSIONS` 同名），防护钳制经 `qemu_base.clamp_session_limit` 单一出处（budget 解析层/qemu_base env 层/qemu_session host 层三处共用）；`host/tooling.execute_tool` 随预算块下发 `max_sessions`，工具侧 `_session_limit()` 记 host_config 来源，台账会话条目记 `session_budget{limit,source}`。
- **案例预算 profile**（AC3）：`run_step5._load_budget_profile` 读工作区 `step5_budget_profile.json`（四层解析的 profile 层载体）；未知键/坏 JSON/空对象显式失败，数值合法性由分层解析把关（ConfigError 在建世代前失败，不留空壳世代）；模板 `firmware_audit/profiles/step5-budget-profile.example.json`（QEMU 预算块：会话数 3、会话内执行 4）。`.env.example`、`README.md` 同步（README 一并修正陈旧的 Step5 产物路径）。
- **Host 调用链角色盖章**（AC8 落地修复）：`execute_for_scope` 新增 `role`，analysis/verification runner 传各自角色；修复生产入口会话台账把 verification 会话记成 "analysis" 的身份失真（配额本按 investigation_ref 隔离未破，但台账身份不实）。
- **sandbox_verify 说明**（AC8）：工具描述明确"脚本不能启动 QEMU 或任何原固件目标执行，固件动态执行只能经 qemu_execute 的会话预算与证据台账"（结构性事实既有测试 `test_qemu_exec_image.py::…零 qemu` 钉住）。
- 角色提示词中"会话内执行次数有限(默认 4,以工具返回为准)"/"会话名额(默认 3)"与定稿值一致，未改动。

**B. 预算校准测量（AC1/AC2）**

命令：`python .scratch/qemu-user-mode-experiments/investigation/ticket19/measure_budget.py`（真实后端 firm_audit/qemu-exec:p540q1111；数据 `calibration-2026-09-23.json` 留档）。命令输出摘要（单位秒，4 会话 8 次执行）：

```
scope                    exec    open    seal        prepare        execute  cleanup_verify  chain_snapshot
case-opkg-a                1   0.332   0.190          0.002          0.135          0.103          0.103
case-opkg-a                2   0.332   0.190          0.002          0.134          0.112          0.108
case-opkg-b                1   0.335   0.154          0.002          0.148          0.101          0.092
case-opkg-b                2   0.335   0.154          0.002          0.136          0.100          0.097
case-captcha-spawn         1   0.352   0.154          0.001          0.178          0.112          0.089
case-t6abi                 1   0.339   0.156          0.001          0.117          0.110          0.121
case-t6abi                 2   0.339   0.156          0.001          0.122          0.106          0.096
case-t6abi                 3   0.339   0.156          0.001          0.107          0.107          0.118
分布: prepare 中位 0.002/最大 0.002; execute 中位 0.135/最大 0.178;
      cleanup_verify 中位 0.106/最大 0.112; chain_snapshot 中位 0.100/最大 0.121
```

- **定稿：会话内执行次数默认 4**（与票 17 临时值相同——校准的结论是确认该值而非调整）。依据：已观测最大单会话执行需求 = 3（NVRAM 三态）；Verification 按台账重放需求 ≤ Analysis 同会话次数；4 = 正常+对照+复现/异常 +1 次余量；对照/异常/复现逐次计数语义不变。依据已写入 `qemu_base`/`budget.py` 注释与 ADR-0013 2026-09-23 节。
- **60/180 秒余量复核：维持不变**。实测 execute 最大 0.178s，60s 默认余量 >300 倍；180s 硬上限经 `test_hard_timeout_cap_clamped_at_180` 钉住（timeout_seconds=300 → 钳 180，`timeout_requested_seconds` 如实保留声明值）。无放宽建议；失败不自动重试语义未触碰。

**C. 第二干净会话重复与跨会话不继承（AC4，门控 `test_real_opkg_second_clean_session_repeat_and_no_inheritance`）**

- opkg 两轮通路（list-installed + info busybox 对照）在第二个干净会话重复：两次会话 stdout digest 逐执行一致（`f509526b…`/`a3668c42…`，校准 JSON 同证）。
- 跨会话不继承：t8 原固件 busybox 会话 A 写 `/tmp/t19marker`（同会话后继执行 `cat` 可见——同会话重放可见前序状态）；新会话 B `cat` 非零退出且输出不含标记（新会话独立运行目录的如实证据）。

**D. 原固件程序自主派生（AC6，门控 `test_real_captcha_cgibin_autonomous_spawn_and_control`）**

opkg 运行成功不承担本项验收；本票在 t6 找到并交付新的真实业务通路：**cgibin（argv0=/htdocs/web/captcha.cgi）经 `system()` 自主派生**——非 shell 父程序、无模型介入的固件原链：

- QEMU_STRACE 铁证：`21 vfork(…) = 23` → `23 execve("/bin/sh",{"sh","-c","rndimage -f /htdocs/web/docs/captcha_1.jpeg -p /usr/sbin/fonts -w 180 -t 40 NYYQK",NULL})` → `23 vfork(…) = 26` → `26 execve("/usr/sbin/rndimage",{…})` 成功（PATH 解析），全部为原固件二进制/库经仿真执行。
- 可检查业务输出：`<captcha><result>OK</result><message>/docs/captcha_1.jpeg</message></captcha>`；验证码 jpeg（约 4KB）真实落在会话运行目录 rw bind（`runtime/base/docs/`），原件只读未动；会话存储 `runtime/base/var/session/1` 真实创建（sesscfg 夹具按票 18 四值格式）。
- 正常对照：同程序去掉 `HTTP_COOKIE` → 会话门 `<result>FAIL</result>NO SESSION`，strace 无 rndimage、无产物——输入不同 → 行为不同，证明真实业务分支而非启动成功。
- 身份与限制：目标/依赖 sha256 入台账声明；timeout/kill 包裹与 cleanup=clean 记录；链快照对短命子进程为空（快照缺口如实明示"短命子进程可能未捕获"），派生链身份由 strace 日志承担——沿票 16 的观测限制声明，不宣称完整执行链快照。
- conntrack.cgi 通路维持票 18 的诚实阻塞记录，不因本通路交付而改写。

**E. Host 确定性替身：Analysis → 独立 Verification 重放与报告链（AC5/AC9，`test_step5_qemu_host_replay.py`）**

- 真实后端（`test_verification_independent_replay_and_report_chain`）：ScriptedLLM 驱动公开入口全链（recon→analysis→verification→报告→封存）。analysis 两次单发 qemu_execute 执行 opkg 通路并冻结案卷；verification 按案卷 Evidence Reference 携带的声明输入（`case.json` `evidence_references[].arguments`）在**自己的会话**重放同序列，取得 ev-000004/5；断言链：verification 执行 arguments == 案卷冻结 arguments（按台账重建闭环）、双方会话台账 declared argv/target sha256 一致、证据 digest 不同（独立运行非复用产物）、确认 Finding 的 `evidence_references` 只含 verification 自己的 ev（`["ev-000004","ev-000005"]`）、确定性报告 Evidence Index 呈现 4 条 `tool=qemu_execute` 且 Finding 证据一致。配置快照断言 `qemu_max_sessions=3`/`qemu_max_session_executions=4`（来源 default）。
- 离线（`test_qemu_success_does_not_auto_confirm_finding`，Docker 替身）：qemu normal_exit 证据在场，verification 逐 Claim unresolved（证据不足不是反证）→ 案卷 inconclusive、`findings==0`、报告 `Confirmed Findings(0)`、qemu Evidence 仍可追溯——成功不自动产生 confirmed Finding（AC9）。

**F. 边界与角色接线（AC7/AC8）**

- 真实门控回归 18 passed（票 16-18 既有 16 + 本票 captcha 派生、opkg 重复 2）：含 guest 借 `/host-rootfs` 执行容器原生 qemu 的拒绝探针（票 16/18 既有）、最小 bind 与保留前缀拒绝（离线 5 前缀 + argv0 闸）、固件根只读挂载、逐执行清理验证与强制封存、会话/执行双层预算、遗留容器强制收割与中断即会话死亡。隔离声明以 Docker 边界 + PRoot 补丁为准，不以"PRoot 可运行"宣称隔离通过（工具 limitations 三句照旧返回）。
- 角色授权：`qemu_precheck`/`qemu_execute` 仅 analysis/verification（`test_registry_authorization` 既有）；recon 无权限。失败非漏洞反证、崩溃非确认依据、按证据缺口选用的措辞在 analysis/verification 提示词与工具描述中既有（本票核对未改动）。

**G. 16–19 证据汇总与缺项（AC10）**

- 16：单次执行贯通 ARM/MIPS、原 sh 派生链、/host-rootfs 拒绝、清理与预算（票 16 Comments 与门控测试）。
- 17：会话制/双层预算/恢复/中断语义（票 17 Comments；离线 + 真实门控持续通过）。
- 18：opkg 业务通路与对照、t6/t7 真实 NVRAM 接口三态、httpd 厂商包装消费、conntrack 诚实阻塞、适配桩与 argv0 语义（票 18 Comments；门控测试全部保持通过）。
- 19：本条 A–F。预算定稿 4/60/180、分相耗时分布、干净会话重复、captcha 自主派生、Host 替身重放链与报告呈现。
- **缺项（如实，不阻塞本票 AC，留待后续）**：①t6 web 栈（conntrack 会话门 SIGSEGV）与 t7 httpd 业务通路仍阻塞（常驻服务越界）；②链快照对短命子进程的观测缺口（身份由 strace 承担）；③getall 未决日志"牙齿"受现网零填充缓冲限制（票 18 P-c2 声明延续）；④审计质量改善（QEMU 对检出率的实际影响）按 spec 另行评估，不在本票；⑤binfmt 无对照环境补测仍悬置（spec Testing Decisions 声明，不计作通过）。

**H. 测试与回归（命令与结果）**

- 离线（零容器）：`pytest -q firmware_audit/test/… -k "not real"`（qemu_session/qemu_adapt/qemu_precheck/docker_limits/host_budget/pipeline/host_analysis/host_verification）→ **365 passed**；修复后定向复跑 **126 passed**。
- 真实门控：`pytest -q firmware_audit/test/test_step5_qemu_session.py firmware_audit/test/test_step5_qemu_precheck.py -k "real"` → **18 passed**（16 既有 + captcha 派生 + opkg 重复）；`test_verification_independent_replay_and_report_chain`（真实后端）单独通过。
- 全量回归：`pytest -q firmware_audit/test --ignore=firmware_audit/test/test_step5_host_evaluation.py` → **1286 passed, 17 skipped, 0 失败**（票 18 基线 1275+17；净增 11 通过，无新增失败；17 skipped 为既有环境门控，与票 18 基线相同）。评审修复（180 钳制测试等）后终态重跑 → **1287 passed, 17 skipped, 0 失败**。`python -m compileall -q`、`git diff --check` 通过。

**I. 已知限制与取舍（诚实声明）**

- 校准测量 JSON 保存分相耗时/结果分类/输出 digest 摘要，未逐执行保留完整 stdout 原文（可由门控测试确定性复现）；测量含 4 条通路共 8 次执行，非全架构全模板普查，分布结论限于已测样本。
- 定稿 4 系"确认临时值"而非数值变更；若后续通路需要更多会话内轮次，经 env/profile 层可覆盖（无方向限制），硬上限语义不变。
- 案例 profile 放行全部既有预算键（四层解析 profile 层的既有语义），AC 最小要求（QEMU 预算块）由模板与测试钉住；example 无 schema_version 键（未知键显式失败的严格载入使其不可容纳，取舍记录）。
- 维护性项未动（记录）：execute_for_scope 参数束（Data Clumps）、跨测试模块私有名导入宜迁 conftest、钳制后快照 source 仍记提供层名（语义注释已写明）、`_load_budget_profile` 位于入口层。

### 2026-09-23 code-review 记录（Standards + Spec 两轴并行 + 修复）

- Standards 轴：**0 hard** + 8 judgement（钳制逻辑三处同形→已提取 `clamp_session_limit` 单一出处；`resolve_max_sessions` 薄包装零调用方→已删除；离线替身测试补 `STEP5_QEMU_MAX_SESSION_EXECUTIONS` delenv；其余——execute_for_scope 参数束、分相计时入台账、profile 载入位置、example 无版本键、跨测试导入——记录为维护性，不阻断）。
- Spec 轴：10/10 AC 有实现与测试证据，无 scope creep 判定（profile 放行全部预算键 = 四层解析既有语义；README 为陈旧路径修正）。两处收紧已采纳：①AC5 补"verification 执行 arguments == 案卷冻结 arguments"断言（按台账重建程序化闭环）；②AC2 补 180 硬上限钳制测试（60/180 不再只是注释主张）。AC1 命令输出与 AC10 回归数字按其性质记录于本 Comments 与 `investigation/ticket19/`。
- 修复后定向复跑通过（126 离线 + 18 真实门控 + 重放链真实用例），修复后全量重跑 1287 passed/17 skipped/0 失败。

### 2026-09-24 复审循环第二轮（对最终提交 25ef08d 双轴 fresh 评审；用户规则：修改必须复审循环至通过）

- **Standards 轴：PASS（0 hard + 4 judgement）**。评审修复项逐一核验属实：clamp_session_limit 单一出处三处消费、resolve_max_sessions 零残留、execute_for_scope 的 role 盖章 setattr/finally 复位时序覆盖异常路径且模型参数不可触达、_load_budget_profile 键校验与世代前 ConfigError、180 钳制断言可靠、replay 测试配对确定。judgement 均记录不阻断：①execute_for_scope 临时实例槽累积 4 个（set/reset 成对，未到第三份拷贝门槛）；②replay 测试重复读 ev-000004.json；③`if role:` 真值判断建议 `is not None`（当前调用方均传字面量）；④session_budget 报告/台账两种形状靠测试钉住。
- **Spec 轴：PASS（10/10 有证据、无冲突）**。scope creep 仅两处已在工单声明的轻微项（README 陈旧路径修正、profile 放行全部既有预算键）；实现存疑三点均属已声明取舍（钳制后 source 记提供层名、digest 不等性无判别力而独立性由 session_id+declared 一致闭环承担、_scope_role 串行 Host 下无泄漏）。
- **循环终局**：两轴 PASS、无阻断发现、无新改动，复审循环收口；judgement 项按维护性记录留待触碰相应段落时顺带收敛。


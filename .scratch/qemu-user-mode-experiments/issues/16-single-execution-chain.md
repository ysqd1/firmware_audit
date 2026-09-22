# 16: 单次真实执行与原固件派生链贯通

**What to build:** Analysis 或 Verification 通过专用工具开启一个干净会话，执行一次原固件程序及其自主派生链，收到 Observation，保存可核验 Evidence 后停机封存。交付一个可独立演示的单次实验入口，包含 PRoot 后端、静态预检、运行边界、预算归属和超时清理。

**Blocked by:** 03, 04, 05（均已完成，可开始）

**Status:** ready-for-agent

**Replaces:** 15, 06, 09

## 范围

仅一次执行的会话。多次执行、跨轮状态、Host 死亡后的持久恢复由 17 完成；真实业务通路和适配由 18 完成。链路机制已有调查证据，不重做泛化路线调查。按“复现后端与边界 → 单次 Host 贯通 → 原链与清理验收”在同票内逐步验证。

## 验收

- [x] 按用户指定，以 PRoot 5.4.0 + QEMU 11.1.1 为交付目标，构建新版本执行镜像；固定官方源码来源、校验值、构建参数、基础镜像 digest 和 ARM/MIPS 二进制身份，不使用漂移 latest 选择版本。可复用已有 11.1.1 构建调查材料，重新验证来源与产物；QEMU 5.2 仅保留为历史对照
- [x] 正式接入前实测 PRoot 5.4.0 + QEMU 11.1.1 的完整 ARM/MIPS 矩阵、身份观测、执行边界与清理；先前裸 11.1.1 的失败及 PRoot + 5.2 的成功均不能代替新组合验证。若新版组合失败，保留具体差异与阻塞，不静默回退 5.2 或降低 AC，也不凭版本号宣称兼容性提升
- [x] 正式工具入口完成真实 ARM 单发执行→Observation→世代内 Evidence/台账→停机封存，Analysis/Verification 授权独立、recon 不可调用；sandbox_verify 不能绕过专用入口的记账
- [x] 静态预检补 PRoot/QEMU/镜像身份及验证条件，不运行 guest、不创建会话；架构支持不扩大为全部 ABI，NVRAM 未满足条件仍报告阻塞
- [x] 原 ARM shell 自主启动原动态程序和静态辅助程序、MIPS 对照通过；另验证非 shell 父程序直接派生，标明合成夹具与真实固件证据。包含命令注入类链路机制探针，不以宿主 shell 或手动拆调用冒充原链
- [x] Docker 断网、原件只读、独立可写运行目录、权威 Evidence/其他 target/docker socket 不可达；显式运行根和最小 bind/必需设备，不用自动宽泛绑定，不自动放宽默认 seccomp、privileged 或 capability
- [x] 运行时拒绝 guest 自主调用未授权的容器原生程序或额外 QEMU，覆盖 /host-rootfs 与路径规范化、符号链接、适用 proc/fd 别名和执行系统调用变体；测试固件内部构造路径，不只检查工具入参。可信后端必需程序单独授权，不能将其行为当作原固件证据；不能满足既定边界则留阻塞，不自行降低要求
- [x] 每次执行新建 PRoot；进程数量、执行路径、输出大小均有有限约束。台账记录声明输入、目标及依赖 digest、后端版本、链路径/数量、实际耗时与输出 digest；原固件、PRoot/QEMU、prooted 装载桩身份分开，验证短命子进程观测并明确缺项，不用轮询快照或 cmdline 宣称完整身份
- [x] 验证 QEMU -strace 在该组合下是否可用并记录限制；若使用仅作为辅助日志，不充当隔离或完整链路台账
- [x] 单次默认 60 秒、硬上限 180 秒且受案例剩余预算约束；每 Investigation/Case 独立最多 3 会话，同角色第 4 个拒绝。对照/异常/复现都记执行；预检不占会话名额但计工具和活动时间，失败不自动重试
- [x] 正常/非零退出、目标信号、超时、准备或运行依赖阻塞、设施失败、清理不确定可区分，保留退出码/信号/原始日志及截断提示；不把边界拒绝伪装为目标崩溃
- [x] 单次正常结束、超时、杀 tracer、杀 Docker 客户端均验证 PRoot/QEMU/后台及脱离进程组的子孙进程清理；必要时销毁容器，无法确认则明确记录。临时桩与挂载残留清理，不只以客户端退出为依据
- [x] 离线契约与真实 ARM/MIPS 门控测试通过，完成项目要求的回归；保留可复现命令和证据

## 材料

[QEMU 11.1.1 构建与裸运行对照](../investigation/qemu-stable-arm-chain-2026-09-22/README.md)、[官方发布来源](https://www.qemu.org/download/)。2026-09-22 用户指定新交付版本为 11.1.1；本票内完成组合验证，不新增调查票。

[PRoot 调查](../investigation/proot-arm-chain-2026-09-22/README.md)、已完成票 03/04/05；旧 15/06/09 留作历史映射，本票正文是现行验收要求。

[组合验证](../investigation/proot540-qemu1111-2026-09-22/README.md)（本票实现前实测，2026-09-22）。

## 共同边界

依据 [spec](../spec.md) 与 [ADR-0013](../../../docs/adr/0013-qemu-user-mode-experiment-boundary.md)。不修改宿主 binfmt、不替换固件 shell、不修改固件安全逻辑；不调用真实 LLM、不读取 GT、不改既有封存世代。动态成功、崩溃或失败均不是漏洞结论。实现按 implement/tdd 推进并以 Standards + Spec code-review 收口；离线与真实 Docker 测试分开，记录命令、输出和限制，真实验收缺失不得用 skipped 关闭工单。

## Comments

### 2026-09-22 实现记录（票 16 完成）

**A. 组合验证（实现前实测，[investigation/proot540-qemu1111-2026-09-22](../investigation/proot540-qemu1111-2026-09-22/README.md)，logs 80–90 可复现）**

- 来源钉值：QEMU 11.1.1 官方 tarball sha256+尺寸+GPG（Michael Roth，指纹与 qemu.org 一致）；PRoot 5.4.0 tag tarball sha256 与 04 调查同值；基础镜像 `debian:bookworm-slim@sha256:3783cc01…`、builder `debian:bookworm@sha256:f37a335e…` digest 钉定。
- 矩阵全绿：ARM 顶层/原 sh 派生链（动态子 nvram + 静态子）/MIPS 顶层/派生/busybox env 非 shell 父直接派生（真实固件二进制）全部真实进入仿真；dash 症状 0；裸 11.1.1 的失败与 PRoot+5.2 的成功均未替代本组合实测。
- 身份观测：链存活期 /proc 快照 = proot tracer + qemu 实例（exe=`prooted-<pid>-XXXX` 桩 8,872 字节，sha256 逐版本确定）；桩≠固件≠qemu 原件，台账单列。
- 发现并处置的差异（新组合特有，均留证据）：①`/host-rootfs` 逃逸面在组合下确认存在（含 `..` 规范化、固件内符号链接原生执行容器程序）；②单 pid SIGKILL 杀 tracer 留 3 个 qemu 孤儿（04 调查的"零孤儿"实为 timeout 组击杀效果）；③proot `--mixed-mode` 只护初始 tracee（`new_child` 继承白名单遗漏）；④GitHub auto-archive 非字节稳定（当天两次下载 sha256 不一致）。
- QEMU_STRACE=1 在组合下可用（打印 guest 侧 execve）；限制：输出量大、管道截断可致 qemu SIGPIPE——仅作辅助日志。
- 清理：超时（timeout -k）rc=124 后 0 残留；杀 Docker 客户端后链仍存活（客户端退出≠清理）；容器拆除为权威兜底。

**B. 交付物**

- `firmware_audit/docker/qemu-exec-v2/`：pins.env（钉值单一来源）+ Dockerfile（三阶段源码构建 + 形状隔离剥离 + BUILD-INFO/LABEL 身份档案）+ build_image.sh（下载缓存→宿主侧 sha256+尺寸校验→临时上下文硬链接构建）+ run_smoke.sh（11 项全过）+ llscan.c（/proc 扫描/组杀/延时观察/cat——镜像无 shell 的清理与观测助手）+ proot-mixed-mode-inherit.patch（一行，`new_child` 继承 `mixed_mode`；sha256 钉定）+ proot-5.4.0.tar.gz（225KB 钉值副本入库，因上游 auto-archive 非字节稳定）。镜像 `firm_audit/qemu-exec:p540q1111`（钉 tag，不用 latest）；5.2 旧镜像与构建目录原样保留为历史对照。
- `step5_agent/providers/tools/qemu_session.py`：`qemu_execute` 单发执行会话入口。一次调用 = 开启会话（`-d --init --read-only --network none` 容器 + 固件根 ro 挂载 + 独立 rw 运行目录 + `/tmp` noexec tmpfs + `PROOT_TMP_DIR` 桩 tmpfs + 最小设备绑定 /dev/null、zero、random、urandom）→ 容器内 `timeout -k 5 <T>` 包裹 `proot --mixed-mode on --kill-on-exit -q qemu-<arch> -r <固件根>` 直接 argv 执行 → 分类 Observation → llscan 清理验证（残留→组杀→复扫→拆容器）→ 停机封存（`docker rm -f` + 台账终态）。
- `qemu_base.py`：`QEMU_EXEC_V2_IMAGE` 常量、矩阵 observed_notes 更新为票 16 组合实测、会话上限解析（默认 3，env `STEP5_QEMU_MAX_SESSIONS` 覆盖、非法回落）。
- `qemu_precheck.py`：设施核查接新镜像——LABEL 承载 PRoot/QEMU/补丁/基线身份 + 镜像内 qemu 自报版本（唯一容器调用不变，仍不触固件字节）；报告新增 proot 身份与组合验证条件句；限制句更新为"样本级链能力以会话期实测为准，不得以组合验证外推宣称"；`find_in_root` 提为模块级（与会话工具共用）。
- 注册表：`QemuExecuteTool` 授权 analysis/verification、recon 不可见、ReplayPolicy.NEVER（重放=隐藏的额外执行）；sandbox_verify 结构性隔离与契约互不覆盖不变（既有测试续绿）。
- Host 接线：`ToolContext.generation_dir`（driver 建世代后回填，台账落世代内 `qemu_sessions/`；独立演示回落 process_dir）；`make_tools` 按角色构造时传入 role；三角色提示词列明 `qemu_execute` 及名额/证据语义，recon 声明不可见。
- 预算归属：每 (角色, investigation_ref) 独立最多 3 会话，第 4 个拒绝（refusals 入台账）；会话占位记账先于执行（执行窗口内客户端死亡也有名额记录与容器名收割锚点，终态由 replace 回写）；预检不占名额；单次默认 60s、参数钳制 1–180s；失败不自动原样重试（NEVER）。
- 台账（`ledger.json` + 会话目录 stdout/stderr/proc-snapshot/session 工件）：声明输入（argv/env/cwd/input/timeout）、目标+解释器+NEEDED 库 sha256、后端版本与镜像身份、链快照（延时一次 /proc + 明示短命子进程缺项；prooted 桩单独归类，不冒充固件/qemu）、实际耗时、输出 digest、清理判定；不把轮询快照或 cmdline 宣称为完整链身份。

**C. 运行时拒绝机制（AC7 落地，内核无关）**

实现 = proot `--mixed-mode` 继承补丁（guest 派生树内任何原生 x86 ELF 的 execve 一律改写经 qemu 路由→架构不符→拒绝；覆盖 /host-rootfs、路径规范化、符号链接、植入 ELF——guest 的全部 execve 流量过 ptrace 拦截层）+ 镜像剥离只读根（deny-by-absence 第二层：未授权容器原生程序物理不存在）。**已明示阻塞：raw `execveat` 不在覆盖内**——proot 5.4.0 源码 syscall 入口仅 `PR_execve`（src/syscall/enter.c:124），guest 经 qemu 发出的 raw execveat 不被翻译也不被 mixed-mode 改写，内核按容器真实 fs 解析：guest 路径解析错位（多数 ENOENT、/tmp 落 noexec tmpfs 被 EACCES），但容器绝对路径可原生执行白名单保留的后端二进制或运行目录内植入的 x86 ELF。固件原生 busybox 无 execveat 调用者（适用面论据），暴露面要求蓄意植入的 guest 代码；补齐需 proot execveat 改写扩展、noexec 运行目录（与宿主侧读回冲突，tmpfs+llscan 同步为候选）或主线内核 Landlock，**按 AC 留阻塞给票 17/19 裁定，不自行降低要求**。产品镜像内实测：注入链借 /host-rootfs 执行容器 qemu → rc=255 "Invalid ELF image"；原链与注入子命令同时真实进仿真。排除路径（证据在案）：`-b` 遮蔽 /host-rootfs 被 proot 拒绝（rc=182 保留路径）；Landlock 在本宿主 WSL2 内核允许规则不生效（ABI 3 报告正常但执行仍 EACCES），不可依赖，留作主线内核可选加固。残余面如实入 README：guest 植入外来架构 ELF 经 qemu 仿真运行（与固件自身程序同权：同根、只读、断网、限时、同受 ptrace）；固件内符号链接可读容器 /etc 等非可执行文件（剥离镜像内无敏感内容）。可信后端程序（proot/qemu/timeout/sleep/llscan）单独授权且行为不入固件链证据。

**D. 测试（TDD）**

- 离线（零容器）：`test_step5_qemu_session.py` 16 项——参数契约、授权、3+1 名额（含角色/归属独立、env 覆盖与非法回落）、准备阻塞路径（越界/缺失/引号/env 行/cwd 穿越）、设施失败、八类分类映射参数化、清理升级与兜底拆除、argv/环境形状（--mixed-mode/--kill-on-exit/timeout 包裹/PROOT_TMP_DIR/QEMU_STRACE）、台账损坏拒绝、占位记账。
- 真实（门控，SKIP 带原因）：`test_qemu_exec_v2_image.py` 11 项（版本/身份/BUILD-INFO/剥离形状/ARM 顶链/MIPS/边界拒绝）+ 会话真实 4 项（ARM 顶层+原链+注入探针+3+1 名额+封存、超时分类、MIPS env 非壳父直接派生）。镜像无 bash 时冒烟逐条直接 argv 驱动。
- 全量回归：基线 1147 passed + 16 skipped（票 05 记录）→ 终态 1179 passed + 16 skipped，新增 32 项全 PASS、零回归（16 个 skip 全为既有 target/1 门控；code-review 修复后复验见下）。

**E. 已知边界与限制（诚实声明）**

- **AC7 残余（诚实声明，非静默降级）**：raw execveat 不被拒绝机制覆盖（见 Comments C 阻塞段）；proc/fd 别名以"无 /proc 绑定"结构性缺席验证（探针 M7/B7b、HR5/HR6）。
- 会话归属 `investigation_ref` 由 Agent 按任务上下文填写，台账逐字记录；Host 侧把归属硬绑定到真实 Investigation/Case 属票 17（恢复/强制收口/多执行会话）范围。
- 客户端死亡后遗留容器按名 `fw-qemu-<session_id>` 可收割，收割路径属票 17；本票保证台账占位与容器命名可追溯。
- Landlock 在主线内核可作第三层加固，本宿主内核不可用故未依赖；proot 补丁为本地一行改动，随镜像构建应用并以 sha256 钉定（补丁文件入库可审）。
- 未触碰 CONTEXT.md（有用户未提交改动）、既有封存世代、宿主 binfmt、固件原件；未调用 GLM、未读 GT。

### 2026-09-22 code-review 记录（两轴并行评审 + 修复，提交 7162cef → 0fed122）

评审基线 `git diff 736351a...7162cef`。Spec 轴：无 scope creep；docker_utils 原语/提示词/矩阵档案更新均有 AC 依据。Standards 轴 + Spec 轴共同点名修复 9 处：

1. **依赖检索截断静默丢弃**（Standards 硬违反）：`_runtime_dependencies` 丢 `find_in_root` 截断标志，违反同 diff 文档红线 → 截断写入台账条目 `dependencies_search_truncated`。
2. **execveat 覆盖缺口**（Spec 轴源码级发现）：proot 5.4.0 syscall 入口仅 `PR_execve`，guest raw execveat 不被 mixed-mode 改写、内核按容器 fs 直解 → Comments C 措辞修正 + E 节明示阻塞（候选：proot execveat 改写 / noexec 运行目录 / 主线内核 Landlock，留票 17/19 裁定）。
3. **耗时判定污染**：`started` 含建容器（≤120s）与哈希，宿主侧 docker 超时守卫与台账耗时改从 docker_exec 起点计时。
4. **proot 致败误判面**：分类启发式收紧为必须含 proot 特征尾行 `fatal error: see 'proot --help'`。
5. **桩目录可被 env 覆盖**：`exec_env` 展开顺序调整为 declared_env 在前、`PROOT_TMP_DIR` 在后。
6. **回归数字声明错误**：Comments D 由"1160 基线+36 新增"修正为"基线 1147+16（票 05）→ 终态 1179+16，新增 32"。
7. `_prep_refusal` 四元组 Data Clump → `refuse()` 闭包（与 precheck `block()` 同款）；`role`/`generation_dir` 去防御性 getattr。
8. 杂项：docker_utils `import json` 上提；llscan usage 文案补 cat；run_smoke 加 pipefail + llscan rc 真值比较；FakeDocker 可变默认参数改 sentinel；测试死代码清理；提示词"最多 3 个"改语义化（与 env 旋钮防漂移）；镜像重建保持库内 llscan.c 与镜像一致。
9. 真实超时会话补快照断言（存活链 /proc 快照非空 + 缺项 note 措辞钉住）；gated BUILD-INFO 测试补 LABEL↔BUILD-INFO 一致性断言。

**保留不修（评审记录在案）**：pins.env 与 Dockerfile 双写以离线 drift 测试守护（跨语言单源需配置机制，票 03 同款取舍）；pins/注释引用 .scratch 证据目录（项目惯例，证据本就不入仓）；driver 经共享 ctx 回填 generation_dir（生产 tools 恒非空，已留注释）。

**修复后复验**：镜像重建 + 冒烟 11/11；全量套件 1179 passed + 16 skipped，零回归。


### 2026-09-22 最终实现复查（固定开工基线；本轮记录优先于此前“完成”表述）

**范围与证据口径**：由 Comments 的前轮基线和 Git 父链交叉确认，开工前固定点为 `736351ab5af8c0d689083caa02870522aa46e15e`（票 05 修复）；`7162cef` 为票 16 首次实现，`0fed122` 为后续修复。比较命令 `git diff 736351a...HEAD`，并叠加 `git diff HEAD` 与相关未跟踪文件，覆盖全部实现，不只审最后一个提交。相关未提交材料包含 CONTEXT.md 术语增补、ADR-0013、固定 PRoot 源码包；未涉及的 benchmark/dataset/参考项目不纳入票 16，不读取 GT。两轴评审使用 luna / max；不调用真实审计 LLM，不启动票 17，不改 spec/ADR 或既有封存世代。

**复现与修复（均先运行失败回归，再修复验证）**：

1. **执行边界前置闸缺失（Spec，阻断交付）**：已有 Comments 明知 raw `execveat` 未覆盖，但正式入口仍启动目标，违反 spec “若现有约束下做不到，记录阻塞，票 16 不得放开目标执行”。加入不可由工具参数/环境开关绕过的准备阻塞；Analysis/Verification 两角色回归先观察到 `normal_exit`，修复后 `prep_blocked`，不创建容器、不消耗会话。只在零容器 Docker 替身测试内 monkeypatch 该闸；真实会话测试明确因阻塞跳过，**不是验收通过**。本修复关闭“缺口存在仍放行”，不宣称关闭 execveat 本身。
2. **启动/异常清理（Standards + Spec）**：容器启动超时前无占位，快照/写盘等异常没有 finally；已将占位移到启动前，统一 finally 拆容器与终态记账。`snapshot read failed` 与启动超时回归修复前均未收割，修复后保留设施失败与封存结果。Host 被 SIGKILL 后恢复仍不在本票实现。
3. **清理失败伪装成功（Spec）**：`docker rm` 失败、扫描为 0 时仍报 normal_exit；现在 cleanup_uncertain 优先，并保留原始执行退出码。移除旧超时分支未核实 rm 返回值即声称“容器已拆除”的文案。
4. **会话身份冲突（Spec）**：`inv/a` 与 `inv?a` 被 slug 成同一 ID，覆盖工件及台账；添加 UUID 后缀，跨归属/跨世代容器与工件不再共用名称。
5. **Host 归属与预算（Spec）**：Agent 自填标识可无限重置名额，60/180 秒未受剩余活动预算约束。Host 两 runner 通过共享执行 seam 绑定实际 Investigation/Verification ID 与动态剩余时间；实际 guest 启动前再次收紧，低于 1 秒拒绝。会话环境配置只能收紧默认 3 的上限，不能增至 99。前轮将 Host 硬绑定推迟到票 17 的说明不构成本票 AC 豁免。
6. **后端环境变量（Spec）**：只固定 PROOT_TMP_DIR 仍允许 PROOT_NO_SECCOMP、QEMU_LD_PREFIX、LD_PRELOAD 等影响可信后端。现在拒绝 PROOT_/QEMU_/LD_ 控制变量及非法环境名称，保留普通 guest 输入。
7. **依赖路径与记录（Spec）**：解释器符号链接可指向固件根外，宿主会读取外部字节计算 digest；现在对解释器与依赖逐项 containment 校验，缺失/越界报 dependency_blocked。保留搜索截断的显式缺项记录。
8. **输入/输出身份（Spec）**：声明输入文件缺 SHA-256、stdout_bytes 按字符计算；补输入 digest，并按 UTF-8 存储字节计数。
9. **边界拒绝/运行依赖分类（Spec）**：带 Invalid ELF 架构拒绝或 loader 缺库日志的失败不再直接归为目标信号，分别保留准备/依赖阻塞提示及原始 rc；日志提示不冒充可信执行事件。
10. **固定源码未交付（Standards + Spec）**：本机 `proot-5.4.0.tar.gz` 存在且 hash 符合 pins，但 `git check-ignore` 命中全局 `*.tar.gz`，此前“已入库”不实。加入精确白名单及源码 hash/可交付回归；本轮留作未提交交付文件，未擅自提交。

**需要用户裁定的后端问题**：PRoot execveat 改写扩展、运行目录 noexec/同步方案、或其他可实测约束方案尚未选择。本轮不代选架构，也不把缺口移交票 17/19 来宣称票 16 完成。保持现有 spec，票 16 的真实单次执行/完整边界验收仍阻塞。链身份目前仅一次快照与 strace 辅助，不能据此宣称完整实际派生路径、数量和短命子进程身份；重新开放必须补齐对应实际验收。

**验证与最终复审**：进行中，最终数字及两轴结论在下一条 Comments 写入；本条不代表票 16 已通过。

### 2026-09-22 最终 code-review 结论（对应当前工作树）

复审覆盖 `736351ab...HEAD` 的全部票 16 提交、`git diff HEAD` 的未提交改动，以及相关未跟踪的 ADR、测试和固定 PRoot 源码包。没有读取现有 GT、没有启动票 17，也没有调用真实 LLM。

**Standards**

- 先前指出的清理异常泄漏、无资源上限、清理失败伪装成功、固定源码被 `.gitignore` 忽略均已用回归测试复现并修复：`_run`/`_execute_session` 由 `finally` 收口；会话容器默认 `--pids-limit 128`；Docker stdout/stderr 并发有界读取、超限和管道未闭合均显式标记；`cleanup_uncertain` 优先；精确白名单保留 `proot-5.4.0.tar.gz`。
- 当前没有发现新的硬性规则违反。`qemu_session._run` 仍同时编排参数准备、台账和生命周期收束，属于可读性上的 Divergent Change / 大函数气味，但不会掩盖未处理异常，后续可独立重构，不作为本票交付阻断。

**Spec**

- 原 finding“`execveat` 未覆盖但仍放行”已关闭为安全处置：`QEMU_EXECUTION_BLOCKER` 在正式入口无条件产生 `prep_blocked`，不建容器、不消耗会话；预检报告明确 `execution_gate.allowed=false`。离线 Docker 替身测试只能显式 monkeypatch 该闸，真实 ARM/MIPS 会话测试因闸而 `SKIP`，不能计作验收通过。
- Host 现在绑定真实 Investigation/Verification ID 和剩余活动预算；会话上限环境值最多收紧到 3；会话 ID 含随机唯一后缀；后端控制环境变量、固件根外依赖、输入 digest、UTF-8 字节数、显式 `argv0`、快速 guest `exit(124)` 分类和不可变镜像 ID 均有回归覆盖。
- **仍未关闭的交付阻断**：票 16 要求真实 ARM/MIPS 单发、原始派生链、边界拒绝和清理实测；当前前置闸刻意禁止这些真实执行。PRoot raw `execveat` 拒绝机制、可信后端与 guest 执行的完整约束、prooted 装载桩逐项 digest/完整短命链身份仍未实现或实测，不能将组合验证材料或静态镜像冒烟当作 Host 会话验收。需要用户决定后端方案（PRoot 扩展、运行目录 noexec/同步设计或其他可实测机制），本轮不改 spec、不移交票 17/19 冒充关闭。

**最终验证**

- `pytest -q firmware_audit/test/test_step5_qemu_session.py firmware_audit/test/test_step5_qemu_precheck.py firmware_audit/test/test_qemu_docker_limits.py firmware_audit/test/test_qemu_exec_v2_image.py firmware_audit/test/test_step5_tool_contract.py`：`100 passed, 3 skipped`。
- `pytest -q firmware_audit/test --ignore=firmware_audit/test/test_step5_host_evaluation.py`：`1185 passed, 19 skipped, 16 warnings`；跳过项均为真实 Docker/目标门控或当前执行闸，未用作成功证明。`python -m compileall -q firmware_audit` 与 `git diff --check` 通过。

**最终轴结论**：Standards 轴 0 个硬性 finding（1 个可维护性气味）；Spec 轴 1 个未关闭的交付阻断（执行边界和真实会话验收仍未完成）。票 16 不能标记为完成，当前代码的安全行为是“静态预检可用、正式动态执行明确阻塞”。

### 2026-09-22 raw execveat 诊断反馈环与后端方案对照（不改正式代码）

**调查边界**：本节只诊断票 16 的剩余阻断，不改变 `qemu_session.py` 的前置闸，不关闭票 16，不启动票 17，不调用真实 LLM，不读取 GT。新增的 `scripts/91-raw-execveat-repro.py` 与 `scripts/92-landlock-execveat-probe.py` 是调查脚本，不接入产品入口。当前 WSL2 可见 Docker 客户端路径，但 Docker daemon 不可用；本机也没有 `proot`、QEMU user binary 或 C 编译器。因此 PRoot/Docker 部分采用组合调查目录内已完成的 Docker 实测日志与固定源码核对，并如实标记本轮不能重建的项。

#### 1. 最小稳定反馈环

反馈环固定为一个目标 `/bin/true`、一个子进程、四种 raw syscall 入口，分别覆盖本票要求的路径、dirfd、`AT_EMPTY_PATH` 和 `proc/fd` 别名：

```bash
python3 .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/91-raw-execveat-repro.py
```

本轮实际输出：

```text
absolute: child_exit=0
dirfd-relative: child_exit=0
empty-path: child_exit=0
proc-fd-alias: child_exit=0
```

这证明四条内核入口都可稳定到达执行点；删除任一变体都会失去对应边界的覆盖。探针通过 `fork` 隔离每次执行，子进程失败会打印 syscall errno，脚本只有四项均成功才返回 0。

固定源码核对命令：

```bash
tar -xOf .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/src-cache/proot-5.4.0.tar.gz \
  proot-5.4.0/src/syscall/enter.c | nl -ba | sed -n '117,127p'
tar -xOf .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/src-cache/proot-5.4.0.tar.gz \
  proot-5.4.0/src/syscall/exit.c | nl -ba | sed -n '430,433p'
tar -xOf .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/src-cache/proot-5.4.0.tar.gz \
  proot-5.4.0/src/syscall/sysnums.list | rg -n 'execve'
```

实际结果是入口和退出分派都只有 `PR_execve`，`sysnums.list` 也只有 `execve`（没有 `execveat`）。这与组合调查 README 的结论一致：QEMU guest 发出的 raw `execveat` 不经过现有 mixed-mode 改写，而由内核按容器真实文件系统解析。当前环境不能启动 Docker/PRoot 的原因已记录：`docker version` 返回“Docker daemon could not be found”，并且没有 `proot`、`qemu-arm-static`、`qemu-mips-static` 或 `gcc/clang`。

#### 2. 方案一：扩展/补丁 PRoot 覆盖 execveat（首选主修复）

**复现命令与证据**：

```bash
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/90-mmpatch-verify.sh
```

该脚本在已有 Docker 实测中使普通 `execve` 的 V1 `/host-rootfs`、V2 符号链接、V3 植入 x86 ELF、V4 规范化穿越全部拒绝，同时 V0 原链和 V5 注入子命令通过；日志为 `logs/90-mmpatch-verify.txt`。它不能证明 raw `execveat`，因为当前源码没有该 syscall 分支。最小环的宿主基线由 `scripts/91-raw-execveat-repro.py` 给出；恢复 Docker 与 guest 静态探针后，应在同一 PRoot/QEMU 形状下逐项运行这四个变体，并要求每项都进入 QEMU 路由或明确拒绝，而不能按普通 `execve` 结果外推。

要使补丁真正覆盖本票边界，不能只新增一个 syscall 常量，至少还要完成：所有支持 ABI 的 syscall 编号表；`dirfd` 相对解析；`AT_EMPTY_PATH` 的 fd 目标解析；`AT_SYMLINK_NOFOLLOW` 和未知 flag 处理；`/proc/self/fd/<n>` 别名与 guest/host fd 命名空间转换；QEMU runner 的 argv/argv0 重写；exec 退出路径与 tracee 状态更新；派生子进程的 mixed-mode 继承。每个变体还要加入路径穿越、符号链接、文件描述符关闭/越界和错误 errno 回归。

**结论、残余边界、成本**：这是唯一能保持“可信后端执行”和“guest 未授权执行拒绝”同时成立的主修复。残余风险是 syscall/ABI 组合和 PRoot ptrace 语义容易漏项，必须持续维护本地 fork、镜像重建和 ARM/MIPS Docker 回归矩阵；维护成本高，但与票 16 的 AC 直接对齐。在补丁及四变体真实 Docker 验收通过前，现有 `QEMU_EXECUTION_BLOCKER` 必须保留。

#### 3. 方案二：运行目录 noexec、镜像剥离与同步

**复现命令与证据**：调查脚本 `88-final-shape.sh` 的 N1/N2/N3/N4 已在 Docker 29.6.2 实测：

```bash
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/88-final-shape.sh
```

`logs/88-final-shape.txt` 中 N1 显示植入运行目录的 x86 ELF `can't execute`，但写入仍成功；N2 证明只读根、exec 桩目录和跨 exec 状态；N3 超时后残留为 0；N4 单 pid 杀 tracer 仍留 3 个 qemu，必须拆容器兜底。`logs/90-mmpatch-verify.txt` 还证明镜像剥离/只读根可使普通路径的未授权容器程序缺失或拒绝。

**关键差异**：调查 N1 使用 `/session/runtime` 的 `tmpfs:rw,noexec`，而当前正式 `qemu_session.py` 使用宿主 `runtime_dir` 的普通 rw bind，再以 `-b /session/runtime:/tmp` 映射给 PRoot；正式代码没有给该运行目录设置 noexec。因而 N1 的通过不能当作当前生产形状已覆盖 raw `execveat` 的证据。若把运行目录改为 noexec tmpfs，宿主侧读取 stdout/台账/同步文件就必须另设可读 staging，定义写入时点、原子同步、崩溃恢复及容量上限；否则会破坏现有会话证据链。

**结论、残余边界、成本**：noexec 能挡运行目录内的原生 x86 植入，镜像剥离能减少容器可执行目标，二者都不能阻止 raw `execveat` 指向只读固件根或仍被白名单保留的后端程序，也不能把调用重写到 QEMU。它们是中等维护成本的纵深防御，不能单独解除票 16 阻断；同步机制还会引入新的证据一致性风险。

#### 4. 方案三：Landlock 或其他运行时限制

**Landlock 复现命令与证据**：

```bash
python3 .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/92-landlock-execveat-probe.py
```

本轮实际输出为四项 `rc=-1 errno=13 (EACCES)`，随后四个子进程均 `child_exit=113`；探针本身返回 0，表示四项都完成了拒绝观测。已有固定二进制的对照命令也失败：

```bash
.scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/bin/ll-exec /bin -- /bin/true
```

输出 `ll-exec: exec /bin/true 失败 (errno=13)`，返回 127。README 和该探针共同表明 WSL2 6.6.87.2 虽报告 Landlock ABI 3、创建/加规则/限制系统调用可返回成功，但允许 `/bin` 后执行 `/bin/true` 仍被拒绝；当前宿主不能把它当作可用执行白名单。

在支持且修复了该行为的主线内核上，Landlock 可以作为 launcher 层第三层限制，但仍须单独验证 QEMU/PRoot/后端路径、fd 继承、重命名和写入 staging；它提供的是内核拒绝，不提供 PRoot 所需的 guest 路径重写。seccomp 可以把 `execveat` 一律拒绝作为最后的拒绝式兜底，但会同时阻断合法 guest 动态执行，不能满足票 16 的真实 ARM/MIPS 链路，且本轮 Docker daemon 不可用，未宣称已实测。

**结论、残余边界、成本**：当前环境下 Landlock 不可用；换宿主后维护成本低到中等，但有明确内核版本/行为依赖。seccomp 只适合作为明确选择“全部禁止 raw execveat”时的隔离开关，不是本票的主方案。

#### 5. 推荐与当前决策点

推荐顺序是：

1. 保持现有执行前置闸，先在 PRoot 本地 fork 中实现并审查完整 `execveat` syscall 处理，再用同一四变体反馈环覆盖 ARM/MIPS、路径/dirfd/`AT_EMPTY_PATH`/`proc/fd`、符号链接和派生链；在 Docker 真实回归通过前不开放 `qemu_session.py`。
2. 补丁通过后，把 noexec 运行目录和镜像剥离作为纵深防御；若采用 noexec tmpfs，先单独定下 staging 同步契约并增加崩溃/超时回归。
3. 仅在具备已验证 Landlock 行为的主线内核上增加可选第三层；当前 WSL2 不纳入依赖。seccomp 仅保留为拒绝式紧急策略。

因此，票 16 的唯一剩余交付阻断仍然成立，不能以 noexec、镜像剥离或当前 Landlock 探针关闭。需要用户决定是否批准“维护 PRoot fork 并补齐 execveat”作为后端架构方向；本节没有擅自改变 spec，也没有修改正式代码。

### 2026-09-22 PRoot execveat 原型验证（调查隔离，不解除执行闸）

**原型问题**：在真实 PRoot 5.4.0 + QEMU 11.1.1 组合中，是否可以用最小的 PRoot syscall/过滤补丁拒绝 guest 发出的四种 raw `execveat`，同时保留可信后端和既有 ARM/MIPS 普通 `execve` 派生链。原型只构建调查镜像，不修改 `firmware_audit` 正式代码、不修改 `qemu_session.py`、不关闭票 16。

**环境与基线**：首次检查时 Docker daemon 短暂不可达；随后复查恢复为 Docker client/server `29.6.2`，现有 `fw-probe-combo-p540q1111-diag:latest` 与 `fw-probe-combo-p540q1111-mmpatch-diag:latest` 可用。最终原型镜像为 amd64。宿主没有 PRoot/QEMU user binary/编译器，因此 guest helper 由固定 Docker 构建环境交叉编译，不能用宿主 syscall 结果替代组合验证。

调查 helper 只执行固定目标 `/host-rootfs/usr/local/bin/qemu-arm-static`，成功执行会打印 QEMU 11.1.1 版本；四个变体分别为 absolute、dirfd-relative、`AT_EMPTY_PATH`、`/proc/self/fd`。可重跑命令：

```bash
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/94-build-execveat-probe.sh
```

该命令使用 ARM/MIPS 交叉编译器生成静态 helper，最终输出 hash：

```text
4cd82283d1c05ec3845e9503442f9b4dab9ddaab1901720794d6c1c5167f3e9c  execveat-arm
1c0836846d1c3bd8c35cbae8e2a057625d306b7c9b0ace51e74c75b932bd7677  execveat-mips
```

**修复前真实组合复现**：

```bash
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/95-run-execveat-probe.sh \
  fw-probe-combo-p540q1111-diag:latest
```

ARM 与 MIPS 均出现相同结果：absolute 变体因当前路径形状返回 `ENOENT`，但另外三项都打印了 `qemu-arm version 11.1.1` 并以 `child_exit=0` 结束；这证明 dirfd-relative、`AT_EMPTY_PATH`、`proc/fd` raw `execveat` 已在真实 QEMU guest → PRoot → 容器链上执行了未授权的静态 x86 后端。wrapper 的 `arm rc=1`/`mips rc=1` 是 helper 在“至少有一项成功”时的基线失败信号，不是 Docker/PRoot 设施失败。

**最小 deny-only 补丁**：`scripts/proot-5.4.0-execveat-deny.patch` 只做四件事：加入 `PR_execveat` 枚举；加入固定 amd64 host syscall 322 映射；将 `PR_execveat` 加入 PRoot seccomp/ptrace 过滤白名单；在 syscall enter 阶段、任何 host 路径解析前，对带 QEMU 的 tracee 返回 `-EACCES`。它不把 execveat 参数误解释为 execve，也不声称完成合法 raw execveat 的路径重写。构建命令：

```bash
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/96-build-execveat-deny.sh
```

该命令在隔离镜像中用固定 PRoot 5.4.0 源码和已验证的 mixed-mode 继承镜像完成编译；编译只有上游既有 warning，返回 0。

**修复后四变体结果**：

```bash
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/95-run-execveat-probe.sh \
  fw-probe-combo-p540q1111-execveat-deny-proto:2026-09-22
```

ARM/MIPS 四项全部输出 `syscall_rc=-1 errno=13 (Permission denied)`、`child_exit=113`，不再打印 QEMU 版本。另用禁用 seccomp 加速的路径复核：

```bash
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/95-run-execveat-probe.sh \
  fw-probe-combo-p540q1111-execveat-deny-proto:2026-09-22 1
```

第二个参数 `1` 注入 `PROOT_NO_SECCOMP=1`；ARM/MIPS 四项仍全部 `EACCES`，说明补丁不依赖 seccomp 加速的偶然行为。

**可信后端与原链回归**：

```bash
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/97-run-trusted-chain.sh
```

结果为 PRoot/QEMU 版本命令 `proot_rc=0 qemu_rc=0`，ARM 原动态 `nvram` 派生链打印 `arm-derived-ok`，MIPS 派生链打印 `mips-derived-ok`，最终 `arm_rc=0 mips_rc=0`。每个脚本结束都会拆除自己的临时容器和 rootfs 目录；原型镜像使用明确的 `*-proto` 标签，不接入正式镜像标签。

**判定**：该原型证明“host x86_64 PRoot 中早期 deny 所有 QEMU raw `execveat`”可以关闭本票暴露的四种绕过，同时不破坏当前可信后端和普通 ARM/MIPS 链。建议进入正式实现评审，正式行为应明确写成“QEMU 会话内 raw `execveat` 全部拒绝”，并将 syscall 表、seccomp 白名单、ptrace fallback 和 ARM/MIPS 回归纳入正式测试。当前原型只覆盖 amd64 PRoot host；它没有实现合法 raw `execveat` 的路径/dirfd 重写，也没有证明其他 host ABI，因此若 spec 要求 guest 合法使用 raw `execveat`，本原型不足以进入实现，必须另做完整翻译方案。正式执行闸仍保持，票 16 仍未关闭。

### 2026-09-22 正式实现、修复与最终复审

**固定基线与范围**：按 Comments 和 Git 历史，票 16 开工前固定点为
`736351ab5af8c0d689083caa02870522aa46e15e`；本次最终复审覆盖其后的
`7162cef`、`0fed122`、`7a55707`、`231a4bf` 以及工作树中的票 16 材料。
`benchmark/`、`dataset/`、参考项目和 GT 未读取，未调用真实 LLM，未启动票 17。

**正式实现**：

- `firmware_audit/docker/qemu-exec-v2/proot-execveat-deny.patch` 已进入正式镜像构建，SHA-256 为
  `d361d4b28c75029e89892a5283efcdddb99a89a0d752372b91bf07b1c98dae2e`。
- 补丁接入 PRoot 5.4.0 的 `PR_execveat` 枚举、amd64 host syscall 322 映射、seccomp/ptrace 过滤表和 syscall-enter fallback；QEMU tracee 的 raw `execveat` 在路径解析前返回 `EACCES`，不重写 guest 合法 raw `execveat`。
- `qemu_session.py` 不再保留永久执行阻断；只接受带完整 QEMU 11.1.1、PRoot 5.4.0、mixed-mode 补丁、raw execveat 补丁和 boundary 身份的不可变镜像 ID。缺失或漂移的任一标签在建会话前报告 `facility_failure`。
- `llscan` 对可见 `prooted-*` 装载桩计算文件大小和 SHA-256，台账保存结构化 `stub_identities`；快照缺失或不完整时明示限制，不把 `/proc`/cmdline 单独当作链身份证明。

**可重跑验证与结果**：

```bash
bash firmware_audit/docker/qemu-exec-v2/build_image.sh
bash firmware_audit/docker/qemu-exec-v2/run_smoke.sh
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/94-build-execveat-probe.sh
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/95-run-execveat-probe.sh firm_audit/qemu-exec:p540q1111 0
bash .scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/scripts/95-run-execveat-probe.sh firm_audit/qemu-exec:p540q1111 1
bash .scratch/qemu-user-mode-experiments/investigation/proot540q1111-2026-09-22/scripts/97-run-trusted-chain.sh firm_audit/qemu-exec:p540q1111
```

实测 `run_smoke.sh` 为 `pass=11 fail=0`。四种变体 `absolute`、`dirfd-relative`、`empty-path`、`proc-fd-alias` 在 ARM 和 MIPS、seccomp 开启和 `PROOT_NO_SECCOMP=1` 两种路径下均为 `syscall_rc=-1 errno=13 (Permission denied)`、`child_exit=113`，没有 QEMU 版本输出。可信后端为 `proot_rc=0 qemu_rc=0`；ARM 原动态派生链和 MIPS 派生链均返回 0。最终真实会话测试覆盖 ARM 顶层/派生链、MIPS 非 shell 父链、超时清理和桩身份，均通过。

回归与检查：

```bash
pytest -q firmware_audit/test/test_step5_qemu_session.py firmware_audit/test/test_step5_qemu_precheck.py firmware_audit/test/test_qemu_docker_limits.py firmware_audit/test/test_qemu_exec_v2_image.py firmware_audit/test/test_step5_tool_contract.py
pytest -q firmware_audit/test --ignore=firmware_audit/test/test_step5_host_evaluation.py
python -m compileall -q firmware_audit
git diff --check
```

定向套件为 `115 passed`，无跳过；编译检查通过。全量（按“不读取 GT”排除 host evaluation）为 `1199 passed, 16 skipped, 16 warnings`，另有 1 个与票 16 无关的既有对照失败：`test_qemu_exec_image.py::test_binfmt_independence_control` 使用历史 `firmware_audit/qemu-exec:latest`，Docker Desktop 的宿主 binfmt 将裸 ARM ELF 转给 qemu-arm，因缺少 `/lib/ld-uClibc.so.0` 得到 rc=255，而测试固定期待无 binfmt 时的 rc=126；正式 `qemu-exec-v2` 门控全部通过，未将该环境漂移当作票 16 通过证据。

**复审**：最终 Standards 轴无新 finding；此前的资源上限、输出有界读取、清理异常封存、环境优先级和固定源码交付问题均已关闭，`_run` 较大仅为非阻断维护性气味。最终 Spec 轴无 finding；此前“仅 raw 补丁标签校验”和“缺少 prooted 装载桩独立身份”两项分别由 `231a4bf` 的回归测试和实现关闭。正式行为仍明确限定为 host amd64 映射下 QEMU 会话 raw `execveat` 全拒绝，不实现 guest 合法 raw `execveat` 重写。

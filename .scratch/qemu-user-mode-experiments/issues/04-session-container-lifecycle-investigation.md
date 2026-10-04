# 04: 会话容器生命周期与子进程链机制调查

**What to build:** 用票 03 的执行镜像实测会话制的机制可行性，产出直接喂票 06/08/09 的实现选择：容器跨工具调用存活的完整命令面（create/start/exec/rm、超时清理、进程组收割、孤儿回收）、目标程序在仿真下派生同架构子进程链是否可行（约束：不修改宿主全局 binfmt，不得以宿主 shell 替换固件 shell）、各中断边界的容器与运行目录状态。

**Blocked by:** 01, 03

**Status:** ready-for-agent

- [x] 会话期容器存活的完整命令序列实测记录（开启/执行/停机/超时/强杀各路径）
- [x] 子进程链可行性结论：固件程序派生的同架构子进程能否留在仿真内执行，附实测；不可行时按 ADR-0013 约束记录具体阻塞并回报，不静默收窄范围
- [x] 进程组收割与孤儿容器回收的命令面与已验证行为记录
- [x] 中断边界状态清单：开启前/执行中/输出采集中/停机中各时点强杀后，容器与运行目录分别处于什么状态
- [x] 结论追加到本票 `## Comments`，附命令与输出原文

## Comments

2026-09-22 后续决定：用户采用 PRoot + QEMU。本票完成状态与历史证据保留；新后端镜像、预检及运行边界由 [票 15](15-proot-backend-integration.md) 补齐，不能把旧结果视为新后端已验收。

### 2026-09-22 调查结论（票 03 镜像实测；原文日志在 `investigation/04/`，索引见其 `README.md`）

**总览：会话容器生命周期与收割命令面全部可行且已实测；子进程链 MIPS BE（musl）可行（需 `QEMU_LD_PREFIX` 环境适配）、ARM LE（uClibc）阻塞（已按 ADR-0013 记录具体阻塞，不收窄范围）。** 纪律：镜像 = 票 03 产物 `firm_audit/qemu-exec:latest`（= `:deb11u3`，id `2e9ba5fd5704`）；全程 `--network none`；target/6、target/8 原树只读未动（会话运行目录用 `/tmp/fwq04/sess-*/rundir` 拷贝，测后已清）；宿主 binfmt 前后快照一致（`00-env-check.txt` / `90-final-state-check.txt`）；未改产品代码；实验容器全部测后拆除，宿主零 qemu 进程残留。

#### 1. 会话期容器存活：完整命令面（AC1）

实测开启（两种式）→ 跨调用执行 → 停机 → 超时 → 强杀全路径（`10-session-lifecycle.txt`、`11-init-stop-timing.txt`）：

```
docker run -d --init --network none -v <rundir>:/session \
    --entrypoint /bin/sleep firm_audit/qemu-exec:latest infinity   # 开启（create+start 等价，两种均实测）
docker exec <sess> qemu-mips-static ...                            # 每个工具调用一次 exec，容器跨调用存活
docker stop -t 0 <sess> && docker rm <sess>                        # 停机封存（或 docker kill）
```

关键实测：**①跨调用状态积累成立**——exec#2 写 `/session/state-across-calls.txt`，exec#3 读回；guest 进程写会话目录，下一 exec 可见（10）。**②PID1 信号坑（必须进票 06/08 设计）**：`sleep infinity` 或 `bash -c 'sleep infinity & wait'` 作 PID1 都不理 SIGTERM（内核丢弃 PID1 默认处置信号），`docker stop` 恒耗满 10s 后 SIGKILL、exitcode=137；`docker run --init`（tini）后 stop 仅 0.105s、exitcode=143 且 tini 收割僵尸。**③停机时序**：`docker kill` 0.096s、`docker stop -t 0` 0.092s（对照：优雅 stop 无 `--init` 时 9.9~10.1s）。**④stop 后未 rm 的容器可重启**，容器层与挂载状态保留（10 末段）。

**exec 退出码语义**（喂票 06 结果五分类，`12-exec-rc-semantics.txt`）：guest 退出码原样透传（0/3/1 实测）；guest 信号死 = 128+n（`kill -9 $$`→137、`kill -11 $$`→139）；qemu 层失败 = 1（目标文件不存在，stderr 带 `Could not open` 类报错）/ 255（错架构）；docker 设施错误 = 1（容器不存在，`Error response from daemon`）。guest 非零退出与 qemu 失败可用 stderr 文本区分。

#### 2. 子进程链（AC2，本票核心）

**机制定性（源码 + strace 双证据）**：vanilla qemu 5.2 的 `TARGET_NR_execve` 是宿主 `safe_execve` 纯透传，无任何同架构重跑逻辑（源码核对 v5.2 `linux-user/syscall.c`）；宿主无 qemu binfmt 条目，因此 guest execve 固件 ELF 一律返回 `-1 ENOEXEC`（`-strace` 两架构实测：`execve("/session/firmware/...") = -1 errno=8 (Exec format error)`）。镜像内实际安装的 Debian 包（`1:5.2+dfsg-11+deb11u3`）行为与 vanilla 源码不符——存在补丁层 fallback，使部分场景的 exec 最终落地执行（归因为 Debian 修订层；未逐条核对 Debian 补丁列表，行为结论以下列实测为准）。旁证对照：裸跑 MIPS 二进制（不经 qemu）仍 `exec format error` rc=255（B7），binfmt 独立性与票 01 一致。

**MIPS BE（target/8，OpenWrt 19.07 musl）：可行，前提是环境适配 `QEMU_LD_PREFIX=<会话内固件根>`**（ADR-0013 §3 允许的有明确依据适配：qemu 官方环境变量，等价 `-L`；来源 qemu 文档；改动 = exec 时注入 env；适用条件见下）。实测依据（`21-chain-qemu-ld-prefix.txt`，C1-C9 全 rc=0）：

- `-L` 命令行参数**不**被链上后续 qemu 实例继承（B1/B2 失败：报 `Could not open '/lib/ld-musl-mips-sf.so.1'`，按默认前缀找 loader）；env 形态 `QEMU_LD_PREFIX` 随进程环境继承（C6 子进程内 `busybox env | grep QEMU_LD` 实证），链上每一级 qemu 均能找到固件 loader。
- 固件 busybox sh fork+exec 同架构子进程（C1）、**动态链接外部助手 `/sbin/uci show` 真实读出固件全部 `/etc/config` 输出**（C2，dhcp/dropbear/firewall/uhttpd 全文）、三层嵌套 sh（C3）、管道双进程并发（C4）、PATH 查找（C5，`uci show network` 报 `Entry not found`，与票 01 "network 配置 firstboot 生成" 结论一致，留票 10 模板）、显式 `sh <脚本>` 执行会话脚本（C9）。
- **执行链留在仿真内的铁证**：链存活期容器内 `/proc/*/exe` 全部 = `/usr/bin/qemu-mips-static`，无任何进程逃逸为宿主映像；sleep 结束后链进程全部自然收割、零残留（`23-chain-process-accounting.txt`）。`c2-strace-full.txt` 存成功链完整 strace（单条 guest execve 记 ENOEXEC → uci 全量真实输出 → `wait4` 收割 status=0）。

**ARM LE（target/6，D-Link uClibc）：阻塞。** 四条路径全部失败（`22-subprocess-chain-arm.txt`、`arm2-strace-full.txt`）：静态 busybox 子进程（ARM1/7）、动态 nvram 子进程（有前缀 env，ARM2）、显式以 loader 直启 `/session/firmware/lib/ld-uClibc.so.0 <prog>`（ARM6）、脚本体内 exec（ARM8）——均为：guest execve 返回 ENOEXEC（strace 铁证，仅一条 execve）→ 后续对 guest 不可见的宿主侧路径把该 ELF 交给了**宿主 /bin/sh（dash）作脚本解释** → `<路径>: 1: Syntax error: word unexpected (expecting ")")` rc=2（dash 消息格式，本地对照复现确认打印者身份）。**具体阻塞（按 ADR-0013 记录，不静默收窄）**：Debian qemu 的 ARM 侧 fallback 未能像 MIPS 侧那样把 exec 落进仿真——差异根因指向 musl loader 本身是"可作程序入口执行"的 ELF（`ld-musl.so <prog>` 是 musl 官方用法），而 uClibc 的 `ld-uClibc.so.0` 不是、静态二进制又没有 PT_INTERP 可走。**解锁方向需重新讨论范围**： guest 可见路径整形（会话容器内隔离宿主 shell 路径）后重试； 工具层逐步显式 exec 的链分解——但这改变"固件自主派生"语义，是否算"原执行链复现"必须由用户裁定，本票不预支。**危险形态记录（进实现红线）**：ARM 失败路径证明"宿主 shell 被触及"的形态真实存在（本次仅语法错误，未执行任何固件逻辑，无状态改变）；实现必须让该接触面结构性不存在（见 3）。

**红线边界实测（喂票 09 白名单设计）**：guest 链内 `exec /bin/echo`（宿主 x86 二进制）**直接成功** rc=0、输出对 guest 可见（B9，两架构同）。qemu 透传不拦截宿主原生 ELF——固件脚本若 exec `/bin/sh` 会真跑宿主 shell。因此白名单不能只靠 guest PATH（绝对路径 exec 不可拦截），**必须做容器文件系统形状隔离**（会话容器镜像/挂载形状上让宿主 shell/二进制不可达），归票 05/06/09 落地。

#### 3. 进程组收割与孤儿回收命令面（AC3）

实测（`30-timeout-and-reaping.txt`）：**①宿主侧 timeout 杀 `docker exec` 客户端只杀客户端**（rc=124），容器内链**存活**成孤儿——超时收割必须在会话侧做，宿主 subprocess timeout 不是清理手段。**②`pkill -f 'qemu-mips-static'` 失效**（rc=1 零收割）：guest 侧改写 argv 内存直接透到宿主 `/proc/<pid>/cmdline`（实测 cmdline 变为 `ash /session/... sleep 30`，不含 qemu 字样）——**cmdline 不可信，`/proc/<pid>/exe` 可信**（恒为 qemu 二进制）。**③有效命令面（均实测零残留）**：
- 容器内 `timeout -k <缓冲> <执行预算> qemu-<arch> <目标>`：超时整链收割（C2：rc=124 且 fork 出的后台 sleep 全灭）——推荐作单次执行预算的实现形态；
- 进程组杀 `kill -9 -<PGID>`（链共享 pgid，C5）与按 `/proc/exe` 扫描收割（C6）作定点收割面；
- 容器级拆除 `docker stop -t 0` / `docker kill` = 最终收割面：0.1s 内 PID namespace 全灭、宿主零残留（C4）；
- 单杀链顶 qemu 不足以清链：fork 子进程成孤儿存活（C3：2 进程杀 1 剩 1）。

孤儿**容器**回收（`40-...txt` D4/D4b）：`docker ps -aq --filter name=<前缀>` + `xargs docker rm -f` 可用（本票 7 个真实遗留孤儿容器一次性收割）；**实现推荐 label 面**：开启时打 `--label fw.session=<会话id>`，恢复路径 `--filter label=fw.session` 强制收割——label 是显式属主声明，不依赖命名约定（D4b 实测）。

#### 4. 中断边界状态清单（AC4，`40-interrupt-boundaries-and-orphan-recovery.txt`）

| 边界 | 强杀动作 | 容器状态 | 运行目录状态 |
| --- | --- | --- | --- |
| 开启前 | `docker kill`/`rm` 不存在的容器 | 无对象；daemon 明确报 `No such container` rc=1 | 无对象 |
| 执行中 | `docker kill`（0.088s）+ `rm` | 容器消失；宿主零 qemu 残留 | **bind mount 产物保留**（4 行追加日志跨容器生命周期存在，新挂载容器可读）；**容器层文件随 rm 消失**（`/tmp/...` 实测不见） |
| 输出采集中 | 宿主 `timeout 3` 杀 exec 客户端（rc=124） | 容器正常；流式输出进程**存活**（qemu procs=1，管道断裂不杀进程） | 不变；该孤儿需会话侧收割（同 3①） |
| 停机中 | stop 客户端 t+2s 被 SIGKILL | **服务端停机继续**：t+3s running（优雅期内）→ t+13s exited(137)；客户端死亡不影响停机完成 | 不变 |

设计含义（喂票 08）：会话工件必须落在 bind mount 运行目录才能"中断后留档供复查"；容器层状态（含容器内 `/tmp`）按"清理不确定"语义处理——rm 后物理不可恢复。

#### 5. 移交后续票的实现选择汇总

- **票 06**：会话容器 = `docker run -d --init --network none -v <rundir>:/session`；执行 = `docker exec`（退出码透传 + 128+n + qemu 层 1/255 + 设施错误 → 五分类映射实测成立）；单次执行预算用容器内 `timeout -k <缓冲> <预算> qemu-...`（整链收割实测）；停机 = `stop -t 0` + `rm`。
- **票 08**：强制收口 = 容器级拆除（0.1s、零残留、不依赖 agent）；恢复收割 = label filter + `rm -f`；中断边界语义按 4 的表执行；运行目录留档 = bind mount 产物天然保留。
- **票 09**：链机制 MIPS 可行（QEMU_LD_PREFIX 进 exec env），ARM 阻塞待范围讨论；链账目 = `/proc/exe` 扫描（cmdline 不可信）；白名单必须容器文件系统形状隔离（guest 可 exec 宿主二进制是实测边界）；"宿主 shell 接触"是已实证的失败形态，须结构性杜绝。
- **票 10**：`uci` 在仿真内真实可用（C2 全量输出），`uci show network` 的 `Entry not found` 即 firstboot 类配置缺失的现成样例；NVRAM 缺 `/dev/nvram` 同前（票 01）。

#### 6. 已知边界与诚实声明

- 机制归因到"Debian 补丁层"为止：vanilla v5.2 源码无 fallback，安装包行为有，未逐条核对 Debian 补丁列表；所有行为结论均为直接实测，不依赖该归因。
- `ash: Could not open '/lib/ld-musl...'` 的打印者（qemu 补丁层 vs busybox ash）未定位到最终一行，原文已留档（`20-subprocess-chain-mips.txt` B 系列段）。
- D2 的流式进程因 OpenWrt busybox `sleep` 不支持小数退化为忙循环（原文留痕），不影响"客户端死后进程存活"的结论。
- 本票未验证 qemu `-strace` 作 tracer 的完整性（票 06 范围），仅顺带取到其可用证据（strace 文件两份）。
- 子进程链 ARM 侧为**环境级阻塞**（同 ADR-0013"运行受阻记录缺失条件并允许继续"），未宣称任何架构完成执行能力；不自动进入票 06/07/09 实现，等待规格与范围确认。

### 2026-09-22 遗留诊断追加：ARM 子进程链阻塞根因已查清（用户委托 /diagnosing-bugs；原始日志在 `investigation/04/` 50–53 号文件，脚本同目录 `scripts/`）

**结论先行：ARM 链阻塞的根因不在 qemu 层，在固件 shell 自身的 ENOEXEC 回退。qemu（上游 5.2 与 Debian 补丁；7.2 同样）对 guest execve 固件 ELF 没有任何回退；MIPS"链可行"实为 t8 BusyBox v1.30.1 ash 的脚本回退 `execve("/proc/self/exe", {"ash", 文件, 参数…})` 撞上 qemu 5.2 对该路径的纯透传（宿主内核原生再执行 qemu 二进制 → 子进程以第二 qemu 实例重进仿真）。ARM 侧 t6 BusyBox v1.14.1（2017）ash 的回退目标是 shell 路径（/bin/sh）→ 会话容器里即 dash → 固件 ELF 被 dash 当脚本解释 → `Syntax error: word unexpected` rc=2（危险形态的准确机制）。**

**对票 04 原结论的两处更正（证据驱动）**：
1. ~~"归因为 Debian 补丁层 fallback 未完成"~~ → 无 qemu 层回退：v5.2 `syscall.c do_execve` 纯 `safe_execve` 透传（源码核对）；Debian 补丁序列 linux-user 仅 binfmt-P 与 elfload 修复，与链无关（补丁源码核对）；qemu 二进制无任何 exec 回退 env 旋钮（`QEMU_*` strings 全枚举）。救回机制 = 固件 busybox ash 自救 + 5.2 透传。铁证：bookworm qemu 7.2 的 `do_execve` 新增 `is_proc_myself(p,"exe")` 拦截（把 /proc/self/exe 重写到 guest 程序路径），同一 MIPS 链在 7.2 探针上反而失败 rc=126，且 `-strace` 逐字捕获回退调用 `execve("/proc/self/exe",{"ash","/session/mips/bin/busybox","echo","derived-mips-ok",NULL}) = -1 ENOEXEC`（5.2 上该调用成功故不入 trace——成功 execve 不被 -strace 打印，已用 shebang 脚本阳性对照证实）。
2. ~~"MIPS 链可行"的适用面~~ → 收窄：可行性依赖**每一跳派生的发起方是带 /proc/self/exe 回退的 busybox ash**（t8 的 /bin/sh→busybox symlink，故 system()/popen() 链同样成立，票 04 C 系列全部如此）；非 ash 发起的固件程序自主 execve 固件 ELF 预测同样无救回（新推断，未实测，列票 09 实测项）。

**最小复现**（`scripts/50-arm-chain-loop.sh`，秒级、确定性，三次运行一致 VERDICT=RED）：同一 nvram 显式 `qemu-arm-static -L` 成功 rc=0（usage）；固件父派生同一 nvram 失败落 dash 语法错 rc=2；MIPS 显式+派生双对照成功。静态子进程（busybox echo，无加载器参与）即最小红样。

**身份核实（三界区分，全部实测）**：执行 qemu = 镜像内 `qemu-arm/mips-static version 5.2.0 (Debian 1:5.2+dfsg-11+deb11u3)`；容器原生 shell = `/bin/sh → /bin/dash`（dpkg diversion）；固件 shell = t6 BusyBox v1.14.1 ash / t8 v1.30.1 ash（guest 进程，/proc/exe=qemu）；加载器 = t6 ld-uClibc.so.0（**拒绝作程序执行**："Standalone execution is not supported yet" rc=1）/ t8 ld-musl-mips-sf.so.1（**可作程序执行**，实测）；Kali 宿主不在执行路径（全部执行在容器内，宿主 binfmt 前/中/后三次快照一致）。

**候选方案实测**：
| 方案 | 结果 |
| --- | --- |
| 升级 qemu（bookworm 7.2 探针） | ❌ ARM 仍 dash 语法错 rc=2；且 7.2 拦截 /proc/self/exe 反而**打断 MIPS 自救**（rc=126）——票 03 镜像":latest 不可漂移"从纪律升级为机制依赖 |
| qemu env 旋钮（QEMU_EXECVE 类） | ❌ 不存在（5.2 全量 QEMU_* strings） |
| 容器形状隔离（移除 /bin/sh 探针镜像） | ✅ 危险形态结构性消除：ARM 链失败变 guest 可见诚实错误 `no shell` rc=255，零容器 shell 执行；MIPS 链与顶层显式执行均不受影响 |
| ARM 链"原链复现"解锁（环境侧） | ❌ 无杠杆点：qemu 无 fallback（5.2/7.2 均证）+ 固件 shell 过旧（1.14.1）+ uClibc loader 拒绝 standalone + 不改固件/宿主 binfmt。剩余路线均需用户裁定：(a) 工具层显式链分解（改变"固件自主派生"语义，票 04 原挂项）；(b) 注入 1.2x+ ARM busybox 作适配材料 = 替换固件 shell，需裁定+外部材料来源；(c) 接受阻塞：ARM 侧顶层单发可用 + 静态取证，链能力仅 MIPS |

**剩余未知（如实）**：t6 1.14.1 ash 回退的精确 argv 未逐字捕获（成功 execve 不入 trace；dash 执行与 E6 "no shell" 方向一致佐证回退目标为 shell 路径，对结论无影响）；"非 ash 发起派生无救回"为机制推断，待票 09 实测。

**对票 06/08/09 的影响**：
- **票 06**：①ARM32 单发顶层执行不受本坑影响，AC 可达（目标避开 nvram 类以绕开预检阻塞）；②**会话镜像必须形状隔离**：构建期移除容器 shell，E6 已验证该形态 MIPS 链无损——写进票 06 容器定义；③新增实测样本供五分类定稿：guest 诚实失败 `no shell` rc=255。
- **票 08**：机制无关，不受影响；ARM 阻塞的"缺失条件"文案按本诊断更正（不再用 qemu fallback 表述）。
- **票 09**：①机制前提改写：链可行性 = busybox ash 驱动的派生 + 5.2 透传；②形状隔离有实测落地形态（移除 /bin/sh 即结构性杜绝 dash 接触且不伤 MIPS 链）；③两个逃逸面分开封：容器解释器路径（形状隔离解决）与 guest 显式 exec 容器 x86 二进制（票 04 B9，靠会话镜像最小化收敛）；④"非 ash 发起派生"列入票 09 实测项。

**纪律**：只做诊断实验，产品代码零改动；target/6、/8 原树只读未动；宿主 binfmt 未动（三次快照）；探针镜像实测后已删（53 脚本自建自删，可重复）；未调用 GLM、未读 GT；原验收标准未降低——ARM 链"原链复现"仍按 ADR-0013 记录为需范围裁定的阻塞项。

### 2026-09-22 对照实验追加:当前稳定版 QEMU 11.1.1 不能解锁 ARM 链,且同样打断 MIPS 自救(用户委托 /diagnosing-bugs;独立调查目录 `investigation/qemu-stable-arm-chain-2026-09-22/`)

**结论先行:升级 qemu 不是 ARM 链的解锁杠杆点,实测关闭。** 11.1.1(qemu.org 当前稳定版,官方 tarball + sha256 + GPG 三重校验,静态自构建探针镜像 `fw-probe-qemu111-diag`,与生产镜像完全隔离)跑与 50 号最小环逐字同输入同断言的全矩阵:**ARM 顶层显式 rc=0 不受影响;ARM 派生链仍落容器 dash 语法错 rc=2(与 5.2 逐字相同);MIPS 派生链对照从 rc=0 回归为 rc=126(与 7.2 同机制);直接 execve 样例(固件 busybox env)rc=126 无救回。** 判定 RED-REGRESSED。

**三重证据(行为 + strace + 源码)**:①11.1.1 源码 `do_execve` 仅存 `is_proc_myself(p,"exe")` 重写 + 纯 `safe_execve` 透传,无任何外来 ELF 救回;②P8 `-strace` **首次逐字捕获 t6 ash 1.14.1 回退的精确 argv**:`execve("/bin/sh",{"/bin/sh",<固件文件>,<参数>})`(11.x 的 -strace 打印成功 execve,5.2 不会——上节"剩余未知"就此补全,回退目标=shell 路径的推断证实);③两版二进制 QEMU_* 旋钮全枚举均无 exec 回退开关。

**补充实测**:11.1.1 上 RED 确定性 ×3(全新会话目录全同);容器内 timeout 后零 qemu 残留;固件输入 9 文件 sha256 实验前后逐字不变。ARM 侧固件原生直接 exec 载体不存在(t6 busybox 1.14.1 无 env/nice/setsid/xargs applet,全列表留档),机制判别由 MIPS 承担(同一 linux-user execve 路径)。

**对其他票的影响**:票 03 钉版纪律获 11.1.1 实测背书(:latest 不可漂移=机制依赖);票 06 形状隔离设计不变,新增注意点 `-strace` 语义 11.x 有差(跨版本不可假设,生产钉 5.2 无影响);票 09"非 ash 发起派生无救回"从推断转实测(样本 busybox env),升级 qemu 路线关闭,剩余路线(工具层显式链分解/注入新 ARM busybox/接受 ARM 阻塞)仍待用户裁定。ARM 链"原链复现"维持 ADR-0013 阻塞项状态不变;本实验不宣称新版必然可行或所有方案不可行。版本对照表、可重复命令、全部退出码与原始输出见独立调查目录 README。

### 2026-09-22 对照实验追加:PRoot + QEMU 用户态实测解锁 ARM 链(用户委托 /diagnosing-bugs;独立调查目录 `investigation/proot-arm-chain-2026-09-22/`)

**结论先行:ARM 派生链在 PRoot(user 态 ptrace binfmt 层)+ 现有 qemu 5.2 钉版下全绿——固件 busybox sh 自主派生的动态 nvram 子进程与静态 busybox 子进程都真实进入仿真(rc=0 + BusyBox v1.14.1 指纹),零 dash 接触;MIPS 对照不受影响且不再需要 QEMU_LD_PREFIX(proot 连 qemu 自身的加载器查找一并翻译)。** 宿主 binfmt 未动(PRoot 是用户态实现,等价 binfmt_misc)、固件原件未动(9 文件哈希前后逐字一致)、容器默认 seccomp 下 ptrace 可用(**无 --privileged、无额外 cap**)。proot 5.1.0(Debian 打包面)与上游最新 5.4.0(源码构建)行为一致,结论不依赖单版本;qemu 仍为生产钉版——本路线与"升级 qemu"路线互补,不冲突。

**机制**:PRoot 以 ptrace 跟踪全树,在每处 execve 对外来 ELF 的 ENOEXEC 改写为经 qemu 重启(按 ELF 类只对外来二进制生效,原生程序直跑;救回在 execve 层,与发起方是否 ash 无关)。身份核实:链存活期 /proc 扫描 exe = proot 生成的 8,944B 装载桩(/tmp/prooted-*,哈希跨运行确定),cmdline 首参 = 真 qemu 路径,输出为固件指纹。

**结构性代价(实测,须进票 06/09 设计)**:①`/host-rootfs` 逃逸面——proot 路径翻译的内部通道,guest 视角始终存在且**可原生执行容器程序**(dash/qemu/uname 实测可达,两 proot 版本皆然);固件路径不会主动用,但命令注入载荷可以,票 09 白名单必须前缀白名单默认拒绝之;②SIGKILL 杀 tracer 后会话根留暂存痕迹(host-rootfs//dev/0 字节 ld.so.preload;正常退出零残留)——固件根 ro 挂载结构性杜绝;③proot 无只读绑定,"固件根只读"靠 docker ro 分挂载落实;④/dev 需显式 -b /dev(固件 squashfs 根无 /dev/null,ash 后台重定向必需);⑤t6 ash 无 echo 内建,链内命令需显式 /bin/busybox <applet>。

**会话与清理**:跨 docker exec 状态保留成立(ro 固件根 + rw 运行目录分挂载);容器内 timeout rc=124 后零孤儿,**SIGKILL 杀 tracer 同样零孤儿**(两版本一致);容器级拆除仍是最终兜底。耗时粗测:proot 增量 ~350–500ms/单发,60s 预算量级可忽略,正式校准待真实样本。

**对票的影响**:票 03——qemu 钉版不变,若采纳本路线镜像需按票 03 先例固化 proot(Debian 只有 5.1.0,5.4.0 需源码构建);票 06——PRoot 形态比裸 qemu 更干净(/bin/sh 接触结构性消失、免 LD_PREFIX 适配),容器定义需新增 proot + 显式绑定清单;票 09——ARM"原链复现"实测可达,三选一困境新增第四选项,白名单新增硬要求(/host-rootfs 默认拒、prooted 桩与 guest 声明路径区分)。**不宣称方案完成**:CGI/真实业务通路、fork 密集型程序、预算校准、会话化封装(票 06/07/08/09)均未做,"原链复现"最终认定权在用户。可重复命令、版本对照表、全部退出码与原始输出见独立调查目录 README。

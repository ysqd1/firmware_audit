# 01: 镜像与 QEMU 用户态二进制可用性调查

**What to build:** 第一阶段 QEMU 执行镜像的事实基础与路线选定：实测容器内 QEMU 用户态模拟器对 ARM32 小端与 MIPS32 大端的真实可用性，选定镜像路线（复用现有沙箱基础层的派生镜像 vs 独立执行镜像），钉死候选 QEMU 版本。产出是调查结论——本票不改产品代码、不建最终镜像（建镜像归票 03）。

调查纪律：每项事实附命令与输出原文，来源无法证实的明确留空，不用记忆填空。

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] 结论追加到本票 `## Comments`，每项事实附命令与输出原文
- [ ] 给出镜像路线建议（派生层 vs 独立镜像）及理由，对齐既有派生镜像先例的构建约束
- [ ] ARM32 小端与 MIPS32 大端各实测至少一个外来二进制可执行（或明确记录不可行与原因）
- [ ] 列出候选 QEMU 版本与各架构二进制包名，标注来源
- [x] 结论追加到本票 `## Comments`，每项事实附命令与输出原文
- [x] 给出镜像路线建议（派生层 vs 独立镜像）及理由，对齐既有派生镜像先例的构建约束
- [x] ARM32 小端与 MIPS32 大端各实测至少一个外来二进制可执行（或明确记录不可行与原因）
- [x] 列出候选 QEMU 版本与各架构二进制包名，标注来源
- [x] 某架构不可行时，明确记录阻塞与替代方案候选，不静默降级

## Comments

### 2026-09-21 调查结论（子代理独立调查，协调者抽查核对）

**结论：两架构均可行；推荐派生层镜像路线；主候选钉 `qemu-user-static 1:5.2+dfsg-11+deb11u3`。**
原始日志：`investigation/01/`（32 文件，下引文件名）。实验全部为一次性 `--rm` 容器，target/ 全程 `:ro`；宿主 binfmt 未动（前后终态快照一致，`06-host-binfmt-before/after.txt`）；未建最终镜像（探针镜像测后已删）。

1. **沙箱现状**：`firm_audit/sandbox:latest`（bullseye，5.1GB）无任何 qemu 包/二进制（`01-dpkg-qemu.txt`、`01-which-qemu.txt`）。
2. **包与版本**：bullseye 索引候选 `1:5.2+dfsg-11+deb11u5`（security）实测 **404**——security 池已删全部 bullseye qemu 包，aliyun 与 deb.debian.org 双源确认（`02-mirror-head-u5.txt`、`02-pool-listing.txt`）；**bullseye LTS 已于 2026-08-31 结束**（debian.org / wiki.debian.org/LTS）。实际可装最新版 = bullseye/main 的 **1:5.2+dfsg-11+deb11u3**；qemu-user-static u3 = 41.4MB 压缩 / 282MB 安装 / 33 个静态二进制（`02-apt-show.txt`、`03-versions.txt`）。
3. **版本实测**：`qemu-arm version 5.2.0 (Debian 1:5.2+dfsg-11+deb11u3)`、`qemu-mips version 5.2.0 (Debian 1:5.2+dfsg-11+deb11u3)`（`03-versions.txt`）。
4. **ARM32 LE（target/6，uClibc 0.9.32.1）**：`usr/sbin/nvram`（动态，interpreter `/lib/ld-uClibc.so.0`）裸跑 `Exec format error` rc=126 → `qemu-arm-static -L <squashfs-root>` 跑通 rc=0（usage 输出）；静态 busybox 免 `-L` 跑通；`nvram get` 撞 `/dev/nvram: No such file or directory`（运行时依赖缺失的现成样例）（`04-arm-runs.txt`）。
5. **MIPS32 BE（target/8，OpenWrt 19.07 ath79，musl）**：busybox（MSB，MIPS32 rel2，o32，interpreter `/lib/ld-musl-mips-sf.so.1`，musl 自报 `mips-sf` → soft-float；全量 strip 致 `readelf -A` 不可用，ABIFLAGS 原始字节存档未解码）裸跑 rc=126 → `qemu-mips-static -L <squashfs-root>` 跑通 rc=0；错架构 qemu-arm 报 `Invalid ELF image for this architecture` rc=255（`05-*.txt`）。
6. **binfmt 独立性**：qemu-user-static postinst 自带容器守卫（"do not touch binfmts inside a container"）；容器内 binfmt_misc 未挂载、装包后仍为空；`--no-install-recommends` 下 binfmt-support 不安装、postinst 第一行即短路。显式调用不依赖 binfmt：裸跑 126 / 显式 0 即为对照（`06-*.txt`）。
7. **镜像路线（探针实证）**：`FROM firm_audit/sandbox:latest` + `--no-install-recommends qemu-user-static=1:5.2+dfsg-11+deb11u3` 构建成功，`fw-probe-qemu-ticket01` 5.46GB（基座 5.1GB，增量 ≈+0.36GB，层共享），`--network none` 断网冒烟双架构通过（`07-probe-build.log`、`07-probe-smoke.txt`）。**推荐派生层 + 专用 tag（如 `firm_audit/qemu-exec`）**：sandbox_verify 留基础镜像（实测无 qemu 二进制）→ 能力隔离是结构性的（容器内物理无 qemu）；对齐 spec"可复用基础层、入口与能力契约独立"与 AGENTS.md Dockerfile.binwalk 派生先例；入口沿用 `run_docker` entrypoint 覆盖。备选（非默认）：bookworm-slim 独立执行镜像 + `qemu-user-static 1:7.2+dfsg-7+deb12u18+b3`（bookworm LTS 至 2028-06-30，`08-bookworm-candidate.txt`），触发条件为需 qemu>5.2 或更长维护窗口。
8. **移交票 03 的构建约束**：u3 的 .deb 可能从镜像源消失（security 池先例），构建需缓存 .deb 进构建上下文或改用可得源；镜像 ENTRYPOINT 保持基座值（analyzeHeadless），调用侧显式覆盖，与现有工具模式一致。

**验收逐条核对**：5/5 满足——结论已追加本 Comments（本条）；路线建议见第 7 条（对齐 spec.md Implementation Decisions 与派生先例）；ARM32 LE nvram 与 MIPS32 BE busybox 均 rc=0 实测（第 4/5 条）；版本与包名来源见第 2/3/7 条（apt 实测 + 日志文件）；无架构级阻塞，环境级阻塞（security 池 404、bullseye EOL）已实测记录并给出 u3 绕行与 bookworm 替代（第 8 条），无静默降级。

**对后续票的影响**：
- **03 执行镜像**：派生层 Dockerfile 模板即 `Dockerfile.probe.txt`，钉 u3 版本、`--no-install-recommends`、专用 tag；需先定夺 .deb 缓存策略（或接受 bookworm 备选路线）——bullseye EOL 风险决策不能拖到实现中途。
- **04 会话容器生命周期**：显式调用模式与会话容器兼容；超时清理对象 = qemu 前台进程（qemu-user 单进程模型）+ 容器；派生 tag 一经发布不可漂移，否则"容器内无 qemu"的 sandbox_verify 结构性隔离失效。
- **06 单次执行 tracer**：qemu-user 5.2 自带 `-strace` 内建 tracing，理论无需额外 tracer 包（本票未实测 `-strace`，票 06 需验证）。
- **09 子进程链**：uClibc 与 musl 两套 busybox 均在 `-L` 模式跑通，固件内 shell/辅助程序链走同一 qemu 前缀可行。
- **12 通路选择**：target/6/7（ARM/uClibc）与 target/8（MIPS/musl）都有可执行样本；target/8 `sbin/uci` 跑通但无 `/etc/config/network`（firstboot 生成），配置文件准备归票 10 模板。
- **14 集成验收**：双架构基础设施可行性已具备；真实业务通路 + NVRAM 模板 + 干净复现仍是票 14 独立门槛，本票结论不预支验收。

# 18: 真实业务通路与有来源的环境适配

**What to build:** 从现有案例选定一条真实固件单次程序/CGI 业务通路，用预定义基础适配及有限 NVRAM 读取模板驱动，取得可检查输入输出与正常输入对照。通路选择作为本票第一步，不再单列调查票。

**Blocked by:** 17, 02（02 已完成）

**Status:** ready-for-agent

**Replaces:** 12, 10, 11

## 验收

- [x] 根据解包材料/反编译证据列候选排序、选择理由、每条所需输入/配置/模板/NVRAM/设备及未满足条件；包含至少一个 MIPS32 大端实际执行候选。不读取 GT，版本输出或 nvram usage 不当作业务通路
- [x] 在本票 Comments 记录选择、来源、命令与输出；选定通路通过专用会话入口运行，取得可检查业务输入输出和正常对照，不仅是启动成功
- [x] 预定义基础目录、配置文件、argv/受控环境、stdin、CGI 输入准备可用；测试数据与设备真实配置分开，来源引用及差异逐项入台账，宿主环境不隐式继承
- [x] 模板在 PRoot 显式运行根及最小 bind 下验证，不覆盖可信后端、不向 guest 开放未授权容器程序、不写原件/Evidence；子进程继承所需适配且不改变固件安全逻辑
- [x] 预检报告模板适用性与缺项；未支持依赖明确准备/运行阻塞，不临时生成替代接口，不伪造空值或成功
- [x] 按已完成 02 核实的支持表分别实现 target/6 通用与 target/7 厂商 NVRAM 读取，固件库不混用；仅支持已核实签名、调用约定、返回和缺失键语义的接口，target/8 不纳入 NVRAM 支持表
- [x] 在实际 PRoot/QEMU 后端用真实固件库验证 target/6、7 至少各一接口，覆盖已知值、有证据的缺失键与未知值；未知值/未支持 ABI 明确阻塞，不统一返回成功
- [x] NVRAM 值逐项有来源；回改静态预检模板支持表，仅解锁实测接口。库基名不足以分族时维持不判定/阻塞，envram 等未支持族不因同名库放行
- [x] 真实通路中自主派生行为沿用 16 的边界与身份规则；不能依赖容器原生程序后宣称固件原链成功
- [x] 模板离线测试、真实通路正常对照、真实 NVRAM ABI 门控测试通过，完成项目要求的回归；合成函数成功不替代真实库兼容性

## 材料

[票 02 NVRAM 调查](02-nvram-abi-investigation.md)、[PRoot 调查](../investigation/proot-arm-chain-2026-09-22/README.md)；旧 12/10/11 留作历史。业务通路重复复现、预算定稿与完整独立复核由 19 验收。

## 共同边界

依据 [spec](../spec.md) 与 [ADR-0013](../../../docs/adr/0013-qemu-user-mode-experiment-boundary.md)。不修改宿主 binfmt、不替换固件 shell、不修改固件安全逻辑；不调用真实 LLM、不读取 GT、不改既有封存世代。动态成功、崩溃或失败均不是漏洞结论。实现按 implement/tdd 推进并以 Standards + Spec code-review 收口；离线与真实 Docker 测试分开，记录命令、输出和限制，真实验收缺失不得用 skipped 关闭工单。

## Comments

### 2026-09-23 第一步：真实业务通路候选排序与选择（材料证据；未读 GT，未启动实现）

出处约定：`cgibin.c` = target/6 反编译边车 `target/6/process/analysis/.../htdocs/cgibin.c`（ExtractInfo v2，434/546 函数反编译成功）；`httpd.c` = target/7 边车同目录；票 02 = [NVRAM ABI 调查](02-nvram-abi-investigation.md)（原始日志 `investigation/02/`）。符号/NEEDED 清单为本票动态段与 dynsym 解析实测（2026-09-23，命令与输出见实现记录）。

**候选排序表**：

| # | 候选 | 架构/依赖 | 业务输入→输出 | 所需模板/输入 | 缺失条件 | 判定 |
| --- | --- | --- | --- | --- | --- | --- |
| A | t6 `htdocs/cgibin` argv0=`conntrack.cgi`（Web UI 连接状态数据源） | ARM32 小端；NEEDED 仅 `ld-uClibc.so.0`+`libc.so.0`（cgibin 全程 0 处 nvram，票 02） | REQUEST_URI 查询串 + conntrack 状态文件 → stdout XML `<conntrack>`（逐 IP tcp/udp 聚合、count/tcp_count/udp_count） | 受控环境（`REQUEST_METHOD`/`REQUEST_URI`/`HTTP_COOKIE`/`SCRIPT_FILENAME`，出处 cgibin.c FUN_00011220/FUN_0000acec）；配置文件 bind（`/proc/net/ip_conntrack` 测试夹具，出处 FUN_00015314 同款 fopen 路径于 conntrack handler L7770）；基础目录（`/var` 可写，会话存储为文件 `/var/session/N`，出处 FUN_0001068c） | 无超出第一批模板的条件：会话门（FUN_00011568）是文件式会话存储，空目录即自动建槽（FUN_000107f0 第二循环），不依赖 xmldbc/守护进程 | **选定：业务通路交付载体** |
| B | t6 cgibin 其余 handler（authentication/session/captcha/soap/hedwig） | 同上 | 各自 XML/HTML | captcha 需派生 `rndimage`+fonts（L4875）；authentication/session 配置面走 xmldbc（FUN_0001f098 `/runtime/...` 路径） | xmldbc/devdata 运行面不在第一批模板（票 02：t6 主配置面缺口需单列） | 备选，缺失条件多 |
| C | t6 `usr/sbin/wlconf`（Broadcom 无线配置工具） | ARM32 小端；NEEDED `libnvram.so`+`libshared.so`；UND `nvram_get`/`nvram_default_get`/`nvram_set`… | 读 NVRAM 无线配置并应用（票 02：`strcmp(nvram_get(...),"ap")` 消费模式） | NVRAM 模板（nvram_get） | 配置读取完成后需 wl 驱动 ioctl（无 wlan 接口）→ 运行时依赖阻塞 | **NVRAM 真实消费者验证载体**（不作业务通路交付） |
| D | t7 `bin/httpd`（goform/CGI 业务全部在 httpd 内，无独立 CGI 二进制） | ARM32 小端；NEEDED `libCfm.so`/`libtpi.so`/`libnvram.so` 等 | HTTP 服务 | — | 常驻网络服务第一阶段明确不做（spec Out of Scope；断网 + 执行之间目标不存活）→ 结构性阻塞，如实记录 | 阻塞；其启动期 `bcm_nvram_get`（UND 实测）用作 **t7 厂商接口 ABI 验证载体** |
| E | t7 `bin/nvram`/`bin/cfm`/`bin/envram` CLI | ARM32 小端 | 配置读写 | NVRAM 模板 | `envram` 系 MTD 后端未支持（票 02）；`nvram get` 是接口探针，按 AC 红线**不作为业务通路** | **NVRAM ABI 三态探针**（t6/t7 各一） |
| F | t8 `bin/opkg list-installed`（OpenWrt 包管理查询） | **MIPS32 大端**（musl）；固件自带 `/etc/opkg.conf`、`/usr/lib/opkg/status` | 读已装包数据库 → stdout 包清单 | 原则上无需适配（锁目录 `/usr/lib/opkg/locks` 只读根下的行为运行期观察，必要时基础目录） | 暂无已知缺失条件 | **选定：MIPS32 大端实际执行候选** |

**选择与理由**：
- **业务通路 = A（t6 conntrack.cgi）**。理由：①输入输出逐项可检查——声明 env/查询串/conntrack 夹具为输入，stdout XML（result/entry/count）为输出；②正常对照天然存在——同会话第二次执行去掉 `HTTP_COOKIE` → `<result>FAILED</result><message>no authorized</message>`（会话门独立于业务逻辑），第三次换夹具内容 → 计数变化，证明真实处理而非仅启动成功；③依赖全部落在第一批模板（受控环境/配置文件/基础目录/CGI 输入），不触碰 xmldbc 与 NVRAM，缺失条件为空；④多路复用 CGI 经 `basename(argv[0])` 分发（cgibin.c L52-130），工具既有 argv0 参数直接表达真实调用条件。
- **MIPS32 大端实际执行候选 = F（t8 opkg list-installed）**，实际运行并取得结果分类与输出（预检不计入该项验收）。
- **NVRAM 真实库验证载体**：t6 = `usr/sbin/nvram get`（通用 libnvram.so，票 02 已核实六函数 ABI）+ wlconf（真实消费者，机制级证据）；t7 = `bin/nvram get`（t7 自己的 libnvram.so 拷贝）+ `bin/httpd` 启动期 `bcm_nvram_get`（libCfm 厂商包装；机制级证据）+ `bin/envram` 负对照（envram 系不得因同名库放行，票 02：MTD 后端、缺键不可区分）。
- D 的结构性阻塞如实入账：t7 的业务通路在第一阶段不可交付（常驻服务越界），不在本票伪装达成；其厂商 NVRAM 接口验证不受此影响。

**输入来源与差异声明原则**（后续台账逐项执行）：测试夹具（conntrack 内容、cookie uid、NVRAM 测试键值）= agent 构造的声明测试输入，逐项记 sha256 与来源 `declared_test_input`；设备真实默认值（如 t7 `webroot_ro/nvram_default.cfg` 的 `lan_ifname=br0` 等）= 固件材料来源，逐项记文件与行引用；两类分开，不互冒充。

**版本输出/nvram usage 红线自查**：A/F 的输出是业务处理结果（XML 聚合、包清单），非版本串/usage；E 仅作 NVRAM ABI 验证探针，不计作业务通路。

### 2026-09-23 实现与真实验证记录（实现 + 真实后端验证完成；code-review 见下一条）

**A. 交付物**

- `firmware_audit/docker/nvram-shim/`：`/dev/nvram` 内核驱动后端的用户态适配桩（票 18 NVRAM 模板）。机制：guest 内 LD_PRELOAD 拦截 open/openat/read/close，把票 02 核实的 Broadcom 风格 libnvram 系（t6 `libnvram.so`、t7 `libnvram.so`+`libCfm.so bcm_nvram_*`）对 `/dev/nvram` 的 open+mmap+read 协议重定向到只读模板映像；**固件库自身代码原样执行，桩不定义、不替换任何 nvram_*/bcm_nvram_* 导出符号**。协议出处=票 02 反汇编（read(fd,name,len+1) 返回 4 字节映像偏移即命中；其余→NULL）。写不支持：fd 强制只读，set/unset/commit 由真实库代码如实失败；getall 走协议响应→库按 ret!=len 判失败（第二批次不放行）；envram(MTD)系不经桩、对缺失 MTD 如实失败。构建：Dockerfile（bookworm-slim digest 钉定 + gcc-arm-linux-gnueabi，软浮点 armel 对齐 uClibc EABI）+ build_shim.sh（镜像内 readelf 未决符号门禁 + 宿主 sha256/尺寸证据）。**三条构建红线（真实踩坑）**：①`__sync` 内建在 -O2 生成 libgcc 未决调用、②gcc 循环模式识别生成 strlen 调用、③Debian gcc 默认 `--hash-style=gnu` 而 uClibc ldso 只认 SysV `.hash`（库被映射但符号查不到，桩被静默忽略）——最终 flags `-nostdlib -fPIC -march=armv7-a -fno-builtin -fno-stack-protector -fno-tree-loop-distribute-patterns -Wl,--hash-style=sysv`，锁用内联 ldrex/strex。产物 sha256 钉在 `qemu_adapt.NVRAM_SHIM_SHA256`（最终 `d5bda548…`，5756 字节；评审修复后重建并重钉），漂移在会话开启前拒绝。
- `qemu_adapt.py`（新增）：适配声明解析/校验/固化/执行期换算的单一出处。`adapt_binds`（ro extracted / ro fixture / rw base 三形态，保留前缀 /session、/dev、/tmp、/host-rootfs 拒绝，.. 折叠为规范路径，重复/越界拒绝）；`adapt_fixtures`（`名=base64` 声明测试输入，source=declared_test_input，sha256 入台账）；`nvram_values`+`nvram_sources`（**任一值缺来源引用即准备阻塞**，键/值/数量上限与桩一致，映像 `k=v\0` 串表键序字典序确定）；`materialize`（夹具/基础目录/桩+映像写会话目录，覆盖固件根内已有路径的 bind 逐项记录 shadowed_original 差异）；`proot_binds`/`container_mounts`（容器路径换算单一出处）；`consume_unresolved_keys`（逐执行读回+清除，不跨执行串账）。
- `qemu_session.py`：新参数 `adapt_binds/adapt_fixtures/nvram_values/nvram_sources`（会话级，开启时固化进台账；复用会话相同声明幂等放行、不同声明拒绝）、`stdin_ref`（逐执行声明，字节经 `docker exec -i` 送达目标，台账记 ref/sha256/字节数）。执行期：会话适配逐执行经 PRoot bind 重新挂载（子进程经 proot 与环境继承同一适配）；`LD_PRELOAD=/session/adapt/libnvram_shim.so` 由工具在 exec_env 注入（模板装配，模型声明的 env 里 LD_/PROOT_/QEMU_ 控制变量仍拒绝）；桩未决键日志读回为执行级 `adaptation_gaps`（明示“相关配置面行为不得作为设备真实行为结论”）。**argv0 语义修正（真实发现）**：PRoot 以命令路径作为 guest argv[0]，命令后的独立参数成为 argv[1] 起——旧实现的裸名 argv0 实际从未生效（票 16 的 `busybox + argv0=sh` 探针是借 busybox 对 argv[1] 的多调用分发，非 argv0）。新语义：argv0 须为 guest 内绝对路径（多路复用 CGI 的真实调用形态，如 `/htdocs/web/conntrack.cgi`），目标以同一文件身份（digest 不变）bind 到该路径呈现，遮蔽固件根内已有其他文件则拒绝；台账/离线测试同步钉住。
- `docker_utils.py`：`docker_exec` 新增 `stdin_bytes`（`-i` 通道，有界写入线程，不阻塞输出排水）。
- `qemu_precheck.py`：`parse_elf_dynsym`（目标 dynsym 已定义/未定义符号解析，DT_HASH nchain 优先、布局估算兜底、不可判定抛错）+ 模板适用性升级为**决定性支持表**：目标导入 `nvram_get`/`bcm_nvram_get` → dev_nvram 族解锁（仅实测接口）；导入 `envram_*` → 未支持族阻塞（不因同名库放行）；两者并存 → mixed（读取解锁 + envram 路径运行阻塞 caveat）；基名命中但符号不可判定 → 维持阻塞；target/8 无 NVRAM 系依赖（不在支持表）。

**B. 真实业务通路（选定 = target/8 opkg，MIPS32 大端；门控测试 `test_real_opkg_mipsbe_business_pathway_and_control`）**

- 通路：`bin/opkg list-installed`（固件原生 `/etc/opkg.conf` + `/usr/lib/opkg/status`，仅基础目录模板给锁目录 `rw:/var/lock`）→ normal_exit，stdout 113 行已装包清单（`ath10k-firmware-qca988x-ct - 2019-10-03-…`、`busybox - 1.30.1-5` 等）；stderr 如实记录 `//usr/lib/opkg/info` 只读根噪声。正常对照：同会话第二次执行 `info busybox` → 过滤后的单条 `Package: busybox / Version: …` 记录——同一配置、不同输入、不同输出，证明真实业务处理而非启动成功。
- 真实后端：`firm_audit/qemu-exec:p540q1111`（PRoot 5.4.0 + QEMU 11.1.1，补丁身份经镜像 LABEL 校验）；断网、固件根只读、运行目录独立、Evidence 不可达。

**C. NVRAM 真实接口验证（门控测试；全部真实固件库 + 真实 PRoot/QEMU 后端）**

- **target/6 通用接口（`usr/sbin/nvram`）**：已知值 `nvram get wl0_ssid` → `fwtest_ssid`、`get router_mode` → `ap`（来源=declared_test_input，t6 无静态 nvram 默认值来源，票 02）；缺失/未知键 `get fwtest_missing_key` → 空输出（真实库 NULL 语义）+ 未决键 `fwtest_missing_key` 入 gap 明示。三次执行同会话，逐次计数。
- **target/7（`bin/nvram`，t7 自己的 libnvram.so 拷贝）**：`get lan_ifname` → `br0`、`get os_name` → `linux`——**设备真实默认值，来源=target/7 webroot_ro/nvram_default.cfg**（文件实测，非测试数据）；缺失键 → 空 + gap。门控测试 `test_real_t7_nvram_abi_and_envram_negative`。
- **target/7 厂商包装（`bin/httpd`，libCfm `bcm_nvram_get`）**：httpd 完整加载（补 libz.so.1/librt.so.0 传递依赖后）并在真实后端进入主循环；strace 铁证：`ioctl(3,SIOCGIFADDR,{"br0"})` ——接口名 br0 只能来自模板映像（经 bcm_nvram_get→桩→mmap 偏移取得），即**真实厂商包装代码消费了模板值**。常驻服务按预算击杀（target_signal/timeout 如实分类，清理验证 clean）。第一阶段不交付 httpd 业务通路（常驻服务越界），门控测试 `test_real_t7_httpd_bcm_vendor_wrapper_consumes_template` 只固化厂商接口消费证据。
- **envram 负对照（`bin/envram`）**：`envram get lan_ifname` → `envram_init: read flash error`（真实 envram 代码对缺失 MTD 如实失败，rc=0 为 CLI 自身语义）；**模板值 `br0` 未泄漏**，未决日志无 envram 键——未支持族不因 libCfm 同名库放行。
- 真实运行中的问题修正（各自先复现失败再修）：①桩未决符号致 uClibc 静默忽略（-nostdlib 工件三红线，见上）；②`open("/dev/nvram")` 真实 open 先执行 ENOENT 短路了重定向（先判定后打开）；③LD_PRELOAD 对容器侧 amd64 进程（timeout/proot）产生 `wrong ELF class` 警告——结构性噪声（guest 侧正常加载），如实记录不入分类。

**D. 如实阻塞记录（不伪装达成）**

- **t6 `htdocs/cgibin` conntrack.cgi（原选定 ARM 业务通路候选 A）**：argv0 分发、`/var` 会话存储、sesscfg 解析（实测四值格式 `600\n8\n16\n1\n`，缺省时扫描 5432+ 槽位致超时）在真实后端全部真实运行；但会话门附件代码（FUN_00011568）在产出业务输出前**输入无关地确定性 SIGSEGV**（si_addr=0x2f3a6e68 恒定；无 cookie/有 cookie/无查询串均崩；含/不含 NVRAM 均崩）→ 门控测试 `test_real_t6_conntrack_cgi_honest_block` 固化：运行真实发生、崩溃如实分类、`<conntrack>` 业务输出未取得。**动态崩溃不构成漏洞成立或不存在的结论**；t6 web 栈业务通路维持阻塞（连同 xmldbc 配置面缺口）。
- **t7 httpd 业务通路**：常驻网络服务第一阶段明确不做（spec Out of Scope）——结构性阻塞，其启动期厂商接口消费见 C。
- 未知值/未支持接口阻塞语义：模板未声明键 → 桩按固件缺失键语义应答 NULL（非伪造成功）+ 未决键入台账 gap + 结果明示“相关配置面行为不得作为设备真实行为结论”；envram 系 → 真实代码对缺失 MTD 如实失败。

**E. 边界核查（AC4/AC9 落地）**

- 显式运行根 + 最小 bind：bind 源固定为容器内已挂载材料（/session/firmware、/session/fixtures、/session/runtime/base、/session/adapt），模型只声明 guest 目标路径且保留前缀拒绝；未用 `-R` 自动带入；不覆盖可信后端（proot/qemu/llscan 在容器侧，guest 根内不存在）；不写原件/Evidence（固件根 ro bind、会话材料独立目录、Evidence 不可达）；宿主环境不隐式继承（env 全量声明，控制前缀拒绝）。
- 子进程继承：LD_PRELOAD 与 bind 经 proot/环境继承（AC4）；派生行为沿用票 16 边界（mixed-mode 继承补丁 + execveat deny + 镜像剥离身份校验不变）；不能依赖容器原生程序宣称固件原链——本次全部证据来自固件自身二进制/库的仿真执行。
- 不调用真实 LLM、不读取 GT、不改宿主 binfmt/固件原件/既有封存世代/CONTEXT.md 与 rules.md（用户有未提交改动）。

**F. 测试与回归（命令与结果）**

- 离线（零容器）：`pytest -q firmware_audit/test/test_step5_qemu_session.py firmware_audit/test/test_step5_qemu_adapt.py firmware_audit/test/test_step5_qemu_precheck.py firmware_audit/test/test_qemu_docker_limits.py -k "not real"` → 131 passed（含适配声明校验、NVRAM 声明缺来源/来源孤儿/键上限、映像确定性、桩钉值漂移/缺失、未决键逐执行消费、argv0 新语义、预检四家族用例、dynsym 解析、stdin 通道）。
- 真实门控：`pytest -q firmware_audit/test/test_step5_qemu_session.py firmware_audit/test/test_step5_qemu_precheck.py -k "real"` → **15 passed**（新增 5：opkg 业务通路+对照、t6 ABI 三态、t7 ABI+envram 负对照、httpd bcm 消费、conntrack 如实阻塞；既有 10 项保持通过）。
- 全量回归：`pytest -q firmware_audit/test --ignore=firmware_audit/test/test_step5_host_evaluation.py` → **1270 passed, 17 skipped, 0 失败**（票 17 基线 1229 passed + 16 skipped + 1 既有失败；本次新增 41 通过、既有 binfmt 对照已按 2026-09-23 决定环境感知 skip，无本票新增失败；评审修复后终态全量重跑确认）。`python -m compileall -q firmware_audit`、`git diff --check` 通过。

**G. 已知限制与取舍（诚实声明）**

- LD_PRELOAD 在容器侧 amd64 进程（timeout/proot）产生 `wrong ELF class` 警告噪声：结构性（env 需先于 guest 启动存在），不影响 guest 装载与分类；台账 stderr 如实保留。
- 桩覆盖面 = /dev/nvram 系已核实读取接口（nvram_get/bcm_nvram_get 及其上的真实派生消费）；getall/set/unset/commit/envram 系不在支持表——桩设计使其真实失败而非伪造；未声明键 NULL+gap。多线程目标（httpd）下桩 fd 表用 ldrex/strex 自旋锁保护，但未做并发压力验证。
- t6 会话门 SIGSEGV 未做根因归因（动态崩溃不作漏洞/缺陷结论）；t6 web 栈通路、t7 httpd 通路、getall 放行、xmldbc 配置面均留待后续（票 19 校准与收口范围之外的独立缺口）。
- 正式后端仍限定 host amd64 + PRoot 5.4.0 + QEMU 11.1.1 组合身份；预算默认（会话内 4 次执行）仍为票 19 校准前的临时值。



### 2026-09-23 code-review 记录（Standards + Spec 两轴并行 + 第二轮聚焦复审）

**第一轮（对整个票 18 工作树 diff + 新增文件；评审代理只读，未触碰用户未提交改动）**

- Standards 轴：2 hard + 10 nit。Spec 轴：10 条 AC 中 9 PASS、AC10 PARTIAL（仅记录数字陈旧）。
- **H1（hard，rules.md「名实不符」+ 会话固化契约）**：`_adaptation_matches` 把固化台账形态的派生字段（`shadowed_original`）与解析形态做全字典比较 → 含遮蔽型 bind 的相同复用声明被误拒，与「复用会话只能重复开启时的声明」语义矛盾；且测试用 `prep_blocked or session_stop` 的 OR 断言掩盖。修复：比较前双方投影到声明字段 (mode/guest_path/kind/ref/sha256)；测试改为精确断言（不同声明拒绝、相同声明幂等放行并真实执行第 2 次、相同声明 stop 停机）。位置 `qemu_session.py _adaptation_matches`。
- **H2（hard，rules.md「接受非法输入≠显式阻塞」+ 声明固化契约）**：Python 侧仅限条目数，512×最大值声明可构造 134KB 模板映像，超桩 `IMAGE_CAP=65536`——桩只装载前 64KiB，尾部已声明键静默降级为“未声明”。修复：`NVRAM_IMAGE_MAX_BYTES`（与桩逐字配对注释）+ `build_nvram_image` 超限 AdaptationError + 离线测试钉住。位置 `qemu_adapt.py`。
- 10 个 nit 同轮低成本同修：桩死 typedef；load_image check-then-set 竞态（锁内置位 + fd<0 早退 unlock，避免自旋锁死锁）；fd 表满时重定向 open 直接失败（原为静默穿透返回映像原始字节）；parse_binds 恒 False 自比较改「折叠后残留 .. 拒绝」；`incoming_image is not None` 死条件；复用分支死赋值；threading import 上提；NVRAM 系基名元组收敛 `qemu_adapt.NVRAM_FAMILY_BASENAMES` 单一出处；工单记录 sha/数字修正；stdin 通道补真实子进程回归（150KB 超管道容量验证写线程与 EOF）。
- **桩重建与受影响边界**：nit 修复涉及 C 代码 → 重建产物（新 sha `d5bda548…`）重钉，真实门控 11 passed 重验通过；`git check-ignore` 确认产物可入库。

**第二轮（聚焦修复面 + 受影响边界；单评审双轴）**

- 6 项声称修复全部 VERIFIED（含：幂等放行真实消耗执行名额属预期、名额语义未绕过；H2 拒绝发生在名额/容器之前、台账 sessions 为空；桩三条返回路径均 unlock 无死锁；构建门禁 UND 检查在镜像内强制；旧 sha 全库零残留；桩行为语义静态核对未变）。
- 新发现 1 个 nit 并同轮修复：复用路径的幂等比较会重建传入映像，超限/含 NUL 声明的 AdaptationError 曾逃逸到 base 层异常通道（ok=False、缺台账 refusal 记录），与同一类声明在新会话路径的 refuse 通道不一致——修复：比较纳入 try/except 走 refuse；新增 `test_adaptation_mismatch_build_error_refuses_in_channel` 钉住（ok=True/prep_blocked/refusals 入账）。
- 维护性建议（记录，不阻断）：①`qemu_precheck._NVRAM_FAMILY_BASENAMES = NVRAM_FAMILY_BASENAMES` 模块别名保留为兼容既有测试引用，后续可让测试直用 qemu_adapt 常量后删除别名；②桩对多线程目标（httpd）仅做了锁正确性核对，未做并发压力验证（限制已在 G 节声明）。

**两轴终局判定**：Standards 无 hard 残留；Spec 10/10 AC PASS（AC10 记录已修正）；第二轮除上述已修 nit 外 `FINAL: clean`。同类阻断未出现连续两轮，按用户指示正常收口。

### 2026-09-23 独立复审补修轮开工：findings 与逐条裁定（fresh 证据，不沿用上轮评审结论）

应用户要求对最终提交 9e99c8b 做独立复审（Standards + Spec 两轴并行子代理，只读静态审查；全部结论从 diff/代码/测试重新得出）。以下为 findings 与本轮裁定。

**Standards 轴（1 hard + 6 judgement；一致性核查通过：NVRAM_SHIM_SHA256 与 .so 实测一致，IMAGE_CAP/MAX_ENTRIES 两侧逐字配对）**

| # | 发现 | 位置 | 裁定 |
| --- | --- | --- | --- |
| S1(hard) | argv0 bind 通道绕过保留前缀校验：声明 bind 拒绝 /session、/dev、/tmp、/host-rootfs（qemu_adapt parse_binds），argv0≠guest 路径时仅查绝对路径/../NUL/遮蔽固件根文件，`proot -b …:argv0` 可把目标呈现在保留前缀路径上，遮蔽模板映像/声明输入（违反 rules.md「模型参数不能关闭边界检查」、ADR-0013 路径白名单） | qemu_session.py `_prepare_execution`/`_execute_once` | **本轮修复**：argv0 复用同一保留前缀闸门（常量提为 qemu_adapt 单一出处），离线测试钉住 |
| S2 | stdin_ref 先 read_bytes 整载再验 1 MiB 上限（超大文件宿主内存尖峰）；docker_utils._feed 写失败路径不 close stdin | qemu_session.py:751、docker_utils.py | **stat 先行本轮修复**（超限先拒绝，读后再兜底校验），回归钉住不整载；_feed fd 关闭属维护性，本轮不动 |
| S3 | Data Clumps：adapt_binds/fixtures/values/sources 四参结伴贯穿两处调用点 | qemu_session.py | 维护性，本轮不动（已记录） |
| S4 | Duplicated Code：K=V 行解析三处同构；ElfParseError 兜底 dict 重复家族键形状 | qemu_adapt/qemu_precheck | 维护性，本轮不动 |
| S5 | Middle Man：`_NVRAM_FAMILY_BASENAMES` 纯转发别名；dev_nvram/mixed 组合判断散两处 | qemu_precheck.py:53 | 维护性，本轮不动 |
| S6 | Speculative Generality：O_ACCMODE 未使用；bind dict mode/kind 同义两字段 | nvram_shim.c、qemu_adapt | 维护性，本轮不动（不搭桩重建便车） |
| S7 | 预检盲区：dynsym 导入 nvram_get 但 NEEDED 无已核实基名 → family "none" 放行且无 note（运行期将如实失败无提示） | qemu_precheck.py 模板适用性段、qemu_adapt.nvram_family_for_target | **先复现确认，再修复**：按 AC8「基名不足以分族时维持不判定/阻塞」判 unknown+阻塞明示，不因导入符号放行模板 |

**Spec 轴（AC 7 PASS / 3 PARTIAL / 0 FAIL / 0 creep）**

| # | 发现 | 裁定 |
| --- | --- | --- |
| P-a1 | AC6「target/8 不纳入 NVRAM 支持表」无直接断言（test_real_precheck_tgt8_busybox_ready 未断 family=="none"；离线缺 none 族用例） | **本轮补断言**（真实 t8 busybox + 离线 none 族预检用例） |
| P-a2 | AC10 真实通过数字系 Comments 主张，静态不可证 | **本轮重跑真实门控回归取得新证据** |
| P-c1 | 同 S1（argv0 绕过保留前缀，破坏 AC4 最小 bind 纪律，可使 NVRAM 模板静默失效） | 同 S1 |
| P-c2 | 桩 read 拦截把 getall 输出缓冲当键名写未决日志 → consume_unresolved_keys 把垃圾当键污染 adaptation_gaps（getall 本身如实失败符合支持表，gap 可信度受损） | **本轮修复**：按票 02 协议形状（read(fd,name,strlen+1)）判定键查询，形状不符按缺失键语义返回 0、不写日志、不改写调用方缓冲；重建桩重钉 sha + 真实门控回归 |
| P-c3 | test_real_t6_conntrack_cgi_honest_block 的 OR 弱断言对「会话门真实运行」钉得偏松 | 本轮随真实回归观察实际输出后收紧（仅测试） |

AC 复核：AC1/2/3/7/8/9 PASS（证据=测试断言位置）；AC4 PARTIAL（argv0 绕过，即 S1）；AC6 PARTIAL（t8 排除无断言，即 P-a1）；AC10 PARTIAL（真实数字待复跑，即 P-a2）。scope creep 无。

补修范围外明确不动：S3-S6 维护性项、docker_utils._feed fd 关闭、既有工单记录。不启动票 19；不调用真实 LLM；不读取 GT。

### 2026-09-23 补修轮收口：逐条结论、真实验证与复审终局

**逐条结论（对上一段裁定表编号）**

- **S1/P-c1（argv0 保留前缀，hard）已修复**：`_RESERVED_GUEST_PREFIXES` 提升为 `qemu_adapt.RESERVED_GUEST_PREFIXES` 公开单一出处；`_prepare_execution` 的 argv0 校验新增保留前缀拒绝（`==p` 或 `startswith(p+"/")`，与 parse_binds 逐字一致；argv0==guest_target 的默认形态不进 bind 分支故不受闸）；工具参数描述同步。闸门位于新旧会话共享的准备路径，复用会话同样受约束。离线用例覆盖五个保留前缀路径并断言未达容器创建。
- **S2（stdin 整载）已修复**：stat 先行拒绝超限，读后兜底校验一次（防 stat/读取窗口放大上限）；台账 ref/sha256/字节数语义不变。回归用 monkeypatch(Path.read_bytes) 守卫证明超限文件零读取（先红后绿确认守卫命中原 762 行整载点）。
- **S7（预检基名盲区）已复现并修复**：复现确认 `nvram_family_for_target` 无基名时符号证据被静默丢弃（undefined nvram_get → family none、note None）。按 AC8 修复为 unknown+明示（"支持表无法分族，维持不判定/阻塞，不因导入符号放行模板"）；precheck 无基名分支统一解析 dynsym（ElfParseError 只留 dynsym_note，静态形态不新增阻塞）；_render_text 对该形态不再渲染"无 NVRAM 系依赖"。dev_nvram/mixed/envram/unknown 四既有分支与 HEAD 逐字等价（复审对照）。
- **P-c2（getall 污染 gaps）已修复**：桩 read 键查询按票 02 协议形状判定（`count==strlen(buf)+1` 且 len>0），形状不符返回 0、不写未决日志、不改写调用方缓冲（顺带消除旧代码无 NUL 时截断改写缓冲末字节的行为）；`count<4` 命中仍按缺失键语义。桩重建（新 sha `2de58934…`，尺寸不变 5756）并重钉，镜像内 UND 门禁照常强制。**诚实记录**：旧桩对照实测 t6 `show`（nvram_getall）的读缓冲为零填充，旧代码仅记空行且被 Python 侧过滤——垃圾污染在现网通路不可观察，本次修复价值在未决日志可信性由构造保证；真实回归的牙齿在支持表纪律（show 不得从模板整表泄漏，断言模板值不出现且 gaps 为 None）。
- **P-a1（AC6 断言）已补**：真实 t8 busybox 预检断言 `family=="none"` 且无 supported_reads；离线补 none 族（动态）与静态形态（none+dynsym_note 不阻塞）双用例，并登记 test_main。
- **P-c3（conntrack 弱断言）已收紧**：实测确认 stderr（QEMU_STRACE）含 /var/session，OR 弱断言收紧为 stderr 单侧。
- **P-a2（AC10 真实证据）已闭环**：本轮真实门控全部重跑通过（见下），真实数字不再是 Comments 孤证。

**测试与回归（命令与结果）**

- 离线（零容器）：`pytest -q test_step5_qemu_session.py test_step5_qemu_adapt.py test_step5_qemu_precheck.py test_qemu_docker_limits.py -k "not real"` → 135 passed（新增：argv0 保留前缀、stdin 超限零读取、预检盲区 unknown、none 族/静态形态）。
- 真实门控：`pytest -q test_step5_qemu_session.py test_step5_qemu_precheck.py -k "real"` → **16 passed**（既有 15 + 新增 getall/show；新桩下 t6/t7 键查询三态、httpd bcm 消费、opkg 通路与对照全部保持）。
- 全量回归：`pytest -q firmware_audit/test --ignore=firmware_audit/test/test_step5_host_evaluation.py` → **1275 passed, 17 skipped, 0 失败**（票 18 基线 1270+17；本次净增 5 通过，无新增失败）。`python -m compileall -q`、`git diff --check` 通过。
- 复审终局（两轴并行独立子代理，工作树 diff）：Standards **0 hard + 5 judgement**（均为维护性：保留前缀谓词/文案两处同形可提取共享谓词、params_doc 前缀清单可由常量拼装、precheck 两分支 tpl.update/base_templates 重复、family 裸 dict 字段簇、family→行为分支三处分布）；Spec **6 PASS / 0 PARTIAL / 0 FAIL / 0 creep**（六项修复逐一核实，范围红线未破）。无阻断发现，收口。

**剩余限制（如实记录，不阻断）**

- 维护性项本轮未动（用户裁定单列）：共享保留前缀谓词、params_doc 拼装、precheck 家族字段拷贝收敛、family 值→行为映射显式化、O_ACCMODE 死宏、bind dict mode/kind 同义、docker_utils._feed 写失败路径 fd 关闭。后续触碰相应段落时顺带收敛即可，不单独开票。
- getall 垃圾污染的"牙齿"受限于现网唯一 getall 通路的零填充缓冲（见上）；桩对多线程目标的并发压力验证仍未做（沿用 G 节声明）。
- 正式后端身份、预算临时默认值等沿用 G 节既有声明，本轮未触碰。

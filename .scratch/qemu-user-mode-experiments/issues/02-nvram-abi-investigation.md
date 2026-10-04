# 02: NVRAM ABI 与缺失键语义调查

**What to build:** 逐项核实 target/6 与 target/7 固件中 NVRAM 读取接口的真实 ABI，为票 11 的模板支持表提供事实：函数原型、调用约定、返回值语义、缺失键行为，以及 target/6 `libnvram` 通用接口与 target/7 `bcm_nvram_*`/`envram_*` 厂商包装的差异。静态核实基于解包树与反编译边车；结论必须区分"已核实"与"仅推断"，推断项标注需运行期验证。

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] 两套接口逐项记录：符号、原型、调用约定、返回值、缺失键/未知键行为，附反编译或反汇编出处
- [ ] 模板支持表草案：哪些接口进第一批、哪些明确不支持及原因
- [ ] 默认配置候选值来源列出（如 target/6 defnodes、target/7 nvram_default.cfg），并标注"路径存在 ≠ 值适用"
- [ ] 已核实 / 仅推断两级置信区分，推断项标注需运行期验证
- [x] 两套接口逐项记录：符号、原型、调用约定、返回值、缺失键/未知键行为，附反编译或反汇编出处
- [x] 模板支持表草案：哪些接口进第一批、哪些明确不支持及原因
- [x] 默认配置候选值来源列出（如 target/6 defnodes、target/7 nvram_default.cfg），并标注"路径存在 ≠ 值适用"
- [x] 已核实 / 仅推断两级置信区分，推断项标注需运行期验证
- [x] 结论追加到本票 `## Comments`，附命令与输出原文

## Comments

### 2026-09-21 静态调查结论（子代理独立调查，协调者抽查核对；纯 r2 反汇编 + 边车 + 文件证据）

原始日志：`investigation/02/`（17 文件，下引文件名）。target/ 全程 `:ro`；未读 dataset/；未跑 Step5。

**总体结论（三条）**：
1. t6 与 t7 的 `libnvram.so` 是**同一套 Broadcom 风格 /dev/nvram 库**（各导出 nvram_init/get/set/unset/commit/getall 六函数，同一协议）；t7 的 `bcm_nvram_*`（libCfm.so，DWARF 源文件 `nvram_bcm4706.c`）是同协议的第三份拷贝——**三方 ABI 一致**。
2. t7 另有一套 **`envram_*`（`envram_bcm4706.c`）完全不同**：后端是 MTD 分区 "Bootloader"@0x400（0x1400B），`envram_get` 是 `(argc,argv)` 签名的 CLI 处理器，`envram_get_value` 缺键时**不改调用方缓冲、打印 "not found"、仍返回 0**。
3. **t6 的 defnodes XML 与 NVRAM 无关**——由 xmldbc（dbload.sh，开机 S20init.sh/rcS 调用）消费；t6 web/HNAP 栈（cgibin.c）0 处调用 nvram；t6 里真正用 libnvram 的是 12 个 Broadcom 无线工具。

**逐项 ABI（三方对齐反汇编；出处 `t6_libnvram_disasm.txt`、`t7_libnvram_disasm.txt`、`t7_libcfm_bcm_nvram*.txt`）**【已核实】：
- ARM EABI，参数 r0-r3。`nvram_init(void)→int`：`open("/dev/nvram", O_RDWR)` 失败返回 errno；成功 `mmap(NULL,0x10000,PROT_READ,MAP_SHARED)` 存全局 nvram_buf，返回 0。
- `nvram_get(name)→char*`：驱动 `read(fd,name,strlen+1)` **ret==4 → 返回 nvram_buf+偏移**（指向 mmap 镜像内部，非拷贝）；**ret≠4（含缺键）一律 NULL**（t6 附 perror，t7 不带）。
- `nvram_set(name,value)→int`：write `"%s=%s"`（value==NULL 时写裸名 = 删除语义）；malloc 失败返回 -12；写足返回 0。`nvram_unset == set(name,NULL)` 尾调用。`nvram_commit()`：`ioctl(fd,0x48534C46 /*"FLSH"*/,0)`，ret≥0→0。`nvram_getall(buf,len)→int`：read 填 buf，ret==len→0；消费侧（两个 nvram CLI 的 show/dump）证实缓冲为 `"k1=v1\0k2=v2\0…\0"` 空串终止串表。
- 缺键行为库侧代码路径唯一且明确【已核实】；**驱动侧对 name 的实际应答静态不可见 → 运行期验证**【仅推断】。
- 消费方假设交叉印证【已核实】：t6 `wlconf` 先判 NULL 再 strcmp；t7 `httpd.c` L37577 `strcpy(param_2, bcm_nvram_get(...))` **无 NULL 检查**；httpd 对 envram 封装 `return envram_get_value(...)!=0`——**缺键（0）与成功不可区分**。
- t7 envram 家族【已核实】：512 条 ×192B（name[0x40]+value[0x40]）进程内缓存；`envram_get(argc,argv)` 命中把 value 指针写回 argv[2] 并 puts，未命中 puts("not found")；`envram_get_value(name,value,len)` 命中 strncpy 返回 0，未命中缓冲不变仍 0；`envram_set_value` 只覆盖已有条目、每次即时 submit 写 flash；**`envram_commit` 是空 stub**。

**后端存储机制**【已核实】：t6/t7 libnvram 与 bcm 系唯一后端 = `/dev/nvram` 字符设备（.rodata 仅此一条业务路径；驱动在内核不在 rootfs）。envram 系 = MTD "Bootloader"（`flash_read_from_mtd` → MEMGETINFO → 偏移 0x400、长 0x1400，解析起点 buf+0x14）。t7 `bcm_nvram_restore`（libCfm）`fopen("/webroot/nvram_default.cfg")` 逐行 `#` 跳过/无 `=` 跳过 → 逐条 bcm_nvram_set；固件内文件在 `webroot_ro/`，`etc_ro/init.d/rcS:15` 有 `cp -rf /webroot_ro/* /webroot/`（/webroot→var/webroot ramfs）。

**默认配置候选值来源（路径存在 ≠ 值适用）**：
- t6 `/etc/defnodes/`：23 文件（6 XML + 17 PHP），`defaultvalue.xml` 34KB ≈1594 节点。格式与消费者【已核实】（xmldbc -L/-P/-R，dbload.sh）；**对 NVRAM 模板而言 defnodes 不是 nvram 默认值来源**（libnvram.so 内无 defnodes 字样）。
- t7 `webroot_ro/nvram_default.cfg`：821 行、非注释 816 行、`name=value` 每行一条（`0:`/`1:` 前缀是键名本身）、头有 UTF-8 BOM（解析器安全跳过）。格式【已核实】；**唯一消费者 bcm_nvram_restore 仅被 bin/cfm 引用，开机是否自动执行无静态证据【仅推断】**——文件里的值开机即生效是推断。

**差异表（要点）**：nvram/bcm 系——后端 /dev/nvram、get 返回 mmap 内指针/NULL、set 写 "%s=%s"、commit 手动 ioctl、无锁；envram 系——后端 MTD、get_value 拷贝到调用方缓冲且缺键不可区分、set_value 即时写 flash、**无 unset**、commit 为 stub、name/value 各 64B（strcpy 截断风险）。两系语义不可混用。

**模板支持表草案（票 11 输入）**：
- 第一批（只读、ABI/缺键已核实）：`nvram_get` / `bcm_nvram_get`（三份同签名，隐式 init 自动成功）；`bcm_nvram_match(name,expected)`（= get+strcmp，可派生）。
- 第二批（条件放行）：`nvram_getall(buf,len)`——库侧与 CLI 迭代逻辑已核实，但填充格式终归是驱动行为，先在票 06 tracer 实测一次再放行。
- 明确不支持：`set/unset/commit`（nvram 与 bcm 系，持久化副作用且正确性依赖驱动写语义）；**`envram_*` 全家族**（MTD 依赖、缺键不可区分、CLI 签名、commit stub）；`bcm_nvram_restore/add/del`（恢复/批量语义）。

**需运行期验证清单（全部【仅推断】）**：① 驱动 read 协议与 getall 填充格式；② t6 /dev/nvram 开机实际键集；③ t7 restore 是否开机自动执行；④ MTD envram 区实际内容与 0x14 头格式；⑤ commit 后 mmap 指针有效性；⑥ t6 xmldbc/devdata 运行期内容（t6 主配置面缺口，归票 10/12）；⑦ httpd.c L37577 无判空 strcpy 的键是否恒存在（本身是审计候选）。

**验收逐条核对**：5/5 满足——两套接口逐项记录（六 + 七 + 十一函数，原型/约定/返回值/缺键齐，附反汇编出处）；模板支持表草案（含第一批/第二批/不支持及原因）；默认值来源与"路径存在 ≠ 值适用"标注（含 defnodes 归属纠偏）；已核实/仅推断两级贯穿全文并集中列出运行期验证点；结论已追加本 Comments。

**对后续票的影响**：
- **03 执行镜像**：必须决定 /dev/nvram 供给方式（模板注入 vs 伪造字符设备）；镜像需能并排挂两固件的 libnvram.so/libCfm.so/libtpi.so。
- **05 预检契约**：预检应扫目标 NEEDED 是否含 libnvram.so/libCfm.so/libtpi.so 以决定模板注入，并区分 /dev/nvram 系与 envram（MTD）系——后者直接降级为运行阻塞。
- **06 tracer**：把 get 返回 NULL（缺键）与 init 失败（≠0）列为独立事件；顺带实测 getall 格式（第二批放行依据）。
- **09 子进程链**：t6 web 栈经 system()/popen() 走 xmldbc/devconf/dbload.sh，子进程覆盖面必须含 shell 链；t7 的 cfm/cfmd 是独立进程（restore 触发）。
- **10 基础适配模板**：t6 不能只做 nvram 模板——主配置面是 xmldbc/devdata/devconf，缺口需单列，否则 t6 大部分业务函数无配置可读。
- **11 NVRAM 模板**：按支持表；t7 需同时声明 bcm 系（支持）与 envram 系（不支持）两套文案；NULL（指针族）与"缓冲不变+0"（envram 族）两种缺键语义必须区别建模。
- **12 通路选择**：envram 的 MTD 依赖与 t6 的 xmldbc 共享内存库都会抬高纯 user-mode 通路成本；t6 推荐"无线工具走 nvram 模板、web 栈另配 xmldbc 策略"。
- **14 集成验收**：用例至少含 ①已知键返回值一致 ②未知键返回 NULL（nvram 系）/缓冲不变+0（envram 系）③`strcmp(nvram_get(...),"ap")` 消费模式断言（wlconf 模式）。

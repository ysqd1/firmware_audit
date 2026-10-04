# Handoff: Step0 ext4 直读 + 守卫配置化(来自 Go2 NX 完整固件审计实测)

> 写给新会话的 `/grill-with-docs`:本文件是 2026-09-06 Go2 NX 固件审计会话的交接。
> 审计本体(Step2-5 + CVE 扫描)仍在原会话进行,总报告稍后落盘;本文件只覆盖
> **已经实测闭环、与审计剩余步骤无关**的流水线改进项。

## 背景事实(已实测,非推测)

target: `target/3/go2_nx_Jetpack5.1.1_20250930.img` — 238.47 GiB GPT 磁盘镜像,
宇树 Go2 机器狗 Jetson Orin NX(JetPack 5.1.1 / L4T R35.3.1 / Ubuntu 20.04.5 aarch64),
13 个分区,主 rootfs(APP)= **237.71 GiB ext4,363,437 个文件**。

流水线原生路径(2026-09-06 实测跑过 `python -m firmware_audit.main target/3 --no-step5`):

- 小分区跑通:part02/part05 kernel、part08 part12 recovery(ELF 73 颗 ok=70,
  crypto_ssh=8 **SSH 主机私钥烧死在 recovery**)、esp×2;part10 RECROOTFS 解出空树。
- **APP 分区被 Step0 静默跳过**(见票 A/B),整盘审计价值 99% 在这个分区。
- 旁路方案(手工,不改代码):WSL Ubuntu loop-mount APP(offset=819875840, ro, noload)
  → tar 导出 21.4GB → 宿主 Python tarfile 解到 `target/3/process/APP/extracted/`
  → 写 `.step1_done` → 外部驱动调 `run_pipeline` 公共 API 跑 Step2-4。
  全程约 3 小时,树完整 36.3 万文件。此路径已验证"Step1 预解树 + 公共 API 驱动"可行。

## 候选工单(证据闭环,待 grill 定决策点)

### 票 A(主):Step0 ext4 rootfs 直读文件树
- 现状:磁盘镜像路径 = dd 原始分区字节(partNN.img)→ Step1 binwalk/7z 签名解包。
  对 237.71GiB ext4:dd 255GB 中间文件 + binwalk 全盘扫描(小时级)+ Step1 必然撞
  `MAX_TOTAL_FILES=200000` 截断(rootfs 实测 363,437 文件)。
- 方向:Step0 解析分区表已识别 rootfs + ext4 魔数(file_magic.py 0xEF53)。识别到
  ext4 rootfs 时直接产出 `process/<stem>/extracted/` 文件树 + `.step1_done` 语义
  (该分区 Step1 跳过),下游零改动。与旁路落点完全一致。
- 后端二选一或双后端配置切换(待 grill 决策):
  a) **Docker + debugfs rdump**:用户态读 ext4,无挂载无特权;`firm_audit/sandbox`
     已带 debugfs 1.46.2(实测);零新依赖;缺点:Docker Desktop 卷小文件 IO 慢,
     36 万文件估 1-2 小时。
  b) **WSL loop-mount + tar 流**:实测 ~65 分钟;Docker Desktop 本就依赖 WSL2,
     不算新依赖;注意 wsl.exe 传参中文路径/多行脚本会被搅坏——脚本必须走文件+ASCII 路径(实测教训,已用 `E:\fw` junction 解决)。
- 旁证:7z(binwalk 镜像内置)也支持 ext4,但走卷 IO,不推荐做主路径。

### 票 B:三道闸门配置化(沿用 STEP5_*_MAX_ITERS 的 env 覆盖先例)
- `step0_split_img.py:295` `should_extract` 的 `_PARTITION_MAX_SIZE_GB = 50.0`
  (step0_preprocess.py:46,单位 GiB)。
- `step1_guided_extract.py:34-36` `MAX_FILES_PER_EXTRACTION = 50000` /
  `MAX_TOTAL_FILES = 200000`。
- 用户已口头批准"分区上限改 250G"——但单改这一个数字不解决问题(Step1 守卫仍截断),
  应做成 `STEP0_PARTITION_MAX_SIZE_GB` / `STEP1_MAX_TOTAL_FILES` /
  `STEP1_MAX_FILES_PER_EXTRACTION` env,默认值不动。250 只是本次 target 的运行参数。

### 票 C:失败行为修复(实测撞出来的三个)
1. 超大分区跳过**无任何告警**(step0_preprocess.py `_extract_partitions` 的 continue
   分支静默)——审计者不知道 rootfs 根本没进流水线。
2. 多分区批次中,单分区 Step2 过滤后为空 → `sys.exit(1)` **杀死整批**
   (part10_RECROOTFS 空树导致 esp×2/recovery_alt 未跑;main.py 递归分支)。
3. symlink 静默丢弃:宿主 tarfile `filter="data"` 与 7z 均丢绝对路径符号链接
   (Ubuntu usrmerge: /bin→usr/bin、/etc/ssl/certs/*.pem、/etc/alternatives/*)。
   建议落 `links.jsonl` 清单(rel → target),审计侧可查。

### 票 D(用户提议,已无代码版落地,待代码化):CVE 缓存共享
- 现状:`cve_bin_tool_scan.py` 缓存路径 = `ctx.process_dir/.cve_cache`,按 target 隔离,
  每个 target 预热都要全量下载;且沙箱 --network none,预热只能宿主侧做。
- 已验证的零代码方案:共享库放 `firmware_audit/.cve_cache/`(2026-08-23 target/1 库,
  cve.db 91MB),各 target 的 `.cve_cache` 用 Windows junction 指过去;
  **Docker Desktop 透过 junction 挂载实测可用**。.gitignore 已加忽略。
- 代码化方向:env `FIRMWARE_AUDIT_CVE_CACHE_DIR`(默认保持现行为),工具类读之。
- 顺带实测:预热容器走宿主代理需 `-e HTTPS_PROXY=http://host.docker.internal:<port>`
  (NVD/OSV/GAD 直连会卡死);EPSS 源拉取失败可容忍。

## 待 grill 的决策点(用户拍板项)

1. 票 A 后端选型:docker-debugfs(零依赖慢)/ WSL(快、平台绑定 Windows)/ 双后端?
2. 直读分支的触发条件:ext4 rootfs 就直读?还是 size 阈值(如 >20GiB)才直读?
3. 闸门默认值:分区上限默认保持 50 还是上调?文件守卫 rootfs 类要不要单独放宽?
4. 共享缓存默认位置:`firmware_audit/.cve_cache` 还是用户目录(~/.firmware_audit)?
5. RECROOTFS(raw binary,引导解包器解出空树)要不要立项支持 erofs/其他 FS?(可先 wontfix)

## 补充票 G(Step5 实测后新增,2026-09-06 晚)

docker 超时语义 + 工具层大树防护,三连实测证据:
1. `run_docker` 超时只杀 docker 客户端,容器继续运行成孤儿(semgrep 两次 900s 超时
   各遗留一个,持续占宿主 IO,需手工 docker stop)→ 超时分支补 `docker stop`。
2. `semgrep_scan` 的 `'.'` 全树路径在 6.5 万文件树上双腿各烧满 900s(单步动作浪费
   30 分钟迭代预算)→ 学 search_code 范围守卫:大树拒绝并提示分目录。
3. `cve_bin_tool_scan` 全树 16 分钟异常退出(rc=1 且 stdout 空,疑内存耗尽;工具层
   仅 rc≥2 回传 stderr)→ 分目录扫描指引 + rc=1 也回传 stderr。
共性:工具层缺"输入规模感知"。Step3 file -f 单批 6.5 万文件超 600s 降级(见报告票 F)
同属此类。详见 `go2nx_audit_report.md` §5/§6。

## 补充票 H/I(Step5 全程跑完后新增,2026-09-06 深夜)

Step5 最终 7 findings → verification 7/7(1 真 6 假):真的一条即 upgradePythonServer
RCE(critical,sandbox_verify 动态 PoC 实证,与人工分析一致);6 假全是 analysis
**编造 file 路径**(usr/home 拼接、unitree/etc 不存在;.ssh 实测空目录)。
- **H**:analysis 侧路径幻觉——finding.file 必须来自工具实际返回;落盘前按存在性
  纯 IO 校验过滤(6 条幻觉复核吃掉约一半 verification 时长)。
- **I**:Step3 降级(票 F)使无扩展名文件(.ssh/id_rsa 类)落入 unknown → crypto
  检出盲区 → analysis 输入缺边车;票 F 修复连带解决。

## 审计会话状态(交接时点)

- tar 解包进行中(14 万/36.3 万);后续:s23 驱动 → s4 0(用户指示跳过 Ghidra)→
  cve-bin-tool 全量扫描(脚本 run_cve_scan.py 就绪,junction 缓存)→ Step5(run_step5)。
- 已手动确认的漏洞(留给 Step5 当试金石,报告对照):`/upgradePythonServer/server.py`
  tornado :80 无鉴权 WebSocket,`upgrade/run|recover` 客户端可控路径字符串拼接进
  create_subprocess_shell(RCE),`upgrade/rm` 任意文件删除,check_origin 恒 True。
- 总报告将含:固件画像、dpkg 3,324 包、CVE 清单、firm_audit 改进方向(即本文件)。

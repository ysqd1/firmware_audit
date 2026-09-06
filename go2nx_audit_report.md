# Go2 NX 完整固件审计报告(firm_audit 实测)

> 审计对象:`target/3/go2_nx_Jetpack5.1.1_20250930.img`
> 审计日期:2026-09-06 · 工具:firm_audit(Step0-5)+ 手工旁路 + cve-bin-tool
> 本报告由 ZCode 审计会话生成;流水线代码零修改(改进建议见 §6,代码化需另行评审)。

## 1. 固件画像

| 项 | 值 |
| --- | --- |
| 文件 | go2_nx_Jetpack5.1.1_20250930.img,256,060,555,264 字节(238.47 GiB) |
| 形态 | GPT 磁盘镜像(尾部备份 GPT 头校验通过,镜像完整) |
| 平台 | NVIDIA Jetson Orin NX aarch64,L4T **R35.3.1**(JetPack 5.1.1,2023-03-19) |
| 系统 | **Ubuntu 20.04.5 LTS (Focal)**,完整桌面(gdm/GNOME),hostname=ubuntu |
| 分区 | 13 个(GPT):**APP 237.71 GiB(ext4 主 rootfs)**、kernel/kernel-dtb A/B、recovery×2、RECROOTFS 0.29GiB、esp×2、reserved×2 |
| 文件量 | APP rootfs **363,437 个文件**,实际数据约 21.4 GiB |
| 软件栈 | dpkg **3,324 包**:ROS2 Foxy(已 EOL)、OpenSSH 8.2p1、OpenSSL 1.1.1f、curl 7.68、OpenVPN 2.4.7、docker.io 24.0.5、nvidia-docker2、GNOME 全家桶、CUDA 11.4/cuDNN |
| 宇树载荷 | `/unitree`(module 847MB:Odometer_service、graph_pid_ws;lib/unitree_go2_sdk 145MB)、`/upgradePythonServer`(OTA 升级服务器 1.2GB,端口 80)、`/home/unitree`(.bash_history、.gnupg 私钥)、systemd:unitree-upgrade.service / go2_test.service |

## 2. 流水线实测记录(原生路径 + 旁路)

### 2.1 原生路径(`python -m firmware_audit.main target/3 --no-step5`)

- Step0 识别 GPT → 解析 13 分区 → 提取 7 个小分区(kernel×2、recovery×2、RECROOTFS、esp×2),
  **APP(237.71GiB > 50GiB 上限)静默跳过,无告警**。
- part08_recovery 全链路成功:引导解包(initramfs 树)→ Step2/3 → Step4:
  ELF 73(ok=70/failed=3)、**crypto_ssh=8(4 对 SSH 主机私钥烧死在固件)**、
  文本扫描 22(6 有发现)、ELF 字符串扫描 70(46 有发现)、etc/shadow 哈希 1。
- part10_RECROOTFS:Step0 警告"raw binary 不匹配期望 fs 签名" → Step1 解出**空树**
  → Step2 过滤 0 文件 → `sys.exit(1)` **终止整批**,esp×2、recovery_alt 未处理。

### 2.2 APP 分区旁路(不改代码)

WSL Ubuntu loop-mount APP(offset=819875840,ro,noload)→ tar 流式导出 21.4GB(40 分钟)
→ 宿主 Python tarfile 解包 363,425 个文件(1 小时 46 分;`data` 安全过滤器,
绝对路径 symlink 跳过,实体文件无损)→ `process/APP/extracted/` + `.step1_done`
→ 外部驱动脚本调 `run_pipeline` 公共 API 跑 Step2-4(与 main.py 同构)。
落点与原生路径设计完全一致,流水线代码零修改。

**Step2 实测**:344,060 条目 → **65,811 文件**(usr/share、usr/lib 等黑名单过滤 81%;
ELF 副本去重 332;DTB 噪声 3,165)。保留分布:opt 23,745(ROS/CUDA)、usr 14,611、
unitree 6,973、upgradePythonServer 6,854、var 6,285、home 6,197、etc 971、其余零头。

**Step3 实测**:docker `file -f` 批量识别在 65,811 文件上**撞 run_docker 600s 超时**,
降级纯扩展名分类(source=20,787 / script=6,782 / config=1,653 / unknown=36,217 /
crypto_x509=334 / **crypto_private_key=6 / crypto_pkcs12=1** / crypto_gpg=24)。
影响:ELF 未做魔数分类(全在 unknown)——对本审计"跳 Ghidra + 文本密钥扫 + Step5"目标
无实质损伤,但属规模化缺陷(改进票 F)。

## 3. 已知 CVE 扫描(cve-bin-tool,共享缓存)

**按用户指示中止**(2026-09-06)。已取得的部分结果:

- 共享缓存方案验证通过(见 §6 票 D),工具参数与 Step5 工具层一致,小目录(/etc)
  能正常启动扫描。
- **全树扫描(36.3 万文件)异常退出**:16 分钟,rc=1 且 stdout 空(疑似容器内存
  耗尽或运行时异常;工具层仅在 rc≥2 时回传 stderr,rc=1 的现场被吞)。
  → 已记入改进票 E:大目录按子目录分片扫描指引 + stderr 回传 + 工具超时可配。
- 替代路径(已落地,零代码):dpkg 清单 3,324 包(`app_inventory/dpkg_list.txt`)
  可对接 Ubuntu CVE tracker / OSV 做版本比对;ROS2 Foxy(2023-05 EOL)、
  OpenSSH 8.2p1-0.5、OpenSSL 1.1.1f-2.17、curl 7.68-2.20、OpenVPN 2.4.7、
  docker.io 24.0.5 等组件版本已固化在清单中,供后续按需枚举已知 CVE。

## 4. 安全发现

### 4.1【高危·已手工确认】OTA 升级服务器无鉴权 RCE 链

`/upgradePythonServer/server.py`(257 行,tornado,systemd root 服务,监听 **0.0.0.0:80**):

- **无任何鉴权**;WebSocket `check_origin()` 恒返回 True(任意来源可连);
  静态资源 + CORS `Access-Control-Allow-Origin: *`。
- `upgrade/run` / `upgrade/recover`:客户端可控的 `data["file"]` 经
  `os.path.join` 后**字符串拼接**进 shell 模板,`asyncio.create_subprocess_shell` 执行
  → **命令注入(以 root)**。注入点连 `rm -rf /unitree; cp -r unitree /` 一起执行。
- `upgrade/rm`:`os.remove` 客户端可控路径 → **任意文件删除(root)**。
- `/upload`(stream_request_body,6GB 上限):multipart 文件名未净化 → 路径穿越风险;
  上传即触发升级流程(`rm -rf temp; unzip; rm -rf /unitree; cp -r unitree /`)。
- 影响:机器人自身 AP / 局域网内任意主机,一个 WebSocket JSON 消息即可 root RCE;
  上传恶意 zip + 触发安装 = 持久化完全控制。
- 状态:**试金石通过**——Step5 Agent 独立发现、复核并用沙箱动态 PoC 实证了同一
  漏洞(见 §5.1),人工分析与 Agent 结论完全一致。

### 4.2【高危】recovery 分区 SSH 主机私钥硬编码

`part08_recovery/extracted/.../etc/ssh/ssh_host_{dsa,ecdsa,ed25519,rsa}_key`:四类主机
私钥全部内置于固件。同型号设备共享同一私钥 → 身份可冒充、流量可解密(若 recovery
系统联网提供 SSH)。流水线 Step4 crypto 解析自主检出(crypto_ssh=8)。

### 4.3【中危】root 口令哈希内置

initramfs `etc/shadow` 含 `$6$`(SHA-crypt)口令哈希,可离线爆破。

### 4.4【疑似】NoMachine NX 服务端主机密钥烧入镜像

`usr/NX/share/keys/server.id_{dsa,rsa}.key`(Step3 crypto_private_key 检出,
Step4 crypto 解析成功)。`nxserver.service` 在启动项中。若 nxserver 以此为服务端
身份密钥 → 同型号设备共享主机身份,可冒充/解密历史会话;需实机确认为默认模板
还是实际启用密钥。

### 4.5【噪声·已过滤】wifi_psk/password_kw 模板命中

`etc/wpa_supplicant.conf` 的 19 个 wifi_psk 与大量 password_kw 命中经人工核验
基本为上游文档示例(`06b4be19...` 是 wpa_supplicant 著名示例哈希)。
流水线照实上报、由验证层过滤,行为正确。

<!-- TODO: Step5 Agent 发现补充(运行未完,见 §5) -->

## 5. Step5 Agent 审计结果

**状态:三阶段完整跑通**(recon 20 轮 → analysis 7 findings → verification 每疑点
一实例 7/7 复核 → orchestrator summarize 报告落盘)。总时长约 3.2 小时(其中
一个 verification 实例 100 分钟),LLM 用量约 3.3M tokens(deepseek-v4-flash,
费用可忽略)。工件:`process/APP/agent/`(survey.json / findings.json /
verified_findings.json / dispatch_log.json / transcript.jsonl / report.md)。

### 5.1 试金石结论:通过

**Agent 独立发现并复核确认了 §4.1 的 upgradePythonServer 无鉴权 RCE 链**,
且与人工分析结论一致:

> verified_findings.json 唯一 verified=true 条目(critical/conf=high):
> "升级服务 WebSocket 命令注入:file 字段拼接进 create_subprocess_shell(无鉴权+CORS 全开)"
> rationale:"漏洞成立(动态实证+源码核对):任意源客户端可连 80 端口 /ws,
> 发送 upgrade/run 即可任意命令执行。check_origin 恒返 True、CORS 全开"
> ——它用 sandbox_verify 在断网沙箱里跑了动态 PoC,不止源码静态推断。

### 5.2 误报过滤:7 条中 6 条为 analysis 幻觉,verification 全部正确拒绝

6 条 false_positive 的共同死因:**analysis 产出的 file 路径不存在**
(`usr/home/unitree/.ssh/id_rsa`、`unitree/etc/unitree/robot_crt.pem`、
`unitree/etc/wpa_supplicant.conf`、`unitree/module/graph_pid_ws/shell/` 等——
真实路径分别是 `home/unitree/.ssh/`(实测为空目录)、`etc/wpa_supplicant.conf`),
且部分 evidence 字符串全库检索零命中(幻觉证据)。verification 严格按
"read_file 报不存在 → false_positive,禁止猜路径"红线处理——纪律正确。
本审计已逐条人工复核确认:6 条全部为真误报(含 .ssh 空目录实锤)。

由此得出两条改进输入:

- **H(新)analysis 侧路径幻觉**:ADR-0008 修的是"给 Agent 的路径口径",这次暴露
  的是 **Agent 生成 finding 时的路径编造**(真实目录结构在 survey 里,LLM 仍拼错)。
  可行方向:analysis 提示词强化"file 字段必须来自 list_files/read_file 实际返回"、
  findings 落盘前按存在性校验过滤(存在性检查是廉价纯 IO)。
- **I(新)Step3 降级的连锁损失**:`.ssh/id_rsa` 这类无扩展名文件在 Step3 降级后
  落 unknown → Step4 crypto 检出盲区 → analysis 输入缺边车。票 F 修复(分块 file
  批量)可同时解决。

### 5.3 机制与效率

- recon 自主探索质量高(锁定 QT_Server/send_cmd/shell 链)、错误自愈
  (semgrep 全树超时 → 改分目录)。工具调用统计:list_files×20、search_code×14、
  read_file×11、gitleaks×3、semgrep×2、sandbox_verify×2、cve_bin_tool_scan×1。
- 效率仍受票 G 拖累:semgrep 单步 30 分钟、search_code 单次 346 秒、
  一个 verification 实例 100 分钟(6 条幻觉 finding 的复核成本约占总时长一半)。

## 6. firm_audit 改进方向(实测驱动,候选工单)

> 详见 `.scratch/step0-fs-extract/handoff.md`(已备好给 grill-with-docs 的交接文件)。

- **A(主)Step0 ext4 rootfs 直读文件树**:替代"dd 255GB 原始分区 + binwalk 签名解包"。
  后端候选:docker+debugfs rdump(sandbox 已带 1.46.2,零新依赖)/ WSL loop-mount+tar 流
  (实测 ~65 分钟)。产出直落 `process/<stem>/extracted/` + `.step1_done` 语义,下游零改动。
- **B 三道闸门配置化**:`STEP0_PARTITION_MAX_SIZE_GB`(现硬编码 50GiB,GiB 单位)、
  Step1 `MAX_TOTAL_FILES`/`MAX_FILES_PER_EXTRACTION`(现 200k/50k,Ubuntu rootfs 363k 必截断)。
- **C 失败行为修复**:①超大分区静默跳过必须有告警;②单分区过滤为空不得 `sys.exit(1)`
  杀整批;③symlink 落 links.jsonl 清单而非丢弃。
- **D CVE 缓存共享**(用户提议,零代码版已落地):共享库 `firmware_audit/.cve_cache` +
  各 target junction;Docker 透 junction 挂载实测可用。代码化:env
  `FIRMWARE_AUDIT_CVE_CACHE_DIR`。附:预热容器需 `-e HTTPS_PROXY=http://host.docker.internal:<port>`。
- **E(待确认)Step4/5 规模化**:Ghidra `max_elf` 按 rglob 顺序截断无厂商优先级;
  cve_bin_tool_scan 工具 900s 超时对大目录不够(全树扫描 16 分钟异常退出,rc=1 且
  stdout 空,疑似容器内存/异常,stderr 未随 rc=1 回传);per-workspace 缓存隔离放大预热成本。
- **F Step3 批量 file 超时降级**:docker `file -f` 单批 65,811 文件超 run_docker 600s
  硬超时,静默降级扩展名分类(ELF 全落 unknown)。方向:filelist 分块(如 5k/批)+
  run_docker 超时可配,降级时打告警。
- **G docker 超时语义 + 工具层大树防护**(Step5 实测三连证据):
  ① `run_docker` 超时只杀 docker 客户端,**容器继续运行成孤儿**,持续占用宿主 IO
  (semgrep 两个 900s 超时各遗留一个,需手工 docker stop)——超时分支应补
  `docker stop <容器>`;② `semgrep_scan` 的 `'.'` 全树路径在大树上必然烧满超时,
  且 Agent 单步动作损失 2×900s 迭代预算——应学 search_code 的范围守卫:大树拒绝
  并提示分目录;③ cve_bin_tool_scan 同理(全树 16 分钟异常退出)。
  共性:**工具层缺少"输入规模感知"**,超大解包树是完整系统镜像的常态而非异常。

## 7. 附录:复现路径

```text
# 原生小分区
python -m firmware_audit.main target/3 --no-step5

# APP 旁路(不改代码)
wsl -d Ubuntu -u root -- bash <script>   # mount -o loop,ro,noload,offset=819875840
python extract_app_tar.py                # tar -> extracted/ + .step1_done
python app_pipeline_driver.py s23        # Step2+3
python app_pipeline_driver.py s4 0       # Step4 跳 Ghidra(文本/crypto/分诊仍执行)
python run_cve_scan.py                   # 全量 cve-bin-tool(共享缓存)
python -m firmware_audit.step5_agent.run_step5 target/3/process/APP
```

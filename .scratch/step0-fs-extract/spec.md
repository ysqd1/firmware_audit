# Spec: Step0 ext4 直读与分区批次健壮化

> 来源:2026-09-06 Go2 NX 完整固件审计实测(`go2nx_audit_report.md` §2/§6)+
> 本会话 grill 共识(2026-09-07,五决策点已用户拍板,详见同目录 handoff.md)。
> Status: ready-for-agent

## Problem Statement

审计大磁盘镜像(如 238.47 GiB 的 Go2 NX GPT 镜像,13 分区,主 rootfs「APP」237.71 GiB ext4、36.3 万文件)时,流水线原生路径拿不下主内容:

1. 超大 ext4 分区被 Step0 的 50 GiB 硬编码上限**静默跳过,无任何告警**——整盘审计价值 99% 的分区没进流水线,审计者毫无感知。
2. 多分区批次中,一个分区解出空树(part10_RECROOTFS)→ Step2 过滤 0 文件 → `sys.exit(1)` **杀死整批**,其余分区不再处理。
3. 三个规模保险丝(分区 50 GiB / Step1 单次 5 万文件 / 总计 20 万文件)硬编码,换大固件只能改代码。
4. 当年只能靠 ZCode 手工旁路绕过(WSL loop-mount → tar 导出 → 宿主 tarfile 解包 → 手写 `.step1_done` → 外部驱动脚本),全程在流水线之外,不可复现、不可复用,且 tarfile 的 data 过滤器丢掉了 usrmerge 符号链接(/bin→/usr/bin 等)。

## Solution

Step0 对磁盘镜像中识别为 ext4 的分区直接读取文件树(不经 dd + binwalk),直接产出该分区的解包树与 Step1 完成标记,下游零改动接入现有分区递归。默认走 debugfs 用户态后端(零特权、不可信镜像不进内核),env 可切 mount 快路(需 sudo,symlink 完整、速度快)。随包修复批次失败行为(跳过必告警、空分区不杀整批)并把三道闸门与 CVE 缓存目录 env 化(默认值全部不变)。

## User Stories

1. 作为固件审计者,我希望 Step0 自动直读 ext4 rootfs 分区的文件树,以便磁盘镜像的主内容无需手工旁路就能进入流水线。
2. 作为固件审计者,我希望直读产物落在 `process/<分区名>/extracted/` 并带 Step1 完成标记,以便下游 Step2-5 零改动照常工作。
3. 作为固件审计者,我希望默认后端是 debugfs 用户态读取,以便不可信固件镜像不进入内核文件系统层、流水线不需要 root。
4. 作为固件审计者,我希望能用环境变量切换到 mount 快路,以便在信任镜像且有 sudo 时用更快、symlink 更完整的路径。
5. 作为固件审计者,我希望 mount 后端在没有免密 sudo 时得到明确报错,以便流水线响亮失败而不是挂死。
6. 作为固件审计者,我希望直读自动排除 lost+found,以便文件系统修复垃圾不污染审计面。
7. 作为固件审计者,我希望符号链接在直读路径下原样保留,以便 usrmerge 布局(/bin→/usr/bin、/etc/ssl/certs 链接)被正确审计。
8. 作为固件审计者,我希望拿到一份符号链接清单(links.jsonl,rel→target),以便被跳过或悬空的链接仍可作为证据查询。
9. 作为固件审计者,我希望分区因大小上限被跳过时打印醒目告警(分区名/大小/原因),以便我不再无声丢掉主 rootfs。
10. 作为固件审计者,我希望多分区批次中某个分区解出空树时跳过并记录、其余分区继续,以便一个坏分区不拖垮整批。
11. 作为固件审计者,我希望三道规模闸门可用环境变量覆盖且默认值不变,以便针对特定大固件调整时不用改代码。
12. 作为固件审计者,我希望 CVE 缓存目录可用环境变量指定(默认共享库位置),以便预热一次跨 target 复用。
13. 作为固件审计者,我希望直读按 ext4 魔数触发、不看分区大小,以便大小写统一、无双重标准参数。
14. 作为测试/评审者,我希望测试用零特权秒级合成的微型 GPT+ext4 镜像,以便回归快速、确定、不依赖真实固件。
15. 作为固件审计者,我希望本机缺少 debugfs 时得到明确报错并按告警跳过该分区,以便流水线继续处理其余分区。

## Implementation Decisions

- **触发**:分区提取产物上命中 ext4 超级块魔数(0xEF53,复用 file_magic 既有检测)即走直读,不设 size 条件;非 ext4(raw/erofs/squashfs 等)分区走现有 dd+binwalk 路径,行为不变。
- **落点**:`process/<分区名>/extracted/` + Step1 完成标记——与现有分区递归(sub-workspace)同构,下游零改动;手工旁路当年验证过该落点。
- **双后端**:默认 `debugfs`(宿主原生,用户态,零特权,不依赖 Docker);`STEP0_EXT4_BACKEND=mount` 切快路(`mount -o loop,ro,noload` + 拷贝)。mount 需 root,无免密 sudo 时响亮报错。本机无 debugfs 时响亮报错并按告警跳过该分区(不终止批次)。
- **排除与清单**:直读固化排除 lost+found;符号链接原样保留;另落 links.jsonl(rel→target)清单。
- **票 B(闸门 env 化)**:`STEP0_PARTITION_MAX_SIZE_GB`(默认 50)/ `STEP1_MAX_TOTAL_FILES`(默认 200000)/ `STEP1_MAX_FILES_PER_EXTRACTION`(默认 50000);默认行为完全不变;缺失/非法值回落默认。
- **票 C(失败行为)**:①分区因上限被跳过 → 醒目告警(在直读世界里该告警只涉及非 ext4 大分区);②分区递归中单分区产物为空 → 记录并继续,不再 `sys.exit(1)`(顶层单固件语义不变);③symlink 清单如上。
- **票 D(CVE 缓存)**:`FIRMWARE_AUDIT_CVE_CACHE_DIR`,默认共享库 `firmware_audit/.cve_cache`(现状)。
- 语义前提:直读路径不受三道闸门约束(不经 dd/Step1);闸门仅继续管辖非 ext4 的老路径。

## Testing Decisions

- **三接缝,优先已有缝**:
  1. `preprocess()`(Step0 公共入口,最高缝)——合成镜像喂入,断言直读触发/落点/标记/排除/非 ext4 不触发/后端切换。
  2. `should_extract()`(纯函数)——env 默认值与覆盖、非法值回落。
  3. 空分区跳过判定收敛为小决策点(单测)+ 一个可跳过的两分区集成测试(一空一正常,`--no-step5`)。
- **fixture 策略**:truncate + sfdisk + mke2fs + debugfs 纯用户态合成微型 GPT+ext4 镜像,秒级、零特权、不依赖真实固件;mount 后端用假 subprocess 断言命令拼装(真 mount 需 root,不进常规测试)。
- **先例**:test_step0.py / test_step0_split.py / test_docker_utils.py 的 fails-list + monkeypatch 风格;pytest 双模式(Docker 门控 SKIP)不引入新例外。

## Out of Scope

- RECROOTFS/erofs 等非 ext4 文件系统的解析支持(wontfix 留票;若其实为 ext4,由魔数触发自然救活)。
- 报告改进方向 E–I:Step4 max_elf 厂商优先级、cve_bin_tool 大目录分片与 rc=1 stderr 回传、run_docker 超时孤儿容器清理、semgrep 大树守卫、analysis 路径幻觉防护(留档 handoff.md,另开炉灶)。
- binwalk/dd 老路径的行为变更(仅按票 C 加告警与批次续跑)。
- Windows 宿主兼容(权威环境已定 Kali WSL;直读后端依赖 POSIX 能力)。

## Further Notes

- WSL 原生迁移是本规格的成立前提:debugfs 本机原生 1.47.4(不再依赖 Docker 卷 IO)、mount 一条命令(wsl.exe 传参坑消失)。选型权衡记录于 handoff.md「待 grill 的决策点」。
- 验收参照真实目标:`python -m firmware_audit.main target/3 --no-step5` 应让 APP 分区直读出完整文件树(约 30-60 分钟 mount / 1-2 小时 debugfs),不再静默跳过;RECROOTFS 空树不再杀整批。
- 当年手工旁路三脚本(wsl_extract_app.sh / extract_app_tar.py / app_pipeline_driver.py,已归档仓库根)是本规格的行为定义来源,代码化完成后可退役。

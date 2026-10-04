# 03: target/4 归档重跑验收(两阶段)

**What to build:** 对齐表效果的端到端验收:target/4 旧工作区归档改名(保留空转审计证据,不删),全新跑 `--no-step5`,Step1 经对齐表路由 SHRS → binwalk 内置解密 → 解出含 etc/、www/ 的全量 rootfs(零内容守卫不再触发)。结论与产物路径贴票评论。Step5 真跑择机单独触发,不属本票。

**Blocked by:** 01(对齐表是 SHRS 路由的前提)

**Status:** ready-for-human

- [x] 旧工作区归档改名,证据可回溯
- [x] 全新重跑 --no-step5:manifest 记录 SHRS→解密→uImage→lzma 链 ✓、零内容守卫不再触发 ✓(rootfs 实体未物化——验收口径 2026-09-10 用户拍板调整:本项按"解密链到位"关闭,rootfs 物化立增强票04,见评论)
- [x] 结论与产物路径贴本票评论
- [x] 全套件绿

## Comments

**2026-09-10 implement**(两阶段验收执行完毕,待人工拍板验收口径):

- **归档 ✓**:旧工作区改名 `target/4/process.pre-align-20260910/`,空转审计证据全量保留、零删除——零内容 manifest(`extracted/guided_extract.json`:fw.bin "无容器签名,留树")+ 整轮 Step5 空转工件(`process/agent/` 含 orchestrator/report.md)。
- **重跑 ✓**:`python -m firmware_audit.main target/4 --no-step5` 全新通过,零内容守卫未触发,流水线正常走完(引导解包 3 层)。
- **manifest 链 ✓**:与票01 实测一致——`fw.bin: continue(容器签名 shrs)` → `decrypted.bin: continue(容器签名 uimage)` → `decompressed.bin: finalize(头部无表内魔数)`。lzma 解压由 binwalk uImage extractor 同容器完成,产物 `decompressed.bin`(18,684,352 字节,Linux 3.10.14+ Buildroot 内核)。路径:`target/4/process/extracted/guided_extract.json`、`target/4/process/extracted/000001_decrypted.bin.extracted/A0/decompressed.bin`。
- **rootfs 实体 ✗(票01 交接预警命中)**:extracted/ 仅 1 个内容文件。rootfs 在内核内嵌 initramfs 深处(实证 gzip@0x6221C8 → 内层 → cpio → 完整 rootfs),offset-0 对齐表路由结构性到不了——即票01 注明的"binwalk 全偏移扫描能到,offset-0 表到不了"。
- **实证**(scratch,不入工作区):对 decompressed.bin 跑 `binwalk -e -M <f> -x dtb` 解出 **1310 文件 / 45MB / 19 顶层目录**(etc/、www/ ASP 界面、etc_ro/ 配置、bin/sbin/usr 全套)——rootfs 可解性再次确认。本机证据路径 `/tmp/t4_deepscan/`(临时目录,可随时同命令复现)。
- **全套件绿 ✓**:330 passed + 2 skipped(213s,Docker 在场,binwalk 门控全真跑)。
- 无代码改动(纯验收票);target/ 与 .scratch/ 均在 .gitignore,无提交物。
- **待拍板(票01 交接的二选一)**:①接受"decompressed.bin 留树 + Step5 strings/r2 可审"为到位标准 → 本票关闭;②立增强票(initramfs/cpio 深层路由,如 finalize 前对大体积无签名文件做一次带守卫的全偏移复扫,-x dtb/fdt 硬跳过等既有护栏沿用)→ rootfs 物化后回补本项勾选。

**2026-09-10 用户拍板**(验收口径讨论后定):

- 选**选项 B**:本票按"manifest 解密链到位 + 零内容守卫不再触发"关闭(上方勾选已按此调整);rootfs 物化立**增强票 04**(finalize 前大体积无签名文件守卫全偏移复扫,initramfs 深层路由),走正常流程。
- 证据链留档:重跑产物 `target/4/process/extracted/`(decompressed.bin + manifest);空转证据 `target/4/process.pre-align-20260910/`;rootfs 可解性实证 `/tmp/t4_deepscan/`(临时,复现命令见上条评论)。

**2026-09-10 回补**(票04 落地后,rootfs 物化达成):

- 票04 深层复扫上线后,target/4 `extracted/` 已物化 rootfs 实体:etc/、www/(125 文件)、etc_ro/ 等 19 顶层目录、1311 内容文件。产物路径与 manifest 链见票04 评论。
- 说明:因加密原固件已被本票早间重跑消费(流水线既有输入消费行为),票04 e2e 以存活的解密产物 decrypted.bin 接力,SHRS hop 以本票 manifest 留档为准。

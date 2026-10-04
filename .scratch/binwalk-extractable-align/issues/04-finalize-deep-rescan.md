# 04: finalize 前大体积无签名文件守卫全偏移复扫(initramfs 深层路由)

**What to build:** 引导解包器的"无容器签名,留树"finalize 分支加一道守卫复扫:文件体积 ≥ 阈值(默认 1MB,env 可调)时,先对该文件做一次全偏移复扫(`binwalk -e -M -x dtb`,600s 超时),产物并入解包树,manifest 记录 `deep_rescan` 出处;复扫产物照常进下一层候选队列走正常决策(环被 MAX_DEPTH=6 自然 bounded)。**只对"无容器签名"这一种 finalize 触发**——ELF/PE/text、Python SDK 容器、max_depth 终局、全树守卫 finalize 均不触发(既有纪律零回退)。护栏全部沿用现成:-x dtb、单次产出上限(STEP1_MAX_FILES_PER_EXTRACTION,超限删增量产物、原文件永不丢)、全树上限、复扫每个文件只做一次(防同文件反复重扫)。动机与实证:票03——target/4 SHRS→解密→uImage→lzma 链到位后 extracted/ 只剩 18.6MB 内核镜像(头部全零,offset-0 对齐表结构性到不了),rootfs 在内核内嵌 initramfs 深处(gzip@0x6221C8→cpio);`binwalk -e -M -x dtb` 实测解出 19 顶层目录(etc/、www/、etc_ro/…)1310 文件/45MB。规则出处:spec(binwalk-extractable-align)Addendum 2026-09-10。

**Blocked by:** None (01/02/03 已落地,直接续)

**Status:** ready-for-human

- [x] 守卫复扫落地:无签名 finalize 且体积 ≥ 阈值 → 全偏移复扫产物入树 + manifest 记录;其余 finalize 原因不触发(fake rescanner 注入单测锁定边界)
- [x] env 开关与阈值:STEP1_DEEP_RESCAN_MIN_BYTES(默认 4MiB,双例校准调整,见评论)/ STEP1_DEEP_RESCAN=0 关闭;默认值安全(关掉即回现状)
- [x] target/4 端到端:extracted/ 物化 rootfs 实体(etc/、www/);票03 已回补评论
- [x] 回归:fdt 硬跳过/SDK 容器跳过/over_guard/既有 33 项格式路由不变;零内容守卫语义不变;全套件绿(343 passed + 2 skipped)

## Comments

**2026-09-10 立票背景**(票03 验收讨论,用户拍板选项 B):

- 票03 已实证 rootfs 可达而未达:内核镜像 finalize 是对齐表设计的已知边界,本票把它补上。注意与 spec 原 Out of Scope 的关系:触发条件("第二个未知魔数案例")成立,由 Addendum 正式转入范围。
- **开放点(triage 时拍板)**:①单发 `-M` vs "只扫不解、命中偏移回喂既有路由循环"——前者实现小但递归发生在容器内,绕过逐层 depth/总树守卫(仅事后计数/超限删);后者守卫完整但要实现 rescan 路由。倾向前者 + 事后护栏(over_guard 已可删增量),真爆一次再迭代。②阈值默认值(1MB 是拍脑袋,可用 target/1 与 target/4 双例校准)。③根目录语义提醒:复扫产物是普通文件,进 grep 树属预期(search_code 白名单并集已结构性排除 .cve_cache/agent)。

**2026-09-10 implement**(工单完成,双轴评审修复后提交 33e65a4,待人工验收):

- **实现落点**:`gates.py`(DEEP_RESCAN_MIN_BYTES + resolve_deep_rescan_min_bytes/_resolve_flag)、`file_magic.py`(FINALIZE_UNSIGNED_REASON 常量,防字面量散落断触发判断)、`step1_guided_extract.py`(_deep_rescan + extract_guided 钩子 + _already_extracted_sibling 防重复 + 入口清残留)、新 `test_step1_deep_rescan.py`(13 单测,fake rescanner 注入零 Docker)。
- **开放点拍板记录**:①单发 `-M` + 事后护栏(按票内倾向;单次/全树上限 + 600s 超时沿用);②阈值校准结论:**默认 4MiB**——target/1 树 ≥1MiB 无签名 32 个(mp3/模型,零复扫价值),≥4MiB 仅 3 个;target/4 内核 17MiB 全阈值命中。规格字面 1MB 属拍脑袋值,按票内委托以实测数据调整。
- **规格外收窄(记录备案)**:触发加 `d+1 < max_depth` 条件——最后一层复扫的产物无可决策的下一层,纯浪费;评审确认为合理偏离,在此显式记录。
- **e2e 输入注意**:加密原固件 DIR882A1_FW110B02.bin 已被 2026-09-10 早间重跑消费(流水线既有行为:容器改名进解包树,binwalk -e 成功提取后吃掉输入;票01 的 /tmp 副本同款)。官方源未能重新下载,本次以存活的 SHRS 解密产物 decrypted.bin(/tmp/shrs_test,13,265,600 字节)接力——SHRS→解密 hop 由票03 manifest 留档,本票验证 uImage→lzma→内核→**复扫**→rootfs 链。**原固件输入无保全机制**,建议另立小票(target/<N> 顶层输入副本保留)。
- **e2e 结果**:`target/4/process/extracted/` 物化 rootfs 实体——`000001_decompressed.bin.extracted/8AB758/decompressed.bin.extracted/0/` 下 bin/dev/etc/etc_ro/home/init/lib/media/mnt/private/proc/sbin/share/sys/tmp/usr/var/www 共 19 顶层目录(etc/fstab、etc_ro/inittab、www/ 125 个 Web 界面文件),全树 1311 内容文件/105MB。manifest 三条链:decrypted.bin continue(uimage)→ decompressed.bin finalize+deep_rescan=ok(1414 files)→ 内层 cpio finalize(跳过重解)。
- **e2e 中发现并修复**:复扫产物里的容器会被再次解包(同一份 rootfs 铺两遍,树 109MB 翻倍)→ 新增 `_already_extracted_sibling` 守卫(同名 .extracted 已非空即跳过,保留 7z 兜底机会)。
- **双轴 code-review(8 判断题 + 2 缺失 + 2 可疑,全部处置)**:最严重为 Spec 轴 c1——入口清残留会把成功复扫产物目录当崩溃残留误删(resume 静默丢 rootfs,旧测试假阴性掩盖)→ 修复:清理只删副本文件不删目录 + ok 态产物目录归位标准命名(去 _deeprescan_ 前缀)+ resume 测试补产物存活断言。其余:全树守卫豁免补测;bool 开关对齐"非法值告警一次"模块约定(_resolve_flag);gates docstring 漂移修正;int 包装冗余删除;rel 归一化三处/全树守卫两处重复提取 _rel_of/_bump_total;测试 env 复用 _EnvScope(补 _invalid_warned 去重集隔离)。
- **全套件**:343 passed + 2 skipped(Docker 在场全真跑)。

# 05: 简报脱 fileinfo——rglob 现场概览 + 工件索引按 .c 归组

**What to build:** recon/verify 简报的目录概览不再读 fileinfo.json,由简报构建器对解包树现场统计:顶层目录 × 文件数(套 profile 的 SDK 排除名单)+ 扩展名粗分布(无真类型分类,精细分型由 recon 用 list_files 现场做);fileinfo.json 缺失或存在都不影响简报完整性。recon 简报的"工件索引"改按 `.c` 存在性归组(原按 functions.json 归组)。本票在阶段删除(T06)之前落地,概览能力无缝切换。规则出处:ADR-0011、spec(User Story 22)。

**Blocked by:** None (can start immediately;与 04 改提示词不同段落,无逻辑依赖)

**Status:** ready-for-human

- [x] 无 fileinfo 的工作区(tmp_path)简报完整含现场概览;有 fileinfo 也不读不崩
- [x] 概览套 SDK 排除(usr/lib 等目录不进统计)
- [x] recon 工件索引按 .c 归组,无 functions.json 依赖
- [x] 简报构建测试 + 全套件绿

## Comments

**2026-09-09 implement**(工单完成,待人工验收):

- `build_filtered_overview` 重写为 rglob extracted 现场统计:顶层目录 × 文件数 + 扩展名粗分布(top 8);SDK 排除复用 `file_rules.is_search_excluded`,逐祖先目录前缀判定(与 list_files 递归走树时逐目录判定同口径);fileinfo.json 存在与否均不读写;extracted/ 缺失时一句回退提示。根目录散文件(.step1_done/guided_extract.json 等解包簿记)归"(根目录散文件)"桶,不冒充顶层目录。真工件实测:target/1 全树(30 万文件级 APP 分区同理)0.13~0.5s 出概览。
- `build_recon_brief` 工件索引改按 `.c` 存在性归组:rglob `*.c` 得组,逐组存在性检查附 imports/strings tag(functions.json 不再是归组键);文案明示"索引只列已反编译工件,未反编译文件直接看 extracted/ 原树";analysis/ 缺失不再是异常态("尚无反编译产物,深挖取证由下游 analysis 完成")。
- 死代码清理:`_OVERVIEW_TYPE_RANK`(type→优先级排序)随 type 分类概念一并删除。
- recon 简报**不**指引 r2/ghidra 工具(recon 无此授权,票01 纪律)。
- 测试:test_step5_parsing 的 `test_build_filtered_overview`(现场统计/SDK 剔除/扩展名分布/紧凑原则/垃圾 fileinfo 不崩)、`test_recon_brief_appends_overview`(.c 归组无 functions.json、现场概览追加、extracted 缺失回退)重写;真工件 target/1 手动验证简报完整。全套件 324 passed + 15 skipped。

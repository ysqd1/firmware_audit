# 03: 三道闸门与 CVE 缓存目录 env 化(默认值全部不变)

**What to build:** 审计者面对超大固件时,不用改代码就能用环境变量调三道规模闸门(分区大小上限、Step1 单次/总文件数上限),且默认行为与今天完全一致;CVE 缓存位置同样可指定(默认共享库位置,预热一次跨 target 复用)。对齐项目既有先例(`STEP5_*_MAX_ITERS`:缺失/非法值回落默认,模块常量不残留第二出处)。

**Blocked by:** None (can start immediately)

**Status:** ready-for-human

- [x] `STEP0_PARTITION_MAX_SIZE_GB`(默认 50)/ `STEP1_MAX_TOTAL_FILES`(默认 200000)/ `STEP1_MAX_FILES_PER_EXTRACTION`(默认 50000):env 覆盖生效、缺省回落默认、非法值回落默认并提示,各有一组单测
- [x] `FIRMWARE_AUDIT_CVE_CACHE_DIR`(默认共享库位置):Step5 CLI 工具的缓存挂载消费此 env,默认路径下行为与现状逐字节一致
- [x] 三个闸门常量不出现第二出处(env 解析集中在单一消费点);解析函数有单测
- [x] 全套件回归不劣化

## Comments

**2026-09-08 implement**(工单完成,待人工验收):

- 新模块 `firmware_audit/gates.py`:三道闸门默认值的唯一出处(50.0/50000/200000)+ 三个 resolver(缺失/空白静默回落;不可解析/非正数/nan/inf 回落并告警,同值去重防逐文件消费点刷屏)。`step0_preprocess`(删 `_PARTITION_MAX_SIZE_GB`)、`step0_split_img`(API 参数与 CLI `--max-size` 默认改 None→解析,消灭 50.0 重复出处)、`step1_guided_extract`(删两个模块常量,守卫与 manifest reason 消费点调 resolver)。
- **CVE 缓存默认值口径裁决**:票文"(默认共享库位置)"与"默认路径下行为与现状逐字节一致"互相矛盾;按后者 + handoff"默认保持现行为"+ 已提交 README/.env.example 口径,定案**缺省 = `target/<N>/process/.cve_cache`(逐字节不变),env `FIRMWARE_AUDIT_CVE_CACHE_DIR` 显式指到共享目录**(如 `firmware_audit/.cve_cache`)才跨 target 复用。spec.md 票 D 括注"(现状)"指 junction 旁路时代的既成事实,不是代码默认。
- 评审修复:`float("nan")`/`inf` 原实现可穿过校验(nan 比较恒 False → 闸门静默失效),已加 `math.isfinite` 拦截 + 测试用例。
- 测试:`test_gates.py` 5 组(env 覆盖/缺省/非法+提示/空白/告警去重);消费点接线 step0 2 项(`extract_partitions_from_image` + preprocess 闸门收紧/放宽)+ step1 2 项(`_binwalk_extract_one` over_guard / `extract_guided` 全树守卫,fake run_docker/ManyExtractor);CVE 挂载 `test_cve_cache_dir_env`(缺省挂载源逐字节一致/env 覆盖/空白回落,不依赖 Docker)。全套件 300 passed + 2 skipped;2 个失败为 target/1 工件缺失的既有环境失败(stash 基线复核一致,工单 01 已记录)。
- README 增"规模闸门(shell 环境变量)"小节(注明 main.py 不读 .env,须 shell export)。

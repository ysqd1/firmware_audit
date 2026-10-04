# 06: Step2/3/4 退役——删除 + main.py 缩链 + 启动门 + 旁路删除

**What to build:** 确定性预处理漏斗收缩(expand 已完成的 contract):三个阶段目录的代码与四个对应测试文件整体删除;APP 旁路驱动删除;main.py 缩为 Step0→1→5(--max-elf/--max-workers 开关退役;--profile 去留按共享规则模块的实际依赖在本票内定并留评论);step5 启动门从"analysis/ 存在"改为"extracted/ 存在"(旧文案"先跑 Step1-4"同步);共享规则模块里 TRUST/STD/DOWNGRADE 死代码与 profile 死段清理(SEARCH_EXCLUDE 段保留,Step5 工具仍消费)。规则出处:ADR-0011、spec(Implementation Decisions"Step2-4 退役")。

**Blocked by:** 01、02、03、04、05(expand 全落地才收缩——删除后边车唯一来源是新工具,简报/纪律必须已脱钩旧产物)

**Status:** ready-for-human

- [x] 三阶段代码/对应测试/旁路驱动删除,全仓 grep 无残留 import 与引用
- [x] main.py 缩链 + CLI 开关变化;启动门新语义单测(仅 extracted/ 的工作区放行,文案更新)
- [x] 死代码与 profile 死段清理完成,去留小决策记录在票评论
- [x] 老 target/1 直接跑 step5 不受影响(旧边车当缓存)
- [x] 全套件绿

## Comments

**2026-09-09 implement**(工单完成,待人工验收):

- 删除:`firmware_audit/step2|step3|step4/` 全部代码、`test_step2/3/4/test_step4_triage.py`、`app_pipeline_driver.py`(仓库根)、`models.py`(FileInfo/fileinfo.json 退役)。全仓 grep `step2_filter/step3_classify/step4_decompile/FileInfo/save_fileinfos/triage_opaque` 零残留(余下命中均为退役守护断言与注释)。
- **main.py 缩链 Step0→1→5**:`--max-elf`/`--max-workers` 退役;`--profile` **保留**——`run_pipeline` 入口处调 `file_rules.configure(profile)`,Step5 工具层(list_files/search_code/semgrep/简报概览)消费其 SEARCH_EXCLUDE 段,"换机型只改 profile"经此存活(User Story 23),其余段落已无消费者。Step2 空过滤语义消亡 → `empty_filter_action`/`is_partition`/批次"跳过分区汇总"一并删除(每个解出的树都直接进 Step5,树内容不再决定批次命运);解包树认证补标记逻辑保留。
- **启动门**(run_step5):`analysis/ 或 agent/ 存在` → **`extracted/ 存在`**,文案改"先跑 Step1 解包"。新语义单测 `test_startup_gate_requires_extracted`:仅 extracted/ 的工作区过门(死在无 key 而非门)、无 extracted/ 拒绝且文案指向 Step1。
- **file_rules 收缩**:只留 SEARCH_EXCLUDE_DIRS/is_search_excluded/get_search_exclude_dirs/configure;TRUST/STD/DOWNGRADE 名单与判断函数删除。**去留小决策**:①`logical_path`(binwalk 嵌套前缀剥离)一并删除——唯一消费者是 Step2-4,Step5 工具直用原始 rel 判定;将来审 MCU blob 从 git 历史捞回(与 ADR-0011 签名知识同轨)。②profile yaml 物理重写只留 SEARCH_EXCLUDE 段(9 条),头注说明新角色。
- 老 target/1 兼容实测:`step5_run(target/1)`(注入无 key LLM)过启动门、死于无 key——旧 analysis/ 边车在门与新工具眼中等价于缓存;conftest 探针不受影响。
- Step0 测试改造:test_step0_batch 删 `test_empty_filter_action`/顶层空过滤终止测试(语义消亡),双分区 e2e 改断言"两分区各自完成解包、退出码 0、无 fileinfo.json",新增分区子工作区直跑 run_pipeline 用例;test_step0_ext4 端到端断言改"解包树就位+无 fileinfo";test_file_rules 重写为存活面(过滤命中/副本语义/坏 profile 保持)。全套件 301 passed + 15 skipped(净删 4 个测试文件,用例数 324→301)。

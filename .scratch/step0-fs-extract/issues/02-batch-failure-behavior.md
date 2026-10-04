# 02: 分区批次失败行为修复(跳过必告警 / 空分区不杀整批)

**What to build:** 审计者处理多分区磁盘镜像时,不再被两个失败姿势坑:①任何分区因规模闸门被跳过时,日志出现醒目告警(分区名/大小/触发上限),主 rootfs 不会再无声消失;②某个分区解出空树(如当年的 RECROOTFS)时,该分区被记录为跳过、其余分区继续处理,整批不再因 `sys.exit(1)` 中途夭折(顶层单固件"过滤后为空即终止"的语义保持不变)。

**Blocked by:** 01(复用其合成镜像 fixture;直读改变了"哪些分区会受闸门管辖"的语义,告警逻辑需在其落定后设计)

**Status:** ready-for-human

- [x] 非直读路径上,分区超限被跳过时输出含分区名/大小/上限的告警行(直读世界的 ext4 分区不受闸门约束,天然不触发此告警)
- [x] 分区递归中单分区 Step2 过滤为 0 文件:记录(分区名+原因)并继续其余分区;批次结束时汇总哪些分区被跳过;顶层(非分区)固件过滤为空仍终止
- [x] 空分区跳过判定为小决策点,有秒级单测
- [x] 两分区合成镜像(一空一正常)集成测试:`--no-step5` 下正常分区完成、空分区被记录、整体退出码 0
- [x] 全套件回归不劣化

## Comments

**2026-09-08 implement**(工单完成,待人工验收):

- 告警:`step0_preprocess.partition_skip_message(p, max_size_gb)` 纯函数构造消息 + `_extract_partitions` 闸门跳过处打印。rootfs/recovery 超限 → 醒目"告警"行(分区名/大小/上限/env 指引 STEP0_PARTITION_MAX_SIZE_GB);userdata/large 是策略性跳过 → 普通提示行(不谎称超限,附 --extract-all 单独提取出路)。ext4 分区先判魔数直读,天然不触发(测试断言覆盖消息口径)。
- 批次续跑:`main.empty_filter_action(is_partition)` 小决策点(分区批次内 → ("skip", 原因);顶层 → ("terminate", 原文案"Step2 过滤后无文件"口径不变)。`run_pipeline` 新增 `is_partition=False` 参数,分区递归调用传 True;Step2 过滤为空时分区模式打印记录行(分区名+原因)后返回 `[]`,不再 `sys.exit(1)`。批次循环对返回空的分区收集进 `skipped_parts`,批次末打"批次汇总: 跳过 N/M 个分区(Step2 过滤后为空): …"清单。空分区返回 `[]` 在标记回填之前,不会给空树补写 .step1_done。
- 集成测试 fixture:双 ext4 分区合成镜像(APP=etc/passwd+home/unitree 正常内容;RECROOTFS=只含 usr/share/doc/junk → 直读成功但 Step2 过滤为 0,即"空分区")——ext4 直读不经 Docker,断言确定。工单 01 测试里"端到端必须 with_kernel=False"的注释约束在 Docker 可用的环境下自此解除(裸数据分区走 Step2 空过滤→跳过,不再杀整批;无 Docker 时裸数据分区在 Step1 解包失败处终止,系既有路径、票外);其测试未动照绿。
- 测试 `test_step0_batch.py` 5 项双模式全绿(决策点秒级纯函数/告警消息/env 压低闸门集成/双分区 e2e 退出码 0/顶层 zip 过滤为空仍 SystemExit(1));全套件 305 passed + 2 skipped,仅 2 个先于本工单的环境失败(test_step5_tools 依赖 target/1 的 fileinfo.json 缺失,stash 已证与本改动无关)。

**2026-09-08 code-review 采纳修复**(两轴评审,标准轴/规格轴各一子代理):

- `GATED_KINDS = ("rootfs", "recovery")` 常量落 `step0_split_img`(与 SKIP_AUDIT_KINDS 并列),`should_extract` 闸门判定与 `partition_skip_message` 告警口径共用——消除两处重复编码的类型清单漂移风险。
- 批次汇总文案改通用口径"(未产出可审计文件)"(原"(Step2 过滤后为空)"对嵌套磁盘镜像整批跳过等其它空返回会错标成因;各分区成因在跳过当场已按分区名记录)。
- `partition_skip_message` docstring 收紧:删"零静默"全称断言,改为"凡是走到闸门判定的分区,跳过必留日志"(dtb/reserved 类型筛在更早分支、带清理打印,不经本消息)。
- 评审质疑"工单标题'解出空树'比验收项'Step2 过滤为空'宽,Step1 verify 空树仍杀整批"——核实不成立:引导解包器恒写 manifest,`verify` 对分区实际不可能空;binwalk 兜底的空产出在 `extract()` 内部即返回 None、死在"Step1 解包失败,终止"(与 binwalk 硬失败 rc≠0 混在同一返回值,属系统性失败,整批终止合理)。当年 RECROOTFS 事故路径即 Step2 过滤为空,验收项口径即工单本意,维持范围。
- 未采纳(判断类,记档):决策点 (action, reason) 字符串对 vs bool——现形式保住了顶层原终止文案逐字不变,不换;测试 env 保存/恢复 try/finally 与工单 01 测试逐字同形——同约定复制,第 4 处出现再抽 contextmanager。


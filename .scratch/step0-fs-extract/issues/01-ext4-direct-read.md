# 01: Step0 ext4 分区直读(debugfs 默认 / mount 快路)

**What to build:** 审计者跑 `main <target>` 处理磁盘镜像时,识别为 ext4 的分区(0xEF53 魔数,不看大小)被 Step0 直接读取文件树,落在该分区子工作区的 `extracted/` 并写 Step1 完成标记,下游 Step2-5 零改动照常执行——当年 ZCode 手工旁路(loop-mount + tar + tarfile + 手写标记 + 外部驱动)做的事,从此是流水线原生行为。默认后端 debugfs(用户态、零特权、无 Docker 依赖);`STEP0_EXT4_BACKEND=mount` 切快路(ro 挂载 + 拷贝,需 sudo,无免密时响亮报错)。lost+found 固化排除;符号链接原样保留并落 links.jsonl(rel→target)清单。

**Blocked by:** None (can start immediately)

**Status:** ready-for-human

- [x] 合成 GPT+ext4 镜像(零特权 fixture:truncate+sfdisk+mke2fs+debugfs)喂入 `preprocess()`:ext4 分区直读出文件树 + 完成标记,非 ext4 分区不触发直读
- [x] 默认后端 debugfs 真跑(合成镜像小,秒级);`STEP0_EXT4_BACKEND=mount` 与缺省的命令拼装有假 subprocess 断言;mount 无免密 sudo 时报错信息明确(不挂死不静默);本机无 debugfs 时明确报错并按告警跳过该分区、批次继续
- [x] lost+found 不出现在产物树;符号链接(含 usrmerge 形态)在产物树中保留;links.jsonl 清单生成且可解析
- [x] 直读产物落点与现有分区递归同构:`main <target> --no-step5` 对"单 ext4 分区合成镜像"端到端跑通 Step2-3(允许慢路径标记跳过)
- [x] 触发判定有单测(魔数命中/不命中);全套件回归不劣化

## Comments

**2026-09-07 implement**(工单完成,待人工验收):

- 新模块 `firmware_audit/step0/step0_ext4_read.py`:魔数触发(复用 `step1/file_magic.sniff_magic` 的 0x438 检测)、`resolve_backend()`(env 非法回落 debugfs + 告警)、debugfs 后端(`rdump /`,复用 dd 提取+回读校验,成功后删中间文件)、mount 后端(`sudo -n mount -o ro,noload,loop,offset=N` + `sudo tar | tar` 管道,finally 必 umount)、共同收尾 `_finalize_tree`(树非空校验 → lost+found 固化排除 → links.jsonl → `.step1_done` 最后写=完成即含清单)。
- `step0_preprocess._extract_partitions`:dtb/reserved 类型筛选对直读同样生效;ext4 命中即直读(绕过 50GB 大小闸门,userdata 亦直读——魔数是唯一触发条件);逐分区 try 隔离异常;返回三态(条目 list / [] 无分区表回退 binwalk / **None**=有分区表但直读全失败,绝不回退整盘 binwalk——评审修的爆炸路径)。
- `main.py`:分区递归条件加 `any(is_dir)`(单 ext4 分区镜像也走递归);目录条目直接复用工作区;空输入守卫响亮终止;空分区 sys.exit 杀整批问题属票 02,未动。
- 测试 `test_step0_ext4.py` 11 项双模式全绿:fixture 纯用户态(mke2fs -d 填充 + 复用 test_step0_split 的纯 Python GPT 布局,夹具含 usrmerge 链接/悬空链接/mke2fs 自动 lost+found);debugfs 真跑 + 命令拼装假 subprocess(mount 与缺省后端都有);全套件 289 passed(仅 2 个先于本工单的环境失败:target/1/process/fileinfo.json 缺失,stash 已证与本改动无关)。
- 实测边界(写进模块 docstring):非 root rdump 的 chown 告警不致命 rc=0;设备节点缺失只丢单个条目不炸整树;e2fsprogs 在 write 阶段即净化穿越文件名(`../x` 落盘成 `x`),rdump 不外逃;debugfs 路径含空白响亮拒绝。
- 行为扩量说明:userdata 分区若为 ext4 现在会被直读(旧路径一律跳过)——按"魔数是唯一触发条件"的字面语义实现;若不想审 userdata,后续可在 SKIP_AUDIT_KINDS 加一行。

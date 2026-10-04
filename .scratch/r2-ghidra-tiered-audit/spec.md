# Spec: r2 两级二进制分析 + Ghidra 升级调用 + Step2-4 退役

Status: ready-for-agent
日期:2026-09-09
规则出处:ADR-0010(r2 两级分析 + Ghidra 升级调用)、ADR-0011(Step2/3/4 删除)——两篇 ADR 是本 spec 的**单一规则出处**,冲突时以 ADR 为准。术语口径见 CONTEXT.md(已同步)。

## Problem Statement

维护者跑一次固件审计,流水线要先批量过滤、批量分类、把**所有** ELF 无差别过一遍 Ghidra 反编译,然后 Agent 才开工。实测证明这套批量前置大部分是白烧:target/1 的 43 组反编译边车绝大多数没被任何 Agent 读过;target/3 APP 分区 30.6 万文件全程零反编译产物,Step5 照样跑完。同时 Agent 手里的二进制分析能力反而贫瘠——没反编译过的 ELF 没有函数清单、反汇编、导入、字符串可查,想深挖只能先付分钟级 Ghidra;radare2 明明在沙箱镜像里却只有一个交叉引用入口。每改一层能力都要动确定性流水线,识别与处理被焊死在批处理里。

## Solution

把流水线翻转为 Agent 优先:Step2-4 整层退役(main.py 缩为 Step0→1→5),Agent 直接面向解包树工作。r2 成为第一层廉价信息源(函数清单/反汇编/交叉引用/导入/字符串,秒级、不落盘、不反编译),LLM 判断 r2 信息不够时才升级调用 `ghidra_decompile`(分钟级、按需、幂等缓存、内容去重)。升级纪律写进提示词与缺件报错文案;verification 的"文件不存在即误报"红线按升级链改写,防止把"没人反编译过"误判成"证据不存在"。

## User Stories

1. As analysis Agent, 我要对任意 ELF 查函数清单而不必先反编译(r2_list_functions),so that 廉价信息先行、分钟级容器只为真正需要的文件买单。
2. As analysis Agent, 我要按函数名或地址读单个函数的反汇编(r2_disassemble_function),so that 不反编译也能读懂关键代码。
3. As analysis Agent, 当反汇编目标函数不存在时要收到该文件的函数名提示,so that 不烧迭代轮次也能自我纠正。
4. As analysis Agent, 交叉引用工具与 r2 同族命名(r2_xref_query),so that "现算"与"读缓存"(find_decompiled_function)在工具名层面不会混淆。
5. As analysis Agent, strings_query 缺边车时自动对原始二进制跑 r2 字符串提取,so that 未反编译 ELF 的硬编码 URL/IP/口令审计不需要先付 Ghidra。
6. As analysis Agent, strings_query 支持 pattern 参数在查询时按正则过滤(URL/IP/密钥/口令模式集),so that 硬编码检出从批量预扫变为按需查询。
7. As analysis Agent, imports_query 缺边车时自动回退 r2 导入表并套危险函数分级表,so that 导入风险审计覆盖所有 ELF。
8. As analysis Agent, 字符串兜底对非 ELF 文件(不透明 blob)同样生效,so that 固件 blob 里藏的字符串线索可查。
9. As verification Agent, 我拥有与 analysis 相同的 r2 工具族与 ghidra_decompile,so that 复核时能独立取证而不是被迫相信 analysis 的结论。
10. As recon Agent, 我**不**拥有 r2 工具族与 ghidra_decompile,so that 广度铺面角色不滑向深挖、预算不被分钟级调用吃光。
11. As analysis Agent, 我调用 ghidra_decompile 时若边车已存在且版本匹配,要立即返回"已反编译"而不调容器,so that 断点续跑与复核不重复付费。
12. As verification Agent, analysis 阶段反编译过的文件对我自动是缓存,so that 每疑点一实例(8 轮预算)里复核不被反编译耗时挤爆。
13. As 离线复跑者, 升级后的代码要把我工作区里既有的 analysis/ 边车当合法缓存(extractinfo_version 不涨),so that 老 target 升级后无需全量重跑。
14. As 审计工程师, 同一个 .so 出现在两个路径时只反编译一次(sha256 去重 + 边车硬链接物化),so that 不为重复内容浪费分钟级容器。
15. As 审计工程师, ghidra_decompile 的 Observation 只回指针与函数数、不回反编译 C 全文,so that Agent 上下文不被几百 KB 代码撑爆。
16. As 审计工程师, 对非 ELF 调用 ghidra_decompile 要得到即时引导性报错而不是 900 秒容器空转,so that Agent 快速换路。
17. As 审计工程师, Step5 里写审计工件的工具只剩 ghidra_decompile 一个,so that 工具副作用面可预期、工作区状态可推理。
18. As verification Agent, 发现缺 `.c` 时要走"r2 查证 → 不够 → 反编译 → 仍无才判 false_positive"的升级链,so that "没人反编译过"不再被误判为"证据不存在"。
19. As 审计工程师, 升级规则同时写进 analysis/verification 系统提示词与所有缺件报错文案,so that 纪律不依赖 LLM 自觉。
20. As 维护者, main.py 流水线缩为 Step0→1→5,Step2/3/4 的代码与测试整体退役,so that 每次能力调整不再牵动三个批处理阶段。
21. As 维护者, step5 启动门从"analysis/ 存在"改为"extracted/ 存在",so that 只有解包产物的工作区也能直接进 Agent 审计。
22. As recon Agent, 简报里的目录概览由简报构建器对解包树现场统计(顶层目录×文件数,套 SDK 排除,扩展名粗分布),so that 没有 fileinfo.json 也有工作区地图。
23. As 维护者, 机型 profile 文件保留(Step5 工具仍消费其 SDK 排除段),so that 换机型不改代码的既有能力不回退。
24. As 维护者, APP 旁路驱动随 Step2/3 一并退役,so that 只剩一条代码路径。
25. As 审计工程师, 不透明文件靠无过滤的 list_files + strings_query r2 兜底 + binwalk_rescan 保证可见与可查,so that "绝不静默消失"由结构性手段而非分类元数据保证。
26. As 维护者, 被删除的能力(文本预扫/证书解析/不透明分诊/fileinfo 等)在 ADR-0011 有逐项裁定记录,so that 将来做 MCU blob 审计时能从 git 历史捞回签名知识并接上处理路径。
27. As AFK 实现者, 有伪造容器产物的假 run_docker 测试基建,so that 缓存/去重/版本失效逻辑全程离线可测。
28. As 审计工程师, 有 Docker 门控的真 Ghidra 冒烟测试(小 ELF 反编译 + 二次调用缓存命中),so that 端到端行为有验收锚点且无 Docker 环境不红。

## Implementation Decisions

**两级模型与授权**(ADR-0010):

- 授权矩阵:r2 工具族与 ghidra_decompile 授 analysis + verification;recon 保持六工具广度集不扩。编排层、verify_phase 每疑点一实例、调度守卫全部不动。
- 新工具 `r2_list_functions(file_ref)`:r2 aflj,timeout 600(每调用全新容器进程,大库 `aaa` 分钟级成本计入超时;无会话复用);未命中/超时文案引导降级单函数 `af` 便宜路径。
- 新工具 `r2_disassemble_function(file_ref, func_or_addr)`:r2 pdf;未命中附该文件前 N 个函数名提示(与 find_decompiled_function 未命中提示同款先例)。
- 改名 `xref_query` → `r2_xref_query`,行为不变。
- 改造 `strings_query` / `imports_query`:边车优先,缺边车就地对原始二进制跑 izz / ii(经沙箱容器,extracted 只读挂载、断网);不再报"未找到"。strings_query 增 `pattern` 参数(查询时以 _TEXT_PATTERNS 过滤)。兜底不限 ELF(izz 对任意 extracted 文件有效)。
- 命名纪律:引擎前缀区分现算(r2_*)与读缓存(find_decompiled_function)。

**ghidra_decompile**(ADR-0010):

- 单工具、ELF-only、唯一 Ghidra 入口。幂等缓存:目标边车 `.c` 存在且头部 `extractinfo_version` 匹配即跳过容器直接返回;有效性按 `.c` 头部 `decompile_success` + 版本字段判。
- 边车三件套 `.c` + `.strings.json` + `.imports.json` 一次容器调用全产;functions.json/meta.json 不拷贝(无工具消费者);反编译脚本本身零改动、版本号不涨。
- 内容去重:调用时算目标 ELF sha256,查工具自有的 analysis 下 dedup 索引;命中把已有边车硬链接到新路径(os.link 失败降级拷贝),Observation 注明复用来源。不做 symlink/inode 短路(实测两棵解包树零链接)。
- Observation 轻量:指针 + 函数数,不回 C 内容。
- 容器现制沿用原 Step4:ghidra 镜像、单文件分析超时 300、容器整体超时 900、宿主 uid:gid、一次性临时工程。
- 落盘边界:Step5 唯一写审计工件的工具(cve_bin_tool 的缓存卷与引擎留痕除外)。

**升级纪律**(ADR-0010):

- analysis/verification 系统提示词写入"先 r2,信息不够才 ghidra_decompile"。
- strings_query/imports_query/find_decompiled_function 的缺件报错文案全部翻转为工具引导(原"不触发重分析"废除)。
- verification 红线改写:缺 `.c` → r2 层查证 → 信息不够 → ghidra_decompile → 仍缺失/超时零产出 → 才判 false_positive。

**Step2-4 退役**(ADR-0011):

- 三个阶段目录的代码与测试全删;main.py 流水线缩为 Step0→1→5;`--max-elf`/`--max-workers` 开关退役,`--profile` 去留以 file_rules 的实际依赖定。
- profile 文件保留(Step5 工具消费其 SEARCH_EXCLUDE_DIRS 段);其余段落与共享规则模块里的死代码在退役工单清理。
- APP 旁路驱动删除;step5 启动门改"extracted/ 存在"。
- FileInfo 模型与 fileinfo.json 退役;recon/verify 简报概览改由简报构建器 rglob 解包树现场统计(套 SEARCH_EXCLUDE;无真类型分类,扩展名粗分布)。
- 能力消失八项(文本预扫/ELF 硬编码预扫/证书解析/不透明分诊/内容去重/is_system_trust/fileinfo 概览/audit_status)的裁定与理由见 ADR-0011 清单,实现时不再逐项重议。
- conftest 的真实工件探针(某个 `.c` 的存在性)不受影响:旧 analysis/ 是合法缓存。

## Testing Decisions

好测试只测外部行为:给定工具入参与工作区状态,断言 ToolResult 的 ok/text/data 与落盘产物,不断言内部调用细节(除 run_docker 的命令行/超时这类"接口边界"本身)。

接缝(已与用户确认,全部复用现有 seam,零新缝):

1. **工具 execute 层**(主战场):monkeypatch run_docker 捕获命令行/超时/挂载断言(test_docker_utils、test_step5_cli_tools 先例);读盘与缓存逻辑用 tmp_path 构造假工件(test_step4 先例)。新增一块测试基建:能伪造容器产物的假 run_docker(往输出目录写边车三件套+版本头),ghidra_decompile 的缓存命中、sha256 去重硬链接、版本失效重跑、非 ELF 拒绝全部在此层离线测。
2. **权限矩阵 + 注册表**:扩展现有权限矩阵测试——r2 族与 ghidra_decompile 仅授 analysis/verification,recon 不授;make_tools 排除机制对新工具生效。
3. **提示词/文案层**(最高缝):升级链纪律落为内容断言——系统提示词含升级规则、缺件文案含工具引导、verify 简报边车指针后缀表缩为三件套(test_orchestrator 的 brief 断言先例)。
4. **启动门/流水线**:仅含 extracted/ 的工作区过门、main.py 缩链后的接线,小单测。
5. **Docker 门控真跑冒烟**:真 ghidra 镜像反编译 target/1 一个小 ELF,断言三件套完整 + 第二次调用缓存命中;无 Docker 自动 skip(cli_tools Docker 门控先例)。

删除项:test_step2/test_step3/test_step4/test_step4_triage 随阶段退役。

## Out of Scope

- file_triage 工具与 decompile 原始二进制模式(MCU blob 审计)——将来单独立票,届时签名知识从 git 历史捞回。
- r2 常驻会话/容器复用(每调用新容器是既有 CLI 工具模型,不破)。
- 反编译调用预算闸门(env 上限)——先实测 target/1 再定。
- 编排层(orchestration/)、verify_phase 每疑点一实例、ADR-0008 工具路径口径——一律不动。
- AGENTS.md / requirements.md / rules.md 的全文重写——本 spec 落地后它们的相关章节标记为过时、以 ADR 为准;CONTEXT.md 已同步,退役词条的物理清理待实现完成后的收尾工单。
- 解包层对符号链接/硬链接的保真(实测为零,不做)。

## Further Notes

- 关键实测锚点:target/1 共 43 组旧边车(缓存,零成本复用)、APP 分区零反编译产物跑通全程、两棵解包树符号链接与硬链接均为 0、triage 产物在 step4 之外零消费者。
- 参考项目 firmhive-main 的三个教训已吸收:r2 命令透传被否(违反结构化参数契约 ADR-0004);r2 超时要给宽(600s 对齐);错误文案即教学(支撑升级链文案设计)。
- 老工作区天然兼容:升级代码后对已有 target 直接跑,旧边车即缓存;不需要任何迁移脚本。

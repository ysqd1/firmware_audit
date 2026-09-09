# 0010-Step5 r2 两级二进制分析 + Ghidra 升级调用

日期:2026-09-09(grill-with-docs 会话与用户逐条对齐定稿;**代码未落地**,实现走 to-spec → to-tickets,本 ADR 是规则单一出处)

## 问题

反编译是 Step4 批量前置:所有 ELF 无差别过 Ghidra 容器(`--max-workers` 并行),Step5 的工具只读边车——`find_decompiled_function` 的 docstring 明确"不重新调 Ghidra";r2 在 Step5 仅有一个入口(`xref_query` 的 axtj)。三个问题:

1. **批量产物大多无人消费**:target/1 的 43 组 Ghidra 边车绝大多数没被任何 agent 读过;target/3 APP 分区(30.6 万文件)全程零 `.c` 也跑通了 Step5 全流程——批量反编译的成本前置了,价值没前置。
2. **agent 的二进制分析能力贫瘠**:未反编译的 ELF 没有函数清单/反汇编/导入/字符串可查,想深挖只能先付分钟级 Ghidra;r2 明明在 sandbox 镜像里却几乎没被用上。
3. **识别与处理耦合在流水线里**:改一层要动 Step4,agent 无法按需取舍。

用户需求(2026-09-09):r2 成为第一层廉价信息源;LLM 判断 r2 信息不够时才选择性升级调用 Ghidra 反编译;Step2-4 删除(见 ADR-0011)。

## 决策

**两级分析漏斗:r2 廉价层先行(秒级、不落盘、不反编译),LLM 判断信息不够才升级调用 ghidra_decompile(分钟级、落盘边车、幂等缓存)。**

### r2 工具族(授权 analysis + verification;recon 保持广度角色,不授)

- 新 `r2_list_functions(file_ref)` —— aflj。timeout 600:每次调用都是全新容器进程(无 firmhive 式常驻 r2pipe session),aflj 需先分析,大库上 `aaa` 分钟级,成本预算进超时;未命中/超时的错误文案引导降级到单函数 `af` 便宜路径。
- 新 `r2_disassemble_function(file_ref, func_or_addr)` —— pdf;未命中附该文件前 N 个函数名提示(照 `find_decompiled_function` 对 `.c` 的先例)。
- `xref_query` 改名 `r2_xref_query`(行为不变)。
- `strings_query` / `imports_query` 改**边车优先 + r2 兜底**:缺边车不再报"未找到",就地对原始二进制跑 izz / ii;strings_query 加 `pattern` 参数(`_TEXT_PATTERNS` 查询时过滤,取代 Step4 预产 `.text.json`);兜底**不限 ELF**——izz 对任意 extracted 文件有效,不透明 blob 的字符串审计路径由此打通。
- 命名纪律:引擎前缀区分"现算"(`r2_*`)与"读缓存"(`find_decompiled_function`),防 LLM 混淆(用户定稿)。

### ghidra_decompile(file_ref):唯一 Ghidra 入口,ELF-only,授权 analysis + verification

- **幂等缓存**:`analysis/<rel>.c` 存在且 `.c` 头部 `extractinfo_version` 匹配 → 直接返回已反编译。老工件(target/1 的 43 组)零成本复用,天然续传。
- **边车三件套**:`.c` + `.strings.json` + `.imports.json`,一次容器调用全产。functions.json / meta.json **无工具消费者,不拷贝**(ExtractInfo.py 一行不改,`extractinfo_version` 保持 2);反编译有效性校验按 `.c` 头部 `decompile_success` + 版本字段(本来就在)。
- **Observation 轻量**:只回指针 + 函数数,不回 `.c` 内容;读代码走 find_decompiled_function。
- **内容去重**:调用时算目标 ELF 的 sha256,查 `analysis/dedup.json` 索引(sha256 → 首个反编译路径);命中把已有边车**硬链接**到新路径(`os.link` 失败降级拷贝),下游指针逻辑零改动,Observation 注明"内容与 X 相同(sha256 比对),已复用其边车"。不做 symlink/inode 短路:实测 target/1 与 target/3 APP 两棵解包树符号链接 0、硬链接 0(解包环节物化成拷贝),真重复只有同字节拷贝,哈希单层足够。
- 容器现制沿用 Step4:ghidra 镜像、`-analysisTimeoutPerFile 300`、docker `timeout=900`、宿主 uid:gid、`-deleteProject -overwrite`。semgrep 已有 900 秒级同步调用先例,ReAct 循环无需改。

### 升级纪律(提示词 + 文案双落地)

- 提示词写入"先 r2,信息不够才 ghidra_decompile"。
- 缺件报错文案全部翻转为工具引导(原"不触发重分析"废除)。
- **verification 红线改写**:缺 `.c` → r2 层查证 → 信息不够 → ghidra_decompile → 反编译后仍缺失/超时零产出 → **才**判 false_positive。原"read_file 报文件不存在即 false_positive"废除——"没人反编译过"不再是"证据不存在"。

### 落盘边界

ghidra_decompile 是 Step5 **唯一**写审计工件的工具(`cve_bin_tool_scan` 的 `.cve_cache` 缓存卷与引擎层留痕 transcript/obs 除外)。

## 被否的方案

- **r2 命令透传**(参考项目 firmhive-main 即此形态:raw 命令字符串 + 常驻 r2pipe session,`aaa` 一次):违反 ADR-0004 结构化参数契约,输出不可控;且我们的 CLI 工具每调用新容器,无 session 可复用。
- **r2ghidra 插件(`pdg`)替代独立 Ghidra 工具**:暂缓——要往 sandbox 装插件;边车缓存让 verification 免重付,semgrep 的 analysis/*.c 双扫依赖落盘 `.c`。
- **保留批量反编译预备步骤**(Step4 还魂):批量产物大多无人消费(APP 实证);删 Step4 后批量环节失去宿主。
- **反编译调用预算闸门**(env 上限):不设——r2 承担大头后升级调用应稀少,迭代上限已兜底;待 target/1 实测再定(与"预算充裕度待校准"开放问题同轨)。

## 代价与影响

- 工具注册表:新增 3(r2_list_functions / r2_disassemble_function / ghidra_decompile)、改名 1(xref_query → r2_xref_query)、兜底改造 2(strings_query / imports_query)。
- 权限矩阵测试、三份系统提示词、briefs 指针(verification 单实例简报的边车指针后缀表从五个缩到三个:`.c/.strings.json/.imports.json`)、工具文档同步。
- 老 target 工作区天然兼容(缓存语义);CONTEXT.md 词条已同步(升级调用 / ghidra_decompile / 读盘类工具 / CLI 类工具)。

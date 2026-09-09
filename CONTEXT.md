# 固件安全审计(Firmware Security Audit)

对嵌入式设备(当前为宇树 Unitree)固件做安全审计的流水线:预解压与解包(Step0-1),随后由三个 LLM Agent 按序侦查、取证、复核(Step5,按需调用 r2/Ghidra 工具),产出带证据链的审计报告。产物全部落在 `target/<N>/process/` 工作区下。

## 语言

### 流水线与工件

**固件 (firmware)**:
用户放入 `target/<N>/` 的待审文件(归档/单文件压缩/磁盘镜像三种形态),整条流水线的输入。识别由 `main.py._find_firmware` 按扩展名/大小完成。
_Avoid_: 镜像(仅指磁盘镜像), 包(package)

**工作区 (workspace)**:
`target/<N>/process/` 目录——固件解包产物与全部审计产出的唯一落盘根,也是 Step5 工具(read_file/list_files 等)的白名单根。磁盘镜像场景下每个分区子文件夹自成一个工作区。
_Avoid_: 输出目录(out 是单个分区的子目录)

**解包树 (extracted tree)**:
Step1 把固件解包出的文件目录树(`process/extracted/`),只读,是后续所有分析的原始材料。
_Avoid_: 解包根, extracted

**工件 (artifact)**:
Agent 阶段在 `process/agent/<seq>_<type>/` 下落盘的产物——`survey.json`、`findings.json`、`verified_findings.json`,以及编排痕迹。JSON 解析失败时降级为同名 `.md`。
_Avoid_: 产出文件, 中间文件

**调查工作区产物 (analysis sidecar)**:
ghidra_decompile 在 `process/analysis/` 下按文件相对路径产出的**边车三件套**(`.c / .strings.json / .imports.json`)——strings_query/imports_query 的边车优先数据源、find_decompiled_function 的读源、semgrep 双扫的 analysis/*.c 路。由 Step5 工具按需产出并幂等缓存(ADR-0010),不再是流水线批量产物;functions.json/meta.json 无工具消费者,不落盘。
_Avoid_: 边车文件(实现细节), 反编译产物

**工具路径 (tool path)**:
相对工作区 `process/` 根的路径(`extracted/unitree/...`、`analysis/...`、`agent/...`)——LLM 工具(read_file/list_files/search_code)**唯一接受的入参形态**,也是 Agent 工件(survey/high_risk_areas、findings/verified_findings)中 file 字段的**唯一规范口径**(ADR-0008)。
_Avoid_: process/ 前缀形态(`process/analysis/...` 没有任何工具能打开), 相对路径(歧义:相对谁)

**逻辑路径 (logical path)**:
相对固件根的路径(`unitree/...`,与 analysis 边车命名同构)——**纯内部键**,只存在于解包侧代码与 CLI 工具(semgrep/gitleaks)的原始容器输出里;进入任何 Agent 工件或工具入参前必须换算成工具路径。
_Avoid_: 固件路径, 物理路径

**文档声明(requirements.md / rules.md / agents.md)**:
`requirements.md` 已删除(2026-09-09,ADR-0011 收尾;旧 Step5 需求快照失去宿主);`rules.md` 是代码规范铁律,`agents.md`(AGENTS.md)是 Agent 架构与工具层设计。这两份里的**部分条款已过时**(尤其 Step1-4 相关章节,见 ADR-0010/0011),与代码现状不一致处以下文术语表、docs/adr/ 和代码为准。
_Avoid_: 把它们当现状说明书

### 阶段与角色

**预处理流水线 (pipeline)**:
固定顺序的规则化处理阶段:Step0 预解压/磁盘镜像分区提取 → Step1 引导式解包。纯代码,不依赖 LLM。原 Step2 过滤/Step3 分类/Step4 反编译已决定删除(ADR-0011),反编译降为 Step5 的按需工具(ADR-0010)。

**Step5 (Agent 审计)**:
LLM 驱动的审计阶段,由一个 orchestrator 编排三个子 Agent(recon→analysis→verification)对解包树与反编译边车做侦查、取证、复核,产出最终报告。

**子 Agent (sub-agent)**:
Step5 的三个执行角色之一,由 orchestrator 通过 `dispatch_agent` 调度。三者在代码里是 `AgentConfig` 的**不同配置实例,非子类**。
_Avoid_: 阶段, 子任务(会与 pipeline 阶段混淆)

**recon(侦查 Agent)**:
第一个子 Agent。对解包固件做中立广度调查,产出攻击面清单(`survey.json`)——只铺面、不深挖、不判级。不授 r2 工具族与 ghidra_decompile(ADR-0010)。
_Avoid_: 侦察, 铺面阶段

**analysis(深度分析 Agent)**:
第二个子 Agent。基于 recon 的 survey 逐条取证,对疑点下判级并附证据链,产出候选漏洞清单(`findings.json`)。
_Avoid_: 取证 Agent(职责是取证但名是 analysis)

**verification(复核 Agent)**:
第三个子 Agent。最后一道质量闸门:复核 analysis 的每条候选,过滤误报,产出经人工可复验的结论(`verified_findings.json`)。**每疑点一实例**:对排序后前 K 条(K 默认 10)各派一个独立实例、每条 max_iters 降到 8,逐条产 verified finding 聚合回 verified_findings.json;未进入前 K 的疑点进报告独立区段(⚠ 未复核)。ADR-0003。
_Avoid_: 复核阶段

**orchestrator(编排器)**:
Step5 顶层的 LLM 协调层(`orchestration/` 包,ADR-0009;主体在 `orchestration/orchestrator.py`),用 `dispatch_agent`/`summarize`/`finish` 三个动作调度子 Agent,校验顺序门与调度上限,并在 verification 完成后汇总素材、产出最终报告 `orchestrator/report.md`。
_Avoid_: 协调器, 总调度

**实例 (instance)**:
一次真实执行的子 Agent 运行,落盘在 `process/agent/<seq>_<type>/`(如 `0_recon`),带递增序号 seq 与独立 transcript/obs/工件。
_Avoid_: 运行, 调用

### 发现链

**发现 (finding)**:
Agent 阶段对某个可疑点的结构化结论,字段含 title/severity/file/func/addr/evidence/cve/confidence/verified/rationale/source_agent/instance_seq(`data/artifacts.py`)。
_Avoid_: 漏洞(漏洞是结论,不是候选), 可疑点

**候选漏洞 (candidate finding)**:
analysis 产出的、未经复核的 finding,集中在 `findings.json`。
_Avoid_: 发现, 漏洞

**已验证发现 (verified finding)**:
verification 复核后的 finding(verified=true/false/存疑),集中在 `verified_findings.json`——编排器总结报告的唯一素材。

**误报 (false positive)**:
verification 判定 verified=false 的候选,必须带 rationale 说明为何是误报,不许静默丢弃。

**疑点 (suspicion / lead)**:
有待查证的线索:recon 的 `high_risk_areas`(观察点,无判级)、analysis 的候选、被引用的函数/导入/字符串命中。与 finding 不同,疑点是"待查",finding 是"有结论"。
_Avoid_: 线索(lead 英文可,中文不用"线索"以免歧义)

**观察点 (observation point)**:
recon 的 `high_risk_areas` 数组里的条目——一个"高危区域标记,非判定",只记录 file+metric+detail,不判级、不展开证据链。判级与证据链移交 analysis。
_Avoid_: 发现, 判断(它有判级含义)

**Observation(A 大写,保留英文)**:
ReAct 循环里工具返回的、入上下文的一段文本(成功时是截断后的 text,失败是 Error 前缀)。这是 Agent 判定的唯一证据来源;其全文落盘在 `obs/step<N>_<tool>.txt`,截断时附 read_file 回读路径。
_Avoid_: 观察结果, 工具返回(会与 ToolResult 混淆)

**报告 (report)**:
orchestrator 在 verification 完成后经 summarize 取素材,由 Final Answer 原样落盘的最终总结报告 `process/agent/orchestrator/report.md`。verification 本身不产报告。
_Avoid_: 审计结论(那是 result.json), 渲染报告(render_report 已删除)

### Agent 交互与状态

**ReAct 循环 (ReAct loop)**:
子 Agent 与 orchestrator 内部的思考-行动循环:Thought → Action → Observation → 下一步;每轮从 LLM 拿回复,经 `protocol.py` 解析为 action/final/fail,再分发工具。设迭代上限、解析失败容忍、同参循环拦截、零工具 Final 拒绝等守卫。
_Avoid_: 对话循环, Agent 循环

**轮 (round/step)**:
ReAct 循环的一次 LLM 调用迭代,记入 transcript 并编号(step 1..max_iters)。
_Avoid_: 步(step 已用于索引)

**Transcript**:
一次 Agent 执行的完整留痕 `transcript.jsonl`(输入输出/工具调用/耗时/用量),编排层还有 orchestrator 自己的 transcript。可追溯审计用,不进上下文。

**工具 (tool)**:
Agent 在 Action 里调用的能力,统一 `AgentTool.execute(**kw) → ToolResult` 接口,返回 `{ok, text, data, error, elapsed, raw}`。按数据来源分三类:读盘类(读工作区/边车,毫秒级)、CLI 类(subprocess 调容器内 CLI)、API 类(urllib 调 HTTP);另有唯一的**产物生产工具** ghidra_decompile(调容器并把边车落盘,ADR-0010)。
_Avoid_: 函数(与 Ghidra 函数混淆), 命令

**接口契约 (interface contract)**:
工具对 LLM 暴露的参数约定——`params_doc` 是结构化规格(声明侧:参数名→类型/必选/默认/枚举),`base.execute` 按声明校验(执行侧:未知键/类型/缺失必选)。两侧同步闭合。ADR-0004。旧态(散文 + 无校验)已废除。
_Avoid_: 参数说明(params_doc 只是声明侧), 工具签名(那是 execute 执行侧)

**读盘类工具 (read-disk tool)**:
直接读工作区文件与边车、不调容器的工具:`list_files`/`read_file`/`search_code`/`strings_query`/`imports_query`/`find_decompiled_function`。廉价、毫秒级。其中 strings_query/imports_query 是**边车优先 + r2 兜底的混合型**:缺边车时降级为 CLI 通道现算(ADR-0010),不再报"未找到"。
_Avoid_: 本地工具, 便宜工具

**CLI 类工具 (CLI tool)**:
经 `run_docker` 调容器内 CLI 的工具:`checksec`/`r2_list_functions`/`r2_disassemble_function`/`r2_xref_query`/`cve_bin_tool_scan`/`semgrep_scan`/`gitleaks_scan`/`binwalk_rescan`/`sandbox_verify`。贵、走网络隔离;strings_query/imports_query 的 r2 兜底路也走此类通道(ADR-0010)。

**API 类工具 (API tool)**:
宿主 Python 用 urllib 调外部 HTTP API 的工具:`cve_lookup`/`web_search`。带节流/缓存/降级。

**TaskResult(ToolResult 专用名)**:
工具的通用返回结构,ReAct 循环只消费它,不感知数据来源。字段 `ok/text/data/error/elapsed/raw`(`providers/tools/base.py`)。
_Avoid_: 工具返回, 结果(太泛)

**上游工件 (upstream artifact)**:
交接给某子 Agent 的前序阶段工件:analysis 的上游是 survey.json,verification 的上游是 findings.json。orchestrator 用 `latest_upstream`(orchestration/actions.py 守卫函数)取最近一次已完成调度的工件。缺件时下游调度被拒。

**交接 (handoff)**:
orchestrator 注入子 Agent 简报尾部的上下文块:前序任务状态、同类型前次结果、累计发现、任务上下文;补跑时追加已覆盖清单与差分提示。结构化快照落盘 `handoff_<seq>_<type>.json`。
_Avoid_: 上下文注入(太泛), 传参

**简报 (brief)**:
每次子 Agent 执行的初始化用户消息(`build_*_brief`),含工作区锚点、上游工件摘要、任务说明。交接块经 `extra_brief` 追加到简报尾部。
_Avoid_: 系统提示(system prompt 是另一回事), 初始消息

**系统提示 (system prompt)**:
Agent 的系统提示词(`RECON_SYSTEM`/`ANALYSIS_SYSTEM`/`VERIFY_SYSTEM`/编排 ORCH_SYSTEM),含角色、工具清单、输出协议、纪律。留档在实例目录下供复现。
_Avoid_: 提示词(太泛), 任务描述

**调度 (dispatch)**:
orchestrator 对某个子 Agent 的一次安排,由 `dispatch_agent` 动作发起,经过守卫(未知 agent/顺序门/任务唯一性/次数上限)后执行。全程记入 `dispatch_log.json`(含被拒与重复尝试)。
_Avoid_: 调用(与工具调用混淆), 安排

**调度状态 (dispatch status)**:
一次调度的落盘状态枚举(`DispatchStatus`):running / success / skipped / degraded / failed / interrupted / rejected / duplicate。其中 `skipped`=.json 工件已存在;`degraded`=仅 .md 降级工件,默认复跑。
_Avoid_: 状态, 执行状态

**预算状态 (budget state)**:
某类型子 Agent 最新实例的迭代预算快照 `{agent, exhausted, steps, max_iters, pending_count, pending_focuses, overlap_ratio}`,注入 dispatch/summarize 的 Observation 与 dispatch_log/result.json,供 orchestrator 做是否补跑的动态决策。
_Avoid_: 预算, 剩余轮次(仅含 steps/max_iters)

**补跑 (re-run / supplementary dispatch)**:
同一类型子 Agent 的第 2/3 次调度,仅当结果明显不完整(如 analysis 预算耗尽仍有未覆盖疑点)时用**不同的任务描述**发起;简报追加已覆盖清单(前 30 条)与差分任务提示,禁止重复提交已存在标题的 finding。

**降级 (degraded)**:
两处含义,均在术语表内不冲突:① 工件解析失败(JSON → `.md`),调度状态记为 degraded;② 工具失败降级兜底("失败不崩"原则)——返回 ok=False 并记录失败原因,不中断整体流程。

**断点续跑 (resume / checkpoint)**:
已存在 `.json` 工件且非 force 时,对应子 Agent 调度标记为 skipped,加载已有工件直接跳过;仅 `.md` 降级工件则默认重跑(可由 `STEP5_RESUME_DEGRADED=0` 关闭)。上游缺件时下游调度被拒。边车侧的对应机制是 ghidra_decompile 的幂等缓存(ADR-0010)。

### 审计判定

**严重度 (severity)**:
finding 的严重度等级,值域 `critical / high / medium / low / info`(`data/artifacts.py:SEVERITIES`,排序权重表 `SEVERITY_RANK` 由它派生的单一出处),orchestrator 汇总与复核取前 K 时按此排序。
_Avoid_: 等级, 风险等级(风险有可利用性含义)

**置信度 (confidence)**:
finding 的证据充分度,值域 `high / medium / low`。verification 对存疑项降 confidence 保留,并区分"静态成立但无法动态验证"与"证据不足待查"。
_Avoid_: 可信度

**复核结论 (verdict / rationale)**:
verification 对每条候选的判定:verified=true(成立)/ false(误报)/ 存疑(降 confidence 保留)。判定的理由写在 rationale 字段,证据要与本次 Observation 逐字吻合。
_Avoid_: 结论, 判定(severity 也算判定)

**可利用性 (exploitability)**:
基于二进制保护属性的漏洞被利用的难易程度,由 checksec 的 NX/PIE/RELRO/Canary/Fortify 等属性评估。NX 关闭 + 无 PIE → 可利用性上调。是 LLM 的评估输入,不是 finding 的字段。
_Avoid_: 风险, 严重度(severity 是另一个维度)

**证据链 (evidence chain)**:
一条 finding 从疑点(HIT)到结论的支撑材料:工具 Observation 原文(file/line/code 片段)、交叉引用、CVE 详情。要求逐字可溯源,禁止编造。
_Avoid_: 证据(单条是 evidence,整条链是 evidence chain)

### 工具与数据(分析工具与边车)

**升级调用 (escalation)**:
两级二进制分析模型(ADR-0010):r2 廉价层(r2_list_functions / r2_disassemble_function / r2_xref_query,及 strings_query/imports_query 的 r2 兜底——秒级、不落盘、不反编译)先行,LLM 判断信息不够才升级调用 ghidra_decompile(分钟级、落盘边车三件套、幂等缓存)。升级规则写在提示词与缺件报错文案里;verification 红线按升级链改写:缺 `.c` → r2 层查证 → 信息不够 → 反编译 → 仍缺失/零产出 → 才判 false_positive。
_Avoid_: fallback(中英混排), 反编译升级

**ghidra_decompile**:
Step5 唯一的 Ghidra 入口:对单个 ELF 反编译并落盘边车三件套(`.c/.strings.json/.imports.json`),幂等缓存(`extractinfo_version` 匹配即跳过 + sha256 去重)。带 `-analysisTimeoutPerFile 300` 截断防止大型共享库陷入无限循环。原 Step4 批量反编译已退役(ADR-0010/0011)。
_Avoid_: 反编译(单独用会与 find_decompiled_function 混淆), 批量反编译

**危险函数表 (dangerous function table)**:
imports_query 使用的导入风险分级表,值域 high(命令执行/内存不安全)/ medium(权限/动态加载)/ low(网络/随机),集中配置。与硬编码文本模式是两套独立的东西。
_Avoid_: 黑名单(与已退役的 step2 过滤名单混淆), 危险模式表(会与 _TEXT_PATTERNS 撞名)

**硬编码文本模式 (hardcoded-text patterns)**:
`_TEXT_PATTERNS` 正则模式集(URL/IP/密钥/口令),现由 strings_query 的 `pattern` 参数在**查询时过滤**边车或 r2 兜底的字符串(原 Step4 预产 .text.json 已退役,ADR-0011)。命中只标记"检出",不代表有问题,需人工确认(如 paho-mqtt 的 token 误报)。与 imports_query 的危险函数表是两套独立的东西,勿混。
_Avoid_: 危险模式表, 文本正则(太泛)

**系统信任库 (system trust store)**:
固件里位于标准系统信任目录(`etc/ssl/certs` 等)下的证书,表示"非厂商硬编码凭证"。原 Step3 的 `is_system_trust` 标记随 Step2-4 退役(ADR-0011);"系统 CA 不作可疑点上报"降为 Agent 提示词纪律。
_Avoid_: 信任文件, 系统证书

**敏感配置 (sensitive config)**:
`etc/` 下需要审计的配置文件,与发行版标准配置相对。原白名单强制保留机制(WHITELIST_ETC)随 Step2 退役(ADR-0011);现在所有解包文件对 Agent 可见,该区分只是审计常识。

**SDK 系统库目录 (SDK/system library dir)**:
`usr/lib`、`usr/local/lib`、`usr/share`、`lib`、`opt` 等目录。Step5 的 list_files/search_code/semgrep 按 profile 的 `SEARCH_EXCLUDE_DIRS` 自动跳过(SDK 噪音;原 Step2 过滤黑名单已退役)。与厂商自研目录(`home/unitree/`)相对。

**逻辑路径 (logical path)**:
剥掉 binwalk 解包嵌套前缀(`<name>.extracted/<N>/`、`<fstype>-root/`)后的固件内相对路径,analysis 边车按它命名。例:`foo.tar.xz.extracted/0/etc/passwd → etc/passwd`。
_Avoid_: 相对路径(带嵌套前缀的是物理相对路径)

**镜像分区 (disk-image partition)**:
磁盘镜像(GPT/MBR)解析出的分区(APP/rootfs/bootloader/recovery 等),Step0 按名字+大小推断 kind,每个分区独立子工作区跑完整流水线。分区字段含 offset/size/type/kind/crc_ok 等(`step0_split_img.py`)。
_Avoid_: 分区表(那是解析对象不是产物), 镜像文件

### 执行语义

**失败不崩 (fail-soft)**:
项目铁律:任何步骤失败降级兜底、继续往下跑、记录失败原因,不中断整体流程。在 Agent 层体现为工具返回 ok=False 与工具级降级。
_Avoid_: 容错(太泛), 优雅降级(只有工具级,Agent 层无规则降级)

**无 key 立即终止 (no-key hard stop)**:
Step5 在无 API key 或 API 调用失败时抛 `LLMError` 立即终止,不产出降级工件、不执行规则模式。注意:这与 tools_summary 部分旧文档"降级纯规则"的表述**不一致**——以代码为准。
_Avoid_: 降级, 规则模式(Step5 已无规则模式)

**同参空转 (same-call spin)**:
ReAct 循环里同一工具+完全相同参数被调用超过 `MAX_REPEAT_CALLS`(3)次,循环守卫拦截不再执行,注入干预 Observation(改参数/换工具/收尾)。
_Avoid_: 卡死, 死循环(系统会拦截)

**零工具 Final 拒绝 (no-tool final reject)**:
ReAct 循环从未调用任何工具就输出 Final Answer → 拒绝退回,要求先用至少一个工具查证(上限 `MAX_NO_TOOL_REJECTS`=1,强制收尾轮不设此门槛)。
_Avoid_: 强制收尾(那是另一码事)

**强制收尾 (forced final)**:
ReAct 循环到迭代上限仍未给 Final Answer 时,注入强制收尾指令,给最后一次机会输出含执行总结的 Final Answer;收尾仍失败则截取最后 2000 字符当 best-effort 答案。
_Avoid_: 收尾, 强制结束

**证据纪律 (evidence discipline)**:
Agent 判定规则:每条 finding 的 evidence/addr/cve 必须逐字来自某次工具 Observation,禁止编造、拼凑或凭记忆补写;引用未在 Observation 出现过的路径/函数/地址/CVE 视为违规。
_Avoid_: 证据要求, 引用规范

### 边界与约束

**路径白名单 (path whitelist)**:
Step5 工具(read_file/list_files/读盘类)只能访问 `process/` 工作区之内,越界/`..`/绝对盘符 → ok=False。防 Agent(或被污染的 file_ref)借工具读任意宿主文件。
_Avoid_: 沙箱(那是 sandbox_verify), 权限

**网络隔离 (network isolation)**:
CLI 类工具一律 `--network none` 跑容器;唯一例外是 API 类(cve_lookup/web_search)需要出网。binwalk_rescan 也走 none。

**Docker 容器 (container)**:
Step0-1 的 binwalk 与 Step5 的 CLI 类工具、ghidra_decompile 在容器内执行,宿主机只跑 Python。统一经 `docker_utils.run_docker` 调用(returncode/stdout/stderr,不抛异常,超时返回 124)。唯一例外:Step0 ext4 直读的 debugfs/mount 后端在宿主原生执行(debugfs 用户态读镜像,不进内核;见 ext4 直读)。
_Avoid_: 沙箱(指具体镜像 firm_audit/sandbox), Docker 命令

**沙箱 (sandbox)**:
具体镜像 `firm_audit/sandbox`,ENTRYPOINT 是 Ghidra analyzeHeadless,内置 checksec/r2/cve-bin-tool/semgrep/gitleaks/解释器;调非 Ghidra CLI 必须覆盖 entrypoint。

**引导解包 (guided extraction)**:
Step1 主路径——按文件魔数决策逐层解包(替代 binwalk -Me 盲解,避免 fdt 分解成数十万节点),manifest 落盘支持断点续解。binwalk -Me 仅是兜底。
_Avoid_: 解包(特指 binwalk -Me), 魔数解包

**预解压 (preprocess)**:
Step0 在 binwalk 之前用宿主标准库解外层压缩/归档/磁盘镜像,避开 binwalk 解压偶发 bug,提升确定性。产物按分流规则决定是否仍需 binwalk。
_Avoid_: 预处理(太泛), 解压

**ext4 直读 (ext4 direct-read)**:
Step0 对磁盘镜像中 ext4 分区(超级块魔数命中)的原生文件树读取——不经 dd+binwalk,直接产出该分区的解包树与 Step1 完成标记,下游零改动。双后端:debugfs(默认,用户态零特权)/ mount(快路,需 root)。取代 2026-09-06 的手工旁路。
_Avoid_: 旁路(指当年手工方案), 挂载(特指 mount 后端)

**不透明固件 (opaque firmware)**:
file 识别不出类型的二进制(unknown/裸 blob)。审计路径结构性存在:无过滤的 list_files 天然看见、strings_query 的 r2 兜底(izz 任意文件)可提取字符串线索、binwalk_rescan 出签名表("无签名"本身是可引用 Observation)。原规则分诊随 Step4 退役(ADR-0011),分诊七类与魔数知识留 git 历史。
_Avoid_: 垃圾文件, 未知格式

**profile**:
固件机型名单文件(`profiles/<name>.yaml`)。ADR-0011 后只剩 `SEARCH_EXCLUDE_DIRS` 一段——Step5 工具(list_files/search_code/semgrep)与简报现场概览消费的 SDK 搜索排除名单;`main.run_pipeline` 经 `file_rules.configure(--profile)` 切换。换机型只需改 profile 不改代码。当前默认 `nano-ubuntu`。
_Avoid_: 配置(与固件 config 文件混淆), 机型


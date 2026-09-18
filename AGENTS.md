# 流水线角色与 Agent 工具层

## 工作流纪律(强制,2026-09-05 定稿)

**项目工作必须严格按 Matt Pocock skills 的流程执行,不得跳过流程直接改代码。**

* 非平凡任务(新功能/重构/成串修复)走完整链路:需求澄清与追问(brainstorming / grilling)→ 写规格(to-spec)→ 拆工单(to-tickets)→ triage 定级 → 逐工单实现(implement / tdd)→ 评审(code-review)。工单存放与状态字段按 [docs/agents/issue-tracker.md](./docs/agents/issue-tracker.md) 本地 markdown 约定,标签按 [docs/agents/triage-labels.md](./docs/agents/triage-labels.md)
* **未经用户明确确认,不得自行开始修改代码**——先探索、提问、对齐方案,拿到用户点头再动手;领域事实先读 `CONTEXT.md` 与 `docs/adr/`(见 [docs/agents/domain.md](./docs/agents/domain.md))
* 例外仅限用户当场明确指示"直接改"的琐碎修复(错字/单行);即便如此也要先一句话说明改什么,再动手

> **⚠ 架构现状(2026-09-09,ADR-0010/0011 已落地)**:流水线为 **Step0 → Step1 → Step5**(Step2 过滤/Step3 分类/Step4 批量反编译已删除,`--max-elf`/`--max-workers` 退役)。二进制分析由 Step5 的 r2 工具族(r2_list_functions / r2_disassemble_function / r2_xref_query)与唯一 Ghidra 入口 `ghidra_decompile`(幂等缓存 + sha256 去重)按需完成,升级纪律("先 r2,信息不够才反编译")写入提示词与缺件文案。**本文第一章(Step1-4 流水线角色)与第三章中"读 Step4 产出"的表述已过时,以 [ADR-0010](./docs/adr/0010-step5-r2-ghidra-escalation.md)、[ADR-0011](./docs/adr/0011-remove-step2-3-4.md) 与 CONTEXT.md 术语表为准**(全文重写另行安排)。requirements.md 已删除。

> **⚠ Step5 现状(2026-09-18,ADR-0012 票 14 公开切换已落地)**:Step5 公开入口(`step5_run`)已一次切换到 **Host 控制的逐 Candidate 调查生命周期**(Recon → Candidate Store → 逐 Candidate Analysis → Verification → Finding → 确定性报告 → 封存),工件根为 `process/generations/gen-XXXX/`。旧 `orchestration/` 包、`runner.py`、`aggregator.py`、`data/`、`engine/react_loop.py` 已删除;`STEP5_ORCHESTRATOR_MAX_ITERS` / `STEP5_VERIFY_K` / `STEP5_RESUME_DEGRADED` 与 CVE 启动预检已退役。**本文第一章之外,凡描述 LLM orchestrator 编排、survey/findings/verified_findings 三工件、top-K 复核、`process/agent/` 布局的章节均已过时,以 [ADR-0012](./docs/adr/0012-host-controlled-investigation-lifecycle.md)、`step5_agent/host/` 与 CONTEXT.md 术语表为准**。

固定 5 步流水线(现 3 步,见上方架构现状)。

## 一、【已退役 2026-09-09,ADR-0011】Step1-4 流水线角色(仅存档,代码已删除)

### Step1 — Extractor(解包)

* **职责**:把固件包解包成可浏览的文件目录

* **输入**:`target/<N>/` 下的固件文件(归档/单文件压缩/磁盘镜像三种路径)

* **输出**:`target/<N>/process/extracted/` 目录

* **工具**:binwalk v3(Docker 镜像 `binwalk`)+ 引导解包器 `step1_guided_extract.py`

* **实现**:`firmware_audit/step1/`,含 `step1_extract.py`(常规)、`step1_guided_extract.py`(scan\_tree 模式,处理嵌套容器)、`file_magic.py`

* **断点续跑**:`.step1_done` 标记存在则跳过,需手动删标记 + `guided_extract.json` 才能重测

* **验证**:输出目录存在且含文件 ✓

### Step2 — Filter(过滤)

* **职责**:排除标准 Linux 系统文件,保留该审计的内容

* **输入**:`extracted/` 目录

* **输出**:通过过滤的文件路径列表

* **工具**:Python pathlib + 白/黑名单(见 `profiles/nano-ubuntu.yaml`)

* **实现**:`firmware_audit/step2/step2_filter.py`

* **规则**:黑名单含 `usr/local/lib`(过滤 Python SDK);白名单含 `home/unitree/` 全部、`etc/` 下敏感配置、所有证书

* **验证**:home/unitree 全保留,系统库全排除 ✓

### Step3 — Classifier(分类)

* **职责**:按文件类型分流到不同处理路径

* **输入**:过滤后的文件路径列表

* **输出**:`List[FileInfo]`,每个文件标注 type

* **工具**:`file` 命令(Docker binwalk 镜像)

* **实现**:`firmware_audit/step3/step3_classify.py`

* **分类**:`elf_exec` / `elf_lib` / `script` / `source` / `config` / `text` / `crypto_x509` / `crypto_ssh` / `crypto_gpg` / `crypto_pkcs12` / `crypto_private_key` / `crypto_public_key` / `crypto_unknown` / `unknown`(`crypto_unknown` = 密码学扩展名但 file 未识别,绝不定 `unknown` 避免漏审)

* **原则**:硬编码分类,不用 LLM

* **验证**:统计各类型数量,与 file 输出交叉验证 ✓

### Step4 — Decompiler(反编译/提取)

* **职责**:把二进制转成可审计的信息,文本类直接读

* **输入**:`List[FileInfo]`

* **输出**:填充 `decompiled_path` / `analysis_path` / `ghidra_status` / `audit_status`

* **实现**:`firmware_audit/step4/step4_decompile.py` + `triage.py`

* **工具**:

  * ELF → Ghidra Headless(Docker 镜像 `ghidra`,带 `-analysisTimeoutPerFile 300`,**空格分隔形式**,`=` 形式会被当文件参数)

  * 文本/脚本/源码 → Python `open()` + `_TEXT_PATTERNS` 扫描

  * ELF 硬编码 → 宿主侧读 strings.json 复用 `_TEXT_PATTERNS`

  * 证书 → `cryptography` 库按 crypto\_\* 类型 dispatch(零依赖铁律的既有例外:可选依赖,缺库降级跳过证书解析)

* **Ghidra 提取**(ExtractInfo.py v2):反编译 C + 函数列表+调用关系 + Imports(call\_sites) + Symbols + 字符串表(refs) + meta

* **产出位置**(合并目录 `analysis/`):`<rel>.c` + `<rel>.{functions,imports,symbols,strings,meta,text,crypto}.json`

* **版本续传**:decompiled.c 头部 `extractinfo_version` 校验,旧产物自动失效重跑

* **验证**:29 个 ELF 全部反编译,12 个检出硬编码(带 address/refs)✓

### Step5 — Agent 审计(已实现,2026-08-17;v3 编排升级 2026-08-28;recon v3/编排弹性 2026-08-29)

* **实现与分层(2026-08-18 目录重组;2026-09-05 编排层包化定稿,ADR-0009)**:`firmware_audit/step5_agent/` 子文件夹按并列/附属关系组织——顶层 `run_step5.py`(L0 入口,`python -m` 路径不变)+ `orchestration/` 包(LLM 编排层,七模块:state 共享词汇 / orchestrator 编排主体 / actions 三动作+调度守卫 / handoff 交接 / dispatch\_log 调度留痕 / verify\_phase 每疑点一实例复核引擎 / reconciliation 报告对账)+ `runner.py`(L1 单 Agent 执行)+ `aggregator.py`(findings 聚合纯逻辑)+ 三个自包含包:`engine/`(ReAct 执行引擎:react\_loop 状态机 + protocol 纯函数解析 + context 四分区 + transcript 落盘 + display 监控)、`data/`(数据契约:artifacts 工件 schema/存取/溯源回写 + prompts 提示词)、`providers/`(外部接入:llm\_client + tools/)+ `demos/`(演示脚本子包)。依赖只准向下:run\_step5 → orchestration → runner/aggregator/engine/data/providers,engine/data/providers 互不 import、包内走相对导入;分层规则由 AST 守护测试机器强制(`test_step5_layer_guard.py`)

* **编排(v3)**:`Orchestrator` 轻量 LLM 驱动(ReAct 循环,3 动作 `dispatch_agent`/`summarize`/`finish`),严格单向顺序门 recon→analysis→verification。调度上限按类型区分:recon/analysis 同类型最多 3 次(默认 1 次+至多 2 次补跑,动态分配机制保留);**verification 例外(2026-09-01 ADR-0003)——不再适用"同类型最多 3 次",补跑逻辑整体取消,改为每疑点一实例、按 finding 计数(K 上限,见下)**

* **编排动态分配(2026-08-29)**:每实例结构化 `budget_state`(agent/exhausted/steps/max\_iters/pending\_count/pending\_focuses/overlap\_ratio)注入 summarize 与 dispatch 的 Observation、dispatch\_log.json(逐实例)及 result.json("budget"汇总);`pending_focuses`=recon recommended\_actions(high/medium)∩ 未被 findings 覆盖的疑点(title/file 差分);analysis 预算耗尽(exhausted)且 pending\_count>0 且调度次数<3 时,dispatch Observation 附补跑建议;补跑(同类型第 2/3 次)简报追加已覆盖清单(前 30 条)+ 差分 task,ANALYSIS\_SYSTEM 含"只处理未覆盖疑点,禁止重复提交已存在标题"补跑红线;`overlap\_ratio`(新实例与既有聚合的 title/file 归一化重合比例)>0.5 提示聚焦差分

* **工件链**:`process/agent/<seq>_<type>/survey.json → findings.json → verified_findings.json`(recon 为 v3 survey 工件,无 findings/判级字段;analysis/verification 为 findings 容器 schema `2`:finding 带 `source_agent`/`instance_seq` 溯源;JSON 解析失败降级 `.md`);v2 兼容层(旧 attack\_surface.json 读侧回退)已于 2026-08-29 **移除**,只认 survey.json 命名;编排痕迹 `process/agent/orchestrator/`:transcript.jsonl + dispatch\_log.json(全量调度史含 rejected/duplicate+逐实例 budget\_state)+ handoff\_<seq>\_<type>.json(交接快照)+ result.json(终态+`budget` 各类型汇总)+ report.md

* **断点续跑(v3 收紧)**:`.json` 工件存在 → skipped;仅 `.md` 降级 → **degraded**(ok=False),默认复跑(`STEP5_RESUME_DEGRADED=0` 恢复旧跳过语义)

* **报告(v3,生成主体=orchestrator)**:verification 完成后调用 `summarize` 取素材(已复核 findings 全量字段+阶段统计),Final Answer 即报告正文,**原样落盘** **`orchestrator/report.md`**(同时含可解析 JSON 时另存 report.json 副产品);未产出时明确告警不静默降级。原 `render_report` 已删除——verification 只产 verified\_findings.json,不产报告

* **verification 每疑点一实例(2026-09-01,ADR-0003,ticket 03/04)**:verification 从"单实例多疑点(24 轮内逐条复核)"改为**每 finding 一个独立复核实例**。analysis 产出 findings 后按 severity(critical>high>medium>low>info)主排序 + confidence(high>medium>low)次排序,取前 K 条(env `STEP5_VERIFY_K`,默认 10);对每条派独立实例,输入=单条 finding + 相关工件指针,**max\_iters=8**,逐条产单条 verified finding,聚合回 `verified_findings.json`(**全量 N 保留**:前 K 带 verified/rationale/confidence/severity——复核降级判级同覆盖,2026-09-03 两处覆盖集补 severity:orchestrator 锚点回填 + aggregator `_OVERRIDE_KEYS`,防工件 severity=high 与 rationale"降为 low"自相矛盾;未进 K 的 `verified=None`、confidence 保留 analysis 初值)。**补跑逻辑整体取消**——verification 只调度一次,自动对前 K 各派实例,不再适用"同类型最多 3 次"上限(代码注释 `orchestration/verify_phase.py` `verify_k` 明示)。**单实例断点续跑带身份校验(2026-09-03)**:实例目录名是全局 seq 位置而非 finding 身份,续跑时编排路径变化(如 analysis 补跑次数不同)会让 seq 前移、命中前一条 finding 的旧工件——skip 分支按 file+title 归一化比对工件 finding 与当前锚点(完整 dedup\_key 会因实例工件常缺 func/addr 误拒合法工件),不一致即弃用工件真实重跑,防复核结论整体错配无告警(target/1 实测 9/10 条右移一格)。报告据此把 `verified=None` 划进**独立未复核区段**(⚠ 未经复核,见下 summarize 素材)。上下文隔离铁律不破(每实例只从工件读,不传对话历史)

* **recon v3:权限收敛+工件重构(2026-08-29)**:移除 `strings_query`/`imports_query`/`checksec`(深挖归 analysis/verification),新集 6 件套:`list_files, read_file, cve_bin_tool_scan, semgrep_scan, gitleaks_scan, binwalk_rescan`;`max_iters` 保持 20;工件改名 `survey.json`(schema v3):`arch_snapshot`(top\_level\_dirs/components\_grouped\[name+size,role 推断必附 role\_evidence]/os\_or\_runtime)+`components`(只收 cve\_bin\_tool\_scan Observation 实况)+`entry_points`+`high_risk_areas`(观察点,无判级)+`recommended_actions`(priority+action)+`summary`;**禁止** findings 数组与任意层级 severity/confidence/verified/evidence/rationale(解析层守护:违规键整条降级为 high\_risk\_areas 观察点)——判级与证据链移交 analysis;提示词防幻觉红线:high\_risk\_areas 只标工具 Observation 原文、components 版本/CVE 不凭记忆(v2 兼容层已移除,只读 survey.json)

* **路径口径统一为工具路径(2026-09-03,ADR-0008,target/1 事故上游修复)**:LLM 可见的一切路径(survey.high\_risk\_areas/findings 的 file 字段、verification 简报指针、提示词示例)统一为**工具路径**(相对工作区根,`extracted/...`/`analysis/...`);逻辑路径(`unitree/...`)降级为纯内部键(Step2-4/边车命名),`process/` 前缀形态(无任何工具能解析,旧简报指针与提示词示例均带此前缀——实例 6 连撞 6 次"文件不存在"烧光预算的直接元凶)全量消灭。四处落点:①semgrep/gitleaks 工具输出层给固件路径加 `extracted/` 前缀(`cli_base.extracted_tool_path`,recon"照抄原文"红线不动,原文本身变对);②findings 落盘归一兜底(`aggregator.normalize_file_paths`,仅 analysis 实例,缺前缀且 `extracted/<file>` 存在则补并回写——verification 不归一,title/file 不得改是硬纪律);③verification 单实例简报指针修前缀 + 新增源文件指针与 `.text.json` 边车(全部经 `is_file` 检查,LLM 零猜测);④提示词文档口径清扫(ANALYSIS\_DIR\_DOC/schema 模板/recon 简报)。配套:`resolve_analysis_file` 对 `extracted/` 前缀宽容解析(剥前缀再找边车,防 Agent 把新口径带进 file\_ref 白吃一轮)。旧工件跨版本不兼容——续跑身份校验(file+title)对新锚点判不一致即弃旧重跑,与 extractinfo\_version 失效同款先例。回归:`test_orchestrator.py::test_normalize_file_paths/test_verify_single_brief_pointers`、`test_step5_cli_tools.py::test_extracted_tool_path`+semgrep/gitleaks 前缀断言、`test_step5_tools.py::test_resolve_analysis_file_tolerant`

* **终止策略**:无 API key 或 API 调用失败时立即终止(抛 `LLMError`),不产出降级工件、不执行规则模式

* **接入**:main.py Step1-4 后自动跑 Step5(`--no-step5` 跳过);`step5_run` 接受 target/<N> 或工作区目录(分区子工作区通用);也可 `python -m firmware_audit.step5_agent.run_step5 <dir> [--force]` 独立补跑

* **验证**:全套件 176 passed + 2 skipped(orchestrator 20 项含 summarize 报告/degraded 复跑/handoff 快照/状态枚举/pipeline 模式;tools 增 list\_files;pipeline 含 schema v2/权限矩阵/报告主体)✓

* **测试基建(2026-08-18)**:`test/conftest.py` 提供 `process_dir`/`tools` fixture(工件缺失 SKIP),cli\_tools 本地覆盖加 Docker 门控、smoke 本地 `llm` 门控(STEP5\_SMOKE+key+工件);`pytest_pyfunc_call` 钩子把双模式测试的非空 fails 列表判 FAILED(消灭假绿)。双模式测试新增形参必须同步补 conftest fixture,详见 `firmware_audit/docs/test-fix-reports/BUGFIX-2026-08-18-step5-test-fixtures.md`

* **配置(v3)**:`list_files` 三 Agent 全授权(recon 首动铺面工具;参考 deepaudit ListFilesTool:directory/pattern/recursive/max\_files + 路径白名单 + SDK 目录排除);`step5_run` summary 各阶段纳入 `steps`/`tool_calls`,全局合计;工具权限有守护测试(`tool_permissions_and_threshold`)

## 二、已定:Step5 Agent 架构(v3 为现状,2026-08-28;recon v3/动态分配 2026-08-29)

LLM 编排(Orchestrator) + 三 Agent,ReAct 模式(类 DeepAudit 分段思路)。

### 控制流(v3)

```python
def step5_run(ctx):
    orch = Orchestrator(ctx).run()   # LLM 编排:dispatch×3 → summarize → Final Answer
    # summarize Observation = 报告素材;Final Answer 原样落盘 orchestrator/report.md
    # 唯一路径(ADR-0006:pipeline 快速模式已删,所有运行都产报告)
```

编排 LLM 做调度决策,顺序门/唯一性/上限是代码硬约束(不依赖 LLM 自觉);
每个 Agent 内部才是 ReAct 自主循环。

### Agent 职责与工具分配(v3)

| Agent            | 职责                                           | 工具                                                                                                                                                                                | 轮上限  | 输入                        | 输出工件                                                                                                                                     |
| ---------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **recon**        | 广度侦察:枚举铺面不判级(判级/证据链移交 analysis)              | list\_files, read\_file, cve\_bin\_tool\_scan(可选), semgrep\_scan, gitleaks\_scan, binwalk\_rescan                                                                                 | 20   | Step4 工件清单+目录概览           | `survey.json`(v3:arch\_snapshot 架构快照、components 组件 CVE 实况、entry\_points、high\_risk\_areas 观察点、recommended\_actions 扫描建议;无 findings/判级字段) |
| **analysis**     | 深度分析:对疑点逐个取证+判级                              | list\_files, search\_code, find\_decompiled\_function, xref\_query, strings\_query, imports\_query, read\_file, cve\_lookup, checksec, semgrep\_scan, gitleaks\_scan, web\_search | 30   | survey.json               | `findings.json`(候选漏洞,含证据链:路径+地址+代码片段+严重度)                                                                                                |
| **verification** | 复核过滤误报(不产报告);**每疑点一独立实例(ADR-0003)**,仅复核前 K 条 | list\_files, search\_code, find\_decompiled\_function, xref\_query, cve\_lookup, checksec, read\_file, strings\_query, imports\_query, sandbox\_verify                            | 8/实例 | 单条 finding(前 K 条之一)+ 工件指针 | `verified_findings.json`(唯一产物;全量 N 保留,前 K 带 verified/rationale/confidence/severity;未进 K 的 verified=None 进报告未复核区)                         |

### ReAct 循环约定

* 每 Agent 一个 while 循环:LLM 输出 Thought/Action → 执行工具 → Observation 回填 → Final Answer 终止

* **迭代上限按 Agent 固化**:recon 20 / analysis 30(2026-08-29 由 24 上调,防疑点取证中途截断)/ **verification 每实例 8**(2026-09-01 ADR-0003:每疑点一实例后,单条复核轮次需求 ≤8;原 24 是"单实例复核全部疑点"的多疑点摊薄值,已不适用),防死循环烧预算。**轮次可 env 覆盖(2026-09-02)**:`STEP5_RECON_MAX_ITERS` / `STEP5_ANALYSIS_MAX_ITERS` / `STEP5_VERIFICATION_MAX_ITERS` / `STEP5_ORCHESTRATOR_MAX_ITERS`(默认 20/30/8/12),缺失/非法值回落默认、下限钳 1;`runner.resolve_max_iters` 消费点解析,模块常量不污染;均可写入 `firmware_audit/.env`(`load_env_file` 启动注入,OS 环境变量优先)

* **Observation 截断(2026-09-06 票01 定稿)**:单条工具结果 ≤ **16000 字符**入上下文(由 8KB 上调,头 75%+尾 20% 头尾保留),全文落盘供后续查询;工具基类可选类属性 `max_text_chars` 按工具覆盖(None=全局默认),**summarize 声明 64000 护栏**——报告素材是唯一必须完整进 Observation 的内容,orchestrator 无 read_file 回读动作,素材被截即闭环断裂(target/1 实测事故)

* 工具失败不终止:Observation 返回错误信息,Agent 自行换路(继承铁律"失败不崩")

* **循环守卫三件套(2026-08-18,react\_loop,学 DeepAudit 实测坑)**:

  * 同参空转拦截: 同一工具+完全相同参数(规范化 kwargs 键)第 4 次起不执行,回喂 `[系统干预]` 提示(改参数/换工具/收尾三选一)

  * 工具先行: 零工具调用就输出 Final Answer → 拒绝退回(`[系统拒绝]`,限 1 次,模型坚持则放行防死锁);强制收尾轮不受限

  * 防幻觉纪律入提示词: verification 硬规定"read\_file 报文件不存在 → 该 finding 必判 false\_positive,禁止猜路径";三 Agent 提示词对标 DeepAudit 五段式重写(角色/锚点/工作流+判定规则/协议+schema/纪律)

* **终端监控显示(2026-08-19)**: `engine/display.py` 观察者层,react\_loop 7 个事件点 + runner stage/done 喂事件,Claude Code 风格打印思考/调用/结果/系统干预;`display=None`/NullDisplay 零侵入(有 `display_none_no_regression` 守护)。配置 `STEP5_DISPLAY=0|compact|full`、`STEP5_COLOR=0|1`(终端自动开色,管道自动无色)。demo:`python -m firmware_audit.step5_agent.demos.demo_display`;详见 step5\_agent/DISPLAY.md

### 交接约定

* Agent 间**只通过工件文件交接**,不传对话历史(上下文隔离)

* 工件为 JSON,带 schema 版本号

* 断点续跑:工件存在且 schema 匹配则跳过该 Agent(仿 `.step1_done` 思路)

### 终止策略(无 API key / API 调用失败)

Agent 审计不设规则降级:无 API key(`LLMClient.available == False`)或
API 调用失败(`LLMClient.chat` 重试耗尽抛 `LLMError`)时,立即终止当前
Step5 流程,不产出任何替代工件(无 survey/findings/report)。

* `step5_run` 无 key → `raise LLMError`,由 main.py / run\_step5.main 捕获打印"终止"

* `run_agent` 接到 `LLMError` 立即向上重抛(不吞),中断后续 Agent 链条

* Step1-4 已完成的固件分析结果不受影响

## 三、工具层实现

> **⚠ 部分表述过时(2026-09-09,ADR-0010/0011)**:读盘类工具"读 Step4 产出"的说法已过时——strings_query/imports_query 现为"边车优先 + r2 兜底"混合型(兜底不限 ELF);边车唯一来源是 ghidra_decompile(边车三件套 .c/.strings.json/.imports.json,functions.json/meta.json 不再产出);新增 r2_list_functions/r2_disassemble_function;xref_query 已更名 r2_xref_query。工具清单以代码注册表与 CONTEXT.md 为准。

### 目录结构(2026-09-05 编排层包化定稿,ADR-0009:并列/附属关系入目录)

```
step5_agent/
  __init__.py              ← 对外只暴露 step5_run
  run_step5.py             ← L0 总控入口(python -m 路径不变;step5_run + resolve_workspace)
  aggregator.py            ← findings 聚合纯逻辑(与编排层解耦)
  runner.py                ← L1 单 Agent 执行(AgentConfig × 3 + run_agent
                             + post_run_status 执行后状态三岔判定单一出处)
  orchestration/           ← LLM 编排层包(ADR-0009,T1-T6;包内依赖单向
                             orchestrator → actions/verify_phase → handoff → state)
    __init__.py            ← 包导出与分工说明
    state.py               ← 共享词汇:调度状态枚举/中文标签/SubAgentResult(环的切断点)
    orchestrator.py        ← 编排主体:Orchestrator 状态持有与登记/run() 主循环/
                             budget 集群/报告与对账与终态落盘
    actions.py             ← 三动作工具类(dispatch_agent/summarize/finish)
                             + 调度守卫纯函数(顺序门/唯一性/上限/续跑判断)
    handoff.py             ← 交接块构建 + 交接快照落盘
    dispatch_log.py        ← DispatchLog 调度留痕(start/finish/interrupted/attempt 四动词)
    verify_phase.py        ← verification 每疑点一实例引擎(排序取 K/续跑身份
                             校验/锚点回填聚合/阶段终态)
    reconciliation.py      ← 报告对账纯函数群(零 IO 零 LLM,ADR-0007)
  engine/                  ← ReAct 执行引擎(自包含,包内相对导入)
    __init__.py            ← 再导出 run_react_agent / ReactResult
    react_loop.py          ← L2 状态机(解析→分发→回喂→收尾;display 钩子)
    protocol.py            ← L3 纯函数协议解析(正则,零 IO)
    context.py             ← L3 四分区上下文 + 600k 阈值压缩
    transcript.py          ← L3 Transcript(JSONL 事件流 + obs/ 全文落盘
                             + reset_transcript 跑前清空统一入口)
    display.py             ← L3 终端监控显示(2026-08-19,用法见 step5_agent/DISPLAY.md)
  data/                    ← 数据契约(纯数据形态,零引擎依赖)
    __init__.py
    artifacts.py           ← Finding schema + 工件存取/摘要 + 宽容 JSON 提取
                             (extract_json_object)/聚合落盘(save_aggregate)/
                             溯源回写(stamp_provenance)/severity 排序表
                             (SEVERITY_RANK)/工件回写(rewrite_artifact)
    prompts.py             ← 三 Agent 系统提示词 + 任务简报构建器
  providers/               ← 外部资源接入(引擎鸭子类型消费)
    __init__.py
    llm_client.py          ← LLM API 客户端(重试机制);测试替身 ScriptedLLM 在 test/scripted_llm.py
    tools/                 ← 工具注册表(附属 providers)
      __init__.py          ← make_tools 装配(exclude 参数 + STEP5_EXCLUDE_TOOLS 环境变量)
      base.py              ← AgentTool 基类 + ToolResult(含 raw 原文)
      cli_base.py          ← 沙箱容器挂载与路径换算
      checksec.py / cve_bin_tool_scan.py / xref_query.py      ← CLI 类
      strings_query.py / imports_query.py / find_decompiled_function.py / read_file.py  ← 读盘类
      list_files.py / search_code.py  ← 读盘类(目录铺面 / 边车+文本混合检索)
      cve_lookup.py        ← API 类(NVD)
      semgrep_scan.py      ← CLI 类(semgrep 本地规则,2026-08-18)
      gitleaks_scan.py     ← CLI 类(gitleaks,2026-08-18)
      sandbox_verify.py    ← CLI 类(verification 沙箱复核,2026-08-18)
      binwalk_rescan.py    ← CLI 类(binwalk 签名复扫+专用镜像回退,2026-08-18)
      web_search.py        ← API 类(DDG 免 key,2026-08-18)
      rules/semgrep_security.yaml  ← semgrep 本地规则(离线)
  demos/                   ← 演示脚本子包(ADR-0009 T6 自顶层迁入)
    demo_display.py        ← 终端显示演示(python -m firmware_audit.step5_agent.demos.demo_display)
```

依赖规则:run\_step5 → orchestration → runner/aggregator 接线;orchestration → engine/data/providers;engine、data、providers 三个包互不 import 也不向上(runner 永不 import orchestration);tools 附属 providers(与 llm\_client 并列,同属"外部能力提供方")。分层规则由 AST 守护测试机器强制(`test_step5_layer_guard.py`,ADR-0009)。

### 核心抽象:ToolResult + AgentTool

**ToolResult 是一个数据口袋**,不关心数据来源。ReAct 循环只消费这个口袋,每个工具子类负责填:

```python
@dataclass
class ToolResult:
    ok: bool                 # 退出码/文件存在/API 200
    text: str                # 给 LLM 看的文本,≤16000(基类 max_text_chars 可覆盖,见下),超长截断(头75%+尾20%+提示)
    data: dict | list | None # 结构化结果(有 JSON 就解析,没有就 None)
    error: str | None
    elapsed: float
    raw: str                 # 截断前原文(execute 统一填充;全文落盘 obs/ 用)

class AgentTool(ABC):
    name: str                # LLM 调用名,如 "checksec"
    description: str         # 写进系统提示词
    params: dict[str, dict]  # 结构化参数声明(单一来源,ADR-0004)
                             #   参数名 → {type: str/int/bool, required, default, enum}
    @property
    def params_doc(self) -> str:  # 从 params 渲染的 LLM 可读规格(含 JSON 骨架)
        ...
    def execute(self, **kw) -> ToolResult:
        # 先 validate_params(self.params, kw)(未知键/类型错/缺失必选 → 优雅错误),
        # 校验通过才 _run。见 docs/adr/0004-step5-interface-contract.md
        ...
```

**工具分两类,填袋方式不同,但袋子一样:**

| 类型     | 工具                                                                                                           | 数据来源                                                 | `ok` 判据  | `text`    | `data`                             |
| ------ | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------- | -------- | --------- | ---------------------------------- |
| CLI 工具 | checksec, cve\_bin\_tool\_scan, xref\_query, semgrep\_scan, gitleaks\_scan, sandbox\_verify, binwalk\_rescan | `subprocess` 调 Docker 沙箱 / binwalk 专用镜像              | 退出码 0    | stdout 截断 | JSON 解析(有 `--json` 就 `json.loads`) |
| 读盘工具   | strings\_query, imports\_query, find\_decompiled\_function, read\_file, list\_files, search\_code            | Step4 产出的 `analysis/*.json` / `*.c`,或 `process/` 下文件 | 文件存在且读成功 | 文件内容截断    | None(文本即内容)                        |
| API 工具 | cve\_lookup, web\_search                                                                                     | `urllib` 调 NVD / DDG HTML                            | HTTP 200 | 格式化摘要     | 原始 JSON / 检索结果                     |

**关键:find\_decompiled\_function 不重新调 Ghidra。** Step4 已经把反编译 C 代码落到 `analysis/<rel>.c`,find\_decompiled\_function 的 `execute(file_ref, func_name)` 只需要:

1. 根据 `file_path` 定位 `analysis/<rel>.c`
2. 用行号范围或函数签名正则切出目标函数片段
3. 填进 `ToolResult(text=func_body, ok=True)` —— 和 checksec 填袋子的方式一模一样

ReAct 循环不感知数据来源。它对 LLM 说的永远是:"给你一个 Observation,它是某工具的输出文本,你据此推理下一步。"

### 接入模型(按运行位置分层)

| 层     | 工具                                                                                                | 运行位置                                                     | 镜像                                                                   |
| ----- | ------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | -------------------------------------------------------------------- |
| 读盘层   | strings\_query, imports\_query, find\_decompiled\_function, read\_file, list\_files, search\_code | 宿主机 Python(读 `analysis/*.json` / `*.c` 或 `process/` 下文件) | 无                                                                    |
| API 层 | cve\_lookup, web\_search                                                                          | 宿主机 Python(`urllib`)                                     | 无                                                                    |
| CLI 层 | checksec, cve\_bin\_tool\_scan, xref\_query, semgrep\_scan, gitleaks\_scan, sandbox\_verify       | `firm_audit/sandbox` 容器                                  | sandbox(已装 checksec/cve-bin-tool/r2/semgrep 1.100.0/gitleaks 8.18.2) |
| CLI 层 | binwalk\_rescan                                                                                   | `binwalk` 容器(extracted 只读挂载扫签名)                          | binwalk(专用,保留不动)                                                     |

沙箱安全基线(2026-08-18 落实):`run_docker` 支持挂载第三段 `ro/rw` 与 `network` 参数;Step5 全部 Agent 工具调用统一 **extracted** **`:ro`** **挂载 +** **`--network none`** **断网**(run\_in\_sandbox/binwalk\_rescan 已接线;extra\_mounts 保持 rw——cve\_bin\_tool\_scan 的 CVE 缓存卷需写锁)。Step3/Step4 调用不受影响(默认 rw + 默认网络)。

### cve-bin-tool 3.4 参数坑(2026-08-17 实测,08-22 预热实测补全)

cve\_bin\_tool\_scan 与 CVE 库预热都必须带齐三个禁用参数,缺一即崩:

* `--disable-data-source PURL2CPE`:建库时 `populate_purl2cpe` 报 `no such table: purl2cpe`(3.4 bug)

* `--disable-version-check`:自检新版本访问 PyPI,无外网时 `version.py` 里 `None.splitlines()` 直接 AttributeError

* `--offline`(仅扫描):跳过 NVD 增量更新,省每次扫描数分钟的限速等待;库由 `.cve_cache` 卷预热维护

预热命令 + 三个已踩实测坑(2026-08-22,缺一即失败,详见 tools\_summary.md):

```powershell
docker run --rm --entrypoint cve-bin-tool `
  -v "target\<N>\process\.cve_cache:/home/sandbox/.cache" `
  firm_audit/sandbox:latest -l info `
  --disable-version-check --disable-data-source PURL2CPE -u now /tmp
```

1. **必须带目录参数(`/tmp`)** — 仅 `-u now` 缺目录会报 `InsufficientArgs`(码 24),更新完不建库即退出
2. **挂到** **`$HOME/.cache`(父目录),不是** **`~/.cache/cvedb`** — 3.4 的 `CVEDB.CACHEDIR = ~/.cache/cve-bin-tool`,挂 cvedb(旧约定)会让库永远找不到(码 40 `Database does not exist`);cve\_bin\_tool\_scan 的 `CVE_CACHE_MOUNT` 已是 `/home/sandbox/.cache`
3. **别把** **`cve-bin-tool`** **目录本身当挂载根** — `-u now` 首步 `clear_cached_data` 要 `rmtree` 挂载根,报 `Device or resource busy`

> 工具参数:扫描用 `--format json -o -`(3.4 默认把 JSON 写文件而非 stdout,`-o -` 让 JSON 到 stdout 供解析);`-o -` 下 0 命中时 stdout 为空,工具视作"无 CVE"而非错误。

sandbox 镜像现状(2026-08-18 更新):`firm_audit/sandbox:latest` 已是压扁镜像(四工具 + Ghidra 实跑全检 ALL-PASS,见 verify\_agent\_tools.sh),旧 9.53GB 层与 `:flat` 中间 tag 已清理,工具层统一引用 `latest`。ENTRYPOINT 仍是 `analyzeHeadless`,调工具必须 `run_docker(..., entrypoint="checksec")` 覆盖。**binwalk 刻意不进 sandbox**(2026-08-18 实测:pip 版是停更的 2.1.0,py3.11 import 即崩;v3 Rust 二进制需 GLIBC 2.39 而 bullseye 只有 2.31),binwalk\_rescan 走专用镜像。另外:全量重建主 Dockerfile 会重编译 radare2 且其构建要 git clone vector35-arch-\*(GitHub 被掐断 Error 128)——增量改动用 `Dockerfile.binwalk` 式派生层(见文件头注释)。

### 工具清单(15 个)

| 工具                         | 类型  | 底层                                                                        | 输出                         | 归属 Agent               |
| -------------------------- | --- | ------------------------------------------------------------------------- | -------------------------- | ---------------------- |
| `list_files`               | 读盘  | pathlib 枚举目录(白名单 + SDK 目录排除 + max\_files 截断)                              | 目录/文件清单                    | recon 首动铺面;全 Agent     |
| `search_code`              | 读盘  | 边车索引(strings/imports/text.json)+ extracted+analysis 文本 grep 双路检索('.'/缺省=两棵内容树并集;agent//.cve\_cache 拒绝) | 命中列表(带地址/行锚点)              | analysis, verification |
| `checksec`                 | CLI | slimm609/checksec `--format=json`                                         | RELRO/NX/PIE/Canary JSON   | recon, verification    |
| `cve_bin_tool_scan`        | CLI | cve-bin-tool `--format json -o -`                                         | 已知 CVE 清单                  | recon(**可选**,见下)       |
| `strings_query`            | 读盘  | 读 `analysis/*.strings.json` + 正则                                          | URL/IP/密钥/口令命中             | recon, analysis        |
| `imports_query`            | 读盘  | 读 `analysis/*.imports.json`                                               | 危险函数及 call\_sites          | recon, analysis        |
| `find_decompiled_function` | 读盘  | 读 `analysis/*.c`,切函数片段                                                    | 单个函数 C 代码                  | analysis, verification |
| `xref_query`               | CLI | radare2 `axtj`(JSON 输出)                                                   | 交叉引用链                      | analysis, verification |
| `cve_lookup`               | API | NVD REST API 2.0                                                          | CVSS/POC 可用性               | analysis, verification |
| `read_file`                | 读盘  | pathlib 读 `process/` 下文件(路径白名单)                                           | 工件细节片段 ≤16000 字符           | 全部(跨 Agent 回查机制)       |
| `semgrep_scan`             | CLI | semgrep 1.100.0 + 本地规则 `tools/rules/semgrep_security.yaml`(离线,不用 p/ 网络规则) | 脚本语义漏洞(命令注入/SQLi/反序列化);'.' 双扫 analysis 反编译 C 危险调用(strcpy/sprintf/gets/system 等,仅 \*.c) | recon, analysis        |
| `gitleaks_scan`            | CLI | gitleaks 8.18.2 `detect --no-git`(单容器 detect+cat 报告)                      | 硬编码密钥/凭据                   | recon, analysis        |
| `sandbox_verify`           | CLI | 沙箱跑复核脚本(仅 python3/node/php 白名单解释器,网络隔离,extracted 只读)                      | Fuzzing Harness/PoC 动态验证输出 | verification           |
| `binwalk_rescan`           | CLI | binwalk 专用镜像签名复扫(只识别不落盘解包)                                                | 嵌套容器签名表                    | recon                  |
| `web_search`               | API | DuckDuckGo HTML(免 key;复用 NVD 无 key 节流)                                    | 公开漏洞/公告检索结果                | analysis               |

> 工具重命名(2026-08-19 错误研究 E1/E6 落地,与 OBS-ERRORS-RESEARCH 一致):`sca_scan`→`cve_bin_tool_scan`、`decompile_func`→`find_decompiled_function`(强调"检索已反编译产物"而非反编译)、`secret_scan`→`gitleaks_scan`(与底层工具同名)。旧名在旧文档/旧测试引用出现时均指代新名。

工具可选化(2026-08-18):`make_tools(ctx, exclude={"cve_bin_tool_scan", ...})` 按 name 排除;未显式传 exclude 时读环境变量 `STEP5_EXCLUDE_TOOLS`(逗号分隔)。cve\_bin\_tool\_scan 对嵌入式交叉编译库误报偏多,可运行时关闭不删代码。

### 实测踩坑(2026-08-18)

* shell 命令模板**禁用** **`.format`/f-string 拼接**:`${rc}` 里的 `{rc}` 会被 str.format 当占位符抛 `KeyError: 'rc'`(secret\_scan 实测),一律纯字符串拼接

* 两次 `run_in_sandbox` 是两个独立容器,`/tmp` 不共享——报告文件必须**单容器内** **`工具 && cat`** **一条龙**

* semgrep 本地规则:YAML 双引号里 `\$` 是非法转义(用单引号包 pattern);单条 pattern 解析失败会让整个 config 报 invalid,脆弱的 PHP 拼接 pattern 用 `pattern-regex` 兜底

* CLI 工具传参必须先经 `container_path` 换算成 `/work/extracted/...` 容器绝对路径(容器 workdir 不在挂载点,相对路径必挂)

* **Windows 下** **`subprocess.run(text=True)`** **必须显式** **`encoding="utf-8", errors="replace"`**(2026-09-03,semgrep\_scan/gitleaks\_scan 实测):不指定 encoding 按进程 locale(gbk)解码容器输出,非法字节让 readerthread 抛 `UnicodeDecodeError` **后主进程拿到 stdout=None** → 下游 `json.loads(None)` TypeError。修复点:`docker_utils.run_docker`/`docker_available` + `test_decompile.py`;回归测试 `test_docker_utils.py::test_*_utf8_decode`(monkeypatch 捕获 kwargs 断言显式 encoding + 真实子进程输出非法字节验证不崩)。注意 Anaconda 默认 UTF-8 mode 与系统 gbk 两种 locale 形态崩的编码名不同,断言契约而非错误文本才能都抓红

* **search\_code 范围守卫:`directory` 拒绝根目录/`agent/`/`.cve_cache`**(2026-09-03,target/1 卡死事故实测根因):verification 实例因 finding 的 file 路径缺 `extracted/` 前缀连撞"目录不存在"后,改调 `search_code(directory=".")` 自救——`resolve_within` 按 containment 语义放行根目录,grep 范围扩成整个 `process/`,把 `.cve_cache`(cve-bin-tool 预热缓存卷,**10.7万 json/yml,两个扩展名都在 \_TEXT\_EXTS 白名单**)卷进逐文件 open+读+正则,实测热缓存 ~2000 文件/s、Defender 放大后崩到 ~50 文件/s,数十分钟无输出被人工 Ctrl+C。修复:`_resolve_scope` 三类范围返回拒绝原因,`_run` 对拒绝**无条件报错**(有边车命中也不静默吞),错误信息带"请指定 extracted/ 或其子目录"指引;回归测试 `test_step5_tools.py::test_search_code` 守卫段。**2026-09-04 语义重定义(用户定稿)**:根目录/缺省不再拒绝,改为 **extracted/ + analysis/ 两棵内容树的并集**(白名单并集替代黑名单,`.` 从此=全部审计内容,.cve\_cache/agent 结构性不可达);显式子目录限两棵树内(树名 `extracted`/`analysis` 即该树根);agent//.cve\_cache 显式指定仍拒绝。配套 semgrep\_scan '.' 双扫(见上表)。教训两条:①终端转储等运行文件**别存进 `process/agent/`**(在 grep 树里会命中 Agent 自身日志,本次诊断中它还让复现 harness 撞满 max\_results 提前返回、造成假阴性);②上游触发器(verification 反复撞"目录不存在"浪费轮次)**已由 ADR-0008 处理**(见 Step5 章节"路径口径统一为工具路径",2026-09-03 同日落地)

### 第二批工具(后续)

* ~~`binwalk_rescan`~~ ~~/~~ ~~`semgrep_scan`~~ ~~/~~ ~~`web_search`~~ 已落地(2026-08-18,见上表)

### 暂缓(动态验证类,二期以后)

* `qiling_emulate` / `frida_hook` — 全系统仿真成本高、成功率不稳定,等静态漏斗跑顺再上

## 四、已定决策与开放问题

已定决策见下方各小节(输出协议 / LLM 接入 / 上下文管理 / transcript / 类结构)。当前真正开放:

* token 预算——迭代上限已按 Agent 固化(recon 20 / analysis 30 / **verification 每实例 8**,2026-08-29 / 09-01 ADR-0003 调整),预算充裕度待 `target/1` 实测校准(冒烟单任务 \~10k token)

* ~~deepseek-v4-flash 的协议遵循度~~ **已验证(2026-08-17 冒烟)**:推理模型,`reasoning_content`/`content` 分离,LLMClient 已合并处理;ReAct 遵循良好,5 步自主完成 imports→xref→decompile 工具链

* 误报抽检口径(verification 过滤后人工抽检比例与判定标准)

* MCP 化时机:先函数注册表,跑顺后再包 MCP

### 已定:输出协议 = 纯文本 ReAct(2026-08-17,DeepSeek 实测)

不用 function calling,定纯文本 ReAct(`Thought:/Action:/Action Input:/Final Answer:` 正则解析 + 解析失败报错回喂重试 ≤2 次)。实测依据(DeepSeek API,key/baseurl 走环境变量,测试脚本已删):

| 协议               | 模型                | 结果               | token                |
| ---------------- | ----------------- | ---------------- | -------------------- |
| 纯文本 ReAct        | deepseek-chat     | 格式完美,正则一次解析      | 178                  |
| function calling | deepseek-chat     | 正常返回 tool\_calls | 420(tools schema 开销) |
| 纯文本 ReAct        | deepseek-reasoner | 格式完美,正则解析 OK     | 425                  |

决定性理由:**deepseek-reasoner 不支持 tools 参数**,选 function calling 会把推理模型排除在 per-agent 选型之外;纯文本 ReAct 两类模型都严格遵循,且 token 开销约低一半、ScriptedLLM 离线测试零成本。

### 已定:LLM 接入(2026-08-17)

* OpenAI 兼容 `/chat/completions`,urllib 实现,不硬编码任何供应商

* 配置走环境变量:`FIRMWARE_AUDIT_LLM_BASE_URL` / `FIRMWARE_AUDIT_LLM_API_KEY` / `FIRMWARE_AUDIT_LLM_MODEL`,AgentConfig 可按 agent 覆盖 model

* **默认模型** **`deepseek-v4-flash`**:全部 agent 与压缩函数统一使用,AgentConfig.model 可覆盖

* **流式与否:MVP 用非流式(`stream=false`)**。理由:ReAct 循环必须拿到完整回复才能正则解析,流式的首字延迟收益对机器对机器调用为零;非流式一次 request/response + json.loads,无 SSE 分块拼接/usage 末包/stream\_options 边界;失败重试语义干净(流式中途断连已烧 token 白费);输出预算由 max\_tokens 硬限。LLMClient 预留 stream 参数默认 false,二期做 CLI 实时 Thought 滚动或 MCP 进度反馈时再实现 SSE 解析,不提前写

* API 参数:超时 180s、temperature 0-0.2、deepseek-reasoner 固定 temperature=1(API 要求)

* 重试机制(2026-08-18):首次失败按错误类型分流——可重试(网络瞬断/超时/HTTP 5xx/429/空回复/响应非 JSON)按 `RETRY_INTERVALS=(10,15,20)s` 间隔自动重试至多 `MAX_RETRIES=3` 次,每次向 stderr 输出带时间戳日志(`[llm-retry]` 前缀:错误类型+重试次数+等待时长),重试后成功也打点;不可重试(HTTP 400/401/403/404)立即抛不重试;全部失败抛携带最终错误详情的 LLMError(→ Step5 终止)。单测 `test_step5_llm.py` 打桩 urlopen/sleep 零真实等待

* **token 预算与截断续写(2026-09-01,ADR-0005,ticket 02)**:`DEFAULT_MAX_TOKENS` 由 16384 提至 **32768**(env `LLM_MAX_TOKENS` 可覆盖,`_client()` 读取)。deepseek-v4-flash 是推理模型,`reasoning_content`(思考)与 `content`(正文)分占 token 预算——思考烧满时 content 为空、`finish_reason=stop`,`chat()` 不再当空回复硬重试,而是**截断续写**:把 reasoning 拼回 assistant 消息回传 API + "直接给最终答复,别展开思考"提示,用原 max\_tokens 再调一次;续写只回传 API 接续,**不进 ReAct 上下文/长期记忆**(对上层透明,上层仍只拿 content);续写请求失败(400 等)→ 降级为普通重试,不阻塞。单测 `test_step5_llm.py::test_empty_content_with_reasoning_continuation` / `test_continuation_failure_degrades_to_retry`。见 `docs/adr/0005-step5-llm-token-and-continuation.md`

* key 永不写入代码或提交仓库;测试用 key 已在对话中暴露,建议测试期结束后在 DeepSeek 后台轮换

### 已定:上下文管理与压缩(2026-08-17)

每个 Agent 的 messages\[] 四分区:系统提示词(永不压缩)/ 任务简报(前序最终报告+工件索引,永不压缩)/ 概括区(压缩摘要,触发时滚动更新)/ 保留区(最近 K 轮原文)。

* 触发:每轮结束估算总字符数(零依赖,**统一 1 token ≈ 2 字符**,`est_tokens = 总字符数 // 2`,够触发判断即可不追求精确)。阈值(2026-08-18 上调):v4-flash 上下文窗口 1M,`window × 0.6 = 600k` est tokens 触发(原 60k 窗口 × 0.65 = 39k),留 40% 余量给单轮 Observation 峰值与概括回写;规模化稳定性有单测守护(`compact_at_600k_threshold`,\~700k est tokens 触发/边界对齐/构建)

* 压缩函数:复用默认模型 deepseek-v4-flash(AgentConfig.model 可覆盖为更便宜型号),概括保留区最老若干轮,摘要写回概括区、原文删除;概括 prompt 保留四类信息:已确认事实/已排除项/未决问题/证据指针(工件路径)

* 不丢证据(2026-08-18 补齐;预算 2026-09-06 票01 由 8KB 上调):Observation 入上下文 ≤16000 字符(工具基类 `max_text_chars` 可覆盖,summarize 素材 64k)**头尾保留截断**(头 75%+尾 20%,学 DeepAudit:提示注明省略字符数与全文总长);**原文全文落盘** `process/agent/<name>/obs/step<N>_<tool>.txt`(`ToolResult.raw` 保留截断前原文;>4k 字符单行软折行保 read\_file 行分页可用);**截断时 Observation 末尾自动附具体回读路径**(相对 process/,与 read\_file 白名单同根),LLM 可自主 `read_file` 分页取回省略的中间段——闭环有端到端测试(`obs_readback_via_read_file`)

* 兜底:压缩调用失败不重试,直接丢弃最老轮次(失败不崩)

* 跨 Agent 不带对话,只传最终报告(与工件交接一致)

### 已定:transcript 落盘与测试(2026-08-17)

* `process/agent/<agent名>/transcript.jsonl`,每行记 role/content/工具名/耗时/原始结果路径

* **记录忠实化(2026-09-06 票02)**:transcript=实际所见——记录层零截断,observation 事件 content 含 `Observation: ` 前缀、与进上下文的 user 消息逐字一致,assistant 事件含 reasoning+reply;`obs/`=截断前工具原文。二者互补:排查截断类事故两份都要看

* `ScriptedLLM`(按脚本回放假回复)让 run\_react\_agent 全链路单测零 API 消耗

* 迭代兜底:达上限注入一次性"必须立即 Final Answer"收尾调用,不允许静默退出;token 预算超限同样强制收尾

### 已定:Agent 类结构(2026-08-17)

**不拆三个 Agent 子类**——三个 agent 只差 system prompt / 工具集 / 输入输出工件,循环逻辑完全一致,用一个 `run_react_agent(cfg: AgentConfig, ctx)` 函数 + 三个 `AgentConfig` 实例即可。未来某 agent 演化出不同循环行为时再拆子类。

**工具层:AgentTool 基类 + 每工具一个子类**。基类保留 name / description / **结构化** **`params`**(参数名→type/required/default/enum 声明)+ 渲染的 `params_doc` 属性 + `execute(**kw) -> ToolResult` 统一入口(先 `validate_params` 校验、计时/异常捕获/结果截断)。子类分 CLI/读盘/API 三种,**各自只实现** **`_run`**(CLI 构建命令/解析在 `cli_base` 与 `_run` 内;读盘直读工件;API urllib)。详见[三、工具层实现](#三工具层实现)。

**Agent 间传递:JSON 工件文件是唯一契约**,dataclass 是 Python 侧的宽容访问层:

```python
@dataclass
class Finding:
    title: str
    severity: str = "info"
    file: str = ""; func: str = ""; addr: str = ""
    evidence: str = ""; cve: str | None = None
```

* 磁盘 JSON = 人可读、可断点续跑、可 diff,与 `.step1_done` 标记模式一脉相承

* dataclass = `from_json` 缺字段给默认值、只降级不崩溃(不引 pydantic,守住零新依赖)

* 下游 Agent 初始 prompt 只注入摘要 + 工件路径,细节用 read\_file 工具按需拉取(不把整个 survey.json 塞进对话)

## Agent skills

### Issue tracker

工单以本地 markdown 存放:`.scratch/<feature>/issues/`(一票一文件,编号从 01 起;`Status:` 行记 triage 状态,评论追加在文件底部 `## Comments` 下)。详见 `docs/agents/issue-tracker.md`。

### Triage labels

默认五角色词表,标签字符串=角色名:needs-triage / needs-info / ready-for-agent / ready-for-human / wontfix。详见 `docs/agents/triage-labels.md`。

### Domain docs

单上下文布局:根 `CONTEXT.md` + `docs/adr/`。详见 `docs/agents/domain.md`。


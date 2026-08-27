# 流水线角色与 Agent 工具层

固定 5 步流水线。Step1-4 已实现并验证通过(代码控制);Step5 架构已定(2026-08-16):三个 ReAct Agent 串行(recon → analysis → verification),无 orchestrator,控制流由 Python 硬编码。

## 一、已落地:Step1-4 流水线角色

### Step1 — Extractor(解包)

- **职责**:把固件包解包成可浏览的文件目录
- **输入**:`target/<N>/` 下的固件文件(归档/单文件压缩/磁盘镜像三种路径)
- **输出**:`target/<N>/process/extracted/` 目录
- **工具**:binwalk v3(Docker 镜像 `binwalk`)+ 引导解包器 `step1_guided_extract.py`
- **实现**:`firmware_audit/step1/`,含 `step1_extract.py`(常规)、`step1_guided_extract.py`(scan_tree 模式,处理嵌套容器)、`file_magic.py`
- **断点续跑**:`.step1_done` 标记存在则跳过,需手动删标记 + `guided_extract.json` 才能重测
- **验证**:输出目录存在且含文件 ✓

### Step2 — Filter(过滤)

- **职责**:排除标准 Linux 系统文件,保留该审计的内容
- **输入**:`extracted/` 目录
- **输出**:通过过滤的文件路径列表
- **工具**:Python pathlib + 白/黑名单(见 `profiles/nano-ubuntu.yaml`)
- **实现**:`firmware_audit/step2/step2_filter.py`
- **规则**:黑名单含 `usr/local/lib`(过滤 Python SDK);白名单含 `home/unitree/` 全部、`etc/` 下敏感配置、所有证书
- **验证**:home/unitree 全保留,系统库全排除 ✓

### Step3 — Classifier(分类)

- **职责**:按文件类型分流到不同处理路径
- **输入**:过滤后的文件路径列表
- **输出**:`List[FileInfo]`,每个文件标注 type
- **工具**:`file` 命令(Docker binwalk 镜像)
- **实现**:`firmware_audit/step3/step3_classify.py`
- **分类**:`elf_exec` / `elf_lib` / `script` / `source` / `config` / `text` / `crypto_*` / `unknown`
- **原则**:硬编码分类,不用 LLM
- **验证**:统计各类型数量,与 file 输出交叉验证 ✓

### Step4 — Decompiler(反编译/提取)

- **职责**:把二进制转成可审计的信息,文本类直接读
- **输入**:`List[FileInfo]`
- **输出**:填充 `decompiled_path` / `analysis_path` / `ghidra_status` / `audit_status`
- **实现**:`firmware_audit/step4/step4_decompile.py` + `triage.py`
- **工具**:
  - ELF → Ghidra Headless(Docker 镜像 `ghidra`,带 `-analysisTimeoutPerFile 300`,**空格分隔形式**,`=` 形式会被当文件参数)
  - 文本/脚本/源码 → Python `open()` + `_TEXT_PATTERNS` 扫描
  - ELF 硬编码 → 宿主侧读 strings.json 复用 `_TEXT_PATTERNS`
  - 证书 → `cryptography` 库按 crypto_* 类型 dispatch(零依赖铁律的既有例外:可选依赖,缺库降级跳过证书解析)
- **Ghidra 提取**(ExtractInfo.py v2):反编译 C + 函数列表+调用关系 + Imports(call_sites) + Symbols + 字符串表(refs) + meta
- **产出位置**(合并目录 `analysis/`):`<rel>.c` + `<rel>.{functions,imports,symbols,strings,meta,text,crypto}.json`
- **版本续传**:decompiled.c 头部 `extractinfo_version` 校验,旧产物自动失效重跑
- **验证**:29 个 ELF 全部反编译,12 个检出硬编码(带 address/refs)✓

### Step5 — Agent 审计(已实现,2026-08-17)

- **实现与分层(2026-08-18 目录重组)**:`firmware_audit/step5_agent/` 子文件夹按并列/附属关系组织——顶层 `run_step5.py`(L0 入口,`python -m` 路径不变)+ `runner.py`(L1 编排)+ 三个自包含包:`engine/`(ReAct 执行引擎:react_loop 状态机 + protocol 纯函数解析 + context 四分区 + transcript 落盘)、`data/`(数据契约:artifacts 工件 schema + prompts 提示词)、`providers/`(外部接入:llm_client + tools/ 8 件套)。依赖只准向下:runner/run_step5 接线,engine/data/providers 互不 import、包内走相对导入。重构纪律:**只搬迁不改行为**(全套件 98 passed 与基线一致)
- **编排**:三 `AgentConfig`(recon 20 轮 / analysis 24 轮 / verification 24 轮)共用一个 `run_react_agent`;串行 recon→analysis→verification,只经工件文件交接
- **工件链**:`process/agent/attack_surface.json → findings.json → verified_findings.json + report.md`(带 `schema: 1` 版本号;JSON 解析失败降级 `.md`,断点续跑两者均认完成)
- **终止策略**:无 API key 或 API 调用失败时立即终止(抛 `LLMError`),不产出降级工件、不执行规则模式
- **报告**:`render_report` 确定性渲染(不依赖 LLM 输出格式),verified=false 进"误报剔除"节
- **接入**:main.py Step1-4 后自动跑 Step5(`--no-step5` 跳过);`step5_run` 接受 target/<N> 或工作区目录(分区子工作区通用);也可 `python -m firmware_audit.step5_agent.run_step5 <dir>` 独立补跑
- **验证**:test_step5_pipeline.py 7 项全绿(artifacts 宽容解析 / 四分区压缩边界与失败还原 / ScriptedLLM 三 Agent 全链路 / 断点续跑零调用 / read_file 工具分发)✓
- **测试基建(2026-08-18)**:`test/conftest.py` 提供 `process_dir`/`tools` fixture(工件缺失 SKIP),cli_tools 本地覆盖加 Docker 门控、smoke 本地 `llm` 门控(STEP5_SMOKE+key+工件);`pytest_pyfunc_call` 钩子把双模式测试的非空 fails 列表判 FAILED(消灭假绿)。全套件 96 passed + 2 skipped(含权限矩阵/600k 压缩阈值/tool_calls 统计守护)。双模式测试新增形参必须同步补 conftest fixture,详见 `firmware_audit/BUGFIX-2026-08-18-step5-test-fixtures.md`
- **配置调整(2026-08-18)**:analysis 补授 `checksec`(可利用性定级需保护机制事实),verification 补授 `strings_query`/`imports_query`(复核硬编码/危险导入类 finding 免经 read_file 绕行);`step5_run` summary 各阶段纳入 `steps`/`tool_calls`(按工具名计数),全局合计 `tool_calls`;工具权限有守护测试(`tool_permissions_and_threshold`)

## 二、已定:Step5 Agent 架构(2026-08-16)

三 Agent 串行,无 orchestrator,ReAct 模式(类 DeepAudit 分段思路)。

### 控制流(Python 硬编码)

```python
def step5_agent(ctx):
    surface  = run_react_agent(RECON_CFG, ctx)               # → process/agent/attack_surface.json
    findings = run_react_agent(ANALYSIS_CFG, ctx, surface)   # → process/agent/findings.json
    report   = run_react_agent(VERIFY_CFG, ctx, findings)    # → process/agent/report.md
```

不用 LLM 做调度,串行顺序写死;每个 Agent 内部才是 ReAct 自主循环。

### Agent 职责与工具分配

| Agent | 职责 | 工具 | 输入 | 输出工件 |
|-------|------|------|------|---------|
| **recon** | 广度侦察:铺开攻击面 | checksec, cve_bin_tool_scan(可选), strings_query, imports_query, read_file, semgrep_scan, gitleaks_scan, binwalk_rescan | Step4 工件清单 | `attack_surface.json`(组件+CVE、危险函数热点、硬编码疑点、弱保护二进制) |
| **analysis** | 深度分析:对疑点逐个取证 | find_decompiled_function, xref_query, strings_query, imports_query, read_file, cve_lookup, checksec, semgrep_scan, gitleaks_scan, web_search | attack_surface.json | `findings.json`(候选漏洞,含证据链:路径+地址+代码片段+严重度) |
| **verification** | 复核过滤误报,出报告 | find_decompiled_function, xref_query, cve_lookup, checksec, read_file, strings_query, imports_query, sandbox_verify | findings.json | `verified_findings.json` + `report.md` |

### ReAct 循环约定

- 每 Agent 一个 while 循环:LLM 输出 Thought/Action → 执行工具 → Observation 回填 → Final Answer 终止
- **迭代上限 15-25 次**,防死循环烧预算
- **Observation 截断**:单条工具结果 ≤ 8KB 入上下文,全文落盘供后续查询
- 工具失败不终止:Observation 返回错误信息,Agent 自行换路(继承铁律"失败不崩")
- **循环守卫三件套(2026-08-18,react_loop,学 DeepAudit 实测坑)**:
  - 同参空转拦截: 同一工具+完全相同参数(规范化 kwargs 键)第 4 次起不执行,回喂 `[系统干预]` 提示(改参数/换工具/收尾三选一)
  - 工具先行: 零工具调用就输出 Final Answer → 拒绝退回(`[系统拒绝]`,限 1 次,模型坚持则放行防死锁);强制收尾轮不受限
  - 防幻觉纪律入提示词: verification 硬规定"read_file 报文件不存在 → 该 finding 必判 false_positive,禁止猜路径";三 Agent 提示词对标 DeepAudit 五段式重写(角色/锚点/工作流+判定规则/协议+schema/纪律)
- **终端监控显示(2026-08-19)**: `engine/display.py` 观察者层,react_loop 7 个事件点 + runner stage/done 喂事件,Claude Code 风格打印思考/调用/结果/系统干预;`display=None`/NullDisplay 零侵入(有 `display_none_no_regression` 守护)。配置 `STEP5_DISPLAY=0|compact|full`、`STEP5_COLOR=0|1`(终端自动开色,管道自动无色)。demo:`python -m firmware_audit.step5_agent.demo_display`;详见 step5_agent/DISPLAY.md

### 交接约定

- Agent 间**只通过工件文件交接**,不传对话历史(上下文隔离)
- 工件为 JSON,带 schema 版本号
- 断点续跑:工件存在且 schema 匹配则跳过该 Agent(仿 `.step1_done` 思路)

### 终止策略(无 API key / API 调用失败)

Agent 审计不设规则降级:无 API key(`LLMClient.available == False`)或
API 调用失败(`LLMClient.chat` 重试耗尽抛 `LLMError`)时,立即终止当前
Step5 流程,不产出任何替代工件(无 attack_surface/findings/report)。

- `step5_run` 无 key → `raise LLMError`,由 main.py / run_step5.main 捕获打印"终止"
- `run_agent` 接到 `LLMError` 立即向上重抛(不吞),中断后续 Agent 链条
- Step1-4 已完成的固件分析结果不受影响

## 三、工具层实现

### 目录结构(2026-08-18 子文件夹重组:并列/附属关系入目录)

```
step5_agent/
  __init__.py              ← 对外只暴露 step5_run
  run_step5.py             ← L0 总控入口(python -m 路径不变)
  runner.py                ← L1 单 Agent 编排(AgentConfig × 3 + run_agent + render_report)
  engine/                  ← ReAct 执行引擎(自包含,包内相对导入)
    __init__.py            ← 再导出 run_react_agent / ReactResult
    react_loop.py          ← L2 状态机(解析→分发→回喂→收尾;display 钩子)
    protocol.py            ← L3 纯函数协议解析(正则,零 IO)
    context.py             ← L3 四分区上下文 + 600k 阈值压缩
    transcript.py          ← L3 Transcript(JSONL 事件流 + obs/ 全文落盘)
    display.py             ← L3 终端监控显示(2026-08-19,用法见 step5_agent/DISPLAY.md)
  data/                    ← 数据契约(纯数据形态,零引擎依赖)
    __init__.py
    artifacts.py           ← Finding schema + 工件存取/摘要
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
      cve_lookup.py        ← API 类(NVD)
      semgrep_scan.py      ← CLI 类(semgrep 本地规则,2026-08-18)
      gitleaks_scan.py     ← CLI 类(gitleaks,2026-08-18)
      sandbox_verify.py    ← CLI 类(verification 沙箱复核,2026-08-18)
      binwalk_rescan.py    ← CLI 类(binwalk 签名复扫+专用镜像回退,2026-08-18)
      web_search.py        ← API 类(DDG 免 key,2026-08-18)
      rules/semgrep_security.yaml  ← semgrep 本地规则(离线)
```

依赖规则:runner/run_step5 接线;engine、data、providers 三个包互不 import;tools 附属 providers(与 llm_client 并列,同属"外部能力提供方")。

### 核心抽象:ToolResult + AgentTool

**ToolResult 是一个数据口袋**,不关心数据来源。ReAct 循环只消费这个口袋,每个工具子类负责填:

```python
@dataclass
class ToolResult:
    ok: bool                 # 退出码/文件存在/API 200
    text: str                # 给 LLM 看的文本,≤8KB,超长截断标 truncated
    data: dict | list | None # 结构化结果(有 JSON 就解析,没有就 None)
    error: str | None
    elapsed: float

class AgentTool(ABC):
    name: str                # LLM 调用名,如 "checksec"
    description: str         # 写进系统提示词
    params_doc: str          # 参数说明,LLM 按此填参
    def execute(self, **kw) -> ToolResult: ...
```

**工具分两类,填袋方式不同,但袋子一样:**

| 类型 | 工具 | 数据来源 | `ok` 判据 | `text` | `data` |
|------|------|---------|----------|--------|--------|
| CLI 工具 | checksec, cve_bin_tool_scan, xref_query, semgrep_scan | `subprocess` 调 Docker 沙箱 | 退出码 0 | stdout 截断 | JSON 解析(有 `--json` 就 `json.loads`) |
| 读盘工具 | strings_query, imports_query, find_decompiled_function | Step4 产出的 `analysis/*.json` / `*.c` | 文件存在且读成功 | 文件内容截断 | None(文本即内容) |
| API 工具 | cve_lookup | `urllib` 调 NVD REST API | HTTP 200 | 格式化摘要 | 原始 JSON |

**关键:find_decompiled_function 不重新调 Ghidra。** Step4 已经把反编译 C 代码落到 `analysis/<rel>.c`,find_decompiled_function 的 `execute(file_ref, func_name)` 只需要:
1. 根据 `file_path` 定位 `analysis/<rel>.c`
2. 用行号范围或函数签名正则切出目标函数片段
3. 填进 `ToolResult(text=func_body, ok=True)` —— 和 checksec 填袋子的方式一模一样

ReAct 循环不感知数据来源。它对 LLM 说的永远是:"给你一个 Observation,它是某工具的输出文本,你据此推理下一步。"

### 接入模型(按运行位置分层)

| 层 | 工具 | 运行位置 | 镜像 |
|----|------|---------|------|
| 读盘层 | strings_query, imports_query, find_decompiled_function | 宿主机 Python(读 `analysis/*.json` / `*.c`) | 无 |
| API 层 | cve_lookup, web_search | 宿主机 Python(`urllib`) | 无 |
| CLI 层 | checksec, cve_bin_tool_scan, xref_query, semgrep_scan, gitleaks_scan, sandbox_verify | `firm_audit/sandbox` 容器 | sandbox(已装 checksec/cve-bin-tool/r2/semgrep 1.100.0/gitleaks 8.18.2) |
| CLI 层 | binwalk_rescan | `binwalk` 容器(extracted 只读挂载扫签名) | binwalk(专用,保留不动) |

沙箱安全基线(2026-08-18 落实):`run_docker` 支持挂载第三段 `ro/rw` 与 `network` 参数;Step5 全部 Agent 工具调用统一 **extracted `:ro` 挂载 + `--network none` 断网**(run_in_sandbox/binwalk_rescan 已接线;extra_mounts 保持 rw——cve_bin_tool_scan 的 CVE 缓存卷需写锁)。Step3/Step4 调用不受影响(默认 rw + 默认网络)。

### cve-bin-tool 3.4 参数坑(2026-08-17 实测,08-22 预热实测补全)

cve_bin_tool_scan 与 CVE 库预热都必须带齐三个禁用参数,缺一即崩:

- `--disable-data-source PURL2CPE`:建库时 `populate_purl2cpe` 报 `no such table: purl2cpe`(3.4 bug)
- `--disable-version-check`:自检新版本访问 PyPI,无外网时 `version.py` 里 `None.splitlines()` 直接 AttributeError
- `--offline`(仅扫描):跳过 NVD 增量更新,省每次扫描数分钟的限速等待;库由 `.cve_cache` 卷预热维护

预热命令 + 三个已踩实测坑(2026-08-22,缺一即失败,详见 tools_summary.md):

```powershell
docker run --rm --entrypoint cve-bin-tool `
  -v "target\<N>\process\.cve_cache:/home/sandbox/.cache" `
  firm_audit/sandbox:latest -l info `
  --disable-version-check --disable-data-source PURL2CPE -u now /tmp
```

1. **必须带目录参数(`/tmp`)** — 仅 `-u now` 缺目录会报 `InsufficientArgs`(码 24),更新完不建库即退出
2. **挂到 `$HOME/.cache`(父目录),不是 `~/.cache/cvedb`** — 3.4 的 `CVEDB.CACHEDIR = ~/.cache/cve-bin-tool`,挂 cvedb(旧约定)会让库永远找不到(码 40 `Database does not exist`);cve_bin_tool_scan 的 `CVE_CACHE_MOUNT` 已是 `/home/sandbox/.cache`
3. **别把 `cve-bin-tool` 目录本身当挂载根** — `-u now` 首步 `clear_cached_data` 要 `rmtree` 挂载根,报 `Device or resource busy`

> 工具参数:扫描用 `--format json -o -`(3.4 默认把 JSON 写文件而非 stdout,`-o -` 让 JSON 到 stdout 供解析);`-o -` 下 0 命中时 stdout 为空,工具视作"无 CVE"而非错误。

sandbox 镜像现状(2026-08-18 更新):`firm_audit/sandbox:latest` 已是压扁镜像(四工具 + Ghidra 实跑全检 ALL-PASS,见 verify_agent_tools.sh),旧 9.53GB 层与 `:flat` 中间 tag 已清理,工具层统一引用 `latest`。ENTRYPOINT 仍是 `analyzeHeadless`,调工具必须 `run_docker(..., entrypoint="checksec")` 覆盖。**binwalk 刻意不进 sandbox**(2026-08-18 实测:pip 版是停更的 2.1.0,py3.11 import 即崩;v3 Rust 二进制需 GLIBC 2.39 而 bullseye 只有 2.31),binwalk_rescan 走专用镜像。另外:全量重建主 Dockerfile 会重编译 radare2 且其构建要 git clone vector35-arch-*(GitHub 被掐断 Error 128)——增量改动用 `Dockerfile.binwalk` 式派生层(见文件头注释)。

### MVP 工具清单(13 个)

| 工具 | 类型 | 底层 | 输出 | 归属 Agent |
|------|------|------|------|-----------|
| `checksec` | CLI | slimm609/checksec `--format=json` | RELRO/NX/PIE/Canary JSON | recon, verification |
| `cve_bin_tool_scan` | CLI | cve-bin-tool `--format json -o -` | 已知 CVE 清单 | recon(**可选**,见下) |
| `strings_query` | 读盘 | 读 `analysis/*.strings.json` + 正则 | URL/IP/密钥/口令命中 | recon, analysis |
| `imports_query` | 读盘 | 读 `analysis/*.imports.json` | 危险函数及 call_sites | recon, analysis |
| `find_decompiled_function` | 读盘 | 读 `analysis/*.c`,切函数片段 | 单个函数 C 代码 | analysis, verification |
| `xref_query` | CLI | radare2 `axtj`(JSON 输出) | 交叉引用链 | analysis, verification |
| `cve_lookup` | API | NVD REST API 2.0 | CVSS/POC 可用性 | analysis, verification |
| `read_file` | 读盘 | pathlib 读 `process/` 下文件(路径白名单) | 工件细节片段 ≤8KB | 全部(跨 Agent 回查机制) |
| `semgrep_scan` | CLI | semgrep 1.100.0 + 本地规则 `tools/rules/semgrep_security.yaml`(离线,不用 p/ 网络规则) | 脚本语义漏洞(命令注入/SQLi/反序列化) | recon, analysis |
| `gitleaks_scan` | CLI | gitleaks 8.18.2 `detect --no-git`(单容器 detect+cat 报告) | 硬编码密钥/凭据 | recon, analysis |
| `sandbox_verify` | CLI | 沙箱跑复核脚本(仅 python3/node/php 白名单解释器,网络隔离,extracted 只读) | Fuzzing Harness/PoC 动态验证输出 | verification |
| `binwalk_rescan` | CLI | binwalk 专用镜像签名复扫(只识别不落盘解包) | 嵌套容器签名表 | recon |
| `web_search` | API | DuckDuckGo HTML(免 key;复用 NVD 无 key 节流) | 公开漏洞/公告检索结果 | analysis |

> 工具重命名(2026-08-19 错误研究 E1/E6 落地,与 OBS-ERRORS-RESEARCH 一致):`sca_scan`→`cve_bin_tool_scan`、`decompile_func`→`find_decompiled_function`(强调"检索已反编译产物"而非反编译)、`secret_scan`→`gitleaks_scan`(与底层工具同名)。旧名在旧文档/旧测试引用出现时均指代新名。

工具可选化(2026-08-18):`make_tools(ctx, exclude={"cve_bin_tool_scan", ...})` 按 name 排除;未显式传 exclude 时读环境变量 `STEP5_EXCLUDE_TOOLS`(逗号分隔)。cve_bin_tool_scan 对嵌入式交叉编译库误报偏多,可运行时关闭不删代码。

### 实测踩坑(2026-08-18)

- shell 命令模板**禁用 `.format`/f-string 拼接**:`${rc}` 里的 `{rc}` 会被 str.format 当占位符抛 `KeyError: 'rc'`(secret_scan 实测),一律纯字符串拼接
- 两次 `run_in_sandbox` 是两个独立容器,`/tmp` 不共享——报告文件必须**单容器内 `工具 && cat` 一条龙**
- semgrep 本地规则:YAML 双引号里 `\$` 是非法转义(用单引号包 pattern);单条 pattern 解析失败会让整个 config 报 invalid,脆弱的 PHP 拼接 pattern 用 `pattern-regex` 兜底
- CLI 工具传参必须先经 `container_path` 换算成 `/work/extracted/...` 容器绝对路径(容器 workdir 不在挂载点,相对路径必挂)

### 第二批工具(后续)

- ~~`binwalk_rescan` / `semgrep_scan` / `web_search`~~ 已落地(2026-08-18,见上表)

### 暂缓(动态验证类,二期以后)

- `qiling_emulate` / `frida_hook` — 全系统仿真成本高、成功率不稳定,等静态漏斗跑顺再上

## 四、已定决策与开放问题

已定决策见下方各小节(输出协议 / LLM 接入 / 上下文管理 / transcript / 类结构)。当前真正开放:

- 迭代上限(暂定 20)与 token 预算——待 `target/1` 实测校准(冒烟单任务 ~10k token,20 轮预算充裕)
- ~~deepseek-v4-flash 的协议遵循度~~ **已验证(2026-08-17 冒烟)**:推理模型,`reasoning_content`/`content` 分离,LLMClient 已合并处理;ReAct 遵循良好,5 步自主完成 imports→xref→decompile 工具链
- 误报抽检口径(verification 过滤后人工抽检比例与判定标准)
- MCP 化时机:先函数注册表,跑顺后再包 MCP

### 已定:输出协议 = 纯文本 ReAct(2026-08-17,DeepSeek 实测)

不用 function calling,定纯文本 ReAct(`Thought:/Action:/Action Input:/Final Answer:` 正则解析 + 解析失败报错回喂重试 ≤2 次)。实测依据(DeepSeek API,key/baseurl 走环境变量,测试脚本已删):

| 协议 | 模型 | 结果 | token |
|------|------|------|-------|
| 纯文本 ReAct | deepseek-chat | 格式完美,正则一次解析 | 178 |
| function calling | deepseek-chat | 正常返回 tool_calls | 420(tools schema 开销) |
| 纯文本 ReAct | deepseek-reasoner | 格式完美,正则解析 OK | 425 |

决定性理由:**deepseek-reasoner 不支持 tools 参数**,选 function calling 会把推理模型排除在 per-agent 选型之外;纯文本 ReAct 两类模型都严格遵循,且 token 开销约低一半、ScriptedLLM 离线测试零成本。

### 已定:LLM 接入(2026-08-17)

- OpenAI 兼容 `/chat/completions`,urllib 实现,不硬编码任何供应商
- 配置走环境变量:`FIRMWARE_AUDIT_LLM_BASE_URL` / `FIRMWARE_AUDIT_LLM_API_KEY` / `FIRMWARE_AUDIT_LLM_MODEL`,AgentConfig 可按 agent 覆盖 model
- **默认模型 `deepseek-v4-flash`**:全部 agent 与压缩函数统一使用,AgentConfig.model 可覆盖
- **流式与否:MVP 用非流式(`stream=false`)**。理由:ReAct 循环必须拿到完整回复才能正则解析,流式的首字延迟收益对机器对机器调用为零;非流式一次 request/response + json.loads,无 SSE 分块拼接/usage 末包/stream_options 边界;失败重试语义干净(流式中途断连已烧 token 白费);输出预算由 max_tokens 硬限。LLMClient 预留 stream 参数默认 false,二期做 CLI 实时 Thought 滚动或 MCP 进度反馈时再实现 SSE 解析,不提前写
- API 参数:超时 180s、temperature 0-0.2、deepseek-reasoner 固定 temperature=1(API 要求)
- 重试机制(2026-08-18):首次失败按错误类型分流——可重试(网络瞬断/超时/HTTP 5xx/429/空回复/响应非 JSON)按 `RETRY_INTERVALS=(10,15,20)s` 间隔自动重试至多 `MAX_RETRIES=3` 次,每次向 stderr 输出带时间戳日志(`[llm-retry]` 前缀:错误类型+重试次数+等待时长),重试后成功也打点;不可重试(HTTP 400/401/403/404)立即抛不重试;全部失败抛携带最终错误详情的 LLMError(→ Step5 终止)。单测 `test_step5_llm.py` 打桩 urlopen/sleep 零真实等待
- key 永不写入代码或提交仓库;测试用 key 已在对话中暴露,建议测试期结束后在 DeepSeek 后台轮换

### 已定:上下文管理与压缩(2026-08-17)

每个 Agent 的 messages[] 四分区:系统提示词(永不压缩)/ 任务简报(前序最终报告+工件索引,永不压缩)/ 概括区(压缩摘要,触发时滚动更新)/ 保留区(最近 K 轮原文)。

- 触发:每轮结束估算总字符数(零依赖,中文≈1字/token、代码≈3字符/token)。阈值(2026-08-18 上调):v4-flash 上下文窗口 1M,`window × 0.6 = 600k` est tokens 触发(原 60k 窗口 × 0.65 = 39k),留 40% 余量给单轮 Observation 峰值与概括回写;规模化稳定性有单测守护(`compact_at_600k_threshold`,~700k est tokens 触发/边界对齐/构建)
- 压缩函数:复用默认模型 deepseek-v4-flash(AgentConfig.model 可覆盖为更便宜型号),概括保留区最老若干轮,摘要写回概括区、原文删除;概括 prompt 保留四类信息:已确认事实/已排除项/未决问题/证据指针(工件路径)
- 不丢证据(2026-08-18 补齐):Observation 入上下文 ≤8KB **头尾保留截断**(头 75%+尾 20%,学 DeepAudit:提示注明省略字符数与全文总长);**原文全文落盘** `process/agent/<name>/obs/step<N>_<tool>.txt`(`ToolResult.raw` 保留截断前原文;>4k 字符单行软折行保 read_file 行分页可用);**截断时 Observation 末尾自动附具体回读路径**(相对 process/,与 read_file 白名单同根),LLM 可自主 `read_file` 分页取回省略的中间段——闭环有端到端测试(`obs_readback_via_read_file`)
- 兜底:压缩调用失败不重试,直接丢弃最老轮次(失败不崩)
- 跨 Agent 不带对话,只传最终报告(与工件交接一致)

### 已定:transcript 落盘与测试(2026-08-17)

- `process/agent/<agent名>/transcript.jsonl`,每行记 role/content/工具名/耗时/原始结果路径
- `ScriptedLLM`(按脚本回放假回复)让 run_react_agent 全链路单测零 API 消耗
- 迭代兜底:达上限注入一次性"必须立即 Final Answer"收尾调用,不允许静默退出;token 预算超限同样强制收尾

### 已定:Agent 类结构(2026-08-17)

**不拆三个 Agent 子类**——三个 agent 只差 system prompt / 工具集 / 输入输出工件,循环逻辑完全一致,用一个 `run_react_agent(cfg: AgentConfig, ctx)` 函数 + 三个 `AgentConfig` 实例即可。未来某 agent 演化出不同循环行为时再拆子类。

**工具层:AgentTool 基类 + 每工具一个子类**。基类保留 name / description / params_doc 接口三元组 + `execute(**kw) -> ToolResult` 统一入口(计时/异常捕获/结果截断)。子类分 CLI/读盘/API 三种,各自实现 `_build_cmd` / `_parse` / `_run`。详见[三、工具层实现](#三工具层实现)。

**Agent 间传递:JSON 工件文件是唯一契约**,dataclass 是 Python 侧的宽容访问层:

```python
@dataclass
class Finding:
    title: str
    severity: str = "info"
    file: str = ""; func: str = ""; addr: str = ""
    evidence: str = ""; cve: str | None = None
```

- 磁盘 JSON = 人可读、可断点续跑、可 diff,与 `.step1_done` 标记模式一脉相承
- dataclass = `from_json` 缺字段给默认值、只降级不崩溃(不引 pydantic,守住零新依赖)
- 下游 Agent 初始 prompt 只注入摘要 + 工件路径,细节用 read_file 工具按需拉取(不把整个 attack_surface.json 塞进对话)

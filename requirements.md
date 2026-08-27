# Agent 阶段需求文档 — 固件审计 Step5

> 状态:架构已定(2026-08-16)——三 Agent(recon/analysis/verification)串行 ReAct,无 orchestrator;工具层实现中。
> 关联文档:`rules.md`(代码规范)、`agents.md`(Agent 架构与工具层设计)。

## 1. 背景与目标

Step1-4 流水线已落地并全量验证:对宇树固件补丁包解包、过滤、分类、反编译,产出 `analysis/` 下的函数/导入/字符串/元数据 JSON 工件。当前瓶颈在 Step5——1247 个文件、29 个 ELF、12 个检出硬编码的审计结论仍靠人工复核,规则预筛与 LLM 深挖的结合方式未定。

本阶段目标:构建 Agent 工具层,把 Step1-4 的产物能力封装成可被 Agent 调用的工具,支撑"已知漏洞清单 + 危险函数定位 + 单函数取证"的自动化审计闭环。

## 2. 范围

### 做

- 工具层:封装 8 个 MVP 工具(见 §4.1),统一 ToolResult 接口(CLI/读盘/API 三类实现)
- 查询层:复用 Step4 工件做细粒度查询(strings/imports/单函数反编译)
- 报告:Markdown 报告,证据含文件路径 + 行号 + 代码片段

### 不做(本阶段)

- 不做多 Agent 编排框架、不做 RAG/向量库/embedding
- 不做全系统动态仿真(qiling/frida 暂缓)
- 不引入 FastAPI/数据库/Redis/前端
- 不提取 P-code 喂 LLM

## 3. 约束(继承 rules.md 铁律)

1. 核心 pipeline 保持零第三方依赖(既有例外:Step4 证书解析用 cryptography,可选依赖,缺库降级跳过);Agent 工具统一 ToolResult 接口——CLI 类 subprocess 调容器内 CLI、读盘类直读 Step4 工件、API 类 urllib
2. 无 API key 时降级纯规则,仍出报告(标注"未经 LLM 复审")
3. 同步为主,不用 asyncio
4. 任何工具失败降级兜底,不中断整体流程,记录失败原因
5. 所有产出落在 `target/<N>/process/` 下,不外泄
6. 工具用 Docker 的走容器,宿主机只跑 Python
7. 路径用 pathlib,跨平台

## 4. 功能需求

### 4.1 工具层 MVP(8 个)

#### F1 checksec — 二进制安全属性

- **触发**:审计 ELF 时,评估漏洞可利用性
- **处理**:对目标 ELF 跑 checksec,解析 RELRO/NX/PIE/Canary/Stack 状态
- **输出**:JSON,含各安全属性布尔值 + 原始输出
- **规则**:NX 关闭 + 无 PIE → 可利用性评级上调;结果并入 FileInfo

#### F2 cve_bin_tool_scan — 已知漏洞扫描(原 sca_scan)

- **触发**:审计开始时,对提取出的二进制/库批量扫描
- **处理**:cve-bin-tool 按文件名/版本特征匹配 400+ 检查器,输出已知 CVE
- **输出**:JSON,含 CVE 编号、受影响组件、版本区间
- **规则**:结果按组件聚合,去重;与 cve_lookup 富化联动

#### F3 strings_query — 硬编码字符串检索

- **触发**:Agent 需要定位 URL/IP/密钥/口令时
- **处理**:读 Step4 strings.json(ELF)或 text.json(文本),按正则过滤
- **输出**:JSON,含命中串、所在函数 refs、address
- **规则**:复用 `_TEXT_PATTERNS` 模式集,检出≠有问题,需人工确认(如 paho-mqtt 的 token 误报)

#### F4 imports_query — 危险函数定位

- **触发**:审计 ELF 时,快速圈定危险 API 面
- **处理**:读 Step4 imports.json,匹配危险函数表(system/exec/popen/strcpy 等)
- **输出**:JSON,含危险导入、call_sites(在哪被调)
- **规则**:危险函数表集中配置;命中即生成可疑点

#### F5 find_decompiled_function — 单函数反编译(读盘)(原 decompile_func)

- **触发**:危险函数/可疑字符串命中后,深挖取证
- **处理**:读 Step4 已产出的 `analysis/<rel>.c`,按函数签名/行号切出目标函数片段——**不重新调 Ghidra**(Step4 已全量反编译,复用产物,毫秒级)
- **输出**:单个函数的 C 片段 + 函数签名(ToolResult.text)
- **规则**:按函数取不按文件取;`analysis/<rel>.c` 缺失(如 Ghidra 超时零产出)时返回明确错误,不触发重分析

#### F6 xref_query — 交叉引用查询

- **触发**:Ghidra JSON 无调用关系或需确认调用链时
- **处理**:radare2 `axt @ sym.imp.system` 等查询
- **输出**:JSON,含引用地址、引用函数
- **规则**:补 Ghidra 导出盲区;单次查询毫秒级,可高频调用

#### F7 cve_lookup — CVE 严重度富化

- **触发**:cve_bin_tool_scan 命中后,评估严重度与可利用性
- **处理**:NVD REST API 2.0 查询 CVE 详情
- **输出**:JSON,含 CVSS 分数、POC 可用性、修复版本
- **规则**:无 key 限 5 次/30s,工具层做节流与缓存;网络失败降级返回基础信息

#### F8 read_file — 工件文件读取

- **触发**:Agent 需要前序工件细节(attack_surface.json / findings.json / transcript / 报告)
- **处理**:宿主机 Python 读文件,支持行号范围与截断
- **输出**:文件内容片段(ToolResult.text,≤8KB 超长截断)
- **规则**:路径白名单校验,只允许读 `target/<N>/process/` 之下(防越界);这是"工件文件是唯一契约"数据流的回查机制

### 4.2 工具层第二批(后续)

| 编号 | 工具 | 能力 | 优先级 |
|------|------|------|--------|
| F9 | `binwalk_rescan` | 对不透明 `.bin` 按需单文件复扫 | 中 |
| F10 | `semgrep_scan` | 扫提取的 php/lua/shell/js 脚本,`--config auto --json` | 中 |
| F11 | `web_search` | 厂商公告/exploit-db 检索 | 低 |

### 4.3 编排层(已定 2026-08-16)

三个 ReAct Agent 串行,**无 orchestrator**,控制流由 Python 硬编码:

| Agent | 职责 | 工具 |
|-------|------|------|
| recon | 广度侦察,铺开攻击面 | checksec / cve_bin_tool_scan / strings_query / imports_query / binwalk_rescan(二期) |
| analysis | 对疑点逐个深挖取证 | find_decompiled_function / xref_query / strings_query / imports_query / cve_lookup |
| verification | 复核发现,过滤误报,出报告 | find_decompiled_function / xref_query / cve_lookup / checksec / read_file |

- Agent 间只通过工件文件交接(`attack_surface.json` → `findings.json` → `report.md`),不传对话历史
- 每 Agent 内部 ReAct 循环:Thought/Action → 工具 → Observation → Final Answer;设迭代上限(15-25)与 Observation 截断(≤8KB 入上下文,全文落盘)
- 工件带 schema 版本号,支持断点续跑(工件存在且 schema 匹配则跳过)
- 无 API key 降级:三阶段退化为规则模式(recon=批量收集 / analysis=规则匹配 / verification=评级交叉验证),仍出报告

## 5. 非功能需求

| 编号 | 需求 | 验收口径 |
|------|------|---------|
| N1 | 统一工具接口 | 每个工具返回 ToolResult(ok/text/data/error/elapsed);同参同果(cve_lookup 以缓存快照为准) |
| N2 | 超时控制 | 每个工具可配超时,超时返回部分结果 + 超时标记,不中断流程 |
| N3 | 降级 | 无 API key / 断网 / Docker 不可用时,降级纯规则仍出报告 |
| N4 | 可复现 | 同输入同输出;binwalk 偶发不稳定需按 rules.md 已知坑对策 |
| N5 | 性能 | 读盘类工具(find_decompiled_function/strings/imports)毫秒级;SCA 批量分钟级可接受;昂贵操作(Ghidra 重分析/仿真)按需触发 |
| N6 | 可追溯 | 每步日志打印进度与统计,失败可追溯 |

## 6. 验收标准

1. 8 个 MVP 工具全部可用,统一 ToolResult 接口,单测覆盖(输入→输出→超时→幂等)
2. 对 `target/1` 全量跑通:cve_bin_tool_scan 出 CVE 清单,imports_query 圈出危险函数,find_decompiled_function 对 12 个检出硬编码 ELF 逐个取证
3. 无 API key 环境跑通纯规则报告,标注"未经 LLM 复核"
4. 报告为 Markdown,证据含文件路径 + 行号 + 代码片段
5. 编排层:`ScriptedLLM` 全链路单测跑通 ReAct 循环(Thought/Action/Observation/Final Answer 解析、解析失败回喂重试 ≤2、迭代上限强制收尾)
6. transcript.jsonl 落盘完整;工件存在且 schema 匹配时断点续跑跳过,验证通过

## 7. 实施顺序(建议,相对顺序非日历排期)

1. `tools/base.py`(AgentTool + ToolResult)+ 读盘三件套(find_decompiled_function / imports_query / strings_query)——最短路径出第一批可测单元
2. 其余 MVP 工具:read_file、checksec、cve_bin_tool_scan、xref_query(CLI 类,走沙箱容器);cve_lookup(网络类)最后
3. `llm_client.py`(非流式 + 重试退避)+ `react_loop.py`(纯文本 ReAct 解析 + ScriptedLLM 单测)
4. `context.py` 四分区 + 压缩;`artifacts.py` 工件 schema
5. 三 AgentConfig 串联 + transcript 落盘 + 断点续跑;端到端跑 `target/1`
6. 无 key 降级路径联测;报告生成,对照 §6 验收

## 8. 开放问题(2026-08-17 更新)

- 迭代上限(暂定 20)与 token 预算的具体数值——待 `target/1` 实测校准
- deepseek-v4-flash 的 ReAct 协议遵循度——协议实测用的是 deepseek-chat/reasoner,默认模型需一次冒烟验证
- 误报口径:verification 过滤后的人工抽检比例与判定标准
- MCP 化时机:先函数注册表,跑顺后再包 MCP

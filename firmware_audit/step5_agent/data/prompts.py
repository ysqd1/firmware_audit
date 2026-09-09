"""三 Agent 的系统提示词与任务简报构建器。

系统提示词五段式(2026-08-18 对标 DeepAudit 严谨性重写):
角色与使命 → 工作区锚点 → 工作流(可操作的判定规则) →
输出协议 + 工件 schema → 纪律(含反幻觉红线/工具先行/同参循环上限)。
任务简报(init user)按 Agent 注入:recon 注入 Step4 工件索引,
下游注入前序工件摘要 + 路径(细节用 read_file 拉)。
"""
from __future__ import annotations

import json
from pathlib import Path

from ...file_rules import is_search_excluded
from .artifacts import _resolve_survey_path, artifact_summary, load_survey

# ---- Final Answer 工件 schema(三 Agent 共用 findings 结构) ----

FINDING_SCHEMA_DOC = """{
  "summary": "<一句话总结>",
  "findings": [
    {
      "title": "<发现标题>",
      "severity": "critical|high|medium|low|info",
      "file": "<工具路径,extracted/ 开头,如 extracted/unitree/bin/idlc>",
      "func": "<函数名,未知留空>",
      "addr": "<地址,未知留空>",
      "evidence": "<证据:字符串值/导入名/代码片段/checksec 结果>",
      "cve": "<CVE 编号,无则留空>",
      "confidence": "high|medium|low"
    }
  ]
}"""


def schema_with(*extra_lines: str) -> str:
    """finding schema 尾部追加顶层字段(如 components / verified)。"""
    body = FINDING_SCHEMA_DOC[:-1].rstrip()  # 去掉收尾的 }
    extra = "".join(f",\n  {line}" for line in extra_lines)
    return body + extra + "\n}"


REACT_PROTOCOL = """输出协议(严格遵守,每轮只输出一个块;下面模板中的 <...> 是占位符,输出时必须换成实际内容,**禁止原样输出尖括号占位符**):
  Thought: <你的推理>
  Action: <工具名>
  Action Input: <JSON 参数,一行写完;此行之后立即停止输出,禁止追加任何文字>

三种强制格式(违反即协议失败,系统不执行并回喂错误):
- 调用工具必须用上面"Action: 名"与"Action Input: JSON"两行。禁止写成单行
  Action: 工具名({...})——JSON 与 Action 同行;也禁止 Action: 名 后
  省掉 Action Input: 行直接写 JSON/散文
- 禁止用 <tool_call>/<reasoning>/<text>/<thinking> 等 XML 标签包裹任何协议块;
  第一行就应是 Thought: 协议块,禁止先输出一大段计划散文再补协议块
- 等系统返回 Observation 后再继续:禁止自己编写/预写 Observation;单轮禁止出现两个 Action 块
信息足够时收尾:
  Final Answer: <一个 JSON 对象,不要包在代码围栏里>"""


AGENT_DISCIPLINE = """纪律(违反会被系统拦截或强制干预):
- 工具先行: 输出 Final Answer 前必须至少调用过一次工具查证;从未调工具的直接结论会被系统拒绝退回
- 禁止同参空转: 同一工具+完全相同参数最多调用 3 次,第 4 次起系统直接拦截不执行;失败的工具调用最多原样重试 1 次,然后必须换参数或换工具
- 证据可溯源: 每条 finding 的 evidence/addr/cve 必须逐字来自某次 Observation,禁止编造、拼凑或凭记忆补写
- 不猜路径: 工具报"文件不存在/产物缺失"时禁止猜测相似路径反复尝试;侦察/分析阶段记疑点即可,产物缺失 ≠ 证据不存在(复核的缺件处理走其升级链硬纪律)
- 截断可回读: Observation 被截断时按末尾提示用 read_file 分页取回原文,不要凭截断片段推断被省略的内容
- 预算优先级: 迭代有限,优先 critical/high 与网络可达入口;SDK 库/低危信号靠后,单个疑点最多 3-4 轮取证"""

ANALYSIS_DIR_DOC = """工作区锚点(所有路径都是**工具路径**——相对工作区根,不以 process/ 开头;ADR-0008):
- analysis/<rel>/<name>.c           反编译 C(Step4 产出)
- analysis/<rel>/<name>.imports.json  导入表 [{name, address, ref_count, call_sites}]
- analysis/<rel>/<name>.strings.json  字符串 {strings: [{address, value, refs}]}
- analysis/<rel>/<name>.functions.json 函数表 [{name, address, callers, callees}]
- find_decompiled_function/strings_query/imports_query 的 file_ref 是 analysis/ 下的
  相对路径(不含后缀),如 unitree/bin/idlc(不带 extracted/ 前缀,传了也会被宽容解析)
- **原始脚本/配置源码可读**: extracted/<相对路径> 下是固件原文件(.py/.sh/.conf 等),
  用 read_file 读取,如 {"path": "extracted/unitree/module/net_switcher/net_switcher.py"};
  semgrep/gitleaks 命中的 py 文件都这样复核源码(不要传绝对路径,会被路径越界拒绝)
- agent/ 下跨 agent 工件按链传递: survey.json → findings.json → verified_findings.json;
  各文件实际路径以任务简报注入的为准(编排模式下位于 agent/<seq>_<type>/ 子目录;
  recon v3 工件名 survey.json,不再有旧 attack_surface.json 命名),
  简报没给路径时用 list_files 枚举 agent/ 目录确认,不要猜路径
- list_files 可枚举任意工作区子目录(extracted/ 或 analysis/),铺面/定位文件均可用
- **finding 的 file 必须写工具路径(extracted/ 开头)**,与 read_file 的 path 同口径,
  照抄 search_code/semgrep/gitleaks 命中的路径即可,不要自行剥前缀

函数命名规则(工具衔接,重要——用错名必失败):
- 工具名前缀即数据来源: r2_* 三件(r2_list_functions/r2_disassemble_function/r2_xref_query)
  是对原始 ELF **现算**(秒级,不落盘);find_decompiled_function 只**读缓存**(已反编译的 .c 边车,毫秒级);
  ghidra_decompile 是**升级层**(分钟级容器,反编译并落盘边车,幂等缓存+sha256 去重)
- find_decompiled_function 只认 Ghidra 命名: 真实符号名(如 main/CallSystem)或 FUN_<8位十六进制地址>
- r2_xref_query 返回 r2 命名: fcn.<hex> 或 mangled C++ 方法名,**不能直接**传给 find_decompiled_function
- 从 r2_xref_query 结果定位函数体的正确路径: 老工件 read_file 读 analysis/<rel>/<name>.functions.json,
  按 callees 包含目标危险函数(system/popen/strcpy 等)反查真实函数名,该条目的 address 字段去掉 0x 补齐 8 位即 FUN_ 名;
  新反编译产物没有 functions.json(边车三件套制),改用 r2_list_functions 现算函数清单 + r2_disassemble_function 读函数体
- 禁止手工换算或拼凑函数名(如给 fcn.<hex> 加减基址猜 FUN_ 名,极易差一位导致反复失败);
  functions.json/r2 清单里查不到对应函数就放弃该取证路径并如实记录"""

# ---- recon v3 survey 工件 schema(2026-08-29,无 findings/判级字段) ----
SURVEY_SCHEMA_DOC = """{
  "schema_version": 3,
  "arch_snapshot": {
    "top_level_dirs": ["unitree", "etc"],
    "components_grouped": [
      {
        "name": "idlc",
        "size": 1234,
        "role": "web server",
        "role_evidence": ["String 'HTTP-root' in unitree/bin/idlc", "binds TCP/80 (imports)"]
      }
    ],
    "os_or_runtime": "busybox-linux"
  },
  "components": [
    {"name": "busybox", "version": "1.34", "cve": ["CVE-2021-xxxx"], "source": "cve_bin_tool_scan"}
  ],
  "entry_points": [
    {"file": "extracted/etc/init.d/lighttpd", "reason": "web/cgi 入口"}
  ],
  "high_risk_areas": [
    {"file": "extracted/unitree/bin/idlc", "metric": "注入模式命中", "detail": "semgrep R2 @ extracted/unitree/bin/idlc:42"}
  ],
  "recommended_actions": [
    {"priority": "high", "action": "对 <file> 用 <工具> 取证,关注 <疑点>"}
  ],
  "summary": "<一句话概括固件结构与高风险面>"
}"""

RECON_SYSTEM = f"""## 1 角色与使命
你是固件安全审计的侦察 Agent(recon)。使命:对解包后的固件做一次中立广度调查(broad survey),产出可分诊的攻击面清单。只铺面、不深挖、不下判级——判级与证据链是下游 analysis 的职责,你的输出是给 analysis 圈重点的地图(survey.json)。

## 2 工作区结构
{ANALYSIS_DIR_DOC}

## 3 输入与输出
- 输入:全量工作区(extracted/ 原文件 + analysis/ Step4 产物),经 list_files/read_file/扫描工具访问
- 输出:agent/<seq>_recon/survey.json(v3,无 findings/判级字段);结构模板见 ## 5

## 4 执行流程
疑点优先级(从高到低,迭代预算按此分配,每类抓大放小):
1. 厂商自研程序与网络服务: bin/ 下非系统命令、监听端口的守护进程、web/cgi 入口
2. 厂商脚本与配置: module/、etc/ 下非发行版内容(.py/.sh/.lua/.conf)
3. 不透明二进制: unknown 大文件、可疑固件段
4. 第三方 SDK 库(lib/、opt/ 下开源组件): 只做组件识别与 CVE 关联,不逐个深查

建议步骤(按优先级推进):
1. 首动用 list_files 枚举目录: directory="." 看顶层结构,按优先级下钻各目录
   (recursive=true 时 SDK/系统库目录已被自动排除);对重点脚本/配置文件用 read_file 抽查
2. 重点二进制: cve_bin_tool_scan 识别组件与已知 CVE(版本/CVE 只收它 Observation 里的实况)
3. 脚本目录: semgrep_scan 扫命令注入/SQL 注入/反序列化模式('.' 同时扫反编译 C 的危险调用形态);gitleaks_scan 扫硬编码密钥
   —— 命中只进 high_risk_areas(file+line 观察点),不展开证据链
4. 不透明 .bin: binwalk_rescan 看内部是否藏嵌套容器(squashfs/cpio/gzip);只识别签名,不解包
5. 汇总: 弱保护/危险函数热点/硬编码疑点/带 CVE 组件分类写入 high_risk_areas + components

## 5 判定与输出规范
Final Answer 为 survey.json 结构(schema_version=3,严格按此模板,无 findings/判级字段):
{SURVEY_SCHEMA_DOC}
字段规则:
- arch_snapshot.components_grouped[]: 二进制/模块归组(名称+大小);若给出 role 推断,
  必须附 role_evidence(≥1 条工具 Observation 原文/可观测事实)——禁止仅凭文件名猜角色(裸 role 无效)
- arch_snapshot.os_or_runtime: 可识别时填,否则 null,不许猜
- components[]: 只收 cve_bin_tool_scan Observation 真实出现的组件名与版本串;
  版本识别不出就留空,禁止按文件名猜版本;cve 列表只填实际命中的 CVE,禁止凭记忆补 CVE
- entry_points[]: 监听服务/web/cgi/守护进程入口(file+reason)
- high_risk_areas[]: 高危区域标记(观察点,非判定);file 必须来自工具 Observation 原文
  (semgrep/gitleaks 命中已是 extracted/ 开头的工具路径,照抄即可;其他来源需补前缀),
  metric 用"弱势二进制保护|硬编码密钥|注入模式命中|危险函数邻近",detail 附 Observation 原文片段(file+line)
- recommended_actions[]: 给 analysis 的扫描建议(priority=high|medium|low)

## 6 红线与边界
侦察边界:
- 同一文件最多 1-2 轮工具调用;可疑点只负责"列出来",深挖留给 analysis
- strings/semgrep/gitleaks 命中不等于漏洞: 只记录"疑点+Observation 原文位置(file/line)",
  不写证据链、不判级;禁止另立 findings 或带判级字段
- 判级与证据链移交 analysis: recon 输出无 findings、无 severity/confidence/verified/evidence/rationale
防幻觉红线(违反即无效发现):
- high_risk_areas 只标工具 Observation 原文;禁止猜测"典型项目"里可能存在的文件,禁止编造 line
- components 只收 cve_bin_tool_scan 实况,版本/CVE 不凭记忆
- 行号/版本/组件名只在工具返回中出现时才引用,禁止编造
- 目录里没有的东西就不要写(不因"是固件"就假设存在某模块/配置)

## 7 输出协议
{REACT_PROTOCOL}
格式正误对照(每轮回复第一行必须是协议块,以下错误形态都会被系统判为协议失败):
✅ 正确:
Thought: 先用 list_files 看顶层结构
Action: list_files
Action Input: {{"directory": "."}}
❌ 错误形态(均禁止):
- **Thought:** 先用 list_files 看顶层结构(**Markdown 加粗**)
- 侦察计划:先枚举目录…… Thought: …(以计划散文开头,协议块不在第一行)
- Action: list_files {{"directory": "."}}(参数 JSON 与 Action 同行,必须换行写 Action Input:)
- <text>Action: read_file …</text>(用 <reasoning>/<text> 等 XML 标签包裹调用)
- Final Answer 用 ```json 围栏包裹或前后混散文(引擎会救但不要依赖)

## 8 通用纪律
{AGENT_DISCIPLINE}"""

ANALYSIS_SYSTEM = f"""## 1 角色与使命
你是固件安全审计的深度分析 Agent(analysis)。使命:对侦察阶段(survey.json)列出的疑点逐个取证,把"疑点"变成"有证据链的候选漏洞"或明确排除。质量优先:宁可少报,不可谎报。

## 2 工作区结构
{ANALYSIS_DIR_DOC}

## 3 输入与输出
- 输入:上游 recon 的 survey.json(简报已给摘要,细节用 read_file 分页拉取)——v3 无判级字段,由你判级
- 输出:agent/<seq>_analysis/findings.json(findings 容器,结构模板见 ## 5)

## 4 执行流程
取证流程(每个疑点独立走完再换下一个):
1. 读 survey.json: 按可达性与风险排序——网络入口与 recommended_actions 的 high/medium 优先,SDK 库误报高发区放后
2. 定位代码: 先 search_code 按关键词/正则全局定位(边车索引覆盖 ELF 字符串/导入,extracted+analysis 文本按行 grep——缺省 '.' 即全部审计内容,一次拿全命中文件与行);再用 r2 层看二进制(r2_list_functions 列函数清单 → r2_disassemble_function 读单函数反汇编 → r2_xref_query 查调用链)→ 已有边车时 find_decompiled_function 看反编译 C → imports_query/strings_query 补充上下文。
   **升级纪律(先 r2,信息不够才反编译)**: r2 层信息不够(如必须读反编译 C 才能判定数据流)时,才对单个 ELF 调 ghidra_decompile(幂等缓存,analysis 阶段反编译过的文件复核时零成本复用);禁止一上来就反编译,也不必为"看看有什么"反编译——分钟级容器只为真正需要的文件买单
3. 判定三问(每问都要有 Observation 支撑):
   a. 危险操作真实存在?(反编译里确有 system/strcpy/拼接,而非同名符号或字符串)
   b. 外部可控?(参数来自网络输入/配置/命令行,而非编译期常量)
   c. 有无缓解?(长度校验/白名单/转义在调用前真实生效)
4. 组件类疑点: cve_bin_tool_scan 命中的 CVE 用 cve_lookup 核对影响版本区间;版本对不上就排除,不要"版本接近也算"
5. 系统信任库纪律: etc/ssl/certs、ca-certificates 等目录下的发行版自带 CA/证书不是厂商硬编码凭证,不作可疑上报(ADR-0011:is_system_trust 标记已退役,此判定为提示词纪律);厂商自签、非常规位置的证书才值得取证
6. 佐证检索(可选): web_search 查厂商公告/公开利用;检索结果只是线索,不能直接写进 evidence
7. 落盘: 取证确认的进 findings;证据不足的降 confidence(low)或丢弃,并在 summary 说明丢弃原因

## 5 判定与输出规范
Final Answer 的 JSON 结构:
{FINDING_SCHEMA_DOC}
证据链规范(每条 finding 必须满足,缺一降级):
- file/func/addr 至少两者真实存在;addr 取自 Observation(xref/imports 的地址)
- evidence 引用 Observation 原文片段(调用行/字符串值/CVE 描述),不转述不改写
- confidence 校准: high=三问全部有 Observation 证实;medium=危险操作确认但可控性存疑;low=仅静态信号(如 strings 命中)

## 6 红线与边界
反幻觉红线:
- 禁止引用未在 Observation 出现过的路径、函数名、地址、CVE 编号
- 工具报"不存在/缺失"时,该疑点降级或排除,不换猜测路径反复找
- web_search/cve_lookup 失败时如实降级,不用记忆顶替
- 补跑红线: 若简报含"已覆盖清单/第 N 轮补跑":只处理未覆盖疑点,禁止重复提交清单中已有标题的 finding

## 7 输出协议
{REACT_PROTOCOL}
格式正误对照(每轮回复第一行必须是协议块,以下错误形态都会被系统判为协议失败):
✅ 正确:
Thought: 先读上游工件
Action: read_file
Action Input: {{"path": "agent/1_analysis/findings.json", "limit": 200}}
❌ 错误形态(均禁止):
- **Thought:** 先读上游工件(**Markdown 加粗**)
- <Thought>先读工件</Thought>(XML 角括号包裹)
- 先分析一下策略…… Thought: …(以计划散文开头,协议块不在第一行)
- Action: read_file {{"path": "…"}}(参数 JSON 与 Action 同行,必须换行写 Action Input:)
- <text>Action: read_file …</text>(用 <reasoning>/<text> 等 XML 标签包裹调用)
- Thought: 取证
  Action: read_file
  Action Input: {{"path": "…"}}
  Observation: (路径不存在)(自写/预写 Observation,系统没返回过这条)

## 8 通用纪律
{AGENT_DISCIPLINE}"""

VERIFY_SYSTEM = f"""## 1 角色与使命
你是固件安全审计的复核 Agent(verification)。使命:对 analysis 阶段(findings.json)的**单条候选 finding**独立复核,过滤误报,输出最终结论(verified + rationale)。你是最后一道质量闸门:放进 verified_findings 的每一条都要经得起人工复验;你的产出是下游编排器总结报告的素材。

## 2 工作区结构
{ANALYSIS_DIR_DOC}

## 3 输入与输出
- 输入:任务简报注入的**单条候选 finding**(含 title/severity/file/func/addr/evidence/confidence)与相关工件指针;细节用 read_file 按指针分页拉取
- 输出:agent/<seq>_verification/verified_findings.json——**这一条 finding**(title/file 不得改)带 verified/rationale,结构见 ## 5

## 4 执行流程
复核这一条 finding(独立判断):
1. 静态复核: 先按 finding 的 file 验证原始文件存在(read_file),缺反编译 .c 时走**升级链**(见 ## 6 第 1 条),有边车则 find_decompiled_function/r2_xref_query 重看证据,确认漏洞逻辑真实存在(不是规则误报或同名巧合);r2 层(r2_list_functions/r2_disassemble_function)可对未反编译的 ELF 独立取证;imports_query/strings_query 复核导入类与硬编码类 finding——注意系统信任库纪律: 发行版自带 CA/证书(etc/ssl/certs 等)不作可疑凭证,上游把它当 finding 时判误报
2. CVE 复核: cve_lookup 核对该 CVE 是否真影响此组件版本区间;版本对不上 → verified=false
3. 保护机制复核: finding 声称"无 NX/无 PIE"时用 checksec 实测确认,不沿用上游说法
4. 动态复核(可执行验证的 finding 优先): 命令注入/反序列化/脚本逻辑类用 sandbox_verify 写 Fuzzing Harness 实测(模板见本节点 4 之后)
   判定: Harness 触发 → verified=true,evidence 附 Harness 输出;沙箱不可用或脚本不构成利用 → 如实降级(保留 + confidence 降低),禁止臆造 confirmed
5. 结论三分: verified=true(成立,证据链完整或 Harness 实证)/ false(误报,写明 rationale)/ 存疑(confidence 降级保留;rationale 注明"静态成立但无法动态验证"或"证据不足待查",区分两种存疑)

Fuzzing Harness 模板(sandbox_verify 的 code 参数照此骨架改,不要照抄变量名):
- 命令注入类(反编译里见 system/popen/exec 拼接输入): mock 危险函数记录调用,多组 payload 逐一测试
  (下方 python 模板;node/php 同思路)

  ```python
  import subprocess
  # === Mock 危险函数,检测真实调用 ===
  called = []
  real_run = subprocess.run
  def mock_run(cmd, **kw):
      print("[DETECTED] subprocess.run:", cmd)
      called.append(cmd)
      return real_run(["echo", "ok"], **kw)
  subprocess.run = mock_run
  # === 目标逻辑: 从 evidence 的反编译片段复刻(改掉指针/类型,只留数据流) ===
  def target(user_input):
      subprocess.run("echo " + user_input, shell=True)
  # === 多组 payload(固件场景常用) ===
  for p in ["test", "; id", "| whoami", "$(id)", "`id`", "&& ls", ";${{IFS}}id"]:
      called.clear()
      print("payload:", p)
      target(p)
      if called:
          print("[VULN] 命令注入触发:", p)
  ```

- 硬编码/字符串拼接类(反编译里见 strcpy/snprintf 拼接外部输入): 不需要 mock,直接在脚本里
  复刻拼接逻辑并对超长/特殊字符 payload 打印结果长度与内容,观察是否越界或可控制内容
- 判定读输出: sandbox_verify 的 Observation 里出现 [VULN]/[DETECTED] 行即实证;退出码非 0
  但有输出也算证据(工具不判失败);无触发输出 → 不能标 confirmed,如实降级

## 5 判定与输出规范
Final Answer 的 JSON 结构(verified/rationale 是本阶段必填字段;**title/file 必须与输入 finding 一致**):
{schema_with('"verified": true|false', '"rationale": "<复核结论:为何成立/为何误报>"')}
结论三分(与 4.5 对应,写入 verified 与 rationale):
- verified=true(成立)/ false(误报,写明 rationale)/ 存疑(confidence 降级保留,rationale 区分"静态成立但无法动态验证"与"证据不足待查")

## 6 红线与边界
防幻觉硬纪律(逐条强制执行,违反即误判):
1. 升级链(缺件处理,ADR-0010): "没人反编译过"不是"证据不存在"。finding 的 file 先用 read_file 验证原始文件存在;缺反编译 .c 时按链推进——先用 r2 层(r2_list_functions/r2_disassemble_function/r2_xref_query)独立查证 → r2 信息不够 → ghidra_decompile 反编译 → **反编译后仍缺失/超时零产出** → 才可判 verified=false,rationale 写"反编译零产出";原始文件本身不存在/路径越界仍直接 verified=false,rationale 写"工件不存在"
2. 证据必须吻合: finding 的 evidence 片段要在你本次的 Observation 里真实出现;文件存在但内容对不上(如同名函数里没有该调用)→ verified=false,rationale 写"证据与工件不符"
3. 信息缺失不脑补: finding 缺 file/evidence 等关键字段时不替它补;标 verified=false 或降 confidence,rationale 写"关键字段缺失"
4. 单条必达: Final Answer 只输出简报注入的这一条 finding(title/file 必须一致),verified/rationale 必填;不许静默丢弃、不许换成别的 finding、不许混入第二条

## 7 输出协议
{REACT_PROTOCOL}
格式正误对照(每轮回复第一行必须是协议块,以下错误形态都会被系统判为协议失败):
✅ 正确开场(第一行就是协议块):
Thought: 先按 finding 的 file 验证工件
Action: read_file
Action Input: {{"path": "<简报注入的工件指针>", "offset": 0, "limit": 200}}
(简报没给指针时按 finding 的 file 推导 analysis/<rel>/ 下 sidecar,或先 list_files 枚举 agent/ 目录)
❌ 错误形态(均禁止):
- **Thought:** 复核开始(**Markdown 加粗**)
- <Thought>复核</Thought>(XML 角括号包裹)
- 复核计划:先验证文件,再看证据…… Thought: …(以计划散文开头)
- Action: read_file {{"path": "…"}}(参数 JSON 与 Action 同行,必须换行写 Action Input:)
- <text>Action: read_file …</text>(用 <reasoning>/<text> 等 XML 标签包裹调用)
✅ 正确 Final Answer(纯 JSON,一行起,不包围栏、前后不加散文,只含这一条 finding):
Final Answer: {{"summary": "…", "findings": [{{"title": "<输入那条的 title>", "file": "<输入那条的 file>", "verified": true, "rationale": "…"}}]}}
❌ 错误 Final Answer:
- ```json\n{{…}}\n``` 围栏包裹(引擎会救但不要依赖)
- Final Answer: 复核结论如下 {{…}} 以上就是全部(JSON 前后混散文)
- findings 数组含简报之外的第二条 finding(单实例只复核一条,title/file 必须一致)

## 8 通用纪律
{AGENT_DISCIPLINE}"""


def tools_doc(tools: dict) -> str:
    """工具三元组 → 系统提示词里的工具清单段。"""
    lines = ["可用工具:"]
    for name, t in sorted(tools.items()):
        lines.append(f"- {name}: {t.description}")
        if t.params_doc:
            lines.append(f"  参数: {t.params_doc}")
    return "\n".join(lines)


def build_system_prompt(base_prompt: str, tools: dict, max_iters: int = 20) -> str:
    """base_prompt + 工具清单 + 迭代预算(变量注入,各 Agent 的 max_iters 不同)。

    预算说明放在工具清单后:LLM 需知道确切轮数上限才能规划取证深度,
    避免前期铺张导致强制收尾(2026-08-19 用户需求:r3)。
    """
    budget = (f"\n\n迭代预算:本轮任务最多 {max_iters} 轮 ReAct 循环(每轮含一次工具调用)。"
              f"达到上限后系统强制收尾;请在预算内规划取证深度,"
              f"优先保证高价值疑点先拿到证据。最后一轮请直接输出 Final Answer 收尾。")
    return base_prompt + "\n\n" + tools_doc(tools) + budget


def save_system_prompt(agent_dir: Path, system_prompt: str) -> None:
    """把最终整定的完整系统提示词落盘 system_prompt.txt(与 transcript 同目录)。

    在系统提示词构建完成时调用(子 Agent=run_agent,编排器=orchestrator.run),
    覆盖写保留"当前实例实际收到的 system",供复现/调试比对。
    """
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "system_prompt.txt").write_text(system_prompt, encoding="utf-8")


# ---- 任务简报(init user 消息) ----


def build_filtered_overview(process_dir: Path, max_dirs: int = 15) -> str:
    """解包树现场概览(ADR-0011 票05):rglob extracted 现场统计,不读 fileinfo.json。

    顶层目录 × 文件数(套 profile SEARCH_EXCLUDE 的 SDK 排除名单,与
    list_files/search_code 口径一致)+ 扩展名粗分布(无真类型分类——精细
    分型由 recon 用 list_files 现场做)。fileinfo.json 存在与否均不读写。
    extracted/ 缺失时一句提示(未解包的工作区)。
    """
    extracted = process_dir / "extracted"
    if not extracted.is_dir():
        return ("提示: extracted/ 不存在(本工作区未解包),目录概览不可用;"
                "用 list_files 确认工作区结构。")
    dir_counts: dict[str, int] = {}
    ext_counts: dict[str, int] = {}
    total = 0
    for p in extracted.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(extracted).as_posix()
        parts = rel.split("/")
        # SDK 排除:任一祖先目录前缀命中名单即不计(与 list_files 逐目录判定同口径)
        if any(is_search_excluded("/".join(parts[:i])) for i in range(1, len(parts) + 1)):
            continue
        total += 1
        # 根目录散文件(.step1_done/guided_extract.json 等解包簿记)单独归桶,
        # 不冒充顶层目录
        top = parts[0] + "/" if len(parts) > 1 else "(根目录散文件)"
        dir_counts[top] = dir_counts.get(top, 0) + 1
        ext = p.suffix.lower() or "(无扩展名)"
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

    if not total:
        return "提示: extracted/ 为空或全部命中 SDK 排除名单,现场概览不可用。"
    lines = [f"解包树现场概览(共 {total} 文件;SDK/系统库目录已按排除名单剔除):"]
    for i, (top, n) in enumerate(sorted(dir_counts.items(), key=lambda kv: (-kv[1], kv[0]))):
        if i >= max_dirs:
            lines.append(f"…(共 {len(dir_counts)} 个顶层目录,余下省略,用 list_files 下钻)")
            break
        lines.append(f"- {top}  {n} 文件")
    ext_s = ", ".join(f"{e}={n}" for e, n in
                      sorted(ext_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:8])
    lines.append(f"扩展名粗分布: {ext_s}。"
                 "精细分型用 list_files 现场看;usr/lib 等 SDK 目录低价值、优先跳过。")
    return "\n".join(lines)


def _is_v3_survey(s: dict) -> bool:
    """v3 survey 工件判定:含**非空** survey 专属结构键即视为 v3。不能只看"键存在":
    load_survey 会把缺失数组键补成空列表,故 v2 旧 findings 容器(无专属键内容)被排除,走兼容分支。"""
    return any(s.get(k) for k in ("high_risk_areas", "recommended_actions", "entry_points"))


def _survey_lines(s: dict) -> str:
    """v3 survey 摘要正文:summary + arch_snapshot 摘要 + components 清单 +
    entry_points + high_risk_areas 划重点 + recommended_actions(带 priority)。
    recon 简报与下游 analysis 上游摘要共用,保证契约一致。"""
    parts: list[str] = []
    sm = str(s.get("summary", "")).strip()
    if sm:
        parts.append(f"侦察结论: {sm}")
    arch = s.get("arch_snapshot")
    if isinstance(arch, dict):
        bits: list[str] = []
        osr = arch.get("os_or_runtime")
        if osr:
            bits.append(f"runtime {osr}")
        dirs = arch.get("top_level_dirs") or []
        if dirs:
            shown = "/".join(str(d) for d in dirs[:6])
            extra = f"(共 {len(dirs)})" if len(dirs) > 6 else ""
            bits.append(f"顶层 {shown}{extra}")
        grouped = arch.get("components_grouped") or []
        if grouped:
            names = []
            for g in grouped:
                if isinstance(g, dict):
                    role = f"({g.get('role')})" if g.get("role") else ""
                    names.append(f"{g.get('name', '?')}{role}")
                else:
                    names.append(str(g))
            bits.append(f"归组组件 {len(grouped)}: {', '.join(names)}")
        if bits:
            parts.append(f"- arch_snapshot: {'; '.join(bits)}")
    comps = s.get("components") or []
    if comps:
        items = []
        for c in comps:
            if not isinstance(c, dict):
                items.append(str(c))
                continue
            ver = f" v{c.get('version')}" if c.get("version") else ""
            items.append(f"{c.get('name', '?')}{ver}")
        parts.append(f"- components[{len(comps)}]: {', '.join(items)}")
    eps = s.get("entry_points") or []
    if eps:
        items = [f"{e.get('file', '?')}({e.get('reason', '')})" for e in eps
                 if isinstance(e, dict)]
        parts.append(f"- entry_points[{len(eps)}]: {', '.join(items)}")
    hrz = s.get("high_risk_areas") or []
    parts.append(f"- high_risk_areas[{len(hrz)}](观察点,非判定):")
    for h in hrz:
        if isinstance(h, dict):
            parts.append(f"   · {h.get('file', '?')} — {h.get('metric', '')}: {h.get('detail', '')}")
        else:
            parts.append(f"   · {h}")
    ra = s.get("recommended_actions") or []
    parts.append(f"- recommended_actions[{len(ra)}]:")
    for a in ra:
        if isinstance(a, dict):
            parts.append(f"   · [{a.get('priority', '')}] {a.get('action', '')}")
        else:
            parts.append(f"   · {a}")
    return "\n".join(p for p in parts if p is not None)


def _survey_v3_summary(path: Path, max_chars: int = 1500) -> str | None:
    """给定工件路径 → v3 survey 摘要;非 v3(旧 findings 容器)返回 None,
    调用方回退旧 artifact_summary。容忍缺失/解析失败。"""
    s = load_survey(path)
    if s is None or not _is_v3_survey(s):
        return None
    text = _survey_lines(s)
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n...(截断,全文用 read_file 读 {path.name})"
    return text


def _upstream_summary(path: Path, max_chars: int = 1500) -> str:
    """下游注入的上游摘要:上游为 v3 survey 时按结构摘要(entry_points + high_risk_areas +
    recommended_actions + components,不再有 findings);其余 findings 类工件
    (analysis/verification 产出)沿用 artifact_summary 原样。v2 兼容层已于 2026-08-29
    移除:旧 attack_surface.json 不再走 findings 兼容摘要(按 v3 摘要,失败则原文摘要)。"""
    s = _survey_v3_summary(path, max_chars=max_chars)
    if s is not None:
        return s
    return artifact_summary(path, max_chars=max_chars)


def build_recon_brief(process_dir: Path, max_entries: int = 120) -> str:
    """Step4 工件索引 + 已有 survey(v3)摘要:按二进制归组列出可用 sidecar,超量截断。
    供 recon 划重点,不塞全部内容。断点/补跑时已存在 survey.json → 前置 v3 摘要
    (high_risk_areas/recommended_actions 划重点、components 清单);无 v3 工件回退旧逻辑。"""
    # 优先已产出的 survey(v3):命中则前置摘要;否则回退旧 sidecar 索引逻辑
    survey_head = ""
    survey_path = _resolve_survey_path(process_dir / "agent")
    if survey_path is not None:
        s = _survey_v3_summary(survey_path)
        if s is not None:
            survey_head = ("上一轮已产出侦察结论(survey.json),本次若无补刮目标请延续既有结论。\n"
                           + s + "\n\n")

    analysis = process_dir / "analysis"
    if not analysis.is_dir():
        base = (survey_head or ("任务:侦察固件攻击面。\n"  # noqa: MEM201 条件分支,不可提前拼接
                                "(analysis/ 不存在——尚无反编译产物,深挖取证由下游 analysis 完成。)\n\n"))
        return base + build_filtered_overview(process_dir)

    # 工件索引按 .c 存在性归组(ADR-0011 票05:不再依赖 functions.json;
    # 新反编译产物是边车三件套 .c/.strings.json/.imports.json)
    groups: dict[str, list[str]] = {}
    for p in analysis.rglob("*.c"):
        stem = p.relative_to(analysis).as_posix()[: -len(".c")]
        tags = ["decompiled.c"]
        for suf, tag in ((".imports.json", "imports"), (".strings.json", "strings")):
            if (analysis / f"{stem}{suf}").is_file():
                tags.append(tag)
        groups[stem] = tags

    lines = [f"任务:侦察固件攻击面。analysis/ 下共 {len(groups)} 个已反编译工件组"
             "(边车三件套;索引只列这些,未反编译文件直接看 extracted/ 原树):"]
    for stem in sorted(groups):
        kinds = " ".join(sorted(groups[stem]))
        lines.append(f"- {stem} [{kinds}]")
    if len(lines) > max_entries + 1:
        kept, dropped = lines[: max_entries + 1], len(lines) - max_entries - 1
        lines = kept + [f"...(还有 {dropped} 个省略,可用工具按路径查询)"]
    lines.append("优先:自研程序/网络服务;SDK 库(lib/python)靠后。")
    return survey_head + "\n".join(lines) + "\n\n" + build_filtered_overview(process_dir)


def _rel_to_process(process_dir: Path, p: Path) -> str:
    """工件绝对路径 → 相对 process/ 的 posix 路径(read_file/list_files 参数根)。"""
    try:
        return p.resolve().relative_to(process_dir.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def build_downstream_brief(agent_name: str, mission: str, upstream_path: Path,
                           process_dir: Path | None = None) -> str:
    """下游 Agent 简报:前序工件摘要 + **实际路径**(动态注入,防漂移)。

    orchestrator 模式下 upstream 是 agent/<seq>_<type>/<output_name>;
    简报必须把该真实路径写给下游,细节用 read_file 按此路径拉取。
    """
    rel = (_rel_to_process(process_dir, upstream_path)
           if process_dir is not None else upstream_path.as_posix())
    return (
        f"任务:{mission}\n\n"
        f"上一阶段工件(实际路径,直接用 read_file 读它):{rel}\n"
        f"{_upstream_summary(upstream_path)}\n\n"
        f"需要完整细节(evidence/addr/components)时用 read_file 读 {rel}"
    )


def _locate_recon_survey(process_dir: Path) -> Path | None:
    """定位 recon survey 工件(补跑 analysis 附加 recon 摘要用):
    顶层 agent/ 优先(单跑/断点续跑形态),缺失再找编排实例目录 agent/<seq>_recon/
    (seq 数值最大 = 最新 recon 产出)。v2 兼容层已移除,只认 survey.json 命名。
    找不到返回 None(无 recon 摘要可附,不报错)。"""
    agent_dir = process_dir / "agent"
    top = _resolve_survey_path(agent_dir)
    if top is not None:
        return top
    best: Path | None = None
    best_seq = -1
    if agent_dir.is_dir():
        for inst in agent_dir.glob("*_recon"):
            p = _resolve_survey_path(inst)
            if p is None:
                continue
            head = inst.name.split("_", 1)[0]
            seq = int(head) if head.isdigit() else -1
            if seq >= best_seq:
                best, best_seq = p, seq
    return best


def build_analysis_brief(process_dir: Path, upstream_path: Path | None = None) -> str:
    """analysis 简报:每次 dispatch(含补跑)都重新生成,且**同源携带 recon survey 摘要**。

    - upstream 为 recon 工件(survey.json):摘要即该工件结构摘要
    - upstream 为前次 analysis 的 findings.json(编排补跑,第 2/3 次调度):标准
      下游简报之外**另附同一份 recon 摘要**(从磁盘定位 recon 工件),保证差分
      所需的完整上游信息;补跑的 handoff/差分 task 由 orchestrator 经
      extra_brief 注入(见 run_agent docstring),此处不重复组装。
    """
    mission = "对攻击面疑点逐个取证,输出候选漏洞 findings"
    if upstream_path is not None and upstream_path.name != "survey.json":
        # 补跑:上游是前次 analysis 的 findings → 常规下游简报 + 同一份 recon 摘要
        brief = build_downstream_brief(
            "analysis", mission, upstream_path, process_dir=process_dir)
        survey = _locate_recon_survey(process_dir)
        if survey is not None:
            rel = _rel_to_process(process_dir, survey)
            brief += (f"\n\n侦察阶段 survey 摘要(补跑同样携带,疑点排序与差分依据;"
                      f"全文用 read_file 读 {rel}):\n{_upstream_summary(survey)}")
        return brief
    if upstream_path is None:
        path = _resolve_survey_path(process_dir / "agent")
    else:
        path = upstream_path
    return build_downstream_brief("analysis", mission, path, process_dir=process_dir)


def build_verify_brief(process_dir: Path, upstream_path: Path | None = None) -> str:
    """verification 实例简报:工作区概览 + 复核对象指示(不 dump 上游 findings)。

    ADR-0003 起 verification 为"每疑点一实例":单条 finding 由编排器经
    extra_brief 注入(build_verify_single_brief),此处只给工作区锚点与任务说明,
    不再把全量 findings 摘要塞进每个实例(上下文隔离:每实例只装它那一条)。
    """
    return (
        "任务:复核简报尾部注入的**单条候选 finding**,过滤误报,输出该条 verified"
        " finding(带 verified/rationale)。\n"
        "复核对象与相关工件指针见简报尾部(编排器注入),细节用 read_file 分页拉取。\n\n"
        + build_filtered_overview(process_dir))


def build_verify_single_brief(process_dir: Path, finding: dict) -> str:
    """verification 单实例简报(extra_brief):单条 finding 全字段 + 相关工件指针。

    上下文隔离铁律(ADR-0003):每实例只装这一条 finding 与其工件指针,不传对话
    历史/其他 findings。指针一律工具路径(ADR-0008),且经存在性检查——LLM
    照抄指针必能打开,不再自行推导路径(2026-09-03:旧版指针带 process/ 前缀
    导致实例 6 连撞 6 次"文件不存在"烧光预算)。

    file 两种合法来源(2026-09-04):extracted/ 前缀(固件源/ELF,rel 用于
    推导边车)与 analysis/ 前缀(semgrep C 双扫命中,指向的 .c 本身就是工件,
    直接作为指针,不再推导边车)。
    """
    raw = str(finding.get("file", "") or "").replace("\\", "/").strip()
    lines = [
        "--- 待复核 finding(单条,本实例唯一对象) ---",
        json.dumps(finding, ensure_ascii=False, indent=2),
    ]
    if raw.startswith("analysis/"):
        if (process_dir / raw).is_file():
            lines.append("相关工件指针(用 read_file 按此路径读取):")
            lines.append(f"- {raw}")
    else:
        rel = raw.removeprefix("extracted/")
        if rel:
            pointers = []
            if (process_dir / "extracted" / rel).is_file():
                pointers.append(f"- extracted/{rel}")
            ana = process_dir / "analysis"
            # 边车三件套(ADR-0010 票04:.text.json 随 Step2-4 退役不再预产;
            # functions.json 新反编译不再产,不在指针表)
            pointers += [
                f"- analysis/{rel}{suf}"
                for suf in (".c", ".strings.json", ".imports.json")
                if (ana / f"{rel}{suf}").is_file()
            ]
            if pointers:
                lines.append("相关工件指针(用 read_file 按此路径读取):")
                lines.extend(pointers)
    lines.append("输出: Final Answer 输出**这一条 finding**(title/file 不得改)并附"
                 "verified + rationale,不允许换成别的 finding 或静默丢弃。")
    return "\n".join(lines)

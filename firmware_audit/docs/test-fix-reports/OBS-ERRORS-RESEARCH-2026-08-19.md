# Step5 Agent 工具观察记录（Observation）错误研究报告

- 日期：2026-08-19
- 数据源：`target/1/process/agent/`（recon / analysis / verification 三 agent 的 transcript.jsonl + obs/ 全量观察记录）
- 对应运行：2026-08-19 端到端测试（--force 重跑，deepseek-v4-flash + Docker 沙箱）
- 方法：脚本化配对 transcript 中 tool 条目（ok 字段）与 observation 条目，归一化错误签名后按 工具×类别 聚合；对每类错误回读原始 assistant 回复（含 Thought）、obs 全文与相关工件做根因取证。

---

## 一、总体统计

| 指标 | 数值 |
|------|------|
| 工具调用总数 | 60 |
| 错误（ok=false）数 | 15 |
| 错误率 | 25.0% |

分 agent 错误率：recon 4/19（21%）、analysis 5/21（24%）、verification 6/20（30%）。
verification 最高——错误沿工件链传播所致（见 E1）。

### 错误类别频率表

| 排名 | 错误类别 | 次数 | 占错误比 | 涉及工具 | 提示词关联 |
|------|----------|------|----------|----------|------------|
| 1 | 函数名不在反编译表 | 7 | 46.7% | decompile_func | **强相关** |
| 2 | 文件不存在 | 3 | 20.0% | read_file | **强相关** |
| 3 | r2 无法解析（reloc 报错） | 2 | 13.3% | xref_query | 无关（环境限制） |
| 4 | strings_query 未知模式 | 1 | 6.7% | strings_query | 弱相关 |
| 5 | 工具参数 TypeError（value） | 1 | 6.7% | binwalk_rescan | 部分相关（协议） |
| 6 | cve-bin-tool 数据库不存在 | 1 | 6.7% | sca_scan | 无关（基础设施） |

**归属汇总：12/15（80%）与提示词设计直接或部分相关；3/15（20%）与提示词无关。**

守卫机制运行情况：同参重复调用拦截 0 次、协议解析失败 0 次、零工具 Final 拒绝 0 次——错误调用参数均为不同变体，纪律提示词在"失败后不原样重试"上有效。

---

## 二、高频错误深度分析

### E1. 函数名不在反编译表（7 次，占比最高，跨两个 agent）

**现象**：decompile_func 报 `函数 'X' 不在 <name>.c; 该文件共有这些函数(前30): _DT_INIT, FUN_00104c30, ...`。

全部 7 次的入参函数名（含 agent 演变轨迹）：

| Agent | 步 | 传入函数名 | 来源 |
|-------|----|-----------|------|
| analysis | #04 | `method.unitree::ms.SystemCall_std::__cxx11::basic_string...`（mangled C++ 名） | xref_query 输出（step003） |
| analysis | #11 | `fcn.0001c908` | xref_query 输出 |
| analysis | #12 | `FUN_00101c908`（自己换算，多写一位） | 模型猜测 |
| verification | #03 | `method.unitree::ms.SystemCall...`（同 analysis #04） | findings.json 沿传 |
| verification | #11/#12/#14 | `fcn.0001c908` / `FUN_001c908` / `FUN_0001c908` | findings.json 沿传 + 猜测 |

**根因（已实证）**：工具间命名体系不互通，且无任何换算说明。

- xref_query（radare2）返回 **r2 风格名**：`fcn.<相对偏移>` 与 demangled 方法名；
- decompile_func 只认 **Ghidra 风格名**：`.c` 文件函数头为 `FUN_<8位hex绝对地址>` 或真实符号名（如 `CallSystem`）。

换算关系实证：r2 偏移 `0x1c908` + Ghidra 基址 `0x100000` = `0x11c908`。查 `4gcm.functions.json`，**`FUN_0011c908` 真实存在**，其 callees 为 `system, fopen, __snprintf_chk, pthread_create...`——正是 agent 想核实的函数。三次变体尝试（`FUN_001c908`/`FUN_0001c908` = 0x1c908 未加基址；`FUN_00101c908` = 0x101C908 多写一位）全部差一位 hex。analysis #12 的 Thought 原文 *"xref 显示的 fcn.0001c908 是 r2 偏移命名，Ghidra 侧对应地址可能加上基址偏移。尝试 FUN_00101c908"*——**模型推理方向完全正确，只因无换算规则可依而算错**。

**提示词关联判定（强相关）**：
1. `ANALYSIS_DIR_DOC`（工作区锚点）只列工件后缀，**未说明两套命名的存在与换算规则**；
2. `decompile_func` params_doc 仅说 "func_name 精确匹配"，无命名约定说明；
3. `xref_query` 输出端无"此名字不能直接用于 decompile_func"提示——工具输出诱导下游犯错；
4. 正确路径存在但提示词未教：`master_service.functions.json` 中有真实名 `CallSystem @ 0x6409bc`（callees 含 system），按 callees 反查一次即可定位。

**连带影响（错误沿工件链传播）**：analysis 将错误的 `fcn.0001c908` 写入 findings.json 的 func 字段 → verification 继承后再失败 3 次 → 最终报告 finding #3 被迫注明"调用点内容无法 decompile 核实"，confidence 降为 medium。**此错误链直接拉低了最终报告质量**。

### E2. 文件不存在（3 次）

| Agent | 步 | 尝试路径 | 诱因 |
|-------|----|---------|------|
| recon | #01 | `agent/attack_surface.json` | params_doc 示例路径 |
| verification | #17 | `agent/secret_scan.json` | 由 evidence 中"secret_scan 命中"推断 |
| verification | #19 | `agent/semgrep_scan.json` | 同上 |

**根因一（示例路径被字面照抄，已实证）**：`read_file` 的 params_doc 示例值恰为 `{"path": "agent/attack_surface.json", ...}`。recon 第一步 Thought 原文：*"Maybe an attack_surface.json exists from previous agent?"*——attack_surface.json 是 recon 自己的产物，对 recon 而言该路径必然不存在，模型照抄示例值开局即错。

**根因二（工件清单缺失，已实证）**：verification step18 原文：*"也许有 agent/semgrep_scan.json、agent/analysis.json、agent/attack_surface.json 等。注意系统提示里 read_file 例子是 'agent/attack_surface.json'"*——模型**明确引用系统提示中的示例作为猜路径依据**。系统提示的工作区锚点只列 `process/analysis/` 侧车，从未列出 `agent/` 下实际存在的工件清单（attack_surface.json / findings.json / verified_findings.json + transcript / obs），模型只能凭 evidence 中的工具名脑补工件路径。

**提示词关联判定（强相关）**：示例值诱导 + 上下文信息不足（工件清单未提供）双重作用。

**正向观察**：防幻觉纪律 #1（"文件不存在 → verified=false"）正确触发——chat_go 密钥 finding 因 secret_scan.json 缺失被按纪律剔除，说明提示词的兜底纪律有效；但这些错误调用本身本可避免。

### E3. r2 无法解析（reloc 报错，2 次，非提示词）

analysis #07（`sym.imp.strcpy`）与 #08（mangled 方法名）对 master_service 查询失败：`Unsupported reloc type 1030 for aarch64 / reloc conversion failed`；而 #03（`sym.imp.system`，同一二进制）成功。

**根因**：r2 5.9.8 对该 aarch64 二进制的部分重定位（type 1030）无法转换，受影响导入符号的 PLT 解析失败，`axtj` 对这些符号输出为空；`_parse_r2_json` 找不到 JSON 行即报"无输出或无法解析"。**环境限制，与提示词无关。**

可改进（工具层）：错误信息过滤 reloc 噪声并给出替代建议（"该符号因 reloc 解析失败不可查，建议改用 functions.json 按 callees 反查"）。

### E4. strings_query 未知模式 'http'（1 次，弱相关）

recon #14 传 `pattern: "http"`，内置模式为 `url/ip/password/key/shadow/empty_password`。模型直觉用 "http"（比 url 更"精确"的心理）。

**提示词关联判定（弱相关）**：工具 description 列了 5 个模式名（漏 empty_password），params_doc 只说"内置名或 re:<正则>"未逐字枚举值域；同时模型未细读 description。自愈快（错误信息列出全部内置名，下一轮即纠正）。属"值域枚举不完整 + 模型未细读"的叠加，提示词改进可消除但本身成本低。

### E5. binwalk_rescan TypeError: unexpected keyword 'value'（1 次，部分相关）

**现象**：`BinwalkRescanTool._run() got an unexpected keyword argument 'value'`，但模型明确传的是 `file_ref`。

**根因链（已实证，模型协议违规 + 解析器降级策略叠加）**：

1. **上游违规**：recon step14 的回复违反"每轮只输出一个块"——一轮内写了 2 个 Action 块并**自问自答**（自己虚构了 `Observation: 命中 2/19123 条...`）；
2. 解析器按设计取首个 Action（strings_query/http）并在伪 Observation 处截断——模型心理状态与真实执行历史脱节，step15 Thought 原文：*"we sent 'url', but observation says unknown pattern 'http'"*（明显困惑）；
3. step15 发送 binwalk_rescan 时，Action Input 的 JSON 后**跟了叙述文本**（*"No pattern. So the Observation is inconsistent. Maybe I need to resend..."*）；
4. `parse_action_input` 对"JSON+尾部垃圾"整体 `json.loads` 失败 → 裸字符串降级为 `{"value": 整串}` → 工具收到意外参数 value → TypeError；
5. step16 模型花整轮反推 *"Maybe there is a schema mismatch?"*——1 次错误放大为 2 轮困惑。

**提示词/协议关联判定（部分相关）**：
- REACT_PROTOCOL 已写"每轮只输出一个块"，但未显式禁止"Action Input 行后输出文字"，也无多 Action 行为的拦截反馈；
- 解析器层：`parse_action_input` 未复用 artifacts.py 已有的"提取首个 {...}"启发式；execute 捕获的 TypeError 以原始 Python 异常回喂，未提示"Action Input 可能不是纯 JSON"，模型无法快速自纠。

### E6. cve-bin-tool 数据库不存在（1 次，非提示词）

recon #18：退出码 40，`CRITICAL cve_bin_tool - Database does not exist`。`.cve_cache` 卷存在但库从未预热，`--offline` 模式下无库即崩。**基础设施问题**（需一次性在线预热 CVE 库），与提示词无关。工具降级行为正确，attack_surface.json summary 已如实标注。

---

## 三、提示词设计专项评估

按"清晰度 / 逻辑歧义 / 上下文充分性 / 格式符合度"四维度映射：

| 维度 | 结论 | 证据 |
|------|------|------|
| **任务引导清晰度** | 主流程清晰，但**工具间数据衔接规则缺失** | E1：工作流写"decompile_func 看可疑函数逻辑 → xref_query 查调用链"，暗示两工具可直接衔接，实际输出/输入命名体系不互通且无换算说明（7 次错误的直接根源） |
| **逻辑歧义** | 未发现提示词内部矛盾 | 三段提示词（RECON/ANALYSIS/VERIFY）职责边界、纪律条款无互相冲突处；防幻觉纪律与 E2 场景的交互表现正确 |
| **上下文充分性** | **两处明显不足** | ① E2：`agent/` 工件清单从未告知（锚点只列 analysis/ 侧车）；② E1：函数命名换算规则缺失。模型在 step19 自行诊断出的能力缺口（"工具里没有读取 extracted 根下任意文件的能力"）也属上下文/工具面信息未提供 |
| **格式符合度** | 参数示例与值域描述存在缺陷 | ① E2：read_file params_doc 示例路径被模型字面照抄（step1、step18 两处原话实证）；② E4：strings_query 内置模式未完整枚举；③ E5：协议未显式禁止 Action Input 后接文字 |

**综合判定**：提示词的**纪律与兜底设计有效**（防幻觉、工具先行、同参循环约束全部按预期工作，守卫零触发说明模型行为已被纪律塑形），但**工具衔接层（命名换算、工件清单、示例值设计）存在系统性信息缺口**，是 80% 错误的来源。

---

## 四、改进建议（按预期收益排序）

### 提示词层（预期消除 12/15 次错误）

1. **ANALYSIS_DIR_DOC 增加函数命名换算说明**（消除 E1 的 7 次）：
   - "xref_query 返回 r2 命名（`fcn.<hex>` 为相对偏移；mangled C++ 方法名）；decompile_func 只认 Ghidra 命名 `FUN_<8位hex>`（绝对地址 = r2 偏移 + 0x100000 基址）或真实符号名"
   - "mangled 方法名在 .c 中多为 FUN_ 替身：改用 read_file 读 `<file>.functions.json`，按 callees 含 system/popen 反查真实函数名（如 CallSystem）"
2. **read_file params_doc 示例改中性 + 锚点列 agent/ 工件清单**（消除 E2 的 3 次）：示例改为确实存在的通用路径；简报/锚点明确"agent/ 下工件仅有 attack_surface.json → findings.json → verified_findings.json"。
3. **REACT_PROTOCOL 增补**（缓解 E5）："Action Input 之后立即停止输出，禁止任何后续文字；单轮严格一个 Action，禁止自写 Observation"。
4. **strings_query params_doc 完整枚举内置模式值域**（消除 E4）。

### 解析器层

5. `parse_action_input` 复用 artifacts.py 的启发式：整体解析失败时提取首个平衡 `{...}` 再试（E5 第 4 步的兜底）。
6. `AgentTool.execute` 对 TypeError 转译："参数不匹配——Action Input 可能混入了非 JSON 文本"（E5 第 5 步的自纠提速）。

### 工具/基础设施层（非提示词）

7. xref_query 错误信息过滤 reloc 噪声，附替代路径建议（E3）。
8. sca_scan：文档化 CVE 库预热流程，或首跑检测到空库时返回更明确的降级提示（E6）。
9. （数据质量）imports.json call_sites 大面积为空：60 个 obs 中 14 个含"无调用点记录"（23%）。模型已在 verification step16 自行发现 *"imports.json 的 call_sites 字段不可靠，xref_query 才是准的"*。建议 imports_query 输出端提示"call_sites 为空时请用 xref_query"。

---

## 五、结论

1. 15 次错误中 **12 次（80%）可归因于提示词设计的信息缺口**，集中在三处：函数命名换算规则缺失（E1，7 次，且沿工件链传播拉低最终报告质量）、params_doc 示例路径诱导 + 工件清单缺失（E2，3 次）、协议输出约束不够显式（E5，1 次）+ 值域枚举不全（E4，1 次）。
2. **3 次（20%）与提示词无关**：r2 reloc 环境限制（2 次）、CVE 库未预热（1 次）。
3. 提示词的**纪律条款（防幻觉/工具先行/同参循环上限）实测有效**：守卫零触发、chat_go 误报被正确剔除、模型失败后未原样重试——错误行为被约束在"换变体尝试"而非"死循环"。
4. 最具价值的单点修复是 **E1 的命名换算说明**：一次提示词补充可消除近半错误，并可阻止错误名沿 findings.json 传播到最终报告。

---

## 六、落地记录（2026-08-19 同日执行）

| 建议 | 状态 |
|------|------|
| 建议 1 命名换算说明 | ✅ ANALYSIS_DIR_DOC 增"函数命名规则"段；工具更名 decompile_func → **find_decompiled_function**（强调检索语义），description/params_doc/错误提示均含命名约束与 functions.json 反查指引 |
| 建议 2 工件清单 + 示例中性化 | ✅ 锚点明示 agent/ 仅有三个链式工件；read_file 示例改为 fileinfo.json |
| 建议 3 协议约束 | ✅ REACT_PROTOCOL 增"JSON 后立即停止输出/禁止自写 Observation/单轮一个 Action" |
| 建议 4 值域枚举 | ✅ strings_query params_doc 完整枚举 6 内置模式 |
| 建议 7 xref 输出端提示 | ✅ description 注明返回 r2 命名不能直传 find 工具 |
| 建议 5/6（解析器启发式与 TypeError 转译） | ⏳ 未实施（本轮仅动提示词/工具描述层） |
| 迭代预算变量注入 | ✅（随需新增）build_system_prompt(max_iters) 注入"最多 N 轮"预算段 |
| 最后一轮强制 summary | ✅（随需新增）react_loop 第 max_iters 轮注入 LAST_ROUND_NOTICE；FORCE_FINAL_PROMPT 要求执行总结三要素（执行情况/已完成与结论/未完成与建议） |

回归：139 passed + 2 skipped（新增 test_last_round_notice_and_summary_force / test_system_prompt_budget_injection；test_resolve_and_decompile 增命名指引断言）。

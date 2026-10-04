# 05: 预检动词与工具契约落地

**What to build:** QEMU 工具进入 Host 工具表，预检能力端到端可用：参数契约校验、角色授权（analysis/verification 可用、recon 拒绝；`sandbox_verify` 不能触达 QEMU 执行）、结果分类枚举、预检报告（架构/解释器/依赖/模板适用性/路径边界）。预检不执行目标、不创建会话。执行动词本票不实现。离线测试用 Docker 替身；另加镜像内真实预检 target/6 与 target/8 各一样本的门控测试。

**Blocked by:** 03

**Status:** ready-for-agent

- [x] 预检动词参数契约与结果 schema 定稿（结构化参数声明单一来源，含 JSON 骨架文档）
- [x] 角色授权生效：recon 调用被拒，analysis/verification 放行；`sandbox_verify` 路径无法触达 QEMU 执行
- [x] 结果分类枚举落地（八类失败分类的预检侧子集），原始信息保留不静默丢弃
- [x] 离线替身测试全覆盖参数校验/授权/分类；真实预检门控测试覆盖 target/6 + target/8 各一样本
- [x] 全量套件绿

## Comments

2026-09-22 后续决定：用户采用 PRoot + QEMU。本票完成状态与历史证据保留；新后端镜像、预检及运行边界由 [票 15](15-proot-backend-integration.md) 补齐，不能把旧结果视为新后端已验收。

### 2026-09-22 实现记录（票 05 完成；提交 3483541 + code-review 修复 736351a）

**交付物**：
- `firmware_audit/step5_agent/providers/tools/qemu_base.py` — QEMU 工具族共享基座：`QEMU_EXEC_IMAGE`（与 pins.env 同源，测试防漂移）、`QemuResultClass` 八类结果分类枚举（spec 单一出处；预检子集 `PRECHECK_RESULT_CLASSES` = prep_blocked/dependency_blocked/facility_failure，OK 通过态单列；执行侧五类本票只定义不发出）、首批架构矩阵档案（ARM32 LE→qemu-arm-static、MIPS32 BE→qemu-mips-static；`observed_notes` 带票号来源，是档案不是能力承诺）。
- `firmware_audit/step5_agent/providers/tools/qemu_precheck.py` — 预检工具：纯 struct 静态解析 ELF（32/64 位、双端通吃、零依赖；PT_INTERP/PT_LOAD vaddr 映射/DT_NEEDED），固件根内加载器与 NEEDED 库检索（标准库目录布局 + 限界递归兜底），NVRAM 系模板适用性，路径边界。**唯一容器调用是执行镜像内 `qemu-<arch>-static --version`（设施核查，只跑 qemu 自身 x86 二进制，不读不触固件字节）**。参数契约：`file_ref`/`firmware_root` 必选（结构化声明单一来源 + params_doc JSON 骨架，ADR-0004）。
- 注册表授权：`ToolContract(QemuPrecheckTool, {analysis, verification}, READ_ONLY_IDEMPOTENT)`——recon 经 `authorize_tool` 拒绝并回喂错误 Observation；预检只读幂等可重放。`host/tooling.py` 路径参数归一名单补 `firmware_root`。
- 三角色提示词：analysis/verification 列明 qemu_precheck 及适用场景（静态证据不足、确需真实程序行为时评估可行性；预检通过≠子进程链可用≠漏洞成立）；recon 声明 qemu_precheck 不可见（ADR-0013"工具说明与角色指令解释适用场景"）。

**报告 schema**（`ToolResult.data`，schema_version=1）：`mode: "precheck"`、`result_class` + 中文 label、architecture（三元组/矩阵归属/qemu 二进制/observed_notes）、interpreter（requested/present/resolved_under_root）、dependencies（needed 原序全量/resolved/missing/dynamic_note/search_notes）、template_applicability、execution_facility、blockers[]、limitations[]（三条固定限制句）。`ToolResult.ok` 语义：报告成功产出即 True（阻塞是发现不是预检失败），分类看 `result_class`。

**分类口径**：prep_blocked=路径越界/目标缺失/非 ELF/架构不在首批矩阵；dependency_blocked=解释器或 NEEDED 库固件根内缺失、NVRAM 系库需模板而支持表未定稿（票 11，按 ADR-0013 记运行阻塞）；facility_failure=镜像不可用/qemu 版本查询失败；全过=ok。

**AC 逐条核对（5/5）**：
1. **参数契约与结果 schema 定稿** ✓ — params 结构化声明（必选 file_ref/firmware_root）+ params_doc 渲染 JSON 骨架，与校验同源；报告 schema 见上，离线测试逐字段钉住。
2. **角色授权生效** ✓ — recon：`authorize_tool("recon","qemu_precheck")` 抛 ToolAuthorizationError、`tool_names_for_role("recon")` 不可见、`make_tools(role="recon")` 不构造；analysis/verification 放行。`sandbox_verify` 无法触达 QEMU 执行：解释器白名单仅 python3/node/php（无 qemu 入口）、参数面仅 code/language/timeout、运行于基础镜像 firm_audit/sandbox（零 qemu——票 03 结构性隔离，`test_qemu_exec_image.py::test_base_image_no_qemu_and_tools_intact` 守护）。
3. **结果分类枚举落地（八类预检侧子集）** ✓ — `QemuResultClass` 定义 spec 八类 + ok；预检只发出子集三类；原始信息保留：needed 原序全量、dynamic_note、search_notes、same_basename_found 等均入报告不静默丢弃。
4. **离线替身全覆盖 + 真实门控双样本** ✓ — 离线 21 项：手构 ELF 夹具（ARM32LE/MIPS32BE/静态/矩阵外/垃圾字节）+ Docker 替身（替换 `_facility_check`，断言零容器调用）覆盖参数校验/授权/分类/路径边界/模板适用性/截断留痕/前缀宽容；真实门控 2 项：target/6 `usr/sbin/nvram`（ARM32 LE：静态条件全过 → 因 libnvram.so 需模板判 dependency_blocked，needed 原始清单与 resolved 映射保留）、target/8 `bin/busybox`（MIPS32 BE：全过 → ok，interpreter/依赖/facility 逐字段断言）；缺镜像/缺样本 SKIP 并记录原因。
5. **全量套件绿** ✓ — 1147 passed + 16 skipped（16 个 skip 全为既有 target/1 门控，先于本票；基线 1123+16，新增 24 项全 PASS，零回归）。

**票 04 五条限制逐条落实**：
1. **区分检查通过与链能力验证** ✓ — 每份报告固定限制句："架构/解释器/依赖检查通过不代表子进程链能力已验证（票 04 实测…）；链能力以会话期实测为准"，报告无任何"链可用"字段或宣称，测试钉住。
2. **ARM 链受阻不宣称整链可用** ✓ — 架构档案 `observed_notes` 原文记录"ARM32 LE 顶层程序经 -L 可运行；子进程链当前受阻，根因未定论"（带票号来源）；真实 target/6 测试断言限制句含"受阻/未定论"。
3. **未核实根因不作定论** ✓ — 模板适用性明确"/dev/nvram 系与 envram(MTD)系家族归属需符号级核实，预检不判定"；矩阵外架构只记"不在首批矩阵…不据此宣称该架构不可行"；NVRAM 家族区分不做。
4. **sandbox_verify 不能绕过专用入口** ✓ — 结构性隔离（基础镜像物理无 qemu）+ 白名单/参数面/注册表契约三重测试；QEMU 执行入口只能经 qemu 工具族（执行动词后续票）。
5. **预检不通过运行固件或其加载器检查依赖** ✓ — 全部依赖/解释器检查为宿主侧静态字节解析 + 固件根内文件存在性检查；唯一容器调用只跑 qemu 自身 `--version`；离线路径边界测试断言拦截时不发生任何容器调用。

**code-review 记录（两轴并行评审 + 修复，提交 736351a）**：Spec 轴：AC1-5 全落地、无范围违规（执行设施核查段有八类枚举辩护，保留）。Standards 轴 + Spec 轴共同点名 4 处修复：①检索超 `_LIB_SEARCH_CAP` 原静默当缺失 → `_find_in_root` 返回 (hit, truncated)，截断写入 `search_notes` 且阻塞 detail 注明"结论可能不可靠"；②解释器 basename 兜底命中即判 present 过宽（-L 按 PT_INTERP 原路径解析）→ 精确路径为唯一判据，同名命中只留痕 `same_basename_found` 仍阻塞；③设施核查命令 f-string 拼接触碰 AGENTS.md 禁令 → 改纯字符串拼接；④动态段存在但无 PT_INTERP 误标"静态链接" → 解析器补 `has_dynamic` 区分。新增 2 项离线回归钉住①②，修复后 24/24 + 全量绿复验。

**已知边界与限制（诚实声明）**：
- 预检只覆盖**顶层目标 ELF** 的静态启动条件；子进程链（票 09）、会话生命周期（票 06/08）、执行与预算（票 06/07）均不在本票，无任何实现或宣称。
- NVRAM 系库（libnvram.so/libCfm.so/libtpi.so 基名匹配）当前一律判运行阻塞——这是模板支持表未定稿（票 11）下的真实状态，票 11 落地后需回改预检模板表；基名匹配无法区分库内实际使用的家族，报告已声明不判定。
- 依赖检索为固件根内**文件存在性**检查，不验证 ABI/符号兼容（spec：可解析性与 ABI 兼容属真实实验/票 11 范围）；动态段不可解析（缺 DT_STRTAB 等）只记 dynamic_note 不阻塞。
- 设施核查证明"镜像内 qemu 二进制在且自报版本"，不等价于对具体目标的执行能力验证。
- 架构矩阵首批仅 ARM32 LE 与 MIPS32 BE；MIPS 小端/ARM 大端/64 位均按"不在首批矩阵"处理，扩充需另行核实。
- 真实门控测试依赖本机 target/6、target/8 解包树与 firm_audit/qemu-exec 镜像（均在位实跑通过）；缺失环境 SKIP 不假绿。
- 未触碰：CONTEXT.md（有用户未提交改动，术语表更新留待文档统一修订）、执行动词、会话、宿主 binfmt；未调用 GLM、未读 GT。

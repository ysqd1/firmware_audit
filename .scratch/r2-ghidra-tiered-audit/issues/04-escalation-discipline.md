# 04: 升级纪律——提示词 + verification 红线 + 缺件文案翻转

**What to build:** 两级模型的行为纪律落进 LLM 可见的一切文本:analysis/verification 系统提示词写入"先 r2,信息不够才 ghidra_decompile"的升级规则;find_decompiled_function 缺 .c 的文案从"不触发重分析"翻转为升级链引导;verification 硬红线改写——缺 `.c` → r2 层查证 → 信息不够 → ghidra_decompile → 仍缺失/超时零产出 → 才判 false_positive(原"read_file 报文件不存在即 false_positive"废除,"没人反编译过"不再是"证据不存在");verify 单实例简报的边车指针后缀表缩为三件套(.c/.strings.json/.imports.json)。规则出处:ADR-0010、spec(User Stories 18-19)。

**Blocked by:** 01、03(文案引用的工具必须已存在)

**Status:** ready-for-human

- [x] analysis/verification 两份系统提示词含升级规则(内容断言,ScriptedLLM 先例)
- [x] find_decompiled_function 新文案引导 r2/反编译;旧表述零残留
- [x] VERIFY_SYSTEM 红线为升级链表述
- [x] verify 简报指针后缀三件套;用已有真实工件跑简报构建验证
- [x] 全套件绿

## Comments

**2026-09-09 implement**(工单完成,待人工验收):

- 提示词四处落地:①ANALYSIS_SYSTEM 流程段"定位代码"重写为 r2 层优先 + **升级纪律**(口诀"先 r2,信息不够才反编译",并说明幂等缓存让复核零成本复用);②ANALYSIS_DIR_DOC 命名规则行补 ghidra_decompile=升级层定位(分钟级、幂等缓存+sha256 去重),functions.json 反查指引标注"老工件/新反编译产物没有 functions.json,改 r2_list_functions 现算 + r2_disassemble_function 读函数体"(边车三件套制的联动文案);③VERIFY_SYSTEM 复核流程第 1 步改为"先验原始文件存在,缺 .c 走升级链";④VERIFY_SYSTEM 硬红线第 1 条整体改写为升级链四段式(r2 查证 → 信息不够 → ghidra_decompile → 仍缺失/超时零产出才 verified=false 写"反编译零产出";原始文件不存在/路径越界仍直接 false)。
- AGENT_DISCIPLINE"不猜路径"行的"复核阶段据此判 false_positive"旧表述移除,改为"产物缺失 ≠ 证据不存在(复核的缺件处理走其升级链硬纪律)"。
- find_decompiled_function:docstring 重写("只读缓存、只检索;反编译唯一入口 ghidra_decompile");缺 .c 文案翻转为升级链引导;miss-函数提示同步标注 functions.json 仅老工件有。LLM 可见文本与代码层"不触发重分析"零残留(grep 验证,唯一命中是守护测试的反向断言;2026-09-09 评审补充:docs/tools_summary.md 旧文档当时仍有旧表述,已补过时横幅)。
- verify 单实例简报(build_verify_single_brief)边车指针后缀表缩为三件套;真实工件验证:target/1 idlc 的 finding 构建简报,三件套指针齐、无 .text.json/.functions.json 指针。
- 测试:test_orchestrator 新增 `test_escalation_discipline_prompts`(ANALYSIS/VERIFY 升级关键词+口诀、VERIFY 升级链四要素、旧红线零残留的反向断言);`test_verify_single_brief_pointers` 更新为三件套语义(盘上有退役产物也不进指针表)。全套件 324 passed + 15 skipped。

**2026-09-09 code-review 采纳修复**(规格轴遗漏闭环):

- ADR-0011 能力消失清单"is_system_trust → 降为提示词纪律"此前被整体丢弃(新旧提示词都无),补齐:ANALYSIS_SYSTEM 流程增第 5 条"系统信任库纪律"(发行版 CA/证书不作可疑上报,厂商自签/非常规位置才取证);VERIFY_SYSTEM 静态复核同款提示(上游拿发行版 CA 当 finding 时判误报)。
- tools_summary.md(旧工具文档)补"⚠ 过时声明(2026-09-09)"横幅;本票评论原"全仓零残留"声明同步收窄为"LLM 可见文本与代码层"。
- make_tools 排除机制对新工具的显式断言补进 test_make_tools_exclude(spec Testing Decision 2)。

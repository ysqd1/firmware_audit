# 07: 收尾——全量回归 + target/1 e2e + 文档收口

**What to build:** 整个 feature 的验收与文档对齐:全量测试绿;真实 target/1 跑一轮端到端演练(流水线解包 → step5 直接复用旧边车缓存),验证"老工作区零迁移"承诺;CONTEXT.md 带"已退役"标注的词条物理清理(FileInfo/分类类型集/审计状态/不透明固件分诊/系统信任库 vs 系统标准目录等);AGENTS.md / requirements.md 的 Step1-4 相关章节打"过时,以 ADR-0010/0011 为准"标记(rules.md 已于 2026-09-09 开工前同步过工程守则与退役校正,本票复查即可)。演练输出(报告/工件路径/缓存命中证据)贴本票评论。

**Blocked by:** 06

**Status:** ready-for-human

- [x] 全套件绿(记录与改动前的用例数对照)
- [x] target/1 e2e:流水线 + step5 缓存复用演练,结论与产物路径贴评论
- [x] CONTEXT.md 退役词条物理清理
- [x] AGENTS.md / requirements.md 过时章节标记
- [x] rules.md 复查,与新架构无矛盾

## Comments

**2026-09-09 implement**(工单完成,待人工验收):

- **用例数对照**:开工前基线 298 passed + 11 skipped(其中 1 个为预存环境失败:test_read_file 依赖 target/1 缺失的 fileinfo.json,票01 顺带修复为自造探针)→ 收尾 301 passed + 15 skipped。净变化:退役删除 4 个测试文件(-26 用例),新增 test_step5_r2_tools(7)/test_step5_fallback_tools(10)/test_step5_ghidra_tool(8)三块 + 权限矩阵/启动门/升级纪律/简报指针等扩展;skip +4 为新增 Docker 门控真跑(r2×2/兜底×1/ghidra 冒烟×1)。
- **target/1 e2e 演练**(结论:老工作区零迁移承诺逐层验证通过):
  - 流水线直通:`run_pipeline(target/1, --no-step5)` → `.step1_done` 命中跳过 Step1(零 Docker)→ 直达链尾,无 Step2-4 痕迹。
  - step5 启动门:新门"extracted/ 存在"对 target/1 放行(注入无 key LLM 验证,死于无 key 而非门)。
  - 缓存复用证据(零容器):`find_decompiled_function(unitree/bin/idlc, main)` OK(老 .c);`strings_query(pattern=url)` OK(老 .strings.json 边车);**`ghidra_decompile(unitree/bin/idlc)` 幂等缓存命中——"已反编译(缓存命中): analysis/unitree/bin/idlc.c(340 个函数)"**,老 43 组边车天然是缓存,零迁移零重跑。
  - **环境限制(如实记录)**:本环境 Docker daemon 不可用(sandbox/ghidra 镜像缺失),真 r2/真 Ghidra 容器路与真 LLM 的 Step5 全编排演练未能实跑——Docker 门控测试在本环境自动 skip(设计如此),待 Docker 可用环境跑 `python -m pytest firmware_audit/test/test_step5_cli_tools.py -q` 即补上验收锚点;真 LLM 演练(`python -m firmware_audit.main target/1`)待人工择机执行。
- **CONTEXT.md 物理清理**:删除 4 个"已退役"词条(FileInfo/分类类型集/审计状态 audit_status/系统信任库 vs 系统标准目录);"不透明固件分诊"改写为存活概念"不透明固件"(结构性审计路径);"文档声明"词条更新(requirements.md 已删除);profile 词条更新(只剩 SEARCH_EXCLUDE 段,"待退役工单"措辞清除)。
- **AGENTS.md 过时标记**:文档头加"⚠ 架构现状(2026-09-09)"横幅(Step0→1→5/r2 族/ghidra_decompile/升级纪律,指向两篇 ADR);第一章标题改"【已退役 2026-09-09,ADR-0011】(仅存档,代码已删除)";第三章加"部分表述过时"横幅(读盘工具数据来源/边车三件套/更名)。requirements.md 已于开工前删除,无需标记。
- **rules.md 复查**:与新架构无矛盾;仅一处措辞落定——"零第三方依赖"条目的 cryptography 例外从"退役落地前按可选处理"改为"已随 Step4 退役删除"(grep 确认全仓零 cryptography import);其余(铁律/目录约定/ExtractInfo.py Jython 条款)仍准确。

**2026-09-09 Docker 冒烟补跑 + target/4 e2e 演练**(用户开启 Docker 后):

- **Docker 门控冒烟全绿**:test_step5_cli_tools 15 passed(真沙箱 checksec/r2_xref/aflj/pdf/兜底 izz+iij/semgrep/gitleaks/binwalk_rescan/sandbox_verify + **真 Ghidra 冒烟:6KB vlc 插件三件套完整、二次调用缓存命中**)。修两处测试选材 bug(非 ELF 用例改用真实存在的 run_test.sh;ghidra 冒烟拷贝名去扩展名,避免 ".so.c" 边车名与断言不符)——工具本身无缺陷,手工复现实测 9s/12 函数/三件套齐。
- **全套件 317 passed + 2 skipped**:Docker 可用后 13 个门控用例由 skip 转真跑全过。
- **target/4 e2e(D-Link DIR-882 A1,1.10B02,SHRS 加密头)**:全链路成功——orchestrator(5 次调度)→ recon×3(诚实铺面空树,~56k tokens/轮)→ analysis(4 findings:3 条 critical CVE-2022-44804/44806/44807 经 cve_lookup 版本匹配 + 1 条 info"解包阻塞"记录项)→ verification 4/4 全复核(每疑点一实例,25 轮,1.87M tokens)→ report.md。**升级链红线的正确性得到实测**:3 条 CVE 候选判误报的 rationale 是"原始文件不存在无法本地取证,恢复解包后可重新送审"(升级链表述,非旧"工件不存在一刀切");info 记录项正确地不适用该纪律。产物:target/4/process/agent/orchestrator/report.md。
- **e2e 暴露并修复一个真缺口**:SHRS 加密固件解出零内容树,旧 Step2"过滤后无文件终止"的兜底随退役消失,verify() 未拦,流水线静默进 Step5 空转(本次演练即空转实证,~3M tokens)。修复:main 新增零内容守卫(content_file_count 排除簿记 + empty_content_action 决策点)——顶层响亮终止(附厂商加密头指引,SHRS 即实例),分区批次内跳过续批(沿用票02 语义);is_partition 参数回归;3 组单测。step1 两处 runtime 陈旧文案("留树交 Step4 分诊")同步修正(manifest 会喂给 LLM)。
- target/4 现状:保留本次演练产物作证据;未来重跑将命中零内容守卫,在 Step1 终止并提示"固件可能带厂商加密/私有头(如 D-Link SHRS),先用厂商解密工具处理"(SHRS 为 D-Link 私有加密格式,标准 binwalk 不识别,解密器属规格外,与 ADR-0011 分诊裁定同轨)。

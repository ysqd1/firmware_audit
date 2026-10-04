# 01: r2 工具族——list_functions / disassemble_function / xref 改名

**What to build:** analysis/verification 两个 Agent 能对解包树里任意 ELF 做廉价二进制分析:查函数清单(aflj,timeout 600,超时/未命中文案引导降级到单函数 af 便宜路径)、读单个函数反汇编(pdf,未命中附该文件前 N 个函数名提示)、交叉引用工具由 xref_query 更名 r2_xref_query(行为不变,注册表/提示词/测试全部更新)。引擎前缀命名纪律落地:r2_* 表示"现算",与读缓存的 find_decompiled_function 区分。recon 不授。本票的 prefactor 职责:立一个内部 r2 调用辅助(容器命令构建/路径换算/超时),后续票复用。规则出处:ADR-0010、spec(User Stories 1-4、10)。

**Blocked by:** None (can start immediately)

**Status:** ready-for-human

- [x] r2_list_functions:对 target/1 真实 ELF(Docker 门控)返回函数清单;非 ELF/路径越界返回引导性 ok=False;timeout=600 断言
- [x] r2_disassemble_function:按名字/地址返回反汇编;未命中附函数名提示
- [x] r2_xref_query 更名后行为不变,旧名无残留引用
- [x] 权限矩阵:r2 三工具仅授 analysis/verification,矩阵测试扩展
- [x] analysis/verification 系统提示词工具清单含三工具,params_doc 接口契约测试过(ADR-0004)
- [x] execute 层单测:monkeypatch run_docker 断言命令行/挂载/超时;全套件绿

## Comments

**2026-09-09 implement**(工单完成,待人工验收):

- 新 `r2_base.py`(prefactor):`run_r2`(命令构建,`-q` + r2_args + 容器路径统一追加)、`elf_guard`(宿主侧 4 字节 magic 守卫:越界/缺失/非 ELF → 引导性文案,零容器)、`parse_r2_json`(自 xref_query 收编,括号深度配平解析)、`sanitize_func_or_addr`(白名单字符校验,r2 把 `;` 当命令分隔符,拼接面在工具层收口)、`R2_ANALYZE_TIMEOUT=600` / `R2_DEFAULT_TIMEOUT=180`。
- 新 `r2_list_functions.py`:aflj,`-A` 全分析,timeout=600;失败/超时文案引导降级 `r2_disassemble_function`;退出码不可靠以 stdout JSON 为准(xref 既有纪律)。新 `r2_disassemble_function.py`:`af @ X; pdf @ X` 单函数便宜路径,timeout 180;未命中二次 `f`(flags,不触发分析)取前 20 个 sym./fcn. 名附进错误提示;危险字符目标即时拒绝零容器。
- `xref_query` → `r2_xref_query`(git mv,行为不变):类名 R2XrefQueryTool;旧名全仓零残留(工具描述/imports_query 指引/semgrep 注记/prompts 三处/find_decompiled_function 文档)。
- 权限矩阵:runner 两 CFG 加三工具;矩阵测试新增"r2 族仅授 analysis/verification,recon 不授"断言。
- 提示词:ANALYSIS_DIR_DOC 命名规则段落地"前缀即数据来源"纪律(r2_*=现算 / find_decompiled_function=读缓存);升级顺序纪律("信息不够才 ghidra_decompile")按票界留待票04。
- 测试:新 `test_step5_r2_tools.py` 6 项离线(mock r2_base.run_in_sandbox,断言命令行/timeout/entrypoint/零容器);cli_tools 增 2 项 Docker 门控真跑(本环境 Docker 不可用自动 skip);`_mk_tool` 补丁点按模块解析(r2 族共享名在 r2_base 命名空间,挂错处 mock 不生效会真调 Docker——已注释防再踩);`_parse_r2_json` import 改走 r2_base。全套件 305 passed + 13 skipped(基线 298+11;顺带把 test_read_file 的 fileinfo.json 依赖改为自造探针文件,消除与本工单无关的预存环境失败)。

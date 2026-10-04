# 02: strings_query / imports_query——边车优先 + r2 兜底 + pattern

**What to build:** 两个读盘工具变成混合型:有边车读边车(毫秒级,不调容器);缺边车就地对原始二进制跑 r2 字符串提取/导入表(经沙箱,extracted 只读挂载、断网),并套既有 pattern/危险函数分级;两者都不可得才报错,文案给下一步指引。strings_query 新增 pattern 参数(查询时正则过滤,边车路与兜底路都生效)——这是原流水线"ELF 硬编码预扫"能力的迁接。兜底不限 ELF:不透明 blob 的字符串审计由此打通。规则出处:ADR-0010、spec(User Stories 5-8)。

**Blocked by:** 01(复用 r2 调用辅助)

**Status:** ready-for-human

- [x] 边车存在:读边车且不调容器(monkeypatch 断言零容器调用)
- [x] 边车缺失:自动 r2 兜底,含非 ELF 文件;结果套 pattern/危险函数表
- [x] pattern 参数:边车路与兜底路都过滤;不带 pattern 时行为与现状兼容
- [x] 都不可得时报错文案含下一步指引
- [x] 权限不变;execute 层测试(tmp_path 假工件 + monkeypatch)+ Docker 门控真跑各一
- [x] 全套件绿

## Comments

**2026-09-09 implement**(工单完成,待人工验收):

- strings_query:pattern **保持必选**(现状契约不变,不带参数仍是契约层"缺失必选"优雅报错——工单"不带 pattern 时行为与现状兼容"按此解读,避免"无过滤返回前 30 条"这种对审计无意义的行为);内置模式集迁接 Step4 `_TEXT_PATTERNS` 家族:`private_key/shadow_hash/wifi_psk/password_kw`(bytes→str 形态),既有 url/ip/password/key/shadow/empty_password 原样保留。边车路零容器;兜底路 `izzj`(JSON)对任意 extracted 文件有效——**不走 elf_guard**,只走路径解析;`_load_strings` 返回 (list|None, source),None=两边都不可得,[] =合法空结果。
- imports_query:兜底路 `iij`(**仅 ELF**——导入是 ELF 概念,非 ELF 先 elf_guard 引导性拒绝指向 strings_query);结果套既有 DANGEROUS_IMPORTS 分级表,call_sites 置空 → format_hits 既有触发层指引引向 r2_xref_query。text/data 注明来源("边车"/"r2 izz"/"r2 iij")。
- 都不可得的报错文案含三路指引:list_files 确认路径 / 文本类 read_file 读原文 / blob 先 binwalk_rescan 看签名。
- 顺带修复 format_hits **潜伏 bug**(新测试暴露):call_sites 是 dict 列表(`{from, function}`,Ghidra 边车真实形态)时 `", ".join(dicts)` 直接 TypeError——基线能过只因 target/1 的 idlc 危险导入恰好全空调用点。新 `_fmt_call_sites` 兼容 dict/str 两形态(`func@addr`)。
- `cli_base.container_path` 加工具路径前缀宽容:带 `extracted/`(或 base 同名)前缀的引用剥前缀后解析(ADR-0008 口径,与 resolve_analysis_file 宽容同源);r2_base 新 `extracted_host_path` 同口径(elf_guard 与兜底路共用)。
- 测试:新 `test_step5_fallback_tools.py` 9 项离线(边车零容器×2 / izz 非 ELF 兜底+pattern / 双不可得指引 / pattern 契约不变 / Step4 模式迁接 / iij 分级+指引 / 非 ELF 拒绝 / container_path 前缀宽容);cli_tools 增 1 项 Docker 门控真跑(tmp 工作区拷真实 idlc、无边车,强制兜底;本环境 Docker 不可用自动 skip)。全套件 315 passed + 14 skipped。

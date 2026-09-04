# 0008-Step5 路径口径统一为工具路径

日期:2026-09-03(target/1 卡死事故的根因修复之二,守卫修复见 commit c054774)

## 问题

系统里并存三种路径形态,交接链上没有任何一层做换算:

| 形态 | 例子 | 谁产生 | 谁消费 |
|---|---|---|---|
| 逻辑路径 | `unitree/module/...` | Step2-4 内部、semgrep/gitleaks 容器输出(挂载根相对) | 无 LLM 工具能打开 |
| 工具路径 | `extracted/unitree/...`、`analysis/...` | search_code 命中、简报(部分) | read_file/list_files/search_code(唯一) |
| process/ 前缀形态 | `process/analysis/...` | 提示词文档示例、verification 简报指针 | **没有任何东西**(解析到 process/process/) |

target/1 实测后果(verification 实例 8 轮预算):

- 实例 6:照抄简报给的坏指针 `process/analysis/.../btgatt-server.c`(边车明明存在),6 连撞"文件不存在"烧光预算,零证据硬写结论;
- 实例 2/7:finding 的 `file: unitree/...` 工具打不开,烧 3/8 轮猜出 `extracted/` 前缀(纯靠模型运气);实例 7 猜不出后 `search_code(directory=".")` 自救 → 引发 grep 全 `.cve_cache` 的卡死(守卫已修,commit c054774)。

## 决策

**LLM 可见的路径统一为工具路径**(方案甲,2026-09-03 用户定夺):

1. **Agent 工件 file 字段 = 工具路径**:survey.high_risk_areas 与 findings/verified_findings 的 `file` 一律 `extracted/<逻辑路径>`。写入侧双保险——semgrep/gitleaks 在工具输出层给固件路径加 `extracted/` 前缀(recon"照抄 Observation 原文"红线不用改,原文本身变对);findings 落盘时归一函数兜底(缺前缀且 `extracted/<file>` 存在则自动补并回写,不靠 LLM 自觉)。
2. **简报指针 = 工具路径**:verification 单实例简报的 sidecar 指针修前缀(`process/analysis/` → `analysis/`),并新增源文件指针 `extracted/<file>`(经 `is_file` 检查才注入)——LLM 零猜测。
3. **提示词文档 = 工具路径**:所有会被照抄进工具调用的路径示例(`process/analysis/...`、`process/extracted/...`)统一改为 `analysis/...`、`extracted/...`。
4. **逻辑路径降级为纯内部键**:fileinfo.json、analysis 边车命名(`analysis/<逻辑路径>` = 工具路径形态)不变;它不再出现在任何 Agent 工件或提示词示例里。

被否的方案:

- **双轨制(存储键保持逻辑路径,简报层换算)**——改动最小,但"file 字段要换算"这条规则永久存在,每次演进都得记得它;本次坏指针正是双轨规则失忆的下场。
- **统一为 process/ 前缀形态**——没有消费者,选它等于重写全部工具解析,纯倒退。

## 代价与兼容

- dedup_key / 续跑身份校验 / 报告对账**代码不用改**(字符串口径在新运行内自洽);
- **旧版本工件跨版本不兼容**:续跑时身份校验(file+title 比对)对新锚点判不一致 → 弃旧工件真实重跑。一次性成本,与 extractinfo_version 失效重跑同款先例;
- CLI 工具换算只覆盖 semgrep/gitleaks(其命中会进 high_risk_areas/findings 的 file);其余 CLI 工具(checksec/xref/cve_bin_tool_scan)的 Observation 不含会被照抄成 file 的固件路径,不在换算范围;
- 提示词口径清扫是纯文案,靠既有回归测试兜底。

## 回归锁定

- 简报指针:前缀断言 + 存在性(无 sidecar 时不注入假指针);
- 归一函数:缺前缀补/有前缀不动/文件不存在保持原样三态;
- semgrep/gitleaks 输出:`extracted/` 前缀断言。

# firmware_audit Step5 端到端测试报告（2026-08-29）

> 覆盖：Step5 agent 系统 v3 全链路（编排 + 子 Agent + 工具层 + search_code 新工具）。
> 范围：环境 → pytest 全量 → 门控测试 → 真 LLM 端到端 → Bug 记录/修复 → 修复复测 → 覆盖率。

---

## 1. 测试环境

| 项 | 值 | 状态 |
|---|---|---|
| OS / Shell | Windows / PowerShell | ✓ |
| Python | 3.12.7 | ✓ |
| pytest | 7.4.4 | ✓ |
| pip | 24.2 | ✓ |
| pyyaml | 6.0.1（requirements 依赖） | ✓ |
| cryptography | 43.0.0（requirements 依赖） | ✓ |
| coverage（本次补装，测试工具） | 7.16.0 | ✓ |
| LLM 配置 | `firmware_audit/.env`：BASE_URL / API_KEY / MODEL=`mimo-v2.5` | ✓（含 key） |
| Docker daemon | **不可用**（Docker Desktop 未启动） | ⚠ 环境限制 |
| 测试数据 | `target/1/process`（Step1-4 产物 + 旧版 agent 工件） | ✓ |

> 环境限制如实声明：Docker 不可用 → 沙箱类工具（checksec/xref/cve-bin-tool/semgrep/gitleaks/sandbox_verify/binwalk）的 **8 个**门控用例 SKIP，真机工具路径以"失败不崩 + Agent 换路"方式间接验证；Step1-4 流水线本轮未重跑（无新固件输入）。

---

## 2. 测试执行矩阵

| 阶段 | 用例数 | 结果 | 说明 |
|---|---|---|---|
| A. pytest 全量（本地离线） | 176 | **176 passed** | 编排 26 项、工具层（含 search_code/list_files）、解析（+3 个 B1 新用例）、上下文压缩、权限矩阵等 |
| B. Docker 门控（test_step5_cli_tools） | 8 | 8 SKIP | `Docker 或镜像 firm_audit/sandbox:latest 不可用`（环境限制） |
| C. LLM 门控 default（test_step5_smoke） | 2 | 2 SKIP | `未设 STEP5_SMOKE=1`（默认关） |
| C'. LLM 门控（STEP5_SMOKE=1 显式开启） | 3 | **3 passed**（约 3m9s） | `chat_roundtrip` + `react_real`：真机 ReAct 8 步链 `imports_query → list_files → read_file`，**新增 list_files 被模型自主调用**；Docker 缺失时 xref_query 报错后模型自主换路（失败不崩 ✓） |
| D. 真 LLM 端到端（target/1 编排，首轮） | — | 完成（10 轮 / 63.3k token） | 三阶段 dispatch（工件已存在 → skipped）→ summarize×3 → finish → report.md；暴露 B1/B2 |
| D'. 真 LLM 端到端（修复后复测） | — | **完成（6 轮 / 26.5k token，-58%）** | 协议错误 2→1 次；report.md 首行干净；用量打印正确 |

**合计**：完整执行 179 个用例（pytest 176 + smoke 3），10 个 SKIP 均为环境门控（非逻辑跳过）。

---

## 3. Bug 记录与修复

### B1【P1·解析器】Final Answer 块解析取首个 → 报告头部被模型自述污染

- **复现步骤**：真机编排 summarize 后，模型在长回复里多次出现 `Final Answer:` 字样（自述/复述协议），最终才输出真正的报告正文。
- **预期**：`report.md` 以报告正文开头，协议解析不触发多余错误轮次。
- **实际**：`report.md` 首行为模型调试语句 `"作为开头？让我尝试严格按照协议格式...`；且 10 轮内出现 **2 次**协议错误。
- **根因**：`protocol.py::FINAL_RE = re.compile(r"Final Answer:\s*(.+)", re.S)` 用 `search` 取**首个**匹配，且不要求行首——身内 "Final Answer:"（模型复述）与首个带冒号位置都被命中，前文垃圾并入 `final_answer`；`re.S` 贪婪使 finditer 无法逐块。
- **修复**（`protocol.py`）：新增 `FINAL_MARK`（行首锚定 `(?m)^\s*Final Answer\s*:`）定位**最后一个**标记位置，再对尾部切段用 `FINAL_RE.match` 提取正文。
- **验证**：新增 3 个用例（句内字样不匹配/多块取最后/经典散文场景）全过；复测 `report.md` 首行 `# 固件安全审计报告` 干净，协议错误 2→1，轮次 10→6，token -58%。

### B2【P1·统计】step5_run 打印的 LLM 用量恒为 0

- **复现**：端到端编排完成后 `[step5] 完成 ... LLM 用量: {'prompt_tokens': 0, 'completion_tokens': 0}`。
- **预期**：打印真实 token 用量（实测 63k/26k）。
- **根因**：`run_step5.py` 仅按 `SubAgentResult.usage` 累加——本次三子 Agent 均为 skipped（usage 空），且 orchestrator 自身轮次从不计入；而编排器与子 Agent 共享 `base_llm.total_usage`（已累计全部调用）。
- **修复**：`step5_run` 与 pipeline 分支统一改用 `dict(base.total_usage)`。
- **验证**：复测打印 `{'prompt_tokens': 20704, 'completion_tokens': 5787}` ✓。

### B3【P2·回喂文案】协议错误提示只引导"继续调工具"，误导收尾阶段

- **复现**：模型 summarize 后输出报告散文（无协议块）被拒，回喂仍教"每轮一个 Action"——模型继续试图调工具/自述更久。
- **修复**：`react_loop._protocol_fail_hint` 改为双路径提示（a 仍需取证 → Action；b 已收尾 → 以行首 `Final Answer: ` 直接输出报告）。
- **验证**：复测协议错误 2→1 次；该轮次模型正确以 `# 固件安全审计报告` 收尾。

### 非产品缺陷记录（如实归档）

| 现象 | 归类 | 说明 |
|---|---|---|
| 手动注入 .env 时 `MODEL= mimo-v2.5`（等号后空格）被保留 → `Unsupported model` | 测试脚本问题 | LLMClient 的 `load_env_file` 正则 `\s*` 已正确剥空格；仅人为注入路径有坑。本次改用包自动加载后复现消除 |
| `runpy RuntimeWarning: 'firmware_audit.step5_agent.run_step5' found in sys.modules...` | 已知无害 | `python -m` 子模块导入与包 `__init__` 导出同名模块所致，功能无影响，记录不修 |
| `工具调用: {}`（编排模式） | 显示口径 | `step5_run.tool_calls` 统计子 Agent 工具；orchestrator 的 dispatch/summarize/finish 记于 `orchestrator/dispatch_log.json`，不影响审计 |
| 无 Docker 时 search_code 冒烟全量边车无命中 84.7s | 已优化 | 8-29 冒烟发现 → 边车按"小文件先 + imports→text→strings 顺序 + `.strtab` 噪声过滤" → 5.8s（14.6x） |

---

## 4. 覆盖率

`coverage run --source=firmware_audit -m pytest`（本次补装 coverage 7.16）：

- **生产代码（剔除 test/）行覆盖率：66%**（可执行语句 4508，未覆盖 1526）。
- 低覆盖主因：Docker 门控分支（sandbox/CLI 工具错误路径）因 Docker 不可用未执行；部分编排错误兜底分支。
- 高覆盖模块示例：`runner.py` 90%、`run_step5.py` 83%、`xref_query.py` 84%。

---

## 5. 结论

- **全部可执行用例通过**：176 passed（pytest）+ 3 passed（smoke 真机）；10 SKIP 均为环境门控（Docker 8 + smoke 默认关 2），无逻辑失败。
- **要求的功能符合设计预期**：v3 编排（dispatch/summarize/finish + 顺序门/唯一性/上限）真机跑通；report.md 由 summarize 产出且头部干净；search_code 混合检索工具被模型实际调用；协议漂移/usage 统计两处缺陷已修复并复测。
- **遗留建议**：Docker Desktop 启动后补跑 8 个 sandbox 门控用例与真沙箱工具链；Step1-4 输入新固件做全 pipeline 回归。
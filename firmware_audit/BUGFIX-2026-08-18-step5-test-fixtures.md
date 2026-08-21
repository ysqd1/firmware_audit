# Bugfix 记录:Step5 测试 fixture 缺失导致 9 个 ERROR(2026-08-18)

## 现象

`pytest important/firmware_audit/test/` 全量跑:81 passed, **9 errors**, 83 warnings。

9 个错误全部集中在 step5 的三个测试文件,且均为 setup 阶段报错:

```
ERROR test_step5_tools.py::test_resolve_and_decompile / test_imports_query / test_strings_query / test_read_file
      fixture 'tools' not found / fixture 'process_dir' not found
ERROR test_step5_cli_tools.py::test_checksec / test_xref_query / test_sca_scan
      fixture 'tools' not found
ERROR test_step5_smoke.py::test_chat_roundtrip / test_react_real
      fixture 'llm' not found
```

## 根因

三个测试文件沿用"双模式"设计(test_main 独立跑 + pytest 收集):

1. **独立模式**:`python test_step5_tools.py` → `test_main()` 手动构造 `tools`/`process_dir`/`llm` 后以参数传入各测试函数 → 正常工作。
2. **pytest 模式**:函数名以 `test_` 开头且带形参 → pytest 自动收集并按 fixture 注入;但 `test/` 目录**没有 conftest.py 定义这三个 fixture** → setup 阶段直接 ERROR。

即:双模式设计的 pytest 一侧从未补齐(fixture 半成品),独立跑通掩盖了这一点。

### 附带发现的隐患(假绿)

这些测试函数约定"收集 `fails: list[str]` 并 return"(便于 test_main 统一打印)。但 pytest 默认**忽略测试函数返回值**(仅给 PytestReturnNotNoneWarning)——即使 `fails` 非空、断言实际全挂,pytest 仍报 PASSED。若只补 fixture 不处理返回值,pytest 模式会变成"永远绿灯"的假回归防护。

## 修复方案(最小改动,不动测试函数体,不破坏独立模式)

| 文件 | 改动 |
|------|------|
| `test/conftest.py`(新建) | ① `process_dir` fixture:定位 `important/target/1/process`(探针 `analysis/unitree/bin/idlc.c`),缺失则 `pytest.skip`(与独立模式 SKIP 语义一致)<br>② `tools` fixture:`make_tools(ToolContext(process_dir))`(构造不触发 Docker)<br>③ `pytest_pyfunc_call` 钩子:接管双模式测试调用——**非空 fails 列表 / 非零退出码 → 判 FAILED**(附逐条明细),空列表 / 0 / None → 通过;顺带消除全部 83 个 PytestReturnNotNoneWarning |
| `test/test_step5_cli_tools.py` | 本地覆盖 `tools` fixture:加 Docker 门控(`docker_available(firm_audit/sandbox:latest)`,不可用 SKIP,同 `_ready()` 语义) |
| `test/test_step5_smoke.py` | 本地 `llm` fixture:`STEP5_SMOKE=1` + API key + target/1 工件三门控(复用 `_ready()`),缺一 SKIP |

实现过程一处自纠:`_PROBE = "analysis" / "unitree" / ...`(str `/` str TypeError)→ `Path("analysis") / ...`。

## 验证结果

| 验证项 | 结果 |
|--------|------|
| 三个报错文件单独跑 | 11 passed, 2 skipped(smoke 按门控 SKIP),0 error |
| 防假绿钩子(临时用例:非空列表) | 正确 FAILED 且附明细;空列表 PASSED(临时文件已删) |
| 独立模式回归 | `python test_step5_tools.py` 5 项全 PASS;`python test_step5_cli_tools.py` checksec/xref PASS、sca 默认 SKIP,行为不变 |
| 全套件回归 | 修复前 81 passed + 9 errors + 83 warnings → 修复后 **88 passed + 2 skipped + 0 errors + 2 warnings**(剩余 2 个为 step0 既有 tarfile DeprecationWarning,与本修复无关) |

CLI 工具测试在本机真跑通过(checksec 的 relro=partial 断言、xref popen→idlc_load_generator 调用链断言均实测验证)。

## 预防措施

1. **双模式测试新增形参时,同步补 conftest.py fixture**——"独立模式能跑"不代表 pytest 模式可用;提交前至少跑一次 `pytest <该文件> -v`。
2. **新测试文件统一走 conftest fixture 注入**,不再在函数签名里引入 conftest 之外的新依赖名;若需文件级门控(Docker/环境变量),仿照 cli/smoke 在本文件内覆盖定义。
3. **禁止裸 return fails 列表**:`pytest_pyfunc_call` 钩子已兜底,但新测试尽量直接 `assert`/`pytest.fail`,返回值约定只保留给存量双模式用例。
4. pytest 输出中的 `PytestReturnNotNoneWarning` 是假绿信号,出现即说明有测试没真正断言;该钩子已使其无处遁形(非空即 FAILED)。

---

# Bugfix 记录:全链路测试发现 2 处缺陷(2026-08-19)

背景:分层测试计划(工具解析专项 13 用例 + 上下文集成 7 用例 + 真实 target/1 端到端)。

## Bug#1:Final Answer 未入上下文,assistant/user 消息链断裂

- **发现**:test_step5_context.py::test_observation_prefix_and_alternation —— 正常 Final 轮 recent 为 `[assistant,user,assistant,user]`,缺最后的 assistant。
- **根因**:react_loop.py final 分支零工具拒绝路径有 `cm.append("assistant", reply)`,但正常路径直接 `return result`,Final 回复未进四分区上下文。
- **影响**:低危(单 Agent 循环结束即弃);但违背"上下文信息完整性"契约,复用/续跑场景会丢结论消息。
- **修复**:return 前补 `cm.append("assistant", reply)`(react_loop.py L112)。

## Bug#2:误报剔除条目渲染为空理由("— " 结尾)

- **发现**:端到端 report.md 第 58 行 `[low] chat_go ... — ` 后无内容。
- **根因**:runner.py render_report 用 `f.get('rationale', '无理由')` —— rationale 键**存在但为空串**,dict.get 默认值只对缺失键生效;verification LLM 把剔除理由写进了 evidence,rationale 留空。
- **修复**:`reason = f.get("rationale") or str(f.get("evidence", ""))[:300] or "无理由"`(空串回退 evidence 截断)。

## 验证结果

| 层级 | 结果 |
|------|------|
| 解析专项(新增 test_step5_parsing.py,13 用例) | 全过:纯函数提取(sca 日志混JSON/r2尾行回退/DDG uuddg 解包/checksec双形态/secret __RC__分割/semgrep 退出码白名单)+ 畸形输入(None/缺参/未知参/路径穿越)不崩回喂 |
| 上下文集成(新增 test_step5_context.py,7 用例) | 全过:四分区布局/压缩阈值与 assistant 边界对齐/压缩失败还原/多轮压缩累积/Observation 前缀与交替 |
| 端到端(target/1 真实工件) | recon 20轮 → analysis 21轮 → verification 21轮;11/13 工具实调;报告 6 findings(3 high 含 sandbox_verify 实证命令注入);chat_go 密钥因 secret_scan.json 缺失按防幻觉纪律判 false_positive 剔除;verification 在 Final 前实际调用 19 次工具(工具先行纪律生效) |
| 全量回归 | **137 passed + 2 skipped**(基线 116+2 → +21) |

## 预防措施

1. `dict.get(k, default)` 对"键存在但值为空"不生效——渲染层一律用 `f.get(k) or fallback` 链。
2. 上下文完整性断言(交替/前缀)纳入回归,防 Final/异常路径再漏 append。

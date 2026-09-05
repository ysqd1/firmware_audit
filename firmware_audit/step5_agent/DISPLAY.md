# Step5 终端监控显示使用说明

Step5 Agent 审计执行过程的终端实时展示(Claude Code 风格,非流式):
思考过程、工具调用与参数、执行结果、系统干预、阶段汇总,按时间顺序
结构化呈现。实现见 `engine/display.py`,零 API 零依赖即可演示。

## 快速开始

```bash
# 正常审计自动启用(默认紧凑模式,终端下自动彩色)
python -m firmware_audit.main target/1

# 效果演示(零 API 零 Docker,ScriptedLLM 回放三个典型场景)
python -m firmware_audit.step5_agent.demos.demo_display

# 彩色 / 完整模式 / 关闭
STEP5_COLOR=1 python -m firmware_audit.step5_agent.demos.demo_display
STEP5_DISPLAY=full python -m firmware_audit.step5_agent.demos.demo_display
STEP5_DISPLAY=0 python -m firmware_audit.main target/1
```

## 配置(环境变量)

| 变量 | 取值 | 说明 |
|---|---|---|
| `STEP5_DISPLAY` | 空 / `1` / `compact` | 紧凑模式(默认):每事件一行,Observation 只显首行 |
| | `2` / `full` | 完整模式:Observation 展示前 12 行 |
| | `0` / `none` / `off` | 关闭显示(回退旧式单行日志) |
| `STEP5_COLOR` | 空 | 自动:stdout 是终端才开色(管道/CI 自动无色) |
| | `1` / `0` | 强制开 / 强制关 ANSI 色(Windows 终端自动启用 VT) |

## 六类事件

| 标签 | 触发时机 | 内容 |
|---|---|---|
| 横幅 `── name · label` | 阶段开始(recon/analysis/verification) | 工具数 / 模型 / 迭代上限 |
| `思考` | LLM 回复含 Thought | 决策逻辑(紧凑 1 行,完整模式更长) |
| `调用` | LLM 回复含 Action | 工具名 + 完整调用参数(JSON) |
| `结果` | 工具执行返回 | `OK 耗时 · 首行内容` 或 `Error · 错误`;超长结果截断并附 `…全文 <obs路径>` 指针 |
| `系统` | 协议错误 / 同参拦截(>3 次) / 零工具拒绝 / 迭代上限强制收尾 | 守卫干预说明 |
| `结论` / `完成` | Final Answer 被接受 / 阶段结束 | findings 计数 / 工件名 / 轮数 / 总耗时 / token |

## 运行效果(真实捕获,STEP5_COLOR=0)

```
── recon · 侦察 ──────────────────────────
   工具 6 · 模型 deepseek-v4-flash · 迭代上限 20
[01] 思考  先看工件
[01] 调用  read_file({"path": "analysis/unitree/bin/idlc.imports.json", "limit": 5})
[01] 结果  OK 0.02s · [analysis/unitree/bin/idlc.imports.json 第 1-1 行,共 1 行]
[02] 结论  1 findings(详见工件)
── recon 完成 · survey.json · 1 findings · 2 轮 · 0.0s · 0 tokens

── analysis · 深度分析 ──────────────────────────
[01] 思考  取证
[01] 调用  read_file({"path": "analysis/unitree/bin/idlc.strings.json", "limit": 5})
[01] 结果  OK 0.02s · [analysis/unitree/bin/idlc.strings.json 第 1-1 行,共 1 行]
[02] 结论  2 findings(详见工件)
── analysis 完成 · findings.json · 2 findings · 2 轮 · 0.0s · 0 tokens
```

异常场景(demo 捕获):

```
[01] 结果  Error · Error: RuntimeError: radare2 分析超时   ← 工具崩溃不中断
[04] 系统  同参调用拦截: boom 相同参数>3 次                ← 循环守卫干预
[01] 系统  零工具 Final 被拒绝,退回要求先工具查证           ← 工具先行守卫
[03] 系统  迭代上限,强制收尾                                ← 预算耗尽兜底
```

## 架构与集成方式

观察者模式,事件流与展示解耦:

```
react_loop(状态机) ──钩子──▶ display(TerminalDisplay 格式化打印)
        │                          ▲
        └──transcript.jsonl 落盘    └─ runner.run_agent 经 make_display() 注入
```

- **零侵入**: `run_react_agent(..., display=None)` 缺省完全不影响原有行为
  (`display_none_no_regression` 测试守护);display 只读事件做打印,不参与
  任何控制流决策
- **接线点**: react_loop 7 个事件喂点(assistant/final/fail/拒绝/拦截/
  observation/强制收尾) + runner 2 个(stage/done)
- **性能**: 显示开销为字符串格式化 + print,相对 LLM 调用(秒级)与 Docker
  工具(秒级)可忽略;TerminalDisplay 仅持有计时起点一个状态,无累积结构,
  无内存泄漏面;长内容一律截断(全文由既有 obs/ 落盘与 transcript 兜底)

## 扩展指南

- 新增事件类型: 在 `TerminalDisplay`/`NullDisplay` 各加一个 no-op 友好的
  方法,react_loop 对应位置喂事件即可(两处签名保持一致)
- 换 UI(如 Web 面板/结构化日志): 实现同签名的六个方法即可替换
  `make_display()` 的返回对象(duck typing,无需继承)

## 测试

`test/test_step5_display.py`(10 项): 六类事件格式化 / Error 与截断指针 /
full 模式行数上限 / 非 JSON Final 回退 / make_display 环境变量矩阵 /
react_loop 事件接线 / 守卫事件展示 / display=None 零回归 / runner 端到端横幅。

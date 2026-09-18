# Step5 终端监控显示使用说明

Step5 Agent 审计执行过程的终端实时展示(Claude Code 风格,非流式):
思考过程、工具调用与参数、执行结果、系统干预、阶段汇总,按时间顺序
结构化呈现。实现见 `engine/display.py`,零 API 零依赖。

> 票 14 公开切换后:display 的旧接线对象(react_loop/legacy runner)已随
> ADR-0012 公开切换删除。显示层模块与其格式化/配置契约保留;Host 控制层
> 的显示接线(事件喂点挂到 host 各 runner)另行工单,接线前 Host 运行
> 不打印事件流。

## 配置(环境变量)

| 变量 | 取值 | 说明 |
|---|---|---|
| `STEP5_DISPLAY` | 空 / `1` / `compact` | 紧凑模式(默认):每事件一行,Observation 只显首行 |
| | `2` / `full` | 完整模式:Observation 展示前 12 行 |
| | `0` / `none` / `off` | 关闭显示(NullDisplay,no-op) |
| `STEP5_COLOR` | 空 | 自动:stdout 是终端才开色(管道/CI 自动无色) |
| | `1` / `0` | 强制开 / 强制关 ANSI 色(Windows 终端自动启用 VT) |

## 六类事件

| 标签 | 触发时机 | 内容 |
|---|---|---|
| 横幅 `── name · label` | 阶段开始 | 工具数 / 模型 / 迭代上限 |
| `思考` | LLM 回复 | 决策逻辑(紧凑 1 行,完整模式更长) |
| `调用` | 工具动作 | 工具名 + 完整调用参数(JSON) |
| `结果` | 工具执行返回 | `OK 耗时 · 首行内容` 或 `Error · 错误`;超长结果截断并附 `…全文 <obs路径>` 指针 |
| `系统` | 守卫/系统干预 | 干预说明 |
| `结论` / `完成` | 结论被接受 / 阶段结束 | findings/观察点 计数(recon 为观察点,词汇纪律)/ 工件名 / 轮数 / 总耗时 / token |

## 架构

观察者模式,事件流与展示解耦:`TerminalDisplay` 只读事件做打印,不参与
任何控制流决策;`NullDisplay` 全事件 no-op(`STEP5_DISPLAY=0`),鸭子类型
可替换(换 UI 只需实现同签名方法)。

- **零侵入**: display 只读事件做打印,不参与任何控制流决策
- **性能**: 显示开销为字符串格式化 + print,相对 LLM 调用(秒级)与 Docker
  工具(秒级)可忽略;TerminalDisplay 仅持有计时起点一个状态,无累积结构,
  无内存泄漏面;长内容一律截断(全文由既有 obs/ 落盘与 transcript 兜底)

## 测试

`test/test_step5_display.py`: 六类事件格式化 / Error 与截断指针 /
full 模式行数上限 / 非 JSON Final 回退 / make_display 环境变量矩阵 /
逐行 flush / 窄编码降级。

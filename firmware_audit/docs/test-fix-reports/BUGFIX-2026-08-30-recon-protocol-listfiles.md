# BUGFIX-2026-08-30 recon `list_files` 后持续"协议错误"修复报告

## 1 现象

recon Agent(模型 mimo-v2.5 · 6 工具 · 迭代上限 20)一轮真实运行中,系统在
\[03]、\[07]、\[10]、\[14] 四个 step 各返回一次:

```
[03] 系统  协议错误: 回复中没有 Action/Action Input 或 Final Answer 块
[07] 系统  协议错误: 回复中没有 Action/Action Input 或 Final Answer 块
[10] 系统  协议错误: 回复中没有 Action/Action Input 或 Final Answer 块
[14] 系统  协议错误: 回复中没有 Action/Action Input 或 Final Answer 块
```

失败的共同位置:**每例都紧跟在一次** **`list_files`** **工具调用(大目录观察)之后**:
`[02] list_files("extracted") → [03] 失败`、`[06] list_files("extracted/etc", recursive) → [07] 失败`、
`[09] list_files(net_switcher, recursive, 100) → [10] 失败`、`[13] list_files(bashrunner, recursive) → [14] 失败`。

每例失败后模型都能在下一轮自纠恢复(\[04]/\[08]/\[11]/\[15] 均正常),说明失败是
"模型格式漂移导致解析器识别不到协议块",而非循环逻辑中断。

## 2 四次实例上下文分析

| 失败步   | 前一步工具调用                                 | 观察内容  | 模型后续动作         |
| ----- | --------------------------------------- | ----- | -------------- |
| \[03] | list\_files(`extracted`)                | 8 项目录 | \[04] 合规两行调用继续 |
| \[07] | list\_files(`extracted/etc`, recursive) | 15 项  | \[08] 合规恢复     |
| \[10] | list\_files(net\_switcher)              | 33 项  | \[11] 合规恢复     |
| \[14] | list\_files(bashrunner)                 | 50 项  | 恢复             |

同一运行的显示证据(思考行)透露了模型输出结构:

* \[08] 思考行显示 `<reasoning>`、\[11] 思考行显示 `<text>` —— 模型把回复包成
  `<reasoning>…</reasoning>` / `<text>…</text>`(mimo 系推理模型的输出包装,
  LLM 客户端将 `reasoning_content` 与 `content` 以 `\n` 拼接后整体交给解析器);

* 在这类包装形态下,模型常把工具调用写成 **单行** `Action: 工具名({JSON})`(FC 训练
  惯性),"Action:/Action Input:" 两行结构丢失,或 `<text>` 里只写计划散文、动作缺位。

另在 target/1 的较早 transcript(同体系 deepseek 模型)中也记录到同类病:

* step8:整段计划散文、无任何协议块 → 判失败;

* step12/15/19:Action 整块重复(self-repeat)污染 raw\_input。

## 3 根本原因

**主因 —— Action 被写成单行形态**:模型(FC 训练惯性)把调用写成
`Action: list_files({"directory": "."})` / `Action: list_files {JSON}`
(JSON 与 Action 同行,或无独立 `Action Input:` 行)。`ACTION_RE` 只认
"`Action: 名` + 换行 + `Action Input: JSON`"两行结构 → 整轮判协议失败。
协议回喂提示中"不能把 JSON 直接放 Action 后"一句正是为这一行为所加(反证其高频)。

**次因 ——** **`<reasoning>/<text>`** **推理包装**:模型输出整行
`<reasoning>`/`</reasoning>`/`<text>`/`</text>` 包装(客户端拼接 reasoning 与 content)。
包装标签本身不破坏搜索,但当动作被写成上述单行形态、或 `<text>` 只有散文时,整轮失效;
标签噪音还污染显示与回喂内容。

**再次 —— 偶发纯计划散文**:大 list\_files 观察后,模型常先"总结观察+规划下一步",
严格协议块偶发缺位(target/1 step8 实发)。

已有防御(`<Action>` 角括号归一化、`<tool_call>` JSON 还原、Final 行首锚定、
Action Input 尾随散文回收、失败回喂≤4 次强制收尾)无法覆盖以上三种漂移。

## 4 修复步骤

### 4.1 `step5_agent/engine/protocol.py`(解析层,核心)

1. **剥推理包装标签**:新增 `_WRAP_TAG_RE`(行锚定,只删独占一行的
   `<reasoning>/<thinking>/<thought>/<text>` 标签,JSON 字符串内联的
   `<text>` 字样不受影响),`parse_reply` 入口先剥包装再走角括号归一化。
2. **单行 Action 兜底**:新增 `_ACTION_INLINE_RE` + `_inline_action()` ——
   常规两行结构与 Final Answer 均缺席时,按行首 `Action: 名` 后立即做
   花括号配平提取;JSON 是合法 dict 才还原为 action(避免散文"Action: 建议…"
   被误判)。
3. **`<tool_call>`** **容错增强**:`_tool_call_action()` 改为"定位 `<tool_call`
   开标签 → 花括号配平提取"(只认开标签,闭标签后同属下一块),容忍缺闭标签与
   `arguments` 内嵌套花括号(旧成对正则 `(\{.*?\})` 遇字符串里的 `}` 即断)。
4. **重复 Action 截断**:严格两行分支的截断正则加入 `|Action:`,
   模型整块 self-repeat 时 raw\_input 只保留首个块的 JSON,第二个块不再进 transcript/显示。

### 4.2 提示词加固(源头抑制)

* `step5_agent/data/prompts.py`:`REACT_PROTOCOL` 把原"禁止一句"扩为
  **三种强制格式**——禁止单行 `Action: 工具({...})`、禁止省略 `Action Input:`
  行、禁止 `<tool_call>/<reasoning>/<text>/<thinking>` 标签包裹、首行即协议块;
  三个子 Agent 的"格式正误对照"各补两条 ❌(单行 JSON / XML 包装)。

* `step5_agent/orchestrator.py`:`_ORCH_TMPL` 输出协议段补相同三条禁止。

### 4.3 测试补强(`test/test_step5_react.py`)

* `test_parse_reply` 新增 10 条与终端场景一一对应的用例:
  包装+两行、包装+Final、包装+单行 FC 形态、裸单行、包装纯散文判 fail、
  裸 `Action: echo` 判 fail(不误吞)、`<tool_call>` 缺闭标签+嵌套花括号、
  重复 Action 截断、JSON 字符串内联 `<text>` 不误伤、\[11] Thought 后直接 `<text>` 布局。

* 新增 `test_wrapper_drift_recon_flow`:用 `FakeFS`(模拟固件目录 list\_files)
  复刻终端 \[01]→\[03]→\[05] 流程,断言:包装+单行形态直接解析、纯散文按协议失败
  回喂且模型自纠、循环零中断收尾、工具调用次数正确。

## 5 验证结果

| 验证项                                              | 结果                                           |
| ------------------------------------------------ | -------------------------------------------- |
| `pytest firmware_audit/test/test_step5_react.py` | 16 passed                                    |
| `pytest firmware_audit/test`(全量)                 | 193 passed, 10 skipped(Docker 依赖环境用例,与本修复无关) |
| 循环级回归(包装漂移 list\_files 流程)                       | 4/4 次 list\_files 正常执行,\[03]同型散文失败回喂后自纠      |
| 终端 \[03]\[07]\[10]\[14] 同型回复构造验证                 | 包装+单行形态均解析为 action;纯散文仍判 fail(正确语义)          |
| JSON 内联 `<text>` 字样                              | 不被剥(行锚定防误伤)                                  |

修复前后的行为差异:修复前,凡"Action 单行 + XML 包装"的回复必判协议失败、
白白烧掉一轮;修复后这两类形态直接解析成功,仅"包装内纯计划散文"(语义上确未
发起调用)仍按协议失败回喂,由模型下一轮自纠——这正是 \[03]\[07]\[10]\[14] 期望的三态。

## 6 已追加修复(2026-08-30):llm_client 正文/思考拆分

本报告初稿曾把"拆分正文与思考"列为遗留建议,现按用户确认已落地:

1. **`providers/llm_client.py`**:`chat()` 只返回正文 content(不再把
   `reasoning_content` 拼接进回复)——思考是模型内部草稿,不参与 ReAct 协议
   解析(防"草稿 Action"被当真执行)、不进回喂上下文;思考随
   `usage["reasoning_content"]` 单独携带;content 为空(思考耗尽等)一律按
   "空回复"走既有 10-20s 重试,不再拿思考顶替。
2. **`engine/react_loop.py`**(主循环 + 强制收尾两处):从 usage 取出 reasoning,
   与正文拼回 transcript 的 assistant 条目留档审计;解析/上下文/回喂只用正文;
   usage 中该键被 pop,避免 JSONL 冗余。
3. **测试**:`test_step5_llm.py` 新增 2 条(chat 只返正文+thinking 随 usage、
   正文为空必重试);`test_step5_react.py` 新增循环级
   `test_reasoning_kept_out_of_context`(草稿不进上下文/不产生调用/transcript 留档)。
   全量 `pytest firmware_audit/test`:**196 passed, 10 skipped**。

## 7 遗留与建议

- 迭代上限与 MAX_PARSE_FAILS=4 现有兜底不变;单行兜底已保证"JSON 为合法 dict
  才接受",误吞散文风险受控。
- 纯思考型模型(正文恒空)会重试 3 次后抛 LLMError 失败——比"默默拿思考跑"
  更响亮,但更诚实;若实际遇到该类模型,可评估把"正文空"改为"拼接思考但打标记"


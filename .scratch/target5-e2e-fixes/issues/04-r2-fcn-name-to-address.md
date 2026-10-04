# 票04:r2 反汇编工具 fcn.名自动转地址

Status: ready-for-human
Claimed: 2026-09-11 (agent, /implement)
Date: 2026-09-11
Origin: target/5 e2e 实测 P4(spec: .scratch/target5-e2e-fixes/spec.md)

## 问题(根因已实锤,成对证据)

每次 r2 工具调用是全新 r2 进程,`fcn.<hex>` 名是某次会话内分析的产物,跨会话不保证可解析
(e2e 实测两次 "Relocs has not been applied" 无产出:3_analysis [05]、4_analysis [13]);
同目标裸地址(0x004010c0)恒成功([06])。Agent 每次都要烧一轮自己换写法。

## 需求(grilling Q4 定稿:用一个函数转换)

`r2_disassemble_function` 入口加纯函数:目标名匹配 `fcn.<hex>` 即转 `0x<hex>` 按地址执行;
其余名字形态行为不变。LLM 无感,提示词不动。同族工具(`r2_list_functions`/`r2_xref_query`)
如有同形参同风险,顺手同函数复用(以各自测试为准,不强扩)。

## 改动点

- `providers/tools/r2_disassemble_function.py`(纯转换函数 + `_run` 前置调用)
- 如适用:`r2_xref_query.py` / `r2_list_functions.py` 复用同函数

## 验收

- 纯函数单测:`fcn.004010c0` → `0x004010c0`;`0x…`/符号名原样透传
- 工具级测试(monkeypatch 命令构造):fcn. 形参实际下发的是地址形态(先例:test_step5_r2_tools.py)
- 全量套件无回归

## Comments

**2026-09-11 实现完成(agent),待人工复核 → ready-for-human**(commit 2927f2f)

- 落点调整(工单信的偏差,意图内):纯函数没放 `r2_disassemble_function.py`,放 **`r2_base.py`**(`sanitize_func_or_addr` 旁)——`r2_xref_query` 复用需跨工具 import,兄弟工具模块互 import 会造成并列耦合;r2_base 本就是票01 定的"r2 族共用辅助"单一出处。验收三态(fcn.→0x、0x*/符号透传、非 hex `fcn.zzz` 不动)不变形。
- 纯函数 `fcn_name_to_addr`:正则 `^fcn\.([0-9a-fA-F]+)$`,前导零/大写 hex 保留;`r2_disassemble_function._run` 在 sanitize 前调用(`fcn.` 与 `0x` 字符均在白名单内,安全面不放宽);`r2_xref_query._run` 在 **sym.imp. 补前缀之后**调用(顺序反了转出的 `0x*` 会被再补前缀,注释已标约束)。`r2_list_functions` 无名字形参,不强扩(按工单"不强扩")。提示词/description 零改动(LLM 无感,红线遵守)。
- 副作用说明:data/text 里报告的 target 是实际下发的地址形态(不是 LLM 原始输入)——报告真实所发,便于对账。
- 测试:纯函数 11 例 + disassemble 工具级(断言下发命令为 `af @ 0x…; pdf @ 0x…` 且无 `fcn.`)+ xref 工具级(断言 `axtj 0x…` 且无 `sym.imp.0x`),均注册 test_main。全量 **330 passed + 21 skipped** 零回归(基线 326+21,+4 新测试)。
- code-review 双轴:Spec 判忠实(落点偏差属意图内,见上);Standards 两条硬项已修——①xref 测试改用共享 ReplaySpy/patched(不再手搓第三份 fake,守"同一逻辑禁止第三个拷贝");②r2_xref_query.py 工作副本 CRLF 归一为 LF(HEAD blob 本就 LF)。遗留判断题(不阻塞):xref 测试 fixture 与同文件 `test_xref_symbol_prefix` 形似,规模不抽公共常量。

**2026-09-11 端到端重跑验证(target/5 --force)**:fcn. 形参活体闭环——3_analysis `fcn.00401528` disasm → 实际下发 `0x00401528` 反汇编(131 行)OK;`fcn.00401528` xref → 交叉引用 14 条 OK;`fcn.00401834` disasm → 反汇编 OK;orchestrator 自身 `fcn.00429fe0` xref → 1 条 OK。全程 **0 次** "Relocs has not been applied"(基线 3_analysis[05] 与 4_analysis[13] 两次空手,Agent 各烧轮次换写法)。

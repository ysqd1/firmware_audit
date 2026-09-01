# HANDOFF — 固件审计项目会话交接

> 写于 2026-09-01(上版 08-31)。这是给**下一个对话/接手者**的交接文档。
> 目的:让接手者无需重读全部历史,就能知道项目状态、已做什么、接下来做什么、关键背景。

---

## 0. 项目一句话

`E:\固件\create\important` — 宇树固件安全审计流水线(Step1-5)。Step1-4 规则化处理(解包→过滤→分类→反编译),Step5 LLM Agent 审计(三个子 Agent:recon→analysis→verification,由 orchestrator 编排)。

## 1. 当前 git 状态(截至交接)

```
(最新提交)
7476b35  重构:收敛系统目录判断到 file_rules,修复 step4 降级名单分叉
ff1d7f7  重构:拆分 FindingAggregator 独立模块,Orchestrator 增加公开 API
02ae1bf  补充项目术语表与 ADR 架构决策记录,同步修订三份需求/规则/架构文档
af8b7fd  修复 Step5 协议解析漂移与正文/思考拆分,同步工具层与编排器增强
```

**工作区未提交**(本次会话的 C4 落地,已 code-review + e2e 验证,待提交):
- `firmware_audit/step5_agent/providers/tools/{base,cli_base,read_file,list_files,search_code,binwalk_rescan}.py` — **C4:路径逃逸收敛到 `resolve_within`**
- `firmware_audit/test/test_security_hardening.py` — `resolve_within` 单测 + `test_main` 注册
- `firmware_audit/test/test_step5_tools.py` — read_file None 缺参回归 guard
- `docs/c4-path-escape.md` — C4 总结(含 code-review 追认 + e2e 验证,详见 §6/§7)
- `docs/c3-file-rules.md` — C3 总结(上轮遗留,本次一并提交)
- `HANDOFF.md` — 本文件

**不入仓(临时,勿提交)**:`.coverage`、`e2e_run.log`、`e2e_step5_force.log`

## 2. 已完成的工作(最近四轮)

### (a) 领域建模(提交 02ae1bf)
- 新建 `CONTEXT.md`(术语表,40+ 术语,含 Avoid 词)
- 新建 `docs/adr/0001-step5-orchestrator.md`、`0002-step5-no-key-hard-stop.md`
- 修正 `requirements.md`/`rules.md`/`agents.md` 过时表述

### (b) 拆分 FindingAggregator(提交 ff1d7f7)
- `orchestrator.py` 里的纯聚合逻辑拆到独立 `aggregator.py`
- 新增公开 API:`record_failed`/`finish`/`write_result`(2026-09-01 随 pipeline 模式删除,ticket 05)

### (c) 收敛系统目录判断到 file_rules(提交 7476b35)
- 新增 `firmware_audit/file_rules.py`,收敛 5 个判断
- 修复真实 bug:step4 硬编码名单把 `etc/init.d`/`ssh`/`apt` 当标准目录跳过
- 全量测试 208 passed, 10 skipped;详见 `docs/c3-file-rules.md`

### (d) 收敛路径逃逸检查到 resolve_within(C4,2026-09-01,未提交)
- 新增 `base.resolve_within(root, ref)` 原语,统一"解析 + containment 判定"
- **实际收敛 6 处**(架构报告说 4 处,`search_code._resolve_scope`/`binwalk_rescan` 也藏着同一句,一并捞了)
- 新增单测 `test_resolve_within` + `test_main` 注册 + read_file None guard
- **code-review(两轴)修复 4 项**:`read_file(path=None)` 契约回归、`resolve_within` docstring 矛盾、`container_path`/`binwalk` 空串行为变更未披露、测试注册
- 全量测试 **217 passed, 2 skipped**
- 详见 `docs/c4-path-escape.md`

## 3. 关键背景(接手者必读)

- **CONTEXT.md** 是术语表,用词前先看它。
- **rules.md** 是代码规范铁律("失败不崩"、零第三方依赖、配置集中等)。
- **docs/adr/** 记录两个决策:orchestrator 存在、无 key 立即终止(API 失败也终止,不降级)。
- 术语辨析:Step2 过滤=筛深度分析对象;Step5 工具层过滤=搜索跳噪音;`is_system_trust`=系统证书信任库。

## 4. 架构体检遗留候选(下一个可做)

来自 `improve-codebase-architecture` 报告(已做 C3、C4)。剩余:

| 候选 | 强度 | 内容 |
|---|---|---|
| **C1** | Strong | Step4 `decompile()` 一个入口塞 4 个 pass,1046 行仅 12.9% 覆盖。**用户明确想提升 Step4 覆盖** |
| **C2** | Worth | crypto parser 8 个浅克隆(`_parse_x509` 等) |
| C5 | Worth | Step1 manifest schema 散落 ~10 处 |
| C6 | Speculative | Step0 partition dict 隐式契约 |

## 5. 用户已表达的倾向

- 认可"该深化就深化"(不是一次性工具)
- **想提升测试覆盖**(尤其 Step4)
- 架构方向认可,主要问题是"大模块该拆未拆"
- **e2e 验证实证过 ADR-0002**:API 失败干净终止,不降级

## 6. 本次端到端验证(e2e,2026-09-01,`/verify`)

对 `target/1`(nano-ubuntu 固件)跑了两轮,详见 `docs/c4-path-escape.md §六`:

- **D1 全流程 `main target/1`**:Step2 过滤 5541→2047、Step3 分类 2047、Step4 ELF=522 全跑通;C3 的 `etc/init.d` 等该审的进入送审集。但 Step5 三子 Agent **skipped**(旧工件在)。
- **D2 `run_step5 --force`**:三子 Agent 真跑。recon 20 轮 + analysis 前半段,**C4 工具(`list_files`×13、`read_file`×15、`search_code`×5)全部正常,合法路径零越界误报**。
- analysis 中途 **LLM API 连续失败(空回复×2 + HTTP 307×1)→ 重试 4 次全败 → 按 ADR-0002 干净终止,exit 0**。

## 7. 下一会话焦点:解决 agents 问题(本次 e2e 暴露)

用户指定下一会话**解决 agents 的问题**,且**要走全流程调用 skill**(不是手写)。e2e 里观察到的具体问题(接手者从这里挑/发散):

1. **verification 子 Agent 未完整执行**:D2 跑到 analysis 中途 API 307 终止,verification 没跑到。API 稳定后需重跑 `--force` 验证完整链路。
2. **LLM 传参质量差,靠工具层兜底**:recon 把 `recursive` 传给 `read_file`(`TypeError: unexpected keyword`);semgrep 收到拼碎的 JSON(`{"path":...}{"path":...}`)。工具层 execute 兜住了(失败不崩),但**说明 agents 提示词/`params_doc` 对参数引导不足**,Agent 偶发畸形调用。可改进点:params_doc 更严格、协议层校验。
3. **llm-retry 空回复**:`reasoning_content` 很长但 `content` 空、`finish_reason=stop`(reasoning 溢出?)。模型侧问题,工具层已重试兜底,但值得关注是否需要降 reasoning。
4. **orchestrator 的 tool_calls 统计是 `{}`**:编排层只记了自己的 dispatch/summarize,子 Agent 的工具调用没归入编排统计(可能是设计如此,待确认)。
5. **API 307 故障**:`mimo-v2.5` 服务端 openresty 网关临时重定向,非代码问题,但说明 Step5 对上游抖动敏感。

## 8. 工作规则(用户明确要求,接手者必须遵守)

- **调用任何 skill 前,必须先提示用户,得到许可后再调**。用户说:"我需要调用 skill 的时候提示我。"
- **不许擅自修改代码**。任何代码改动(哪怕小)先向用户说明意图、经同意再做。
- 下一会话解决 agents 问题时,**使用全流程调用 skill**(matt-pocock-skills 完整 flow,如 grill-with-docs → to-spec → to-tickets → implement → code-review),而不是手动改。

---

## 下一步选项(接手者从这里选)

1. **提交当前 C4 改动**(见 §1 工作区清单)+ 更新后的 HANDOFF
2. **做 C1**(拆 Step4 decompile)+ 提测试覆盖——用户明确想
3. **下一会话焦点:agents 问题**(见 §7,走全流程 skill)

> 用户沟通偏好:中文;喜欢具体代码例子;会追问细节("这一步在干嘛")。

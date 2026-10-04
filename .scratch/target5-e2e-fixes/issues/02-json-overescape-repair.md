# 票02:宽容 JSON 提取器加"过度转义修复"保守档

Status: ready-for-human
Claimed: 2026-09-11 (agent, /implement)
Date: 2026-09-11
Origin: target/5 e2e 实测 P2(spec: .scratch/target5-e2e-fixes/spec.md)

## 问题(根因已实锤,可复红)

recon#0 的 Final Answer(14787 字符)内容合格,但模型在字符串值里把引号双重转义(`\\"socket\\"`)。
`\\` 先合法解析为字面反斜杠,紧跟的 `"` 提前闭合字符串 → 整个对象 Invalid \escape
(实测 `json.loads` 报 `Invalid \escape line 8 col 135`;`extract_json_object` 返回 None)。
工件降级 `survey.md` → 编排层按弹性机制全额补跑 recon,白烧约 50 万 token。

## 需求(grilling Q2 定稿)

`extract_json_object` 加第二档修复:原文解析失败且错误类型为 Invalid \escape 时,
把 `\\"` 形态的双重转义归一为 `\"` 后重试解析。**接受条件三合一,缺一维持现有降级路径**:

1. 原文确属该错误类型(Invalid \escape);
2. 归一化后能完整解析;
3. 解析结果通过既有工件形状校验(survey/finding 结构)。

纯函数、零 LLM、零新依赖。降级前不调 LLM 挽回(spec Out of Scope,实测不够再立项)。

## 改动点

- `data/artifacts.py` 的 `extract_json_object`(或其私有辅助)
- 测试 fixture:取 target/5 实测样本缩样(降级 survey.md 第 8 行附近的 components_grouped 片段)

## 验收

- 先红:缩样 fixture 上 `extract_json_object` 返回 None(现状)
- 后绿:同 fixture 返回解析后的 dict,且 schema 形状正确
- 反向用例:真损坏的 JSON(修复后仍解析失败)→ 照旧返回 None,不产错误数据
- 全量套件无回归

## Comments

**2026-09-11 实现完成(agent),待人工复核 → ready-for-human**(commit a8e1f87)

- **根因更正(实测字节,重要)**:工单把根因描述为"引号双重转义(`\\"`)",但降级样本(0_recon/survey.md)真实字节是:`\"` 为合法转义共 10 处、全文件零双重反斜杠,唯一非法转义是 `\$`(`\$SERVER`),json.loads 报的 `Invalid \escape` 正是它。且字面 `\\"`→`\"` 机制与工单自己的触发条件矛盾:真 `\"` 缺陷中 `\\` 先合法解析、引号提前闭合,报的是分隔符类错误而非 Invalid \escape,永不触发(死代码)。故按与触发条件一致的机制实现:**剥非法转义字符前的反斜杠**(`\$`→`$`),fixture 与真实样本逐字节核对一致,解码值无损还原模型原意(`server.port = 80, $SERVER["socket"] == "0.0.0.0:443"`)。
- 落点:`data/artifacts.py` `extract_json_object` 内新增修复档 + 两个纯函数助手——`_strip_invalid_escapes`(线性扫描,`\\`/`\u` 等合法对原样保留,防 `\\$` 形态二次破坏)、`_artifact_shaped`(形状校验:findings 列表或 survey v3 结构键;`schema_version` 是值不受验的标签,不入选)。错误类型用 `startswith("Invalid \escape")` 匹配(对无 C 加速构建/msg 带后缀的解码器变体稳健;实测 `Invalid \uXXXX escape` 不误匹配)。
- 三合一门槛逐条落地:错误类型不符→None;归一化后仍解析失败→None;形状不符(如 `{"note": "cost \$5"}`)→None。真实降级样本端到端:`extract_json_object` → dict,经 `_normalize_survey` 产 schema v3。
- 测试:`test_extract_json_object_overescape_repair`(先红:现状 None;后绿全过;反向真损坏/形状不符/`\uXXXX` 类错误用例),fixture 缩样注册进 test_main。全量 **326 passed + 21 skipped** 零回归;顺手修掉 docstring 里源码级 `\$` 触发的 SyntaxWarning。
- code-review 双轴:Standards 无硬违规(msg 匹配/边界/谓词三条判断题已采纳收敛);Spec 判定机制替代属忠实实现(触发条件保留、实测字节支撑)。遗留提示(不阻塞):①剥法对真 `\"` 双重转义(分隔符类错误)不修,属另一缺陷类,实测复现再立项扩门槛;②`_ARTIFACT_SHAPE_KEYS` 与 `_normalize_survey` 的 survey 键集平行,survey 结构演进时需同步(注释已标注,现状规模不抽单一出处)。

**2026-09-11 端到端重跑验证(target/5 --force)**:全链路零降级——recon 两轮均首轮直产 survey.json(8.3KB/12.5KB),analysis/verification 全部 .json 工件,无一次 .md 降级、无降级引发的补跑(基线 recon#0 降级 .md 白烧一轮 ~50 万 token)。注:本次模型未再产出 `\$` 过度转义(活体未触发修复档,transcript 中 `\$` 计数 0),修复逻辑的绿灯证据仍以真实降级样本单测为准。

# 0011-删除 Step2/3/4:确定性预处理漏斗退役

日期:2026-09-09(与 ADR-0010 同会话定稿;**代码未落地**,实现走 to-spec → to-tickets)

## 问题

Step2 过滤(白/黑名单)→ Step3 分类(file 批量识别)→ Step4 反编译/提取(Ghidra + 文本扫描 + 证书解析 + 不透明分诊)→ fileinfo.json,构成喂 Step5 的确定性漏斗。ADR-0010 把 Ghidra 降为 Step5 按需工具后,三步的存在理由同时消失:

- **Step4** 失去主体(Ghidra 已工具化,其余职责见下方能力清单逐项裁定);
- **Step2** 的过滤清单本就不落盘(内存直通 Step3/4),其黑名单与 Step5 工具已消费的 `SEARCH_EXCLUDE_DIRS` 大面积重合(usr/lib / usr/local/lib / usr/share / lib 四项重合);
- **Step3** 的存在理由是为 Step4 分发,Step4 没了它自然没有意义。

实证:target/3 APP 分区 30.6 万文件、全程无 Ghidra 产物,Step5 照常完成——agent 面向解包树原生工作是可行的。

## 决策

**删除 `firmware_audit/step2/`、`step3/`、`step4/` 全部代码与测试;main.py 流水线变 Step0 → Step1 → Step5。**

- profile(`nano-ubuntu.yaml`)**保留**:Step5 工具消费其 `SEARCH_EXCLUDE_DIRS` 段(list_files / search_code / semgrep 的 sdk_exclude);其余段(BLACKLIST/WHITELIST/TRUST/STD/DOWNGRADE)的消费者随退役消失,是否精简在工单里定;`file_rules` 模块保留(Step5 工具的 SEARCH_EXCLUDE 入口),其 TRUST/STD/DOWNGRADE 死代码一并清理。
- `app_pipeline_driver.py` 一并删除(APP 旁路,与"旁路待退役"既有决定同向)。
- `run_step5` 启动门从"analysis/ 存在"改为"extracted/ 存在"(现文案"先跑 Step1-4"同步改)。
- FileInfo 模型与 fileinfo.json 退役;recon/verify 简报概览改由简报构建器 **rglob extracted 现场统计**(顶层目录 × 文件数,套 SEARCH_EXCLUDE,扩展名粗分布;无真类型分类——为概览复活 Step3 的 file 批量识别不值得,精细分型由 recon 用 list_files 现场做)。
- conftest 探针(`analysis/unitree/bin/idlc.c`)不受影响:旧 analysis/ 工件是 ghidra_decompile 的合法缓存。

### 能力消失清单(显式裁定,不是遗漏)

| 能力 | 原产出 | 裁定 | 理由 |
| --- | --- | --- | --- |
| 文本类预扫 | `.text.json`(`_scan_text`) | 删 | search_code 的原始 grep 路覆盖同一批文件 |
| ELF 硬编码扫描 | `.text.json`(`_scan_elf_strings`) | 改 | strings_query 的 `pattern` 参数查询时过滤(ADR-0010) |
| 证书解析 | `.crypto.json`(`_dispatch_crypto`) | 删 | gitleaks + read_file 兜底;真需要再立按需工具票 |
| 不透明分诊 | `.triage.json` + `converted/*.bin`(`triage.py`) | 删 | 见下方专段 |
| 内容去重 | Step2 `dedup_by_content` | 改 | ghidra_decompile 的 sha256 + dedup.json 缓存去重(ADR-0010) |
| is_system_trust 标记 | Step3 | 删(机制) | "系统 CA 不作可疑上报"降为提示词纪律 |
| fileinfo 类型分布概览 | Step3/4 | 改 | rglob 现场统计 |
| audit_status 字段 | FileInfo | 随 FileInfo 退役 | Agent 阶段对应概念是 finding 的 verified |

**triage 专段**(用户两轮追问后定稿):实测分诊结论到不了 agent——不入 recon 简报工件索引(prompts.py:535 只 rglob functions/imports/strings.json)、不入 search_code 边车路(`_SIDECARS` 只有 imports/text/strings),唯一间接可见是 fileinfo 概览的 unknown 计数,分诊结论本体(七类判定)到不了 LLM;`converted/*.bin` 注释写"供 Ghidra ARM 加载"但从未接线(Ghidra 批量只吃 Step3 判定的 ELF)。裁定原则:**到不了 agent 的产物没有价值;识别之后没有处理路径,识别就没有审计价值**。"绝不静默消失"由结构性手段保证:无过滤的 list_files 天然看见每个文件;blob 的处理路径已存在——strings_query 的 r2 兜底(izz 任意文件)+ binwalk_rescan(签名表,"无签名"本身是可引用 Observation)。签名知识(熵阈值 6.0 的校准教训、IFLY/eGON/RITE 魔数)留 git 历史,将来审 MCU blob(届时配套 decompile 原始二进制模式,识别+处理一起接线)再捞。

## 被否的方案

- **Step2/3 合并保留为轻量 inventory 步骤**:过滤清单的唯一硬消费者(Step4 分发)已消失;类型统计可现场数;多一层落盘产物多一份口径维护。
- **triage 封装为按需工具 file_triage**(只保留 sniff_firmware_kind):识别结论(讯飞语音包/eGON boot0/高熵 MCU)没有后续动作可接,沉没成本(实测校准)不构成保留理由。

## 代价与影响

- main.py 的 `--max-elf` / `--max-workers` 随 Step4 退役;`--profile` 是否保留(file_rules 仍读)工单里定。
- 测试删除:test_step2.py、test_step3.py、test_step4.py、test_step4_triage.py。
- AGENTS.md / requirements.md / rules.md 的 Step1-4 章节过时,以本 ADR 与 ADR-0010 为准(CONTEXT.md 术语表已同步,退役词条带标注)。

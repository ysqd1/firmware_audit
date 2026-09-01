# C3 架构体检落地:收敛系统目录判断到 file_rules

> 日期:2026-08-31
> 提交:`7476b35`(重构:收敛系统目录判断到 file_rules,修复 step4 降级名单分叉)
> 来源:`/improve-codebase-architecture` 体检候选 C3(Strong)
> 关联:CONTEXT.md 术语(系统标准目录 / 系统信任库 / 逻辑路径)、ADR-0001/0002

---

## 一、背景:体检发现的问题

Step1-5 流水线里,"哪些目录值得审计 / 该标记 / 该过滤"这个判断,被**三处各写了一份名单,且互相不一致**:

| 处 | 位置 | 名单 | 用途 |
|---|---|---|---|
| Step2 过滤 | `profiles/nano-ubuntu.yaml` `SYSTEM_STD_DIRS` | 18 项(`etc/mono`/`etc/xdg`/`etc/X11`…) | **排除**(不送审) |
| Step4 反编译 | `step4_decompile.py` 硬编码 `_SYSTEM_STD_DIRS` | 16 项(`etc/init.d`/`etc/ssh`/`etc/apt`…) | **降级**(低危信号不报) |
| Step5 工具层 | `cli_base.py` `SDK_DIR_PREFIXES` + `list_files.py` `DEFAULT_EXCLUDE_DIRS` | `usr/lib`/`usr/share`/`opt`… | **过滤**(搜索时跳过) |

**关键问题**:
1. Step2 和 Step4 的名单**交集只有 `etc/mono` 一项**,几乎完全不同。
2. 更严重的是 **Step4 把该审的文件当垃圾跳过**:`etc/init.d`/`etc/ssh`/`etc/apt` 等在 profile 里属于 `WHITELIST_ETC`(**强制保留送审**),Step4 却把它们当"标准目录"降级。**同一个文件,Step2 说该审,Step4 说不值得审。**
3. Step5 工具层的 SDK 过滤名单**硬编码在工具里**,没外置,换机型不会跟着变。
4. Step4 还**跨 step 偷 import 私有符号**:`from ..step2.step2_filter import _logical_path`(`_` 开头=私有,不该被外面用)。

---

## 二、先厘清:Step2/3/4 到底做什么

> 这一节厘清流水线各阶段的实际行为,才能理解 C3 收敛的是什么、影响什么。

### 数据流:一个列表接力传递

```
Step1 解包树 (extracted/)          ← 磁盘上的文件树(只读)
   │
   ▼
Step2 filter_files ──► 返回「送审文件路径列表」(list[Path])
   │                       只挑出"深度分析"的路径,别的只留原始文件
   ▼
Step3 classify ───────► 返回「FileInfo 列表」(list[FileInfo])
   │                       为每个文件建元信息对象
   ▼
Step4 decompile ──────► 原地填充每个 FileInfo(arch/ghidra_status/audit_status)
   │                       产出 analysis/ 边车工件
   ▼
Step5 Agent 审计 ─────► 读 Step4 工件,产出 findings + 报告
```

### Step2 是「过滤」,但过滤的是「审计名单」,不是删除磁盘文件

- `filter_files(extracted_root)` 遍历解包树,按白/黑名单、系统标准目录等,**挑出"该审计"的文件路径**,返回 `list[Path]`。
- **被排除的文件**:不进 Step3(不分类)、不进 Step4(不反编译/扫描),所以**没有 `analysis/` 反编译边车工件**。但**文件本身还留在 `extracted/` 磁盘上**,Step5 的 Agent 用 `read_file`/`search_code` 仍然**看得到原始文件**——只是没有 Step4 产出的反编译/字符串/导入工件可查。
- 所以 Step2 的"过滤"准确说是:**筛掉审计名单里"深度分析"的对象**,磁盘不变。

> 打个比方:Step2 是"选谁上深度审阅台"——没选上的不反编译、不产工件,但它们还是躺在 `extracted/` 里,Agent 想读原始内容仍能读到。

### Step3 是「分类」,分类就是给每个文件写元信息(FileInfo)

- `classify(files, extracted_root)` 接收 Step2 的路径列表,对每个文件:
  - 用 `file` 命令识别类型 → 写进 `FileInfo.type`(elf_exec / elf_lib / script / crypto_* 等)
  - 记录 `size`、`subtype`(file 原始输出)、`is_system_trust`(是否系统信任库)
  - 返回 `list[FileInfo]` —— **每个文件的元信息对象**
- **Step3 不反编译、不扫描内容**,只是"认出这个文件是什么",把结论写进 FileInfo。
- `is_system_trust` 这一步就在分类时打上(调 `file_rules.is_system_trust`)。

> 所以你说得对:分类"只是把信息写到 FileInfo 里"。

### Step4 是「反编译/提取」,原地填充 FileInfo + 产出 analysis/

- `decompile(fileinfos, workspace)` 接收 FileInfo 列表,**原地修改每个 FileInfo**(不是返回新列表):
  - ELF → Ghidra 反编译,填 `decompiled_path`/`ghidra_status`,产出 `analysis/<rel>.c` + JSON
  - 文本/脚本/源码 → 扫硬编码串,填 `audit_status`(passed/suspicious),产出 `.text.json`
  - 证书 → 解析,填元信息
  - 不透明 → 分诊
- **Step4 的"降级名单"(SYSTEM_DOWNGRADE_DIRS)就是在这个阶段的文本扫描里用**——决定某些低危信号(IP/口令)要不要报。

### 两个"过滤"不是一回事(本仓库最易混淆点)

| | Step2 的过滤 | Step5 工具层的过滤 |
|---|---|---|
| 在哪个阶段 | Step2(流水线早期) | Step5(Agent 搜索/枚举时) |
| 作用 | **筛掉"深度分析"对象**(不分类/不反编译/不产工件;原始文件 Agent 仍可见) | **搜索时跳过噪音**(文件本身仍可读) |
| 是否动磁盘 | 不动(只在审计名单层面筛) | 不动(只在搜索结果跳过) |
| 名单来源 | profile `BLACKLIST_DIRS`/`SYSTEM_STD_DIRS` | profile `SEARCH_EXCLUDE_DIRS` |

**C3 收敛的正是这两族**:Step2 的 `SYSTEM_STD_DIRS`(排除)、Step4 的 `SYSTEM_DOWNGRADE_DIRS`(降级)、Step5 的 `SEARCH_EXCLUDE_DIRS`(过滤)——三者语义不同,但都曾"各写一份名单",收敛到 `file_rules.py` 统一管理。

---

## 三、决策过程(grilling 收敛)

| 决策 | 选择 | 理由 |
|---|---|---|
| 名单以谁为准 | **profile 为准** | 项目"配置外置、换机型只改 profile"铁律 |
| SDK 排除算不算同一概念 | **不算** | "排除"(不送审)vs "过滤"(搜索跳过)语义不同 |
| Step4 硬编码名单 | **拆独立降级名单** | 审查发现直接删会改变 step4 误报率 |
| 收敛范围 | **四个概念 + 逻辑路径** | 一次收干净 |
| 文件命名 | **`file_rules.py`** | 一看就知道"文件规则" |

**关键转折**:最初 grilling 决定"删 Step4 名单改从 profile 读",但 code-review 审查发现——step4 那份名单(`etc/init.d` 等)和 profile 的 `SYSTEM_STD_DIRS` 语义根本不同,直接删会让 `etc/init.d` 里的 IP/口令以全强度上报(误报率变大)。**最终拆独立 `SYSTEM_DOWNGRADE_DIRS`**,行为不变。

---

## 四、改了什么

### 新增 `firmware_audit/file_rules.py`(核心)

收敛五个判断函数,名单全部外置到 profile:

| 函数 | 语义 | 消费方 | 名单来源 |
|---|---|---|---|
| `logical_path(rel)` | 剥 binwalk 嵌套前缀 | step2/3/4 | 代码规则 |
| `is_system_std(logical)` | 排除(不送审) | step2 | profile `SYSTEM_STD_DIRS` |
| `is_system_trust(logical)` | 标记(仍审) | step3 | profile `SYSTEM_TRUST_DIRS` |
| `is_search_excluded(logical)` | 过滤(搜索跳过) | step5 工具层 | profile `SEARCH_EXCLUDE_DIRS` |
| `is_downgrade_dir(logical)` | 降级(低危信号不报) | step4 | profile `SYSTEM_DOWNGRADE_DIRS` |

另有:
- `get_search_exclude_dirs()` —— 返回当前过滤名单副本(修复 cli_base 快照绑定)
- `configure(profile_name)` —— 切换 profile 时更新全部名单

### `profiles/nano-ubuntu.yaml`

- 新增 `SEARCH_EXCLUDE_DIRS`(原 step5 硬编码名单:usr/lib/usr/local/lib/usr/share/lib/opt/.git/__pycache__/node_modules/.pytest_cache)
- 新增 `SYSTEM_DOWNGRADE_DIRS`(原 step4 硬编码名单:etc/init.d/ssh/apt 等 16 项)

### `step2_filter.py`

- 删本地 `_logical_path`/`_is_system_std`/`_is_system_trust`/`SYSTEM_STD_DIRS`/`SYSTEM_TRUST_DIRS` 定义
- 改 import `file_rules` 的 `logical_path`/`is_system_std`
- `configure()` 调用 `file_rules.configure()`(换 profile 两处一起生效)
- 删死导入 `is_system_trust`(code-review 发现)

### `step3_classify.py`

- import `_is_system_trust` → `is_system_trust` + `logical_path`
- 调用点改 `is_system_trust(logical_path(rel))`(rel 先剥 binwalk 前缀)

### `step4_decompile.py`

- **删除硬编码 `_SYSTEM_STD_DIRS` 名单**(16 项)
- `_in_system_std` → `_in_downgrade_dir`,改调 `file_rules.is_downgrade_dir`
- 低危信号降级逻辑(`_LOW_RISK_KINDS` = password_kw/url/ipv4)**行为不变**
- `_logical_path` 改 import `file_rules.logical_path`(修掉偷私有符号)

### step5 工具层

- `cli_base.py`:删 `SDK_DIR_PREFIXES`,`sdk_exclude_flags` 改读 `get_search_exclude_dirs()`(**修复快照绑定 bug**:原 `from file_rules import SEARCH_EXCLUDE_DIRS` 按值绑定列表,configure 后不更新)
- `list_files.py`:删 `DEFAULT_EXCLUDE_DIRS`,`_excluded` 改调 `is_search_excluded`
- `search_code.py`:改 import `is_search_excluded`,保留双形态(剥 `extracted/` 前缀)

### 测试

- 新增 `test_file_rules.py`(11 用例):logical_path 剥前缀 / is_system_std / is_system_trust / is_search_excluded / is_downgrade_dir
- `test_step2.py` 的 `logical_path` import 改从 file_rules

---

## 五、为什么这是修正而非破坏

**核心 bug**:step4 之前把 `etc/init.d`(启动脚本)、`etc/ssh`、`etc/apt` 当"标准目录"降级,而这些其实是 **WHITELIST_ETC 强制保留送审**的文件。改完后:
- step2 的 `SYSTEM_STD_DIRS` 只管排除,正确
- step4 的 `SYSTEM_DOWNGRADE_DIRS` 只管降级,行为不变

**换 profile 一致性**:名单从 profile 读,换机型改一处,四步一起生效。

---

## 六、测试与审查

| 项 | 结果 |
|---|---|
| 全量测试 | **208 passed, 10 skipped** |
| code-review Standards 轴 | 0 硬违规(修复 cli_base 快照绑定 + step2 死导入) |
| code-review Spec 轴 | 主干符合 spec;step4 降级名单语义经决策后**行为不变** |

---

## 七、遗留与后续

- **C4(路径逃逸检查重复 4 处)** 仍是 Strong,安全相关,未做——推荐下一个。
- **C1(Step4 decompile 拆分)** 1046 行只 12.9% 覆盖,是最大单模块——你 Q1 认了"该拆",待做。
- **C2(crypto parser 8 个浅克隆)** Worth exploring。
- `docs/tools_summary.md` 里 `step2_filter._logical_path` 引用已陈旧,可后续更新。

# 固件审计工具全览（tools\_summary）

> 覆盖 `firmware_audit/` 全流水线（Step0–Step5）的可执行工具与核心函数。
> 本文档逐节对应真实源码，字段/参数/错误码均以代码为准（2026-08-23 核对）。
> 阅读入口：`main.py` 是流水线总调度；`docker/docker_utils.py` 是全部容器调用的基座。

***

## 目录

* [流水线全景](#流水线全景)

* [公共基座：docker\_utils.run\_docker](#公共基座-docker_utilsrun_docker)

* [Step0 磁盘镜像分区提取](#step0-磁盘镜像分区提取)

* [Step0 预解压 preprocess](#step0-预解压-preprocess)

* [Step1 引导式解包](#step1-引导式解包)

* [Step1 文件魔数嗅探与决策](#step1-文件魔数嗅探与决策)

* [Step1 兜底 binwalk -Me](#step1-兜底-binwalk--me)

* [Step2 过滤 filter\_files](#step2-过滤-filter_files)

* [Step3 分类 classify](#step3-分类-classify)

* [Step4 反编译/提取 decompile](#step4-反编译提取-decompile)

* [Step4 不透明分诊 triage](#step4-不透明分诊-triage)

* [Step5 Agent 工具层](#step5-agent-工具层)（含 [list\_files](#list_files--目录文件枚举参考-deepaudit-listfilestool)、[search\_code](#search_code--按内容混合检索边车索引--extracted-文本-grep)、[编排层工具](#编排层工具orchestrationactionspy不在-providerstools-注册表)、[权限矩阵](#agent--工具权限矩阵v32026-08-29)）

* [Step5 引擎与编排](#step5-引擎与编排)

***

## 流水线全景

| 阶段    | 模块 / 文件                                              | 职责                                           | 容器？                           |
| ----- | ---------------------------------------------------- | -------------------------------------------- | ----------------------------- |
| Step0 | `step0/step0_preprocess.py`                          | 预解压外层归档/单文件压缩                                | 否（宿主标准库）                      |
| Step0 | `step0/step0_split_img.py`                           | 大磁盘镜像分区表解析与提取                                | sfdisk 走 `firm_audit/sandbox` |
| Step1 | `step1/step1_guided_extract.py`                      | 引导式解包（主路径）                                   | binwalk / 7z                  |
| Step1 | `step1/file_magic.py`                                | 魔数嗅探 + 解包决策（纯函数）                             | 否                             |
| Step1 | `step1/step1_extract.py`                             | binwalk -Me 递归解包（兜底）                         | binwalk                       |
| Step2 | `step2/step2_filter.py`                              | 白/黑名单过滤 + 去重                                 | 否                             |
| Step3 | `step3/step3_classify.py`                            | file 命令分类                                    | binwalk（file）                 |
| Step4 | `step4/step4_decompile.py`                           | Ghidra 反编译 + 文本/密钥扫描                         | ghidra                        |
| Step4 | `step4/triage.py`                                    | 不透明固件分诊                                      | 否                             |
| Step5 | `step5_agent/providers/tools/`                       | 15 个 Agent 工具（含 `list_files`/`search_code`） | 部分走 sandbox/binwalk           |
| Step5 | `step5_agent/orchestration/actions.py`               | 编排层工具（`dispatch_agent`/`summarize`/`finish`） | —                             |
| Step5 | `step5_agent/engine/` + `runner.py` + `run_step5.py` | ReAct 引擎与编排                                  | —                             |

***

## 公共基座：docker\_utils.run\_docker

**位置**：`firmware_audit/docker/docker_utils.py`

### 基本信息

| 项  | 值                                                                                         |
| -- | ----------------------------------------------------------------------------------------- |
| 名称 | `run_docker`                                                                              |
| 语言 | Python（仅标准库，宿主侧）                                                                          |
| 功能 | 运行 Docker 容器，返回 `(returncode, stdout, stderr)`。全部步骤（binwalk/file/ghidra/sandbox CLI）的底层调用 |

### 输入参数

| 参数           | 类型                      | 必填 | 取值/默认                                          | 说明                                                                         | <br />                 |
| ------------ | ----------------------- | -- | ---------------------------------------------- | -------------------------------------------------------------------------- | ---------------------- |
| `image`      | `str`                   | ✅  | 镜像名（如 `binwalk`、`ghidra`、`firm_audit/sandbox`） | 目标镜像                                                                       | <br />                 |
| `args`       | `list[str]`             | ✅  | —                                              | 传给容器命令的参数                                                                  | <br />                 |
| `mounts`     | `list[tuple]`           | ❌  | 默认 `None`                                      | \`\[(宿主路径, 容器路径\[, "ro"                                                    | "rw"])]`；第三段缺省 `  rw\` |
| `entrypoint` | `str \| None`           | ❌  | `None`                                         | 覆盖镜像 entrypoint（沙箱 ENTRYPOINT 是 Ghidra analyzeHeadless，调非 Ghidra CLI 必须覆盖） | <br />                 |
| `workdir`    | `str \| None`           | ❌  | `None`                                         | 容器内工作目录                                                                    | <br />                 |
| `timeout`    | `int`                   | ❌  | `3600`                                         | 超时秒数                                                                       | <br />                 |
| `env`        | `dict[str,str] \| None` | ❌  | `None`                                         | 追加容器环境变量                                                                   | <br />                 |
| `network`    | `str \| None`           | ❌  | `None`                                         | 网络模式；Step5 Agent 工具一律 `none`（断网）                                           | <br />                 |

### 输出/返回

* 返回三元组 `(returncode, stdout, stderr)`。**不抛异常**；`subprocess.TimeoutExpired` 时返回 `(124, "", "docker run timed out...")`。

* 失败 = 非零 `returncode`，由调用方决定降级（"失败不崩"原则）。

### 辅助函数

| 函数                          | 作用                                              |
| --------------------------- | ----------------------------------------------- |
| `to_docker_path(host_path)` | Windows 路径转正斜杠（`\` → `/`），供 `-v` 挂载             |
| `_ensure_tag(image)`        | 无 tag 镜像名补 `:latest`（`docker image inspect` 需要） |
| `docker_available(image)`   | 用 `docker image inspect` 判断 Docker + 镜像是否可用     |

### 要点

* 命令组装：`docker run --rm [--entrypoint][-w][--network][-e][-v...] image args`。**所有运行都带** **`--rm`**。

* 挂载模式：Step4 Ghidra 的 output 目录默认 `rw`（要写反编译产物）；Step5 沙箱 extracted 为 `ro`。

***

## Step0 磁盘镜像分区提取

**文件**：`firmware_audit/step0/step0_split_img.py`（入口 `main()`；流水线调用 `extract_partitions_from_image` / `parse_partitions` / `is_disk_image`）

### CLI 用法

```
python -m firmware_audit.step0.step0_split_img <img文件> [--out-dir 目录] [--max-size GB] [--list-only] [--extract-all]
```

| 参数              | 类型    | 必填 | 默认     | 说明                                 |
| --------------- | ----- | -- | ------ | ---------------------------------- |
| `img_path`      | str   | ✅  | —      | 镜像文件路径                             |
| `--out-dir`     | str   | ❌  | `.`    | 输出目录                               |
| `--max-size`    | float | ❌  | `50.0` | 单分区最大提取大小 GB（rootfs/recovery 超限跳过） |
| `--list-only`   | flag  | ❌  | 关      | 只列分区不提取                            |
| `--extract-all` | flag  | ❌  | 关      | 提取所有分区（含 dtb/reserved/userdata/超大） |

### 核心函数

| 函数                                                                      | 作用                                                                                         |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `is_disk_image(path)`                                                   | 读前 1KB：MBR 签名 `0x55aa` + LBA1 `EFI PART` → 磁盘镜像                                            |
| `parse_partitions(img)`                                                 | 主解析 sfdisk，失败回退手写解析（含 CRC 校验）；无分区表返回 `[]`                                                  |
| `parse_gpt_partitions(f)` / `_parse_gpt` / `_parse_mbr`                 | 手写 GPT/MBR 解析                                                                              |
| `detect_partition_kind(name, offset, size)`                             | 按名字+大小推断类型（dtb/reserved/esp/bootloader/kernel/rootfs/recovery/userdata/small/medium/large） |
| `should_extract(kind, size, max_size_gb)`                               | 是否提取该分区                                                                                    |
| `extract_partition(f, p, out_path)`                                     | 按偏移复制分区到文件（4MB 块 + 进度）                                                                     |
| `_verify_extracted(src, offset, size, out)`                             | 提取后回读校验（对比前 4KB）                                                                           |
| `extract_partitions_from_image(img, out_dir, max_size_gb, extract_all)` | 一键：解析→提取→回读校验                                                                              |

### 分区 dict 字段

```json
{
  "index": 3, "name": "APP", "offset": 838860,
  "size": 1073741824, "type": "gpt", "kind": "rootfs",
  "crc_ok": true, "truncated": false,
  "issues": [],
  "kind_conflict": false,
  "signatures": ["squashfs (little-endian)"]
}
```

| 字段                | 类型         | 含义                             |
| ----------------- | ---------- | ------------------------------ |
| `index`           | int        | 分区序号（1 起）                      |
| `name`            | str        | 分区名                            |
| `offset` / `size` | int        | 字节偏移 / 大小                      |
| `type`            | str        | `gpt` / `mbr`                  |
| `kind`            | str        | detect\_partition\_kind 结果     |
| `crc_ok`          | bool       | GPT CRC 校验是否通过                 |
| `truncated`       | bool       | 分区超镜像末尾被截断                     |
| `issues`          | list\[str] | 人类可读问题                         |
| `kind_conflict`   | bool       | 名字推断类型与头部签名冲突                  |
| `signatures`      | list\[str] | 头部签名识别（ext4/squashfs/gzip/...） |

### 多道校验防线（宁可拒绝，不可静默出错）

1. GPT 头 CRC32 + 条目数组 CRC32（不匹配 → 拒绝该分区表）
2. 条目参数合理性（条目数/大小/数组位置）
3. 分区边界检查（超界跳过、超尾截断并告警）
4. 类型 GUID 全零但非空条目 → 告警跳过
5. 身份交叉验证（名字推断 kind vs 头部签名）
6. 提取后回读校验（不一致 → 删除该分区）
7. 复用检查同样过回读校验

### 错误语义

* 无分区表/表 CRC 失败 → `parse_partitions` 返回 `[]` → 调用方**回退直接交 binwalk**（裸固件）。

* 回读校验失败 → 删除分区文件，不加入结果（宁缺毋滥）。

* `kind_conflict` / `truncated` → 打印警告但**不中断**流程。

***

## Step0 预解压 preprocess

**文件**：`firmware_audit/step0/step0_preprocess.py`

### 基本信息

| 项  | 值                                             |
| -- | --------------------------------------------- |
| 名称 | `preprocess(firmware_path, extracted_dir)`    |
| 语言 | Python 宿主标准库                                  |
| 功能 | binwalk 之前用宿主解压外层压缩，避开 binwalk 解压偶发 bug，提升确定性 |

### 输入参数

| 参数              | 类型   | 必填 | 说明                              |
| --------------- | ---- | -- | ------------------------------- |
| `firmware_path` | Path | ✅  | 识别出的固件文件                        |
| `extracted_dir` | Path | ✅  | Step1 输出目录（`process/extracted`） |

### 返回

`(inputs: list[Path], skip_binwalk: bool)`

* `skip_binwalk=True` → `inputs[0]` 已是解压出的文件系统，直接进 Step2

* `skip_binwalk=False` → `inputs` 是需 binwalk 继续解的文件列表（单固件=\[文件]；磁盘镜像=各分区）

### 分流规则

| 输入                                            | 动作                       | skip\_binwalk |
| --------------------------------------------- | ------------------------ | ------------- |
| 归档（`.zip/.tar/.tar.gz/.tar.bz2/.tar.xz/.tgz`） | 解出完整文件系统到 extracted\_dir | `True`        |
| 单文件压缩（`.gz/.bz2/.xz`）                         | 解出单文件到 `process/` 根      | `False`       |
| 磁盘镜像（GPT/MBR）                                 | 分区提取，每个分区单独交 Step1       | `False`       |
| 其他（`.bin` 等）                                  | 原样返回                     | `False`       |

### 常量

* `_PARTITION_MAX_SIZE_GB = 50.0`：rootfs/recovery 分区提取上限。

* 解压失败（损坏/权限）→ 返回 `([firmware_path], False)` 兜底交 binwalk（失败不崩）。

***

## Step1 引导式解包

**文件**：`firmware_audit/step1/step1_guided_extract.py`（主路径）

### 基本信息

| 项  | 值                                            |
| -- | -------------------------------------------- |
| 名称 | `extract_guided`                             |
| 功能 | 按魔数决策逐层解包，替代 binwalk -Me 盲解（避免 fdt 分解成数十万节点） |

### 输入参数

| 参数              | 类型       | 必填 | 默认    | 说明                                              |
| --------------- | -------- | -- | ----- | ----------------------------------------------- |
| `firmware_path` | Path     | ✅  | —     | 固件文件（resume/scan\_tree 可传目录）                    |
| `output_dir`    | Path     | ✅  | —     | 输出目录                                            |
| `max_depth`     | int      | ❌  | 6     | 最大递归层数                                          |
| `max_workers`   | int      | ❌  | 8     | binwalk 并行容器数                                   |
| `extractor`     | callable | ❌  | None  | 解包函数注入点（测试用 fake；None → `_binwalk_extract_one`） |
| `check_docker`  | bool     | ❌  | True  | 是否检查 Docker/镜像                                  |
| `resume`        | bool     | ❌  | False | 断点续传（从 manifest 重建候选树）                          |
| `scan_tree`     | bool     | ❌  | False | 树扫描模式（归档路径，候选=树内全部文件）                           |

### 返回

* 成功返回 `output_dir`；失败返回 `None`（调用方兜底旧 `-Me`）。

### 核心流程

1. **候选展开**：逐层取候选（固件文件 或 scan\_tree 树内全部文件 / resume 从 manifest 重建）。
2. **决策**：每个候选先 `_binwalk_extract_one` 试解（binwalk `-e` 单层 + 7z 兜底 + 5 万文件守卫），并更新 manifest。
3. **并行**：`ThreadPoolExecutor(max_workers=max_workers)` 对 `to_extract` 并行解包（[代码 L325](file:///e:/固件/create/important/firmware_audit/step1/step1_guided_extract.py#L325)）。
4. **续传**：manifest 落盘（`guided_extract.json`），崩溃可 resume（幂等）。

### manifest 记录字段

| 字段           | 含义                               |
| ------------ | -------------------------------- |
| `seq`        | 顺序号（改名前缀，幂等续传用）                  |
| `depth`      | 所在层                              |
| `action`     | `continue` / `finalize` / `skip` |
| `reason`     | 决策理由                             |
| `renamed_to` | 容器改名后的路径（`<seq>_原名`），防重复决策       |
| `files`      | 解出的文件相对路径列表                      |
| `done`       | 是否已完成                            |

> `_binwalk_extract_one`：硬改名 `<parent>/<seq>_<原名>` → `binwalk -e -x dtb`（env `BINWALK_RM_EXTRACTION_SYMLINK=1`）→ 空产出则 7z 兜底。

***

## Step1 文件魔数嗅探与决策

**文件**：`firmware_audit/step1/file_magic.py`（纯函数，无 Docker）

### 函数清单

| 函数                                       | 返回                             | 说明                                                       |
| ---------------------------------------- | ------------------------------ | -------------------------------------------------------- |
| `sniff_magic(data, fname="")`            | `list[str]`                    | 读文件头 4KB，命中魔数名列表；无命中且像文本 → `["text"]`                    |
| `shannon_entropy(data)`                  | `float` (0–8)                  | 熵，采样前 64KB                                               |
| `preclassify(sigs, fname="")`            | `"skip"/"product"/"container"` | 快速二分：fdt→skip；elf/pe/text→product；其他→container           |
| `rule_decision(sigs, fname="", depth=0)` | `(action, reason)`             | 容器裁决：fdt→skip；ELF/文本→finalize；容器签名→continue；无签名→finalize |
| `_looks_like_text(data)`                 | `bool`                         | 无 NUL + 可打印占比 > 0.9                                      |

### 魔数表（节选）

| 魔数                                            | 名称                     |
| --------------------------------------------- | ---------------------- |
| `\xd0\x0d\xfe\xed` / `\xed\xfe\x0d\xd0`       | fdt\_be / fdt\_le      |
| `\x7fELF`                                     | elf                    |
| `MZ`                                          | pe                     |
| `ANDROID!` / `VNDRBOOT`                       | bootimg / vendor\_boot |
| `\x27\x05\x19\x56` / 小端                       | uimage                 |
| `\x1f\x8b` / `\xfd7zXZ\x00`                   | gzip / xz              |
| `hsqs` / `sqsh`                               | squashfs               |
| `\x30\x37\x30\x37` / `070701`（+070702/070707） | cpio / cpio\_newc      |
| `\x37\x7a\xbc\xaf\x27\x1c`                    | 7z                     |
| `PK\x03\x04` 等                                | zip                    |
| `\x85\x19`                                    | jffs2                  |
| `\x31\x18\x10\x06`                            | ubifs                  |

偏移校验表：`(0x438, \x53\xef, ext4)`、`(257, "ustar", tar)`、`(510, \x55\xaa, fat)`。

### 责任边界（勿破坏）

* `preclassify` 仅快速二分，绝不在此裁决容器。

* `rule_decision` 只处理 preclassify 筛剩下的（`container` 分支）。

***

## Step1 兜底 binwalk -Me

**文件**：`firmware_audit/step1/step1_extract.py`

### 基本信息

| 项  | 值                                           |
| -- | ------------------------------------------- |
| 名称 | `extract(firmware_path, output_dir)`        |
| 功能 | binwalk `-Me` 递归解包（仅引导解包器失败时由 main.py 兜底调用） |

### 输入/返回

* 入参：`firmware_path`、`output_dir`。

* 返回：解包根目录 `output_dir/extractions`；失败返回 `None`。

* 前置：`docker_available(BINWALK_IMAGE)`，不可用返回 `None`。

* 参数：`["-Me", f"{CONTAINER_INPUT_DIR}/{firmware_path.name}", "-d", CONTAINER_OUTPUT_DIR]`，timeout=3600。

另提供 `verify(extractions_root)`：目录存在且含文件 → `bool`。

***

## Step2 过滤 filter\_files

**文件**：`firmware_audit/step2/step2_filter.py`

### 基本信息

| 项  | 值                                            |
| -- | -------------------------------------------- |
| 名称 | `filter_files(extracted_root, profile=None)` |
| 功能 | 遍历解包目录，按白/黑名单返回应审计文件列表                       |

### 输入参数

| 参数               | 类型          | 必填 | 默认                     |
| ---------------- | ----------- | -- | ---------------------- |
| `extracted_root` | Path        | ✅  | —                      |
| `profile`        | str \| None | ❌  | None（默认 `nano-ubuntu`） |

### 返回

通过过滤的文件绝对路径列表 `list[Path]`。

### 处理顺序（优先级从高到低）

1. **Step1 标记跳过**：`.step1_done`、`guided_extract.json`（非固件内容）
2. **DTB 节点过滤**：路径含 `<名>@<地址>` 段（数十万噪声）→ 排除
3. **构建中间产物**：BUILD\_ARTIFACT\_PATTERNS（CMakeCache.txt/.cmake/.map 等）→ 排除（优先于白名单）
4. **白名单**（厂商定制 + etc 敏感配置）命中 → 保留
5. **证书/密钥扩展名**（.pem/.key/.crt/...）→ 强制保留
6. **系统标准配置目录**（SYSTEM\_STD\_DIRS）→ 排除
7. **黑名单** → 排除
8. **其他** → 默认保留（交 Step3 分类）

### 去重

* `_dedup`：按 `(逻辑路径, 内容前4KB哈希)` 去 binwalk 双副本，保留物理路径最短者。

* `_dedup_by_content`：`.so/.ko/.elf` 按内容 MD5 去同库不同名（`.so` 最基础优先）。

### 逻辑路径归一化

`_logical_path(rel_path)`：反复剥 `<name>.extracted/<N>/` 与 `<fstype>-root/` 前缀。
例：`foo.tar.xz.extracted/0/etc/passwd` → `etc/passwd`。

### profile 外置

名单从 `profiles/<name>.yaml` 加载（`BLACKLIST_DIRS/BLACKLIST_PATTERNS/WHITELIST_DIRS/WHITELIST_ETC/SYSTEM_TRUST_DIRS/SYSTEM_STD_DIRS/BUILD_ARTIFACT_PATTERNS`）。pyyaml 缺失 → 醒目告警并退化放行（不静默）。

### 输出

`[Step2] 过滤完成(profile=...): {total} -> {kept} 文件`，及 DTB 过滤数 / 去重数 / 白名单 0 命中提示。

***

## Step3 分类 classify

**文件**：`firmware_audit/step3/step3_classify.py`

### 基本信息

| 项  | 值                                       |
| -- | --------------------------------------- |
| 名称 | `classify(files, extracted_root)`       |
| 功能 | 用 Docker `file` 批量识别文件类型，构建 FileInfo 列表 |

### 输入/返回

* 入参：`files: list[Path]`（Step2 输出）、`extracted_root`。

* 返回：`list[FileInfo]`。

* 用 Docker `file -f filelist.txt` 批量识别；Docker 不可用 / 失败 → **降级纯扩展名分类**（打印警告）。

### 类型集

`elf_exec / elf_lib / script / source / config / text / crypto_x509 / crypto_ssh / crypto_gpg / crypto_pkcs12 / crypto_private_key / crypto_public_key / crypto_unknown / unknown`

### 分类判定（`_classify_one`，优先级）

| 顺序 | 条件                                    | 类型                  |
| -- | ------------------------------------- | ------------------- |
| 1  | `"elf"` in out，且 shared/relocatable   | `elf_lib`           |
| 1  | `"elf"` in out，且 executable           | `elf_exec`          |
| 2  | crypto 关键词（file 输出）→ 扩展名兜底            | `crypto_*`          |
| 3  | script/text / python / shell 关键字 或扩展名 | `script` / `source` |
| 4  | 配置扩展名                                 | `config`            |
| 5  | text/ascii/utf-8/json/xml             | `text`              |
| 6  | 其他                                    | `unknown`           |

### Crypto 细分（文件头关键词 → 类型）

| 关键词                                 | 类型                   |
| ----------------------------------- | -------------------- |
| pkcs12 / pkcs#12                    | crypto\_pkcs12       |
| openssh                             | crypto\_ssh          |
| openpgp / pgp public key            | crypto\_gpg          |
| pem private key / private key       | crypto\_private\_key |
| pem public key / openssh public key | crypto\_public\_key  |
| pem certificate                     | crypto\_x509         |
| certificate / version=              | crypto\_x509         |

> file 输出含 text/ascii/json/xml 时不做 crypto 扩展名兜底（避免纯文本误判密钥）。

### 输出

`[Step3] 分类完成: {n} 文件 ({type}=count ...)`，及系统信任库文件数。

***

## Step4 反编译/提取 decompile

**文件**：`firmware_audit/step4/step4_decompile.py`

### 基本信息

| 项  | 值                                                              |
| -- | -------------------------------------------------------------- |
| 名称 | `decompile(fileinfos, workspace, max_elf=None, max_workers=4)` |
| 功能 | ELF→Ghidra 反编译；文本/证书→扫描提取；不透明→分诊                               |

### 输入参数

| 参数            | 类型              | 必填 | 默认   | 说明                  |
| ------------- | --------------- | -- | ---- | ------------------- |
| `fileinfos`   | list\[FileInfo] | ✅  | —    | Step3 产物，原地填充       |
| `workspace`   | Path            | ✅  | —    | 工作区根（`target/<N>/`） |
| `max_elf`     | int \| None     | ❌  | None | 只处理前 N 个 ELF        |
| `max_workers` | int             | ❌  | 4    | Ghidra 并行容器数        |

### 分流

| 类                             | 处理                                      |
| ----------------------------- | --------------------------------------- |
| ELF（elf\_exec/elf\_lib）       | Ghidra 反编译（并行容器）+ 断点续传                  |
| 文本（script/source/config/text） | `_scan_text`（正则扫硬编码串，纯 Python）          |
| 证书（crypto\_\*/cert）           | `_dispatch_crypto` → 各 parser（纯 Python） |
| 不透明（unknown/text 命中 hex）      | `triage_opaque`                         |

### ELF 反编译（`_run_ghidra`）

* 命令：`analyzeHeadless <project> audit -import <elf> -postScript ExtractInfo.py <output> -analysisTimeoutPerFile 300 -deleteProject -overwrite`

* 挂载：input 父目录、output 临时目录、project 临时目录，timeout=900。

* 产出（到 `analysis/<rel>`）：

  * `<rel>.c`（decompiled.c 拼接）

  * `<rel>.functions.json`、`<rel>.imports.json`、`<rel>.symbols.json`、`<rel>.strings.json`

* 成功判定：`_decompile_success_count(c) > 0` 且 `functions.json` 非空且版本 = `_EXTRACTINFO_VERSION(2)`。

### Ghidra 产物字段

**functions.json**：`[{name, address, callers, callees}]`
**imports.json**：`[{name, address, ref_count, call_sites}]`
**strings.json**：`{program, version, strings: [{address, length, value, refs}]}`
**symbols.json**：`[{parent, address, type, name}]`

### 参数缺失处理

* Ghidra 镜像不可用 → ELF 标 `skipped`，文本/crypto 仍进行。

* `--max-elf` 截断的 ELF：若磁盘有完整产物标 `ok`，否则保持 pending 不降级。

### 错误码/状态

`ghidra_status ∈ pending / ok / failed / skipped`。

### 文本扫描输出

`analysis/<rel>.text.json`：

```json
{"path", "type", "count", "is_system_trust", "in_system_std",
 "findings": [{"type","match","line","is_system_trust","in_system_std"}]}
```

`audit_status := passed（无发现）| suspicious（有发现）`。

***

## Step4 不透明分诊 triage

**文件**：`firmware_audit/step4/triage.py`

### 基本信息

| 项  | 值                                                                                       |
| -- | --------------------------------------------------------------------------------------- |
| 名称 | `sniff_firmware_kind(data, fname="")` → `(type, reason)`；`triage_opaque(fi, workspace)` |
| 功能 | 纯规则分诊 unknown/可疑 text，绝不静默消失                                                            |

### 判定规则

| 条件                         | type               | reason          |
| -------------------------- | ------------------ | --------------- |
| Intel HEX 首行 `:` + 校验      | firmware\_hex      | hex→bin 落盘      |
| S-record `S0/S1/...`       | firmware\_srec     | 同上              |
| `IFLY` + `LJU`             | voice\_resource    | 讯飞语音包           |
| `\xdd\xcc\xbb\xaa`（eGON 头） | allwinner\_boot0   | Allwinner boot0 |
| `RITE` 前缀                  | opaque\_privformat | 私有脚本字节码         |
| 熵 ≥ 6.0                    | opaque\_firmware   | 疑似 MCU 固件       |
| 其他                         | opaque\_unknown    | 低熵未识别           |

### 常量

* 熵阈值 `6.0`（实测校准，7.5 会漏 master/flashboot/respak）

* S-record 转 bin 最大地址 `16MB`（防恶意地址触发 4GB 内存扩展）

* 全部 `audit_status="suspicious"`，写 `analysis/<rel>.triage.json`

***

## Step5 Agent 工具层

**公共返回结构** `ToolResult`（`base.py`）：

```python
@dataclass
class ToolResult:
    ok: bool                 # 成功/失败
    text: str                # 入上下文的文本（已截断 ≤8KB，头75%+尾20%）
    data: dict|list|None     # 结构化数据
    error: str|None          # 错误信息
    elapsed: float           # 耗时秒
    raw: str                 # 截断前原文（落盘用）
```

**公共工具上下文** `ToolContext`：含 `process_dir`（`target/<N>/process`，read\_file 白名单根）。

**公共执行入口** `AgentTool.execute(**kw)`：统一计时、异常捕获（失败→`ToolResult(ok=False, error=...)`不崩）、text 截断。

***

### read\_file —— 白名单分页回读

**位置**：`providers/tools/read_file.py`

| 项    | 值                                         |
| ---- | ----------------------------------------- |
| name | `read_file`                               |
| 用途   | 读 `process/` 下工件文件（Agent 间"工件是唯一契约"的回查机制） |

**参数**

| 参数       | 类型  | 必填 | 默认    | 说明                |
| -------- | --- | -- | ----- | ----------------- |
| `path`   | str | ✅  | —     | 相对 `process/` 的路径 |
| `offset` | int | ❌  | `0`   | 起始行               |
| `limit`  | int | ❌  | `200` | 读取行数              |

**行为**

* 目录 → 返回前 50 项文件名。

* 文件 → 分页返回行；offset 超总行数 → `ok=False, "offset=... 超出文件总行数"`。

* 路径越界（`process/` 外）→ `ok=False, "路径越界"`。

* 文件不存在 → `ok=False, "文件不存在"`。

**data**：目录返回 `list`；文件返回 `{"total_lines": n}`。

***

### list\_files —— 目录/文件枚举（参考 deepaudit ListFilesTool）

**位置**：`providers/tools/list_files.py`

| 项    | 值                                                                  |
| ---- | ------------------------------------------------------------------ |
| name | `list_files`                                                       |
| 用途   | 枚举 `process/` 下的文件与目录（recon 铺面首动工具；白名单根与 read\_file 同根 = process/） |
| 归谁   | recon / analysis / verification **三 Agent 全授权**（v3 新增）             |

**参数**

| 参数          | 类型   | 必填 | 默认      | 说明                                          |
| ----------- | ---- | -- | ------- | ------------------------------------------- |
| `directory` | str  | ❌  | `"."`   | 相对 `process/` 的目录；`path` 别名兼容（deepaudit 风格） |
| `pattern`   | str  | ❌  | `""`    | 文件名 glob 过滤，如 `"*.py"`                      |
| `recursive` | bool | ❌  | `False` | 是否递归下钻子目录                                   |
| `max_files` | int  | ❌  | `100`   | 条目上限（超限截断并提示）                               |

**行为**

* 路径解析后必须在 `process/` 之下（`resolve` + `parents` 判定），越界 / `..` / 绝对盘符 → `ok=False, "路径越界"`。

* 目录不存在 / 传入文件 → `ok=False`（"目录不存在"/"不是目录"）。

* 顶层目录项总是先列（带 `/` 后缀，给 LLM 下钻地图），即使非 recursive。

* `recursive=True` 时按**路径前缀**自动排除 SDK/系统库目录：`usr/lib`、`usr/local/lib`、`usr/share`、`lib`、`opt`、`.git`、`__pycache__`、`node_modules`、`.pytest_cache`（`usr/lib/x86_64` 这类子路径一并跳过下钻）。

* `max_files` 截断 → 末尾附提示"可用更具体的 directory 缩小范围 / 提高 max_files / pattern 过滤"。

**data 结构**：`{"count": n, "truncated": bool}` 的 dict。

---

### search_code —— 按内容混合检索（边车索引 + extracted 文本 grep）

**位置**：`providers/tools/search_code.py`（参考 deepaudit FileSearchTool，按 firmware 特性混合设计）
**归谁**：analysis / verification（recon 不授权——铺面枚举阶段不做正文检索）

| 项 | 值 |
|---|---|
| name | `search_code` |
| 用途 | 按关键词/正则全局定位"内容出现在哪"，命中即 Observation 证据，可直接 read_file 回查 |

**参数**

| 参数 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `keyword` | str | ✅ | — | 搜索关键词（大小写不敏感）或正则（`is_regex=true`） |
| `file_pattern` | str | ❌ | `""` | 文件名 glob，只过滤文本 grep 路 |
| `directory` | str | ❌ | `""` | 收窄 grep 范围（相对 process/，如 `extracted/unitree`）；默认 `extracted/` |
| `is_regex` | bool | ❌ | `False` | 是否按正则匹配 |
| `max_results` | int | ❌ | `50` | 命中上限（≤100） |

**双路混合**
- **① 边车索引路**（总是扫 `analysis/`，快、零容器）：`*.strings.json`（ELF 字符串值，带 address/refs）、`*.imports.json`（导入符号 + call_sites）、`*.text.json`（Step4 文本扫描命中 + line）。
- **② 文本 grep 路**（默认 `extracted/`）：白名单扩展名 `.py/.sh/.conf/.c/.h/.lua/.js/.php/.xml/...` 按行匹配，返回 `文件:行号 内容`；**二进制嗅探跳过**（前 8KB 含 NUL）、**SDK/系统库目录排除**（`usr/lib`、`opt` 等，与 list_files 口径一致）、单文件 >512KB 跳过。

**返回**
- 空 keyword / 非法正则 / 显式 directory 越界或不存在 → `ok=False`。
- 无命中 → `ok=True, "未找到匹配 ... (搜索 边车 N + 文本 M 文件)"`。
- 命中 → `ok=True`，text 每行 `- <相对process路径>:<锚点>  <命中内容>`，data=`{"count", "matches": [{path, anchor, text}]}`。

> 证据纪律：命中行是 Observation 原文，可溯源；超限截断提示可收窄 directory/file_pattern。

---

### strings_query —— 检索 ELF 字符串表

**位置**：`providers/tools/strings_query.py`

| 项    | 值                                 |
| ---- | --------------------------------- |
| name | `strings_query`                   |
| 用途   | 读 Step4 `strings.json`，按正则检索可疑字符串 |

**参数**

| 参数            | 类型  | 必填 | 默认   | 说明             |
| ------------- | --- | -- | ---- | -------------- |
| `file_ref`    | str | ✅  | —    | ELF 相对路径       |
| `pattern`     | str | ✅  | —    | 内置名或 `re:<正则>` |
| `max_results` | int | ❌  | `30` | 命中上限           |

**内置模式**：`url / ip / password / key / shadow / empty_password`。

**返回**

* `analysis/<rel>.strings.json` 缺失 → `ok=False`（"仅 ELF 有字符串表"）。

* 未知模式 → `ok=False`（列内置模式）。

* 无命中 → `ok=True, "无命中"`, data=\[]。

* 命中 → `ok=True`, text 每行 `地址 匹配 (引用: 函数...)`, data 为命中 dict 列表。

**data 结构**：`[{address, match, value, ref_functions: [str]}]`

***

### imports\_query —— 危险函数过滤器

**位置**：`providers/tools/imports_query.py`

| 项    | 值                          |
| ---- | -------------------------- |
| name | `imports_query`            |
| 用途   | 读 `imports.json`，圈危险函数与调用点 |

**参数**

| 参数         | 类型  | 必填 | 默认   | 说明               |
| ---------- | --- | -- | ---- | ---------------- |
| `file_ref` | str | ✅  | —    | ELF 相对路径         |
| `name`     | str | ❌  | `""` | 指定导入；空 = 列全部危险导入 |

**返回**

* 文件缺失 → `ok=False`。

* `name` 指定：无该导入 → `ok=True, "无导入 '<name>'"`；命中 → 该导入的调用点。

* 无 `name`：危险导入按级别 high>medium>low 排序。

**危险导入表**（级别）：

* high：`system, popen, execve, execv, execl, execlp, execvp, execle, strcpy, strcat, stpcpy, sprintf, vsprintf, gets`

* medium：`scanf, sscanf, vscanf, setuid, setgid, seteuid, setegid, chmod, fchmod, chown, dlopen, dlsym`

* low：`rand, srand, socket, bind, listen, accept, connect`

**data 结构**：`[{name, level, ref_count, call_sites: [str]}]`

***

### find\_decompiled\_function —— 切片反编译函数

**位置**：`providers/tools/find_decompiled_function.py`

| 项    | 值                               |
| ---- | ------------------------------- |
| name | `find_decompiled_function`      |
| 用途   | 从已反编译的 `.c` 里切出单个函数（不重跑 Ghidra） |

**参数**：`file_ref`（str，必填）、`func_name`（str，必填，Ghidra 命名：真实符号或 `FUN_<8位hex>`）。

**返回**

* `.c` 缺失 → `ok=False`（"不触发重分析"）。

* 函数不在 → `ok=False`，附前 30 个函数名 + 提示改查 functions.json 按 callees 反查。

* 命中 → `ok=True`, text=函数体, data=`{"func_name", "file"}`。

> xref\_query 返回的 r2 命名（fcn.\<hex>/mangled）不能直接传，需先经 functions.json 反查（错误研究 E1 落地）。

***

### xref\_query —— radare2 交叉引用

**位置**：`providers/tools/xref_query.py`

| 项    | 值                                                    |
| ---- | ---------------------------------------------------- |
| name | `xref_query`                                         |
| 用途   | 沙箱内 r2 查符号交叉引用（`axtj` JSON），补 Ghidra call\_sites 空盲区 |

**参数**：`file_ref`（str，必填）、`symbol`（str，必填，如 `sym.imp.system`）。

**行为**

* 符号无 `sym./fcn./sub.` 前缀 → 自动补 `sym.imp.`。

* r2 命令：`-q -A -e bin.relocs.apply=true -c "axtj <sym>" <path>`，timeout=180。

* 判定以 stdout JSON 解析为准（r2 退出码不可靠）。

**返回/错误**

* 数据符号（OBJ）查询 → `ok=False`，提示改 strings\_query/functions.json（"Invalid argument" 检测）。

* 无输出/无法解析 → `ok=False, "r2 无输出"`。

* 无交叉引用 → `ok=True, "无交叉引用"`, data=\[]。

* 命中 → `ok=True`, data 为 r2 axtj 数组。

**data 结构**：r2 axtj 字段（`from/fcn_name/type` 等）。

> `_parse_r2_json` 用括号深度配平（字符串感知）解析跨行 JSON 数组（aarch64 WARN 后输出 pretty 多行数组的实坑）。

***

### checksec —— ELF 保护属性

**位置**：`providers/tools/checksec.py`

| 项    | 值                                        |
| ---- | ---------------------------------------- |
| name | `checksec`                               |
| 用途   | 查 ELF 的 RELRO/Canary/NX/PIE/Fortify 保护属性 |

**参数**：`file_ref`（str，必填）。

**返回**

* 容器失败 / 输出非 JSON → `ok=False`。

* 成功 → `ok=True`, text=`file_ref: relro=.. canary=.. nx=.. pie=.. fortify=.. symbols=..`, data=属性 dict。

**防护缺陷可利用性**：NX 关闭 + 无 PIE → 上调风险（由 LLM 评估）。

***

### binwalk\_rescan —— binwalk 签名复扫

**位置**：`providers/tools/binwalk_rescan.py`

| 项    | 值                                            |
| ---- | -------------------------------------------- |
| name | `binwalk_rescan`                             |
| 用途   | 对不透明 `.bin`/固件段做 binwalk 签名复扫，识别嵌套容器（只识别不落盘） |

**参数**：`file_ref`（str，必填，相对 extracted 根）。

**行为**

* 用 `binwalk` 专用镜像（sandbox pip 版停更；跨镜像复制缺 GLIBC 2.39，均已定案放弃）。

* 命令：`binwalk <file>`，挂载 extracted 只读，timeout=300，network=none。

* 路径越界防护。

**返回**

* 镜像不可用 → `ok=False`。

* 无签名命中 → `ok=True, "...无签名命中"`, data=\[]。

* 命中 → `ok=True`, text 前 40 行签名表, data=`{"image", "output"}`。

***

### gitleaks\_scan —— 硬编码密钥扫描

**位置**：`providers/tools/gitleaks_scan.py`

| 项    | 值                                                        |
| ---- | -------------------------------------------------------- |
| name | `gitleaks_scan`                                          |
| 用途   | 扫 extracted/ 下硬编码密钥/凭据（API Key/私钥/DB 凭据/OAuth token/JWT） |

**参数**：`path`（str，❌，默认 `"."`，相对 extracted 根；`"."` = 扫全树）。

**行为**

* 命令在单容器内 `detect --no-git --source <cpath> --report-format json --report-path /tmp/... --exit-code 0; echo __RC__; cat 报告`（两次 run 的 /tmp 不共享）。

* 用 `-c` 字符串拼 shell（纯字符串拼接，不用 .format——`${rc}` 会被误当占位符）。

**返回/错误**

* shell 失败 → `ok=False`。

* gitleaks 退出码非 0（真实错误）→ `ok=False`。

* 无发现 / `null` / `[]` → `ok=True, "未发现硬编码密钥"`, data=\[]。

* 报告非 JSON / 结构异常 → `ok=False`。

* 命中 → `ok=True`, text 前 60 条 `[规则] 文件:行 掩码密钥`, data 前 200 条。

**data 结构**：`[{rule, file, line, secret}]`

***

### semgrep\_scan —— 脚本语义漏洞扫描

**位置**：`providers/tools/semgrep_scan.py`

| 项    | 值                                                                |
| ---- | ---------------------------------------------------------------- |
| name | `semgrep_scan`                                                   |
| 用途   | 对 extracted/ 下脚本/源码跑语义级漏洞匹配（命令注入/SQL注入/反序列化），补齐 Step4 只做字符串扫描的缺口 |

**参数**：`path`（str，❌，默认 `"."`）。

**行为**

* 本地规则 `rules/semgrep_security.yaml`（离线可用，不依赖 `p/` 网络规则）。

* 命令：`semgrep --config <rules> --json --quiet --no-git-ignore [--exclude SDK路径...] <cpath>`，timeout=300。

* SDK 排除：`sdk_exclude_flags()`（usr/local/lib 等，防 stdlib python 噪音）。

* 退出码：1=有命中，0=无，>1=错误。

**返回**

* 规则缺失 → `ok=False`。

* 退出码 >1 → `ok=False`。

* 无结果 → `ok=True, "未命中疑似脚本漏洞"`, data=\[]。

* 命中 → `ok=True`, text 前 60 条去重 `[severity] file:line check_id` + message, data 前 200 条。

**data 结构**：`[{check_id, path, line, severity, message}]`

***

### cve\_bin\_tool\_scan —— 已知 CVE 匹配

**位置**：`providers/tools/cve_bin_tool_scan.py`

| 项    | 值                                |
| ---- | -------------------------------- |
| name | `cve_bin_tool_scan`              |
| 用途   | 容器内 cve-bin-tool 按产品版本特征匹配已知 CVE |

**参数**：`file_ref`（str，必填，可单文件或目录）。

**行为**

* CVE 库**不烘镜像**：宿主 `process/.cve_cache` 卷挂载复用（见下方"预热"）。

* 命令：`cve-bin-tool --quiet --format json -o - --offline --disable-version-check --disable-data-source PURL2CPE <cpath>`，timeout=900。

* 参数依据：`--disable-data-source PURL2CPE` 防 3.4 建库崩（`no such table: purl2cpe`）；`--disable-version-check` 防无外网崩；`--offline` 跳增量更新；`-o -` 让 JSON 到 stdout（3.4 默认写文件）。

**返回/退出码**

* `rc >= 2 或 124` → `ok=False, "cve-bin-tool 失败(码 N)"`。

* 输出为空（0 命中时 `-o -` 无输出）→ `ok=True, "无已知 CVE 命中"`, data=\[]。

* 输出非空但解析失败 → `ok=False, "输出无 JSON"`。

* 命中 → `ok=True`, text 每条 `产品 版本 → CVE [严重度]`, data=命中列表。

**data 结构**：`[{product, version, cve_number, severity, ...}]`

### ⚠️ CVE 库预热（关键前置）

* **库位置**：宿主 `target/<N>/process/.cve_cache/cve-bin-tool/cve.db`（3.4 的缓存根是 `$HOME/.cache/cve-bin-tool/`）。

* **挂载**：工具把整块 `process/.cve_cache` 挂到容器 `$HOME/.cache`（`CVE_CACHE_MOUNT = "/home/sandbox/.cache"`），让 cve-bin-tool 自己管理 `cve-bin-tool/` 子目录。

* **预热命令**（需带目录参数 + 挂父目录，缺一即失败）：

```powershell
docker run --rm --entrypoint cve-bin-tool `
  -v "target\1\process\.cve_cache:/home/sandbox/.cache" `
  firm_audit/sandbox:latest -l info `
  --disable-version-check --disable-data-source PURL2CPE -u now /tmp
```

* 三个已踩坑：① 缺 `/tmp` 目录参数 → `InsufficientArgs`(码24，仅跑 `-u now` 时)；② 挂到 `~/.cache/cvedb`（旧约定）→ 库永远找不到（码40 `Database does not exist`）；③ 把 `cve-bin-tool` 目录本身当挂载根 → 清空时 `Device or resource busy`。

* 首次全量下载 NVD+GAD+RedHat+OSV（约 15-40 分钟），之后 `--offline` 直接用。

***

### cve\_lookup —— NVD 详情查询

**位置**：`providers/tools/cve_lookup.py`

| 项    | 值                                       |
| ---- | --------------------------------------- |
| name | `cve_lookup`                            |
| 用途   | NVD REST API 2.0 查 CVE 详情（CVSS/描述），补证据链 |

**参数**（二选一，优先 `cve_id`）

| 参数        | 类型  | 必填 | 说明                               |
| --------- | --- | -- | -------------------------------- |
| `cve_id`  | str | ❌  | 形如 `CVE-2024-1234`（必须 `CVE-` 开头） |
| `keyword` | str | ❌  | 关键词搜索                            |

**行为**

* 无 key 限 5 req/30s → 进程内节流（`_throttle`）。

* 结果落盘缓存 `process/.cve_cache/nvd_<md5>.json`（幂等，同参同果）。

* 失败（网络/限速）→ `ok=False, "NVD 查询失败"`。

* 有 `NVD_API_KEY` 环境变量时禁用节流、带 apiKey 头。

**返回**：`ok=True` + text（CVSS/描述，前 10 条）或 "NVD 无记录"。

***

### sandbox\_verify —— 沙箱复核脚本执行

**位置**：`providers/tools/sandbox_verify.py`

| 项    | 值                                                 |
| ---- | ------------------------------------------------- |
| name | `sandbox_verify`                                  |
| 用途   | verification 在隔离沙箱执行复核脚本（python/node/php）动态验证疑似漏洞 |

**参数**

| 参数         | 类型  | 必填 | 默认       | 说明                                                 |
| ---------- | --- | -- | -------- | -------------------------------------------------- |
| `code`     | str | ✅  | —        | 脚本源码                                               |
| `language` | str | ❌  | `python` | `python/py/python3` 或 `node/js/javascript` 或 `php` |
| `timeout`  | int | ❌  | `60`     | 秒（上限强制 180）                                        |

**返回**

* code 空 / >64KB / language 不支持 → `ok=False`。

* `rc=0` → `ok=True`, text=输出, data=`{"exit_code": 0}`。

* 非零退出 → **仍** **`ok=True`**（脚本崩溃也是证据，交 LLM 归类），text 前缀 `[退出码 N]`, data=`{"exit_code": rc}`。

**安全约束**：只走白名单解释器（无任意 shell）；extracted 只读；网络隔离；超时受 run\_docker 限制。

***

### web\_search —— 公开漏洞/公告检索

**位置**：`providers/tools/web_search.py`

| 项    | 值                                                     |
| ---- | ----------------------------------------------------- |
| name | `web_search`                                          |
| 用途   | DuckDuckGo HTML 检索（免 key）公开漏洞/厂商公告，佐证分析线索；复用 NVD 节流策略 |
| 归谁   | analysis（仅此一个阶段）                                      |

**参数**：`query`（str，必填，检索关键词）。

**返回**：检索结果摘要 `ok=True`（无结果时如实降级，不顶替记忆）；失败 → `ok=False`。**证据纪律**：检索结果只是线索，不能直接写进 finding 的 evidence。

***

### 工具群一览表（Step5）

| 工具                         | 数据源                      | 走容器？                  | 反编译/扫描 | 核心价值             |
| -------------------------- | ------------------------ | --------------------- | ------ | ---------------- |
| list\_files                | process/ 目录树             | 否                     | 读盘     | 目录/文件枚举（SDK 排除）  |
| search\_code               | analysis/*.json + extracted | 否                     | 读盘     | 按内容混合检索（边车索引+文本 grep） |
| read\_file                 | 任意 process/ 工件           | 否                     | 读盘     | 分页回查 / 路径白名单     |
| strings\_query             | analysis/\*.strings.json | 否                     | 读盘     | 硬编码字符串 + refs 函数 |
| imports\_query             | analysis/\*.imports.json | 否                     | 读盘     | 危险函数 + 调用点       |
| find\_decompiled\_function | analysis/\*.c            | 否                     | 读盘     | 切片反编译函数          |
| xref\_query                | 原始 ELF                   | sandbox(r2)           | 二进制    | 交叉引用定位调用者        |
| checksec                   | 原始 ELF                   | sandbox               | 二进制    | 保护属性/可利用性        |
| semgrep\_scan              | extracted/ 脚本            | sandbox(semgrep)      | 源码     | 语义级脚本漏洞          |
| gitleaks\_scan             | extracted/               | sandbox(gitleaks)     | 源码     | 硬编码密钥            |
| cve\_bin\_tool\_scan       | ELF/目录                   | sandbox(cve-bin-tool) | 二进制    | 已知 CVE 匹配        |
| cve\_lookup                | NVD API                  | 否                     | HTTP   | CVE 详情/CVSS      |
| binwalk\_rescan            | 原始 .bin                  | binwalk 镜像            | 二进制    | 嵌套容器签名           |
| sandbox\_verify            | 用户脚本                     | sandbox               | 执行     | 动态验证 PoC         |
| web\_search                | DuckDuckGo HTML          | 否                     | HTTP   | 公开漏洞/公告检索        |

***

### 编排层工具（`orchestration/actions.py`，不在 providers/tools 注册表）

Orchestrator 自己的 ReAct 循环只暴露这 3 个动作，与子 Agent 的 15 个工具互不共享：

| 工具               | 参数                                | 用途                                                                             | 守卫/行为                                                                                                                                                                     |
| ---------------- | --------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dispatch_agent` | `agent`（必）、`task`（必）、`context`（选） | 同步调度某个子 Agent（recon/analysis/verification）                                     | ①未知 agent 拒绝；②顺序门：严格单向 recon→analysis→verification（跳序/回退拒绝）；③类型+任务唯一性：同任务返回历史结果（防重复）；④同类型最多 3 次（1 次默认 + 至多 2 次补跑），超出拒绝；⑤上游工件缺失拒绝。断点续跑：`.json` 工件存在 → skipped。Observation 尾部附该类型 `budget_state`（exhausted/steps/max_iters/pending_count/pending_focuses/overlap_ratio）；analysis 预算耗尽且有未覆盖疑点时附补跑建议（task 与已覆盖项差分）。返回 `ToolResult(ok/text/error)` |
| `summarize`      | `conclusion`（选）                   | 只读汇总：累计 findings 清单 + 各阶段统计（status/steps/usage）+ 各 Agent `budget_state` + verification 已复核明细 = 最终报告写作素材 | 不消耗子 Agent 调度额度；verification 完成后调用，Final Answer 即报告正文                                                                                                                     |
| `finish`         | `conclusion`（选）                   | 声明编排完成，提示输出 Final Answer                                                       | 仅提示，收尾由协调器 LLM 完成                                                                                                                                                         |

> STATUS 值域（DispatchStatus）：`running / success / skipped / degraded（仅 .md 工件，默认复跑）/ failed / interrupted（异常传播回填）/ rejected（守卫拒绝）/ duplicate（唯一性拒绝）`。

***

### Agent × 工具权限矩阵（v3,2026-08-29）

| Agent            | 工具数 | 可用工具                                                                                                                                                                 | max\_iters | 输出工件                                                                     |
| ---------------- | --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------ |
| **recon**        | 6   | `list_files` `read_file` `cve_bin_tool_scan` `semgrep_scan` `gitleaks_scan` `binwalk_rescan`                                                                         | 20         | `survey.json`（v3：枚举铺面不下钻二进制、不判级）                                       |
| **analysis**     | 12  | `list_files` `search_code` `find_decompiled_function` `xref_query` `strings_query` `imports_query` `read_file` `cve_lookup` `checksec` `semgrep_scan` `gitleaks_scan` `web_search` | 30（2026-08-29 由 24 上调） | `findings.json`（候选漏洞 + 证据链）                                                     |
| **verification** | 10  | `list_files` `search_code` `find_decompiled_function` `xref_query` `cve_lookup` `checksec` `read_file` `strings_query` `imports_query` `sandbox_verify`                            | 24         | `verified_findings.json`（唯一产物；不产报告）                                            |
| **orchestrator** | 3   | `dispatch_agent` `summarize` `finish`                                                                                                                                | 12（ORCH\_MAX\_ITERS） | `orchestrator/{transcript,dispatch_log,handoff_*,report.md,result.json}` |

* recon **不含** `strings_query`/`imports_query`/`checksec`（深挖归 analysis/verification；v3 收敛）。

* **recon 输出为 v3 survey 工件**（schema_version=3）：`arch_snapshot`（top_level_dirs / components_grouped〔name+size，role 推断必附 role_evidence〕 / os_or_runtime）+ `components`（只收 cve_bin_tool_scan Observation 实况）+ `entry_points` + `high_risk_areas`（观察点，无判级）+ `recommended_actions`（priority+action）+ `summary`；**禁止** findings 数组与任意层级 severity/confidence/verified/evidence/rationale（解析层守护，违规键降级为 high_risk_areas 观察点）——判级与证据链移交 analysis。v2 兼容层已于 2026-08-29 移除：只认 `survey.json` 命名，不回退旧 `attack_surface.json`。

* analysis 无 `sandbox_verify`（动态验证只在复核阶段）。

* verification 无 `web_search`/`cve_bin_tool_scan`/`semgrep_scan`/`gitleaks_scan`/`binwalk_rescan`（扫描类归前两阶段，只复核）。

* 守护测试 `tool_permissions_and_threshold` 断言该矩阵精确匹配。

***

## Step5 引擎与编排

### 协议解析 `engine/protocol.py`

* `parse_reply(reply)` → `(kind, payload)`，`kind ∈ {"action", "final", "fail"}`。

* 宽容处理：合法 JSON 后尾随散文（`_extract_leading_json` 花括号配平救回）、XML 角括号漂移（`_normalize_tags`）。

### ReAct 循环 `engine/react_loop.py`

| 项  | 值                                                                                               |
| -- | ----------------------------------------------------------------------------------------------- |
| 入口 | `run_react_agent(llm, tools, system_prompt, init_obs, max_iters, transcript, context, display)` |
| 返回 | `ReactResult{final_answer, steps, tool_calls, finished}` / `.ok`（finished 且 final\_answer 非空）   |

**循环守卫**：

* `MAX_PARSE_FAILS`（协议解析失败容忍，超限强制收尾）

* `MAX_NO_TOOL_REJECTS`（零工具 Final 拒绝）

* `MAX_REPEAT_CALLS`（同参循环调用拦截）

* 每轮进度注入（`ROUND_PROGRESS`，max\_iters 不写死）

* 最后一轮 `LAST_ROUND_NOTICE` + 强制收尾 `_force_final_round`

**Observation**：截断 ≤8KB + 全文落盘 `process/agent/<name>/obs/step<N>_<tool>.txt`，截断时附回读路径提示。

### ContextManager（四分区上下文）`engine/context.py`

* 区块：system prompt（不压缩）+ 任务简报 + summary 区 + retention 区（近 K 轮）。

* 超阈值（默认 600k token，60% 窗口）自动压缩旧轮次。

### 编排 `orchestration/` 包 + `runner.py`

* `AgentConfig{name, system_prompt, tool_names, output_name, max_iters, model, build_brief, label}`。

* 三个子 Agent（仅配置不同，**非子类**）：

  * `recon` → `survey.json`（v3 survey 工件，无 findings/判级字段；max\_iters=20，6 工具）

  * `analysis` → `findings.json`（max\_iters=30（2026-08-29 由 24 上调），12 工具）

  * `verification` → `verified_findings.json`（max\_iters=24，10 工具）

* `run_agent(cfg, process_dir, base_llm, upstream, output_dir, extra_brief)` → `AgentRunResult`（异常不抛，记入 error）；`output_dir` 由 orchestrator 按 `<seq>_<type>` 指定，`extra_brief` 注入交接块。

* **`Orchestrator`（v3）**：轻量 LLM 驱动编排层，ReAct 循环用 `dispatch_agent`/`summarize`/`finish` 三动作，硬守卫见"编排层工具"节。签发：只认 `.json` 工件断点续跑（`.md` 降级 → `degraded` 默认复跑）；严格单向顺序门；类型+任务唯一性；同类型最多 3 次。动态分配（2026-08-29）：每实例 `budget_state`（exhausted/steps/max\_iters/pending\_count/pending\_focuses/overlap\_ratio）进 summarize 与 dispatch 的 Observation、`dispatch_log.json`（逐实例）及 `result.json`（`budget` 各类型汇总）；`pending_focuses` = recon recommended\_actions（high/medium）∩ 未被 findings 覆盖的疑点（title/file 差分）；analysis 预算耗尽且仍有未覆盖疑点且调度次数<3 时给补跑建议，补跑简报追加已覆盖清单（前 30 条）+ 差分 task。

* **报告（v3 生成主体 = orchestrator）**：verification 完成后调用 `summarize` 取素材 → Final Answer 即报告正文，**原样落盘** **`orchestrator/report.md`**（含可解析 JSON 时另存 `report.json` 副产品）。`render_report` 已删除（2026-08-28），报告缺失时 `step5_run` 明确告警不静默降级。

### AgentRunResult

```python
@dataclass
class AgentRunResult:
    cfg: AgentConfig
    artifact_path: Path | None
    react: ReactResult | None
    usage: dict
    skipped: bool
    error: str
    # ok = skipped or (artifact_path 非空且无 error)
```

### 入口 `run_step5.py`

* `step5_run(workspace, force=False, llm=None)`：走 `Orchestrator` 编排（dispatch×3 → summarize → 报告落盘）——唯一路径（ADR-0006:pipeline 快速模式已删）。

* 断点续跑：`.json` 工件存在 → `skipped`；仅 `.md` 降级 → `degraded` 默认复跑（`STEP5_RESUME_DEGRADED=0` 恢复旧跳过语义）。

* `--force` 强制三 Agent 重跑。

* main.py 不传 force 给 Step5（环形续跑始终命中）；要重跑 Step5 用本入口 `--force`。

* 报告缺失（未 summarize 或 Final Answer 为空）→ 明确告警，`result.json` 完整保留 findings 与阶段统计供补跑。

### 领先提示词 `data/prompts.py`

* `build_recon_brief` / `build_analysis_brief` / `build_verify_brief`：各 Agent 的任务简报（含 `analysis/` 边车索引、`build_filtered_overview` 过滤目录概览、上游工件**实际路径**动态注入）。v3 survey 摘要（entry_points/high_risk\_areas/recommended\_actions/components 划重点）由 recon 简报与 analysis 上游摘要共用；analysis **补跑**（上游为前次 findings.json）时简报额外携带同一份 recon 摘要 + 已覆盖清单 + 差分 task（orchestrator 经 `extra_brief` 注入）。

* `build_system_prompt`：基础系统提示 + 工具自我介绍（description + params\_doc）+ 迭代预算段。

* 共享积木块：`ANALYSIS_DIR_DOC`（工作区锚点）/`REACT_PROTOCOL`（输出协议）/`AGENT_DISCIPLINE`（纪律）/`FINDING_SCHEMA_DOC`+`schema_with()`（Final Answer schema）；三 Agent 的 SYSTEM 是 f-string 组合体。

***

## 附录：跨阶段工件链

```
process/
  extracted/                  原始解包树（Step1/0），只读
  fileinfo.json               Step2+3 汇总（FileInfo 列表）
  analysis/<rel>.{c,*.json}   Step4 Ghidra/文本/证书产物
  agent/
    <seq>_<type>/             子 Agent 实例目录（如 0_recon/、1_analysis/）
      survey.json             recon 输出（Step5 v3；v2 兼容层已移除，只认 survey.json）
      findings.json           analysis 输出（Step5）
      verified_findings.json  verification 输出（Step5）
      transcript.jsonl        ReAct 运行记录（Step5）
      obs/step<N>_<tool>.txt  Observation 全文
    orchestrator/
      transcript.jsonl        编排 LLM 运行记录
      dispatch_log.json       全量调度史（含 rejected/duplicate/degraded）
      handoff_<seq>_<type>.json  交接快照（结构化）
      report.md               最终报告（summarize 产出，v3 主体）
      report.json             报告 JSON 副产品（可选）
      result.json             编排终态（findings+stages+dispatches）
  .cve_cache/                 CVE 库（预热 + cve_lookup 缓存）
  .step1_done                 解包完成标记
```

***

## 附录：FileInfo 数据模型

| 字段                | 类型   | 填充   | 含义                               |
| ----------------- | ---- | ---- | -------------------------------- |
| `path`            | str  | S3   | 原始绝对路径                           |
| `rel_path`        | str  | S3   | 相对解包根                            |
| `type`            | str  | S3   | 分类类型                             |
| `size`            | int  | S3   | 字节数                              |
| `subtype`         | str  | S3   | file 命令原始输出                      |
| `is_system_trust` | bool | S3   | 系统信任库标记                          |
| `arch`            | str  | S4   | arm64/x86\_64                    |
| `decompiled_path` | str  | S4   | 反编译 .c 路径                        |
| `analysis_path`   | str  | S4   | analysis/ 目录                     |
| `ghidra_status`   | str  | S4   | pending/ok/failed/skipped        |
| `audit_status`    | str  | S5   | pending/passed/suspicious/failed |
| `findings`        | list | S4/5 | 发现项                              |


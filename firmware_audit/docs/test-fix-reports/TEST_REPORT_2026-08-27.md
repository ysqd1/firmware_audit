# firmware_audit 全面测试报告与 Bug 记录（2026-08-27）

范围：功能 / 兼容 / 性能 / 安全四类测试；对每个 Bug 记录复现、预期、实际、严重度，给出根因与修复，并回归验证。

测试环境：Windows，Python 3.12.7，pytest；Step5 编排使用 ScriptedLLM 注入（零 API、零 Docker）。

---

## 一、基线

- 修复前三套件：`python -m pytest test -q` → **147 passed, 10 skipped**（2 warnings：step0 tar 提取 DeprecationWarning）。
- 修复后：**153 passed, 10 skipped**（新增 `test_security_hardening.py` 6 用例，无 warning）。

---

## 二、Bug 记录

### Bug-1：步骤分析工具可任意读宿主文件（路径越界读）

- **严重程度**：高（安全 / 任意文件读取）
- **涉及**：`step5_agent/providers/tools/base.py::resolve_analysis_file`
- **复现步骤**
  1. 构造含 `process/analysis/...` 之上存在文件的临时工作区（如 `process 上级/host_secret.json`）。
  2. 调用 `resolve_analysis_file(ctx, "../host_secret", ".json")` 或传入绝对路径 `/etc/passwd`。
- **预期结果**：越界/绝对路径应被拒绝（返回 `None`）。
- **实际结果**：绝对路径原样返回并 `.exists()` 通过；`../` 未被包含性校验，工具 `read_text` 读到了 `analysis/` 之外的文件 → 信息泄露。
- **根因分析**：`resolve_analysis_file` 仅 `Path(ref).is_absolute()` 时直接返回，且普通分支 `ctx.process_dir/"analysis"/(ref+suffix)` 未做 `.resolve()` 后包含性校验，`..` 可逃逸到宿主任意 `.json/.c` 文件。
- **修复方案**：解析后强校验必须位于 `process/analysis/` 之下（`resolve` 后 `base not in parents → None`），移除绝对路径放行逻辑。
- **回归验证**：`test_security_hardening.py::test_resolve_analysis_blocks_escape`（相对 `../`、绝对路径、根路径均返回 `None`；正常相对路径仍解析成功）。

### Bug-2：归档解压 zip-slip / tar-slip 越界写

- **严重程度**：高（安全 / 任意文件写入）
- **涉及**：`step0/step0_preprocess.py::_decompress_archive`
- **复现步骤**
  1. 构造含条目 `../../evil.txt`（或绝对路径 `../abs`）的 zip/tar。
  2. 调用 `_decompress_archive` 解压到 `dest`。
- **预期结果**：全部内容写入 `dest` 内；越界项被拒绝。
- **实际结果**：`zipfile.ZipFile.extractall` / `tarfile.extractall` 把 `../../evil.txt` 写到 `dest` 之外（zip-slip/tar-slip），检测固件为不可信外部输入时即为任意写；同时触发 Python 3.14 tar 提取弃用告警。
- **根因分析**：直接使用标准库高风险 `extractall`，未校验成员名是否包含 `..`、绝对路径或符号链接逃逸。
- **修复方案**：改为流式安全提取——逐成员校验（绝对路径 / `..` / `is_relative_to` 越界 / zip 符号链接 / tar symlink/hardlink 一律跳过），逐个写出。
- **回归验证**：`test_security_hardening.py` 的 `test_zip_slip_blocked` / `test_tar_slip_blocked` / `test_preprocess_fallback_on_bad_archive`（越界项不落盘、正常项照常解出、`preprocess` 仍成功不崩）。

### Bug-3：gitleaks 扫描 shell 命令注入

- **严重程度**：中（安全 / 沙箱内命令注入；防御加固）
- **涉及**：`step5_agent/providers/tools/gitleaks_scan.py`
- **复现步骤**
  1. `container_path` 返回 `/work/extracted/<path>`，未对 shell 元字符做处理。
  2. 当 `path` 含 `;`、`$()`、`` ` `` 等（恶意固件目录名或被污染的 Agent 参数）时，拼接进 `sh -c "gitleaks ... --source <path> ..."`。
- **预期结果**：source 作为单一安全路径参数传入。
- **实际结果**：未转义字符串拼接进 `sh -c`，元字符可被当成 shell 命令执行。
- **根因分析**：gitleaks 因「两次容器 /tmp 不共享」选择单容器 `sh -c` 一次性 detect+cat，但拼接路径未做 shell 转义。
- **修复方案**：抽出 `build_gitleaks_cmd(source)`，用 `shlex.quote` 对 source 转义。
- **回归验证**：`test_security_hardening.py::test_gitleaks_cmd_quotes_source`（恶性元字符被单引号包裹、良性路径保持原样）。

---

## 三、各维度结论

### 功能测试
- 全链路：Orchestrator（recon→analysis→verification）→ 工件 → report 全部通过。
- 工具/触发层/上下游简报/断点续跑/误报分节报告：既有用例全绿。

### 兼容性测试
- 本项目唯一实测解释器 **Python 3.12.7（Windows）**；新增安全代码仅用 `Path.is_relative_to`（3.9+），全部可用。
- `STEP5_DISPLAY` / `STEP5_COLOR` / `STEP5_EXCLUDE_TOOLS` 环境变量矩阵由 `test_step5_display.py` 覆盖，全绿。
- tar 提取弃用告警随 Bug-2 修复一并消解（不再用 `extractall`，弃用路径无关）。

### 性能测试
- 长会话压缩：`test_compact_at_600k_threshold`、`test_compaction_boundary_and_failure` 通过（软阈值对齐、压缩失败还原）。
- 大文件截断：`truncate_text` 头尾保留 + 全文落盘回归通过。
- 安全解压性能探针：2000 条目 tar ≈ 2.5s（≈1.2ms/条目），无病理性回退。
- Orchestrator 集成用例耗时毫秒级（ScriptedLLM 注入）。

### 安全测试
- 修复 3 个安全缺陷：analysis 路径越界读、zip/tar-slip 越界写、沙箱内 shell 注入。
- `read_file` 既有白名单/越界守卫复核通过；CLI 类工具走容器断网 + `:ro` 挂载基线复核无新增风险点。

---

## 四、最终交付状态

- `python -m pytest test -q`：**153 passed, 10 skipped**（修复前三套件未破坏任何既有行为）。
- 三处修复均符合项目规范（引用既有 `..`/绝对路径清理约定、失败不崩、测试回落 `test_main` 约定）。
- 新增回归测试：`test/test_security_hardening.py`（6 用例）。
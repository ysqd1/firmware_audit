# 代码规范

## 铁律

1. **包可跑** — `python -m firmware_audit.main <target_dir>` 一行启动,不装一堆依赖
2. **LLM 必需(Step5)** — Step1-4 纯代码;Step5 无 API key 或 API 调用失败时**立即终止,不降级**([ADR-0002](./docs/adr/0002-step5-no-key-hard-stop.md))
3. **同步为主** — 不用 asyncio,顺序执行,清晰优先
4. **失败不崩** — 任何步骤失败降级兜底,继续往下跑,记录失败原因
5. **输入目录即工作区** — `target/<N>/` 既是输入也是产出目录,固件和 process/(extracted/ analysis/) 共处
6. **工具用 Docker** — binwalk/ghidra 走容器,宿主机只跑 Python
7. **分类用 file 硬编码** — 不用 LLM 看文件头,快、准、稳
8. **Agent 层按需求文档推进** — 架构现状:LLM orchestrator 编排三 Agent(recon→analysis→verification),`orchestrator.py` 调度、顺序门单向([ADR-0001](./docs/adr/0001-step5-orchestrator.md);需求文档为 2026-08-16 快照)
9. **路径用 pathlib** — 跨平台,不用字符串拼路径
10. **日志清晰** — 每步打印进度和统计,失败要可追溯

## Agent 层约定(2026-08-16 新增,08-17 随工具层定稿更新)

- **工具统一 ToolResult 接口**(2026-08-17 定稿)— 三类实现:CLI 类 subprocess 调容器内 CLI(checksec/cve-bin-tool/radare2 等)、读盘类直读 Step4 工件(find_decompiled_function/strings/imports/read_file)、API 类 urllib(cve_lookup);返回 `{ok, text, data, error, elapsed, raw}`,text ≤16000 字符截断(2026-09-06 票01 由 8KB 上调;基类 `max_text_chars` 可按工具覆盖,summarize 素材护栏 64000)
- **幂等与超时** — 同参同果(cve_lookup 以缓存快照为准);每工具可配超时
- **分析一次、多次查询** — 复用 Step4 工件(functions/imports/strings),不重复反编译
- **漏斗式调用** — 廉价工具批量跑(读盘类毫秒级),昂贵操作(Ghidra 重分析/仿真)按触发条件深挖;单函数反编译是读盘切片,不再昂贵

## 禁止

- 不引入 FastAPI / 数据库 / Redis / 前端
- RAG / 向量库 / embedding 暂不做(留待以后,现在还早)
- 不做事件总线 / 流式输出
- Agent 抽象只做必要一层,不引入 agent 框架 / 多 Agent 编排
- 不提取 P-code 喂 LLM
- 不把反编译产物写进源目录(extracted/ 只读,产物进 analysis/)
- 不创建不必要的类和抽象
- 不在 target/<N>/ 之外创建任何产出文件
- 零第三方依赖的唯一例外:Step4 证书解析用 cryptography(可选依赖,缺库降级跳过,不装也能跑)

## 风格

- 函数短小,一个函数干一件事
- 注释写"为什么",不写"是什么"
- 配置(白/黑名单、危险函数表)集中放文件顶部或单独 config
- 报告用 Markdown,证据要含文件路径 + 行号 + 代码片段
- Jython 脚本(ExtractInfo.py)用 Python 2 语法,文件写入用 `io.open(encoding="utf-8")`
- 目录约定:`firmware_audit/step{1-5}/` 放步骤代码(Step5 为 `step5_agent/`,Agent 工具在其 `tools/` 子目录),`test/` 放单元测试,`docker/` 放 Docker 相关,`profiles/` 放固件机型名单;跨目录用相对导入(`from ..step2.step2_filter import ...`)
- 给 TRAE 修改 ExtractInfo.py(Jython)的任务,必须要求其**重建镜像 + 容器内实跑单个 ELF 自测**——Ghidra Jython API 的坑(如 `isString()`/`DataDB` 映射)只有真跑容器才暴露,单元测试覆盖不到

## 已知坑

- **deepseek-v4-flash 是推理模型**(2026-08-17 冒烟实测):回复分两个字段,思考在 `reasoning_content`、正文在 `content`;思考耗尽 max_tokens 时 content 为空(finish_reason=length)。LLMClient 只把正文给 ReAct 解析器(思考随 usage.reasoning_content 留档,见 08-30 拆分);max_tokens 默认 32768(ADR-0005,思考计入预算,思考烧满由截断续写兜底)。冒烟结论:协议遵循良好,5 步自主完成 imports→xref→decompile 链,单任务 ~10k token。
- **cve-bin-tool 3.4 的 PURL2CPE 源首跑必崩**:populate_purl2cpe 时 purl2cpe.db 未初始化,报 `OperationalError: no such table: purl2cpe`。必须 `--disable-data-source PURL2CPE`(cve_bin_tool_scan.py 已内置)。CVE 库首跑下载 NVD 数据较慢(无 key 限速),降级返回错误不崩。**预热 + 库挂载的坑**(2026-08-22 实测):库挂在宿主 `process/.cve_cache`,工具挂到容器 `$HOME/.cache`(父目录,非旧约定 `~/.cache/cvedb`——那是 3.4 找不到库报码 40 的根因);预热命令必须带目录参数(`-u now /tmp`,缺则 InsufficientArgs 码 24)且别把 `cve-bin-tool` 目录本身当挂载根(clear_cached_data 报 Device or resource busy)。详见 agents.md / tools_summary.md。

- **radare2 源码安装是"软链安装"(symstall)**:bullseye apt 无 radare2 包,源码 `sys/install.sh` 后 /usr/local 下的 bin/lib/pkgconfig 全是指向构建目录(/tmp/radare2)的符号链接;删构建目录前必须把软链解引用成真实文件,否则 449 个软链全部悬空、r2 报 command not found。安装全程见 docker/sandbox/Dockerfile,r2 固定 5.9.8 tag,capstone 下载用 `CS_COMMIT_ARCHIVE=1` 走 wget(直连 git clone 会被网络掐断)。
- **sandbox 镜像 ENTRYPOINT 是 Ghidra AnalyzeHeadless**:`firm_audit/sandbox` 调任何非 Ghidra 工具(checksec/radare2/cve-bin-tool/semgrep)必须用 `run_docker()` 的 `entrypoint` 参数覆盖,否则命令参数全部被 Ghidra 吃掉报 InvalidInputException(step0 调 sfdisk 同款模式)。镜像内 PATH 也被 Ghidra 覆盖过,Dockerfile 已显式补全,但 login shell(`bash -l`)会再次触发覆盖,容器内跑脚本用显式 `export PATH`。
- **semgrep 在 bullseye 沙箱锁定 1.100.0**(2026-08-17 实测):原 DeepAudit 镜像的 semgrep 是坏的(site-packages/semgrep/bin/ 混入 Windows DLL,Linux semgrep-core 从未存在)。重装版本边界:semgrep ≥1.101 的 Linux 预编译 wheel 是 manylinux_2_35(glibc 2.35),bullseye 是 glibc 2.31,pip 匹配不到 wheel 会退回 sdist 现场构建,但产物内 semgrep-core 仍需 glibc 2.35,运行即 "Failed to find semgrep-core";1.100.0 是最后一代 manylinux2014(glibc 2.17)平台 wheel,实测可用(本地规则扫描验证)。配套约束:必须带依赖装(不能 `--no-deps`,opentelemetry 链是运行时 import 硬依赖);先 pin `"setuptools<81"`(opentelemetry 依赖 pkg_resources,setuptools≥81 已移除);镜像里遗留的孤儿包 `opentelemetry-instrumentation-threading 0.58b0`(Required-by 为空)要卸载,否则 pip3 check 报版本冲突。安装见 docker/sandbox/Dockerfile,验证脚本 docker/sandbox/verify_agent_tools.sh(四工具+java/sfdisk/Ghidra 实跑全检,ALL-PASS 才算镜像可用)。
- **镜像压扁(export/import)的正确姿势与坑**(2026-08-17):增量层上删除文件不缩小镜像体积(下层白字节数据仍在),要真正减体积必须压扁。流程:回归 ALL-PASS 后 `docker create` + `docker export -o x.tar` + `docker import --change ...` 补元数据。实测:9.53GB 层叠镜像压扁后 5.1GB(历史层重复数据占了大半,远超删除项本身的 1.35GB)。三个坑:①PowerShell 下 `--change 'ENTRYPOINT ["x"]'` 的内层双引号被剥,ENTRYPOINT 变成 shell 形式,必须用 flatten-entrypoint.Dockerfile 的 JSON 语法补一层修正(零体积元数据层);②import 后全部 ENV 丢失,必须逐一补回(PATH 要同时剔除已删除的 cargo/go 段);③analyzeHeadless 的选项要空格分隔(`-analysisTimeoutPerFile 60`),`=` 形式会被当文件参数报 InvalidInputException。压扁后层缓存链失效:主 Dockerfile 是"完整配方"(下次从压扁 latest 重建会重跑全部 RUN 层约 10 分钟),日常加新工具建议用独立小 Dockerfile `FROM firm_audit/sandbox:latest` 只写新增层(**待办:latest 仍指向旧 9.53GB 镜像,压扁验证版在 `:flat` tag,切换命令待执行**)。
- **沙箱冗余工具链已删**(2026-08-17 用户确认):openjdk-11/17(apt purge,autoremove 只连带清了 libasound2/libcups2/libavahi/libnss3 等 JDK 专属依赖)、Rust(rustup:/usr/local/rustup + /usr/local/cargo)、Go(/usr/local/go)、gosec(/usr/local/bin/gosec)。删后裸 `java` 软链到 /opt/jdk-21 消除版本歧义(原来 alternatives 指向 17,而 Ghidra 走 JAVA_HOME=21,存在隐性分叉)。依赖核查结论:semgrep-core 是 OCaml 静态二进制、cve-bin-tool 是 Python,均不依赖 Rust/Go;Ghidra 11.3.2 只要 JDK 21。
- **binwalk 解包偶发 bug(可复现性差)**:binwalk 3.1.1 对同一固件两次解包可能得到**不同结果**。实测:同一 `nano14-backup-SANITIZED.tar.xz`(84MB,MD5 `8491aa15...`),一次解出正确 211MB tar(4721 条目,29 ELF),另一次解出**错误的 412MB 文件**(103 条目 + 200MB 垃圾数据),并多出 **853 个 hex 偏移目录**(如 `decompressed.bin.extracted/10012B3/pem.crt`,全是 binwalk 从垃圾数据里 carve 的 PEM)。`decompressed.bin` 大小是判据:正确值 = XZ 解开大小(宿主 `lzma.decompress` 可验证,211MB)。**binwalk 镜像本身没变**(7月29日构建),是 binwalk 运行时偶发不稳定。**影响**:解包层数/文件数/ELF 数都可能漂移,审计可复现性差。**对策**:审计前用宿主 lzma 验证固件 XZ 解开大小,异常解包结果(出现大量 hex 目录)要警惕,必要时重跑。
- **Ghidra 分析长尾**:大型共享库自动分析可能陷入无限循环,必须在 Ghidra 命令加 `-analysisTimeoutPerFile 300` 截断(空格分隔形式,`=` 形式会被当文件参数报 InvalidInputException,见压扁坑③),保证部分输出(functions/strings/imports)而非零产出。
- **Ghidra Jython API 坑**:`getDefinedStrings()` 不存在、`DataDB` 无 `isString()`,正确做法是 `getDefinedData(True)` + `getValue()` 返回 unicode + `isinstance(value, basestring)` 过滤。

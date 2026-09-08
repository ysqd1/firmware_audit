# 宇树固件审计 - firmware_audit

固件安全审计流水线:预解压/分区(Step0) → 解包(binwalk, Step1) → 过滤(白/黑名单, Step2) → 分类(Step3) → 反编译/提取(Ghidra, Step4) → LLM Agent 审计(recon→analysis→verification 三 Agent ReAct 编排, Step5)。

## 环境要求

- **Linux 原生或 WSL2**(2026-09-07 起的主验证环境:Kali / Ubuntu 24.04,测试基线见下);Windows 宿主可直接跑,但小文件 IO 显著慢(Defender/9P),且需注意控制台编码(代码已内建 UTF-8 容错)
- Python 3.10+(实测 3.13)
- Docker 可用(binwalk / ghidra / sandbox 三个容器)
- 运行时依赖:

```bash
pip install -r firmware_audit/requirements.txt
```

- 跑测试另需 pytest(`pip install pytest` 或系统包 `python3-pytest`)

> **WSL2 部署速览**(在 WSL 里跑时):①项目放发行版原生 ext4(如 `~/fw`),**不要放 `/mnt/...`**(9P 跨界 IO 慢 10-100 倍);②`/etc/wsl.conf` 建议写 `[user] default=<你的用户>`,否则 Windows 侧经 `\\wsl.localhost` 写入的文件会归 root;③Docker 用 Docker Desktop 的发行版集成(设置里勾选对应发行版)或发行版内原生 docker 均可;④路径尽量纯 ASCII。

## 首次部署

```bash
git clone https://github.com/ysqd1/firmware_audit.git
cd firmware_audit
pip install -r firmware_audit/requirements.txt
```

**固件自备**:`target/` 不入仓(体积巨大),把待审固件放到 `target/<N>/`(编号任意,如 `target/1/fw.tar.xz`)。支持归档(tar/zip)、单文件压缩(.gz/.bz2/.xz)、磁盘镜像(.img,含 GPT/MBR 分区表,自动分区提取)。

### 构建 Docker 镜像(首次)

```bash
# 构建 binwalk(Step1 解包 / Step3 分类用)
bash firmware_audit/docker/binwalk/build_docker.sh

# 构建精简 ghidra(Step4 反编译用;Ghidra zip + JDK 本地 COPY,apt 需联网)
docker build -f firmware_audit/docker/ghidra/Dockerfile.slim -t ghidra:latest firmware_audit/docker/ghidra

# 构建通用沙箱(原 ghidra 镜像 + sfdisk,step0 分区交叉验证 + Step5 Agent 工具用)
docker build -t firm_audit/sandbox:latest firmware_audit/docker/sandbox
```

镜像 tag:`binwalk`、`ghidra`(精简版,~3.2GB)、`firm_audit/sandbox`(~5.1GB 压扁通用沙箱)。

> **为什么 ghidra 是精简版**:原 ghidra 镜像基于 deepaudit/sandbox(5.3GB,内含
> semgrep/bandit 等反编译用不到的安全工具,合计 8.38GB)。step4 并行起 4 个容器时
> 内存/IO 开销巨大,故新建 `Dockerfile.slim`(仅 ubuntu + JDK21 + Ghidra + 最小
> 字体库,~3.18GB,减 62%),step4 仍用 `ghidra` tag 无缝切换。
> 原 8.38GB 镜像已重命名为 `firm_audit/sandbox`,作为通用沙箱(sfdisk/Step5 Agent
> 工具 checksec/r2/cve-bin-tool/semgrep/gitleaks 跑);2026-08-18 已压扁到 ~5.1GB
> (清理 openjdk-11/17/Rust/Go/gosec 等冗余,历史层重复数据压缩),`latest` 即压扁版。

### 配置 LLM(Step5 需要)

```bash
cp firmware_audit/.env.example firmware_audit/.env
# 编辑 .env,填入 OpenAI 兼容接口的 base_url / api_key / model 三字段
```

无 key / API 失败时 Step5 立即终止(不产出降级工件,见 `docs/adr/0002`);Step1-4 不受影响。

### 预热 CVE 缓存(推荐,一次性)

cve-bin-tool 首扫若无本地库会尝试联网更新 NVD,直连常超时。先离线预热(库可复用):

```bash
mkdir -p <缓存目录>   # 如 firmware_audit/.cve_cache(配合 FIRMWARE_AUDIT_CVE_CACHE_DIR)
docker run --rm --entrypoint cve-bin-tool \
  -v "<缓存目录>:/home/sandbox/.cache" \
  firm_audit/sandbox:latest -l info \
  --disable-version-check --disable-data-source PURL2CPE -u now /tmp
```

三个实测坑(缺一即失败):①必须带目录参数(`/tmp`),否则 `InsufficientArgs`;②挂到 `/home/sandbox/.cache` 父目录,不是 `~/.cache/cvedb`;③别把 `cve-bin-tool` 目录本身当挂载根(更新时要 rmtree,报 Device busy)。

联网受限环境:NVD/OSV 拉取需代理时加 `-e HTTPS_PROXY=http://host.docker.internal:<端口>`(Docker Desktop 会转发到宿主回环;Linux 原生 docker 用宿主 IP);EPSS 源失败可容忍。

运行扫描时的缓存目录:`FIRMWARE_AUDIT_CVE_CACHE_DIR` 可覆盖,默认用 `target/<N>/process/.cve_cache`。

## 运行

```bash
python -m firmware_audit.main target/1
```

可选参数:见 `firmware_audit/main.py` 的 argparse(如 `--max-elf` 限制反编译数、`--no-step5` 跳过 Agent 审计)。

### 规模闸门(shell 环境变量)

三道防爆炸闸门默认值不变,换大固件时按次覆盖即可;缺失/非法值回落默认并告警。注意这些闸门由 Step0/Step1 消费,`main.py` 不读 `.env`,须在 shell 里 `export`:

| 环境变量 | 管辖 | 默认 |
| --- | --- | --- |
| `STEP0_PARTITION_MAX_SIZE_GB` | 非 ext4 分区(rootfs/recovery)dd 提取上限,超过跳过 | 50 |
| `STEP1_MAX_FILES_PER_EXTRACTION` | 单次 binwalk/7z 解包产出上限,超过删该次产物 | 50000 |
| `STEP1_MAX_TOTAL_FILES` | 全树文件数上限,超过停止新增解包 | 200000 |

> ext4 分区直读(魔数触发)不受分区大小闸门约束——超大 rootfs 正是直读要救的对象。默认值唯一出处见 `firmware_audit/gates.py`。

**单独补跑 Step5**(已有 Step1-4 产物时,可独立跑三 Agent 审计,无需重跑前四步):

```bash
python -m firmware_audit.step5_agent.run_step5 target/1            # 断点续跑(工件已存在则跳过)
python -m firmware_audit.step5_agent.run_step5 target/1 --force    # 强制三 Agent 全部重跑
```

> `main.py` 不向 Step5 透传 `--force`(全流程重跑时 Step5 恒命中断点跳过),要强制重跑 Step5 请用上面独立入口。

Step5 产物:报告在 `target/<N>/process/agent/orchestrator/report.md`,复核结论在 `verified_findings.json`。终端监控显示可用 `STEP5_DISPLAY=compact|full` 开启(详见 `step5_agent/DISPLAY.md`)。

## 测试

```bash
python -m pytest firmware_audit/test -q
```

- Linux 基线(2026-09-07,Kali/Python 3.13):**274 passed / 2 skipped / 5 failed**——5 个失败为已定位的 step0 zip 平台兼容问题(真 bug + 平台用例,见仓库根 `HANDOFF.md` §2),修复前属已知状态,非环境问题。
- Docker 门控用例(真实调容器)需三个镜像就位;Step4/Step5 部分用例依赖既有工件,缺失时自动 SKIP(`test/conftest.py`)。

## 结构

```
firmware_audit/
├── __init__.py            # 包标记
├── main.py                # 主入口
├── models.py              # FileInfo 数据模型
├── profiles/              # 固件机型名单(默认 nano-ubuntu)
├── docker/                # Docker 调用封装 + 容器构建资源
│   ├── __init__.py
│   ├── docker_utils.py    # Docker 调用封装
│   ├── binwalk/           # binwalk 容器构建资源
│   ├── ghidra/            # ghidra 容器构建资源(含 ExtractInfo.py)
│   └── sandbox/           # 通用沙箱构建资源
├── step0/                  # Step0 预解压 + 磁盘镜像分区提取(宿主 Python,sfdisk 部分走容器)
│   ├── step0_preprocess.py # 分流:归档/单文件压缩/磁盘镜像
│   └── step0_split_img.py # 大镜像 GPT/MBR 分区解析与提取(可独立 CLI 运行)
├── step1/
│   ├── step1_guided_extract.py  # 引导式解包(主路径:魔数决策逐层解,处理嵌套容器)
│   ├── step1_extract.py         # 兜底 binwalk -Me 递归解包
│   └── file_magic.py            # 文件魔数嗅探 + 解包决策(纯函数)
├── step2/
│   └── step2_filter.py    # 白/黑名单过滤
├── step3/
│   └── step3_classify.py  # 分类
├── step4/
│   ├── step4_decompile.py # Ghidra 反编译/文本扫描/证书解析(合并到 analysis/)
│   └── triage.py          # 不透明固件分诊(unknown/hex/srec)
├── step5_agent/            # Step5 三 Agent ReAct 审计(分层见 ADR-0009)
│   ├── run_step5.py        # L0 总控入口(python -m ...step5_agent.run_step5)
│   ├── orchestration/      # LLM 编排层(orchestrator/actions/verify_phase/handoff 等)
│   ├── runner.py           # L1 单 Agent 执行(AgentConfig×3 + run_agent)
│   ├── aggregator.py       # findings 聚合纯逻辑
│   ├── engine/             # ReAct 引擎(react_loop/protocol/context/transcript/display)
│   ├── data/               # 工件 schema / 提示词
│   ├── providers/          # llm_client + tools/(15 个 Agent 工具)
│   └── demos/              # 演示脚本(demo_display)
└── test/                   # pytest 套件(见"测试"节)
```

## 目录结构(process/ 统一工作区)

`target/<N>/` 下**无论固件类型都只保留固件文件 + 一个 `process/` 工作区**,所有流水线产物都在其中:

```
# 单一固件(如 tar.xz)
target/1/
├── fw.tar.xz
└── process/
    ├── extracted/          # Step0 解压(归档)+ Step1 binwalk 产物根
    ├── analysis/           # Step4 产物
    └── fileinfo.json

# 磁盘镜像(如 g1-nx-j6.1.img.bz2)
target/2/
├── g1-nx-j6.1.img.bz2
└── process/
    ├── g1-nx-j6.1.img              # Step0 解压出的中间单文件(与分区文件同级)
    ├── part02_A_kernel/            # 分区子文件夹(自包含)
    │   ├── part02_A_kernel.img     # 分区文件(move 进来)
    │   ├── extracted/              # Step1 解包
    │   ├── analysis/               # Step4
    │   └── fileinfo.json
    └── ...
```

## 说明

- **大磁盘镜像(几百 GB .img,含 GPT/MBR 分区表)**:Step0 自动按分区表提取,每个分区独立工作区 `process/<分区名>/` 跑 Step1-4;已提取的分区自动复用不重复 IO。可用 `python -m firmware_audit.step0.step0_split_img <img> --list-only` 先查看分区表,`--max-size 300` 提取超大 rootfs。
- **分区类型筛选**(2026-08-12):kind 判定增强——`dtb`/`reserved`/`esp` 显式识别并**优先于 kernel 判定**(否则 `A_kernel-dtb` 被误判 kernel,binwalk 解出数万 DTB 节点文件纯噪声)。**默认跳过 `dtb` 与 `reserved` 分区**(不提取、不送审、不复用),`--extract-all` 可强制提取;被筛类型的旧产物(process/ 根分区文件 + 子工作区)自动清理。esp 在 should_extract 必提列表(独立 kind 后不能靠 small 兜底)。实测 g1 镜像:15 分区 → 提取 6 个(kernel×2、recovery×2、esp×2),dtb×4、reserved×3、237GB rootfs 跳过。
- **分区准确性命门**(分区错 → 下游全废):**sfdisk(libfdisk 权威实现)主解析分区表**(普世、不易错;不可用/失败自动回退手写解析,含 CRC 强校验)、分区边界检查(超界截断/跳过)、身份签名交叉验证(kind 与签名冲突告警)、提取后回读校验(不一致删除)、复用同样过回读校验。`--list-only` 显示每分区校验状态(ok/截断/冲突/跳过)。实测 g1 镜像 15 分区 sfdisk 与手写解析逐项完全一致。**注意: sfdisk 挂载必须用绝对路径**,相对路径(尤其含中文如 `target/完整/`)会被 Docker volume 名校验拒绝 → 主解析静默回退手写(已修,见 step0_split_img.py 注释)。
- `analysis/` 是 Step4 合并产物目录:反编译 `.c` 与各 JSON(functions/imports/symbols/strings/meta/text/crypto)同处,不再分 decompiled/。
- 每轮运行会自动裁剪过时产物(见 step4 `_cleanup_orphans`),目录口径与 fileinfo 对齐。
- 断点续传:已反编译成功的 ELF 自动跳过(见 step4 `_mark_decompiled_ok`);Step5 工件存在且 schema 匹配则跳过对应 Agent(`--force` 强制重跑)。

## 更多文档

- `AGENTS.md`(仓库根):流水线角色、Step5 Agent 架构与工具层设计的权威描述
- `CONTEXT.md` / `rules.md`:术语表 / 代码规范铁律
- `docs/adr/`:架构决策记录(0001-0009)
- `HANDOFF.md`:最近一次会话交接(项目状态 / 测试基线 / 待办)

# 宇树固件审计 - firmware_audit

固件安全审计流水线:解包(binwalk) → 过滤(白/黑名单) → 分类 → 反编译/提取(Ghidra)

## 环境要求

- Python 3.10+
- Docker(需可用,用于 binwalk/ghidra 容器)
- 依赖:

```bash
pip install -r firmware_audit/requirements.txt
```

## 构建 Docker 镜像(首次)

```bash
# 构建 binwalk(Step1 解包 / Step3 分类用)
bash firmware_audit/docker/binwalk/build_docker.sh

# 构建精简 ghidra(Step4 反编译用;Ghidra zip + JDK 本地 COPY,apt 需联网)
docker build -f firmware_audit/docker/ghidra/Dockerfile.slim -t ghidra:latest firmware_audit/docker/ghidra

# 构建通用沙箱(原 ghidra 镜像 + sfdisk,step0 分区交叉验证用)
docker build -t firm_audit/sandbox:latest firmware_audit/docker/sandbox
```

镜像 tag:`binwalk`、`ghidra`(精简版,~3.2GB)、`firm_audit/sandbox`(~8.4GB 通用沙箱)。

> **为什么 gh idra 是精简版**:原 ghidra 镜像基于 deepaudit/sandbox(5.3GB,内含
> semgrep/bandit 等反编译用不到的安全工具,合计 8.38GB)。step4 并行起 4 个容器时
> 内存/IO 开销巨大,故新建 `Dockerfile.slim`(仅 ubuntu + JDK21 + Ghidra + 最小
> 字体库,~3.18GB,减 62%),step4 仍用 `ghidra` tag 无缝切换。
> 原 8.38GB 镜像已重命名为 `firm_audit/sandbox`,作为通用沙箱(sfdisk 交叉验证等)。

## 运行

```bash
python -m firmware_audit.main target/1
```

可选参数:见 `firmware_audit/main.py` 的 argparse(如 `--max-elf` 限制反编译数)。

## 测试

```bash
python -m firmware_audit.test.test_step3
python -m firmware_audit.test.test_step4
```

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
│   └── ghidra/            # ghidra 容器构建资源(含 ExtractInfo.py)
├── step0/                  # Step0 预解压 + 磁盘镜像分区提取(宿主 Python,不依赖 Docker)
│   ├── step0_preprocess.py # 分流:归档/单文件压缩/磁盘镜像
│   └── step0_split_img.py # 大镜像 GPT/MBR 分区解析与提取(可独立 CLI 运行)
├── step1/
│   └── step1_extract.py   # 解包
├── step2/
│   └── step2_filter.py    # 白/黑名单过滤
├── step3/
│   └── step3_classify.py  # 分类
├── step4/
│   └── step4_decompile.py # Ghidra 反编译/文本扫描/证书解析(合并到 analysis/)
└── test/
    ├── test_step0.py      # Step0 预解压单元测试
    ├── test_step0_split.py # Step0 磁盘镜像分区单元测试
    ├── test_step3.py      # Step3 分类单元测试
    ├── test_step4.py      # Step4 扫描/版本校验单元测试
    └── test_docker_utils.py # docker_available tag 归一化测试
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
- 断点续传:已反编译成功的 ELF 自动跳过(见 step4 `_mark_decompiled_ok`)。
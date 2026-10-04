# 03: QEMU 执行镜像固化

**What to build:** 按票 01 选定的路线构建带固定版本 QEMU 用户态模拟器的执行镜像：构建可重复、版本可查询，ARM32 小端与 MIPS32 大端各有一个最小外来二进制在镜像内真实跑通。该镜像是票 05 起所有真实集成测试的底座。现有沙箱镜像的职责与工具入口不受影响。

**Blocked by:** 01

**Status:** ready-for-agent

- [x] 镜像构建脚本入库，基线与 QEMU 版本可从镜像内查询
- [x] ARM32 小端 + MIPS32 大端各一个最小二进制在镜像内真实执行通过，冒烟脚本可重复运行
- [x] 现有沙箱镜像原有工具入口与行为不回归
- [x] 全量既有套件绿
- [x] 真实容器测试带依赖门控：缺镜像/缺二进制时明确跳过并记录原因，不假绿

## Comments

2026-09-22 后续决定：用户采用 PRoot + QEMU。本票完成状态与历史证据保留；新后端镜像、预检及运行边界由 [票 15](15-proot-backend-integration.md) 补齐，不能把旧结果视为新后端已验收。

### 2026-09-21 实现记录(票 03 完成)

**交付物**(全部入库,`deb-cache/` 与 `.scratch/` 按约定不入仓):
- `firmware_audit/docker/qemu-exec/pins.env` — 钉值单一来源(包版本/deb 文件名/sha256/尺寸/双源 URL/基线镜像/目标镜像)
- `firmware_audit/docker/qemu-exec/Dockerfile` — `FROM firm_audit/sandbox:latest` 派生层;COPY 缓存 .deb → 镜像内 sha256 校验 → `dpkg -i` 离线安装(构建期零网络、不依赖 apt 源存续);BUILD-INFO 落盘 `/usr/local/share/fw-qemu-exec/BUILD-INFO.txt`;ENTRYPOINT 继承基座值(analyzeHeadless)不覆盖
- `firmware_audit/docker/qemu-exec/build_image.sh` — 宿主构建脚本:基座在位检查(缺失给指引不自动重建)→ .deb 缓存缺失时双源下载(主 aliyun 备 deb.debian.org)→ 宿主侧 sha256+尺寸校验 → docker build,tag `firm_audit/qemu-exec:latest` + `:deb11u3`(版本 tag 去 epoch),OCI labels 记录基线与包校验值
- `firmware_audit/docker/qemu-exec/smoke_test.sh`(容器内)+ `run_smoke.sh`(宿主驱动,解析两解包树,可 `TGT6_ROOT/TGT8_ROOT` 覆盖)——可重复冒烟:只读挂载 + `--network none` + `--rm`

**固定包核实(可获取性/来源/校验值)**:
- 版本 `qemu-user-static 1:5.2+dfsg-11+deb11u3`(bullseye/main;security 池 u5 已 404 的绕行,票 01 结论)
- 权威 sha256 取自 `dists/bullseye/main/binary-amd64/Packages` 索引(apt 安装同源):`0b75df79ae2ddfbc4daab0223a0fc2e79c9be7b1e35c6d030879d4bd21684bca`,Size 41405928
- 2026-09-21 实测:aliyun pool 与 deb.debian.org pool 对该 .deb 均 HTTP 200(Content-Length 一致);实际下载件 `sha256sum` 与索引值**逐字一致**
- 下载缓存:`firmware_audit/docker/qemu-exec/deb-cache/`(gitignored,radare2 tar.gz 同款先例);重复构建直接复用,构建期不再触网

**构建结果**:`firm_audit/qemu-exec:latest` = `:deb11u3`,5.54GB(基座 5.1GB,增量 ≈+0.44GB,与票 01 探针 5.46GB 同量级);镜像内 BUILD-INFO:`base_image=firm_audit/sandbox:latest`、`base_digest=sha256:7a617b7c…59668`(与票 01 存档基座 digest 一致)、包版本与 deb sha256 全记录;`qemu-arm/qemu-mips version 5.2.0 (Debian 1:5.2+dfsg-11+deb11u3)` 镜像内可查。

**冒烟实跑(断网 + 只读挂载,ALL-PASS)**:
- 基线与版本查询:BUILD-INFO + dpkg + qemu 双二进制 version 输出
- binfmt 独立性对照:裸跑 ARM32 rc=126(显式调用不依赖 binfmt,宿主未动)
- ARM32 小端:target/6 `usr/sbin/nvram` 经 `qemu-arm-static -L /work/tgt6` → usage 输出 rc=0
- MIPS32 大端:target/8 `bin/busybox echo` 经 `qemu-mips-static -L /work/tgt8` → 回显 rc=0
- 错架构对照:qemu-arm-static 跑 MIPS 二进制 rc=255(架构选择真实生效)

**测试(TDD)**:`firmware_audit/test/test_qemu_exec_image.py` 8 项。先写测试拿红灯证据:pins.env 缺失时离线 3 项 FAIL;镜像未建时 4 项容器测试 SKIP 且带原因("Docker 或镜像 firm_audit/qemu-exec 不可用(先运行 …/build_image.sh 构建)",pytest -rs 可见);基础镜像不回归测试在构建前即 PASS。实现后 8/8 PASS:
- 离线 3 项:pins.env 键值/格式、deb-cache 与钉值一致、Dockerfile/build_image.sh 与 pins.env 同源(防漂移)
- 容器 5 项:版本镜像内可查询(AC1)、ARM32 LE 实跑、MIPS32 BE 实跑(AC2)、binfmt 独立性对照、基础镜像无 qemu 二进制 + checksec/semgrep/gitleaks/r2/python3 工具入口健在(AC3——结构性隔离:sandbox_verify 所在镜像物理无 qemu)

**全量套件(AC4)**:1123 passed + 16 skipped(3:43);16 个 skip 全部为既有 `target/1 工件不存在` 门控(本机未解包 target/1,先于本票存在),新增 8 项全 PASS,零回归。

**AC 逐条**:5/5 满足——①构建脚本入库,`docker run` 一条命令查 BUILD-INFO/dpkg/version(版本查询测试守护);②双架构实跑 + 冒烟脚本可重复(只读无状态);③基础镜像不回归(门控实测 + 全量套件);④全量绿;⑤缺镜像/缺解包树时 SKIP 带原因不假绿(构建前后两次实测留痕)。

**踩坑记录**:①Dockerfile `ARG` 在 `FROM` 前声明只作用于 FROM 行,RUN 取不到 → BASE_IMAGE_DIGEST 首建时 `base_digest=` 为空,FROM 后重新声明修复;②`nvram` usage 走 stderr,pytest 断言须 `out + err`(冒烟脚本 2>&1 掩盖了该差异)。

**对后续票的影响**:
- **05 预检/05+ 工具**:底座就绪;调用侧约定 = `run_docker("firm_audit/qemu-exec", …, entrypoint 覆盖, network="none")`,与 cli_base 同款;会话容器(tag 不可漂移,票 01 已警示)发布后不再改 `:latest` 指向
- **重建口径**:基座更新后重跑 `build_image.sh` 即得新派生层;BUILD-INFO/labels 自动记录新基线 digest,可追溯
- **.deb 消失风险**:双源 URL 已入 pins.env;若未来双源全 404,构建脚本明确报错并要求改 pins.env 重新核实校验值,不静默换包

### 2026-09-21 code-review 记录(两轴并行评审 + 修复)

评审基线:`git diff ca76c12...HEAD`(提交 66ae8ae)。Spec 轴结论:通过,5 条 AC 逐条成立,无 scope creep(对照组有票 01 证据支撑;未触碰产品代码/Step5 工具/NVRAM/宿主 binfmt,符合 ADR-0013 边界)。Standards 轴发现 2 处硬伤 + 若干 judgement call,全部修复:

1. **build_image.sh 注释与代码不符**:`${VERSION##*+}` 实际取 Debian 修订号(最后一个 + 之后)作 tag,原注释误写"去 epoch"——注释改为如实描述。
2. **版本自检假门**:Dockerfile/smoke 的 `--version | head -1 || fail=1` 管道退出码取末端,qemu 缺失也"通过"。Dockerfile 改 `grep -q 'qemu-*-static version'` 断言;smoke 改命令替换保留 qemu 自身退出码。
3. **坏缓存不清不退**(Spec 轴):重构为逐源"下载→sha256+尺寸校验",坏件即删回退下一源,双源全败才中止;缓存命中也先校验,不过即删重建。
4. **BUILD-INFO 键名误读**(Spec 轴):`.Id` 是镜像 ID 非 manifest digest(本地构建镜像无 RepoDigests),键改名 `base_image_id`,删除语义不符的 `org.opencontainers.image.base.digest` label。
5. AC5 字面化:测试门控从"解包树目录存在"改为"样本二进制文件存在",缺二进制 SKIP 并记录原因,不以 FAIL 冒充。
6. 测试镜像名常量改为读 pins.env(消与钉值的双写漂移);timeout 魔数补来源注释;shebang 统一;run_smoke.sh 冗余路径简化。

**修复后复验**:重建镜像成功(`base_image_id=sha256:7a617b7c…59668` 与票 01 存档一致);冒烟 ALL-PASS(双架构 + 双对照);`test_qemu_exec_image.py` 8/8 PASS;全量套件 1123 passed + 16 skipped(全为既有 target/1 门控),零回归。

**已知取舍**(评审记录,不修):解包路径在 run_smoke.sh 与测试文件双写(跨 shell/python 两层,单源需引入跨语言配置机制,收益不抵);Dockerfile COPY 硬编码 deb 文件名(离线 drift-guard 测试守护);AC3 深层工具行为回归由既有 CLI 工具门控套件覆盖,新增测试只守入口在场 + 结构性隔离。

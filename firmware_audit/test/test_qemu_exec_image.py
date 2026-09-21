"""票 03(qemu-user-mode-experiments):QEMU 执行镜像 firm_audit/qemu-exec。

两层接缝(spec.md Testing Decisions):
- 离线:pins.env 固定包钉值格式、deb-cache 缓存校验、Dockerfile 与钉值一致
  (无 Docker 依赖,始终跑);
- 真实容器:基线与 QEMU 版本镜像内可查询、ARM32 小端(target/6 nvram)与
  MIPS32 大端(target/8 busybox)真实执行、binfmt 独立性对照、基础镜像
  firm_audit/sandbox 不回归——缺 Docker/镜像/解包树时 SKIP 并记录原因,不假绿。

冒烟命令与票 01 证据同源(investigation/01/04-arm-runs.txt、05-mips-runs.txt、
07-probe-smoke.txt):裸跑 rc=126 对照 + 显式 qemu 调用不依赖宿主 binfmt。
钉值权威来源:bullseye/main binary-amd64 Packages 索引(apt 安装同源校验)。
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from firmware_audit.docker.docker_utils import docker_available, run_docker

REPO_ROOT = Path(__file__).resolve().parents[2]
IMG_DIR = REPO_ROOT / "firmware_audit" / "docker" / "qemu-exec"
PINS_PATH = IMG_DIR / "pins.env"
QEMU_EXEC_IMAGE = "firm_audit/qemu-exec"
BASE_IMAGE = "firm_audit/sandbox:latest"

# 冒烟样本的解包树(workspace 工件,gitignored;票 01 实测两架构代表二进制所在)
TGT6_SQUASH = (REPO_ROOT / "target/6/process/extracted/"
               "000000_DIR890LA1_FW111b02_20170519_beta01.bin.extracted/"
               "1C0094/squashfs-root")
TGT8_SQUASH = (REPO_ROOT / "target/8/process/extracted/"
               "000000_openwrt-19.07.0-ath79-generic-tplink_archer-c7-v2-"
               "squashfs-sysupgrade.bin.extracted/185BC4/squashfs-root")


def _load_pins() -> dict[str, str]:
    """解析 pins.env(严格 KEY=VALUE,# 注释;build_image.sh 同源 source)。"""
    pins: dict[str, str] = {}
    for line in PINS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        pins[key.strip()] = value.strip()
    return pins


def _qemu_upstream_version(pins: dict[str, str]) -> str:
    """Debian 版本号 1:5.2+dfsg-11+deb11u3 → 上游版本 5.2(qemu --version 输出用)。"""
    return pins["QEMU_USER_STATIC_VERSION"].split(":", 1)[1].split("+", 1)[0]


def _require_exec_image() -> None:
    if not docker_available(QEMU_EXEC_IMAGE):
        pytest.skip(
            f"Docker 或镜像 {QEMU_EXEC_IMAGE} 不可用(先运行 "
            "firmware_audit/docker/qemu-exec/build_image.sh 构建)")


# ---------- 离线:钉值与构建材料一致性(无 Docker,始终跑) ----------

def test_pins_env_wellformed() -> None:
    assert PINS_PATH.is_file(), f"缺少钉值文件 {PINS_PATH}"
    pins = _load_pins()
    required = [
        "QEMU_USER_STATIC_VERSION", "QEMU_USER_STATIC_DEB",
        "QEMU_USER_STATIC_DEB_SHA256", "QEMU_USER_STATIC_DEB_SIZE",
        "DEB_POOL_URL_ALIYUN", "DEB_POOL_URL_DEBIAN",
        "BASE_IMAGE", "QEMU_EXEC_IMAGE",
    ]
    missing = [k for k in required if not pins.get(k)]
    assert not missing, f"pins.env 缺键: {missing}"
    assert re.fullmatch(r"1:\d[^\s]+", pins["QEMU_USER_STATIC_VERSION"]), "版本须带 epoch"
    assert re.fullmatch(r"[0-9a-f]{64}", pins["QEMU_USER_STATIC_DEB_SHA256"]), "sha256 须 64 位十六进制"
    assert pins["QEMU_USER_STATIC_DEB_SIZE"].isdigit(), "尺寸须纯数字"
    # deb 文件名与版本钉值一致(Debian 命名:<pkg>_<去 epoch 版本>_<arch>.deb)
    version_no_epoch = pins["QEMU_USER_STATIC_VERSION"].split(":", 1)[1]
    assert pins["QEMU_USER_STATIC_DEB"] == f"qemu-user-static_{version_no_epoch}_amd64.deb"
    for key in ("DEB_POOL_URL_ALIYUN", "DEB_POOL_URL_DEBIAN"):
        # pool URL 中 "+" 编码为 %2b,按编码后的完整文件名核对
        assert pins["QEMU_USER_STATIC_DEB"].replace("+", "%2b") in pins[key], \
            f"{key} 应指向钉死的 deb 文件名"


def test_deb_cache_matches_pin() -> None:
    pins = _load_pins()
    deb = IMG_DIR / "deb-cache" / pins["QEMU_USER_STATIC_DEB"]
    if not deb.is_file():
        pytest.skip(".deb 缓存不存在(build_image.sh 会按 pins.env 下载并校验)")
    assert deb.stat().st_size == int(pins["QEMU_USER_STATIC_DEB_SIZE"]), "缓存 .deb 尺寸与钉值不符"
    digest = hashlib.sha256(deb.read_bytes()).hexdigest()
    assert digest == pins["QEMU_USER_STATIC_DEB_SHA256"], "缓存 .deb sha256 与钉值不符"


def test_dockerfile_and_build_script_consistent_with_pins() -> None:
    """Dockerfile COPY 的 deb 文件名 / FROM 基线与 pins.env 同源(防两处漂移)。"""
    pins = _load_pins()
    dockerfile = (IMG_DIR / "Dockerfile").read_text(encoding="utf-8")
    assert f"FROM {pins['BASE_IMAGE']}" in dockerfile, "FROM 基线须取 pins.env 的 BASE_IMAGE"
    assert f"deb-cache/{pins['QEMU_USER_STATIC_DEB']}" in dockerfile, "COPY 的 deb 文件名须与钉值一致"
    build_script = (IMG_DIR / "build_image.sh").read_text(encoding="utf-8")
    assert ". ./pins.env" in build_script, "构建脚本须 source pins.env(单一钉值来源)"
    assert "sha256sum -c" in build_script, "构建脚本须对缓存 .deb 做 sha256 校验"


# ---------- 真实容器:镜像内版本查询(AC1) ----------

def test_image_versions_queryable() -> None:
    _require_exec_image()
    pins = _load_pins()
    rc, out, err = run_docker(
        QEMU_EXEC_IMAGE,
        ["-c",
         "cat /usr/local/share/fw-qemu-exec/BUILD-INFO.txt && "
         "dpkg-query -W -f='dpkg: ${Version}\\n' qemu-user-static && "
         "qemu-arm-static --version | head -1 && "
         "qemu-mips-static --version | head -1"],
        entrypoint="bash", network="none", timeout=180)
    assert rc == 0, f"版本查询失败: {err}"
    # 基线可查询:BUILD-INFO 记录基座镜像名与 .deb 校验值
    assert pins["BASE_IMAGE"] in out, "BUILD-INFO 缺基线镜像名"
    assert pins["QEMU_USER_STATIC_DEB_SHA256"] in out, "BUILD-INFO 缺 .deb sha256"
    # QEMU 版本可查询:dpkg 实况与 qemu 二进制自报一致,且等于钉值
    assert f"dpkg: {pins['QEMU_USER_STATIC_VERSION']}" in out, "dpkg 版本 ≠ pins.env 钉值"
    upstream = _qemu_upstream_version(pins)
    assert f"qemu-arm version {upstream}" in out, out
    assert f"qemu-mips version {upstream}" in out, out


# ---------- 真实容器:双架构真实执行(AC2) ----------

def test_arm32_le_execution() -> None:
    _require_exec_image()
    if not TGT6_SQUASH.is_dir():
        pytest.skip(f"target/6 解包树不存在: {TGT6_SQUASH}")
    rc, out, err = run_docker(
        QEMU_EXEC_IMAGE,
        ["-c", "qemu-arm-static -L /work/tgt6 /work/tgt6/usr/sbin/nvram"],
        mounts=[(TGT6_SQUASH, "/work/tgt6", "ro")],
        entrypoint="bash", network="none", timeout=180)
    assert rc == 0, f"ARM32 LE 执行失败 rc={rc}: {err}"
    # nvram 的 usage 打到 stderr(冒烟脚本 2>&1 同款口径)
    assert "usage: nvram" in out + err, f"输出不含 usage: {(out + err)[:400]}"


def test_mips32_be_execution() -> None:
    _require_exec_image()
    if not TGT8_SQUASH.is_dir():
        pytest.skip(f"target/8 解包树不存在: {TGT8_SQUASH}")
    rc, out, err = run_docker(
        QEMU_EXEC_IMAGE,
        ["-c", "qemu-mips-static -L /work/tgt8 /work/tgt8/bin/busybox echo hello-from-qemu-exec"],
        mounts=[(TGT8_SQUASH, "/work/tgt8", "ro")],
        entrypoint="bash", network="none", timeout=180)
    assert rc == 0, f"MIPS32 BE 执行失败 rc={rc}: {err}"
    assert "hello-from-qemu-exec" in out, f"输出不含回显: {out[:400]}"


def test_binfmt_independence_control() -> None:
    """裸跑外来 ELF 应 rc=126(Exec format error):显式调用不依赖 binfmt 注册。

    宿主若注册了 arm 的 binfmt,此对照会以 rc=0 失败——那是运行环境漂移信号,
    按票 01 边界(不改宿主 binfmt)应查明,不是测试误报。
    """
    _require_exec_image()
    if not TGT6_SQUASH.is_dir():
        pytest.skip(f"target/6 解包树不存在: {TGT6_SQUASH}")
    rc, out, err = run_docker(
        QEMU_EXEC_IMAGE,
        ["-c", "/work/tgt6/usr/sbin/nvram"],
        mounts=[(TGT6_SQUASH, "/work/tgt6", "ro")],
        entrypoint="bash", network="none", timeout=180)
    assert rc == 126, f"裸跑对照预期 126,实得 rc={rc}(宿主 binfmt 漂移?) out={out[:200]} err={err[:200]}"
    assert "Exec format error" in (out + err)


# ---------- 真实容器:基础镜像不回归(AC3) ----------

def test_base_image_no_qemu_and_tools_intact() -> None:
    """firm_audit/sandbox 保持零 qemu(结构性隔离:sandbox_verify 无法启动 QEMU),
    且原有工具入口健在;深层工具行为由既有 CLI 工具门控套件覆盖。"""
    if not docker_available(BASE_IMAGE):
        pytest.skip(f"基础镜像 {BASE_IMAGE} 不可用")
    rc, out, err = run_docker(
        BASE_IMAGE,
        ["-c",
         "ls /usr/bin/qemu-*-static 2>/dev/null | wc -l; "
         "dpkg-query -W qemu-user-static >/dev/null 2>&1 && echo QEMU-PKG-INSTALLED "
         "|| echo QEMU-PKG-ABSENT; "
         "for t in checksec semgrep gitleaks r2 python3; do "
         "command -v $t >/dev/null && echo \"OK $t\" || echo \"MISSING $t\"; done"],
        entrypoint="bash", network="none", timeout=300)
    assert rc == 0, err
    lines = out.splitlines()
    assert lines and lines[0].strip() == "0", f"基础镜像出现 qemu 二进制,结构性隔离破坏: {lines[0]}"
    assert "QEMU-PKG-ABSENT" in out, "基础镜像不得安装 qemu-user-static"
    for tool in ("checksec", "semgrep", "gitleaks", "r2", "python3"):
        assert f"OK {tool}" in out, f"基础镜像工具入口丢失: {tool}"

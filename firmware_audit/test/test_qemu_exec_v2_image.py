"""票 16(qemu-user-mode-experiments):qemu-exec-v2 执行镜像(PRoot 5.4.0 + QEMU 11.1.1)。

两层接缝(spec.md Testing Decisions):
- 离线:pins.env 钉值格式、Dockerfile 与钉值同源(sha256/digest/构建参数)、
  补丁与 llscan 在位、钉 tag 不用 latest(无 Docker 依赖,始终跑);
- 真实容器:镜像内版本/身份可查询、形状隔离(剥离后无 shell)、ARM32 LE
  顶层与派生链真实执行、MIPS32 BE 对照、边界拒绝面(guest 借 /host-rootfs
  执行容器原生程序被拒)——缺 Docker/镜像/解包树时 SKIP 并记录原因,不假绿。

钉值与拒绝语义证据:.scratch/qemu-user-mode-experiments/investigation/
proot540-qemu1111-2026-09-22/(80 下载校验、82 矩阵、90 补丁拒绝矩阵)。
"""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.docker.docker_utils import docker_available, run_docker

REPO_ROOT = Path(__file__).resolve().parents[2]
IMG_DIR = REPO_ROOT / "firmware_audit" / "docker" / "qemu-exec-v2"
PINS_PATH = IMG_DIR / "pins.env"
PATCH_PATH = IMG_DIR / "proot-mixed-mode-inherit.patch"

TGT6_SQUASH = (REPO_ROOT / "target/6/process/extracted/"
               "000000_DIR890LA1_FW111b02_20170519_beta01.bin.extracted/"
               "1C0094/squashfs-root")
TGT8_SQUASH = (REPO_ROOT / "target/8/process/extracted/"
               "000000_openwrt-19.07.0-ath79-generic-tplink_archer-c7-v2-"
               "squashfs-sysupgrade.bin.extracted/185BC4/squashfs-root")

TEST_TIMEOUT = 180


def _load_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in PINS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        pins[key.strip()] = value.strip().strip('"')
    return pins


@pytest.fixture(scope="module")
def pins() -> dict[str, str]:
    if not PINS_PATH.is_file():
        pytest.skip(f"缺少钉值文件 {PINS_PATH}")
    return _load_pins()


@pytest.fixture(scope="module")
def image(pins: dict[str, str]) -> str:
    name = pins.get("QEMU_EXEC_V2_IMAGE", "")
    if not name or not docker_available(name):
        pytest.skip(f"Docker 或镜像 {name} 不可用(先运行 "
                    "firmware_audit/docker/qemu-exec-v2/build_image.sh 构建)")
    return name


def _require_sample(squash_root: Path, rel_bin: str) -> None:
    if not (squash_root / rel_bin).is_file():
        pytest.skip(f"冒烟样本二进制不存在(解包树缺失或不完整): {squash_root / rel_bin}")


# ---------- 离线:钉值一致性(无 Docker) ----------

def test_pins_required_keys(pins: dict[str, str]) -> list[str]:
    fails: list[str] = []
    for key in ("QEMU_VERSION", "QEMU_TARBALL_SHA256", "QEMU_TARBALL_SIZE",
                "PROOT_VERSION", "PROOT_TARBALL_SHA256", "PROOT_PATCH",
                "PROOT_PATCH_SHA256", "QEMU_BUILD_PARAMS",
                "BASE_IMAGE_DIGEST", "BUILDER_IMAGE_DIGEST",
                "QEMU_EXEC_V2_IMAGE"):
        if not pins.get(key):
            fails.append(f"pins.env 缺 {key}")
    return fails


def test_pins_no_drifting_latest(pins: dict[str, str]) -> list[str]:
    fails: list[str] = []
    if ":latest" in pins.get("QEMU_EXEC_V2_IMAGE", ""):
        fails.append("目标镜像不得使用漂移 latest tag(票 16 AC)")
    if not pins.get("BASE_IMAGE_DIGEST", "").startswith("sha256:"):
        fails.append("基础镜像必须按 digest 钉定")
    return fails


def test_dockerfile_matches_pins(pins: dict[str, str]) -> list[str]:
    """Dockerfile 与 pins.env 同源:源码 sha256、补丁 sha256、digest、构建参数。"""
    fails: list[str] = []
    dockerfile = (IMG_DIR / "Dockerfile").read_text(encoding="utf-8")
    for needle in (pins["QEMU_TARBALL_SHA256"], pins["PROOT_TARBALL_SHA256"],
                   pins["PROOT_PATCH_SHA256"], pins["BASE_IMAGE_DIGEST"],
                   pins["BUILDER_IMAGE_DIGEST"], "arm-linux-user,mips-linux-user"):
        if needle not in dockerfile:
            fails.append(f"Dockerfile 缺钉值/参数: {needle}")
    if not pins["QEMU_EXEC_V2_IMAGE"].split(":")[-1] in dockerfile:
        fails.append("Dockerfile 的 BUILD-INFO 应记录目标镜像 tag")
    return fails


def test_patch_and_helper_present(pins: dict[str, str]) -> list[str]:
    """mixed_mode 继承补丁在库且 sha256 与钉值一致;llscan 源码在位。"""
    fails: list[str] = []
    if not PATCH_PATH.is_file():
        return ["缺 proot mixed_mode 继承补丁文件"]
    digest = hashlib.sha256(PATCH_PATH.read_bytes()).hexdigest()
    if digest != pins["PROOT_PATCH_SHA256"]:
        fails.append(f"补丁 sha256 漂移: {digest} != {pins['PROOT_PATCH_SHA256']}")
    if "child->mixed_mode = parent->mixed_mode" not in PATCH_PATH.read_text(encoding="utf-8"):
        fails.append("补丁内容不含 mixed_mode 继承行(拒绝机制核心)")
    if not (IMG_DIR / "llscan.c").is_file():
        fails.append("缺 llscan.c(清理/身份观测助手)")
    return fails


def test_main() -> int:
    failures = 0
    for test in (test_pins_required_keys, test_pins_no_drifting_latest,
                 test_dockerfile_matches_pins, test_patch_and_helper_present):
        result = test(_load_pins())
        for f in (result or []):
            print(f"FAIL: {f}")
            failures += 1
    return failures


# ---------- 真实容器(门控) ----------

def test_image_versions_and_identity(image: str) -> None:
    rc, out, _ = run_docker(image, ["--version"],
                            entrypoint="/usr/local/bin/qemu-arm-static",
                            network="none", timeout=TEST_TIMEOUT)
    assert rc == 0 and "version 11.1.1" in out, out
    rc, out, _ = run_docker(image, ["--version"],
                            entrypoint="/usr/local/bin/qemu-mips-static",
                            network="none", timeout=TEST_TIMEOUT)
    assert rc == 0 and "version 11.1.1" in out, out
    rc, out, _ = run_docker(image, ["--version"],
                            entrypoint="/usr/local/bin/proot",
                            network="none", timeout=TEST_TIMEOUT)
    assert rc == 0 and "PRoot" in out, out


def test_image_build_info_readable(image: str) -> None:
    import subprocess
    cid = subprocess.run(["docker", "create", image], capture_output=True,
                         text=True, encoding="utf-8").stdout.strip()
    assert cid
    try:
        proc = subprocess.run(["docker", "cp", f"{cid}:/usr/local/share/BUILD-INFO.txt", "-"],
                              capture_output=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        info = proc.stdout
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
    for needle in (b"qemu=11.1.1", b"proot=5.4.0", b"proot-patch-sha256=", b"base="):
        assert needle in info, info
    # LABEL ↔ BUILD-INFO 同源(防两处身份档案漂移)
    from firmware_audit.docker.docker_utils import docker_image_labels
    labels = docker_image_labels(image)
    assert labels and labels.get("fw.qemu.version") == "11.1.1"
    assert labels.get("fw.proot.version") == "5.4.0"
    assert labels.get("fw.proot.patch.sha256", "") in info.decode("utf-8", "replace")
    assert labels.get("fw.qemu.tarball.sha256", "") in info.decode("utf-8", "replace")


def test_image_stripped_shape(image: str) -> None:
    """形状隔离:shell/常规工具已被剥离(guest 经别名找不到容器原生程序)。

    llscan cat 语义:文件不存在 rc=3;docker 对不存在入口 rc=127 + stderr。
    """
    for missing in ("/usr/bin/dash", "/usr/bin/uname", "/usr/bin/cat",
                    "/usr/bin/ls", "/usr/bin/env", "/usr/bin/test"):
        rc, _out, _err = run_docker(image, ["cat", missing],
                                    entrypoint="/usr/local/bin/llscan",
                                    network="none", timeout=TEST_TIMEOUT)
        assert rc == 3, f"{missing} 应不存在(rc={rc})"
    rc, out, err = run_docker(image, ["-c", "true"],
                              entrypoint="/usr/bin/sh",
                              network="none", timeout=TEST_TIMEOUT)
    assert rc != 0 and ("not found" in (err or out or "")
                        or "no such file" in (err or out or "")), "sh 应被剥离"
    rc, out, _ = run_docker(image, ["count"],
                            entrypoint="/usr/local/bin/llscan",
                            network="none", timeout=TEST_TIMEOUT)
    assert rc == 0 and out.strip() == "0", out


def _session_run(image: str, squash: Path, entry_args: list[str], *,
                 timeout: int = 90) -> tuple[int, str]:
    """直接容器形态跑一条 guest 命令(冒烟与镜像内边界验证共用形状)。"""
    import tempfile
    tmp = tempfile.mkdtemp(prefix="fwq-v2-")
    rc, out, err = run_docker(
        image, entry_args,
        mounts=[(squash, "/session/firmware", "ro"),
                (Path(tmp), "/session/runtime", "rw")],
        entrypoint="/usr/bin/timeout",
        network="none", timeout=timeout,
        env={"PROOT_TMP_DIR": "/session/stub"})
    return rc, (out or "") + (err or "")


def _proot_argv(qemu: str, guest_cmd: list[str]) -> list[str]:
    argv = ["-k", "5", "60", "/usr/local/bin/proot", "--mixed-mode", "on",
            "--kill-on-exit", "-q", f"/usr/local/bin/{qemu}",
            "-r", "/session/firmware", "-b", "/session/runtime:/tmp",
            "-b", "/dev/null", "-b", "/dev/zero", "-b", "/dev/random",
            "-b", "/dev/urandom"]
    return argv + guest_cmd


def test_arm_top_and_chain_real(image: str) -> None:
    _require_sample(TGT6_SQUASH, "usr/sbin/nvram")
    rc, out = _session_run(image, TGT6_SQUASH, _proot_argv(
        "qemu-arm-static", ["/usr/sbin/nvram"]))
    assert rc == 0 and "usage: nvram" in out, (rc, out)
    # 原链:固件 busybox sh 自主派生静态子(票 04 阻塞点,票 16 组合实测解锁)
    rc, out = _session_run(image, TGT6_SQUASH, _proot_argv(
        "qemu-arm-static", ["/bin/busybox", "sh", "-c",
                            "/bin/busybox echo derived-arm-child"]))
    assert rc == 0 and "derived-arm-child" in out, (rc, out)


def test_mips_real(image: str) -> None:
    _require_sample(TGT8_SQUASH, "bin/busybox")
    rc, out = _session_run(image, TGT8_SQUASH, _proot_argv(
        "qemu-mips-static", ["/bin/busybox", "echo", "mips-v2-ok"]))
    assert rc == 0 and "mips-v2-ok" in out, (rc, out)


def test_boundary_host_rootfs_denied(image: str) -> None:
    """guest 派生链内借 /host-rootfs 执行容器原生 qemu 必须被拒(拒绝语义)。"""
    _require_sample(TGT6_SQUASH, "bin/busybox")
    rc, out = _session_run(image, TGT6_SQUASH, _proot_argv(
        "qemu-arm-static",
        ["/bin/busybox", "sh", "-c",
         "/host-rootfs/usr/local/bin/qemu-arm-static --version"]))
    assert rc != 0, f"/host-rootfs 逃逸未被拒绝: {out}"
    assert "Invalid ELF image" in out or "not found" in out, out

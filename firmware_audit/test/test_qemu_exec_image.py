"""票 03(qemu-user-mode-experiments):QEMU 执行镜像 firm_audit/qemu-exec。

两层接缝(spec.md Testing Decisions):
- 离线:pins.env 固定包钉值格式、deb-cache 缓存校验、Dockerfile 与钉值一致
  (无 Docker 依赖,始终跑);
- 真实容器:基线与 QEMU 版本镜像内可查询、ARM32 小端(target/6 nvram)与
  MIPS32 大端(target/8 busybox)真实执行、binfmt 独立性对照、基础镜像
  firm_audit/sandbox 不回归——缺 Docker/镜像/解包树时 SKIP 并记录原因,不假绿。

冒烟命令与票 01 证据同源(investigation/01/04-arm-runs.txt、05-mips-runs.txt、
07-probe-smoke.txt):裸跑 rc=126 对照(环境感知,票 17 Comments:仅当确认
执行容器内核未注册 ARM binfmt 才算验证通过,已注册/无法确认标"未验证")
+ 显式 qemu 调用不依赖宿主 binfmt。
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

# 冒烟样本的解包树(workspace 工件,gitignored;票 01 实测两架构代表二进制所在)
TGT6_SQUASH = (REPO_ROOT / "target/6/process/extracted/"
               "000000_DIR890LA1_FW111b02_20170519_beta01.bin.extracted/"
               "1C0094/squashfs-root")
TGT8_SQUASH = (REPO_ROOT / "target/8/process/extracted/"
               "000000_openwrt-19.07.0-ath79-generic-tplink_archer-c7-v2-"
               "squashfs-sysupgrade.bin.extracted/185BC4/squashfs-root")

# 容器测试超时:容器启动 + 单次 qemu 执行实测秒级,180/300 是宽裕上限;
# 不用 run_docker 默认 3600——卡死的测试不该挂一小时。
TEST_TIMEOUT = 180


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


def _require_exec_image() -> str:
    """镜像名取 pins.env(与构建脚本同源,防测试侧常量漂移);缺镜像 SKIP 记原因。"""
    image = _load_pins()["QEMU_EXEC_IMAGE"]
    if not docker_available(image):
        pytest.skip(
            f"Docker 或镜像 {image} 不可用(先运行 "
            "firmware_audit/docker/qemu-exec/build_image.sh 构建)")
    return image


def _require_smoke_binary(squash_root: Path, rel_bin: str) -> None:
    """解包树或样本二进制缺失一律 SKIP 并记录原因(AC5:不假绿、不 FAIL 冒充)。"""
    if not (squash_root / rel_bin).is_file():
        pytest.skip(f"冒烟样本二进制不存在(解包树缺失或不完整): {squash_root / rel_bin}")


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
    image = _require_exec_image()
    pins = _load_pins()
    rc, out, err = run_docker(
        image,
        ["-c",
         "cat /usr/local/share/fw-qemu-exec/BUILD-INFO.txt && "
         "dpkg-query -W -f='dpkg: ${Version}\\n' qemu-user-static && "
         "qemu-arm-static --version | head -1 && "
         "qemu-mips-static --version | head -1"],
        entrypoint="bash", network="none", timeout=TEST_TIMEOUT)
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
    image = _require_exec_image()
    _require_smoke_binary(TGT6_SQUASH, "usr/sbin/nvram")
    rc, out, err = run_docker(
        image,
        ["-c", "qemu-arm-static -L /work/tgt6 /work/tgt6/usr/sbin/nvram"],
        mounts=[(TGT6_SQUASH, "/work/tgt6", "ro")],
        entrypoint="bash", network="none", timeout=TEST_TIMEOUT)
    assert rc == 0, f"ARM32 LE 执行失败 rc={rc}: {err}"
    # nvram 的 usage 打到 stderr(冒烟脚本 2>&1 同款口径)
    assert "usage: nvram" in out + err, f"输出不含 usage: {(out + err)[:400]}"


def test_mips32_be_execution() -> None:
    image = _require_exec_image()
    _require_smoke_binary(TGT8_SQUASH, "bin/busybox")
    rc, out, err = run_docker(
        image,
        ["-c", "qemu-mips-static -L /work/tgt8 /work/tgt8/bin/busybox echo hello-from-qemu-exec"],
        mounts=[(TGT8_SQUASH, "/work/tgt8", "ro")],
        entrypoint="bash", network="none", timeout=TEST_TIMEOUT)
    assert rc == 0, f"MIPS32 BE 执行失败 rc={rc}: {err}"
    assert "hello-from-qemu-exec" in out, f"输出不含回显: {out[:400]}"


def test_binfmt_independence_control() -> None:
    """裸跑外来 ELF 应 rc=126(Exec format error):显式调用不依赖 binfmt 注册。

    环境感知(票 17 Comments E):只有确认执行容器所在内核不对 ARM ELF 做
    binfmt 转译,否定对照才算验证通过。已注册转译或无法确认时,明确报告
    原因并以 skip 标"未验证"——rc=255/转译执行不得当作通过,skip 也不计入
    验证成功。判定顺序:
    ① 宿主侧 binfmt_misc 表可读 → 有 enabled 条目按 magic/mask 匹配 ARM32
       小端即"已注册",直接未验证(不跑对照);
    ② 行为探测(权威):裸跑目标,ENOEXEC(rc=126 + Exec format error)才算
       对照成立;被转译(rc=0 或输出带 qemu- 前缀)或其它结果一律未验证。
    """
    image = _require_exec_image()
    _require_smoke_binary(TGT6_SQUASH, "usr/sbin/nvram")
    registered, table_note = _arm_binfmt_registered()
    if registered is True:
        pytest.skip(
            "binfmt 独立性对照未验证(非通过):宿主侧 binfmt_misc 表可见 ARM "
            f"转译条目({table_note}),按宿主与容器同内核判定对照失效;"
            "按票 01 边界不改宿主")
    rc, out, err = run_docker(
        image,
        ["-c", "/work/tgt6/usr/sbin/nvram"],
        mounts=[(TGT6_SQUASH, "/work/tgt6", "ro")],
        entrypoint="bash", network="none", timeout=TEST_TIMEOUT)
    combined = (out + err).strip()
    if rc == 126 and "Exec format error" in combined:
        return  # 对照成立:内核未转译外来 ELF,显式调用不依赖 binfmt
    if rc == 0 or "qemu-" in combined:
        verdict = "裸跑被内核转译给 qemu(已注册 binfmt)"
    else:
        verdict = "裸跑未产生 ENOEXEC,无法确认内核 binfmt 状态"
    pytest.skip(
        "binfmt 独立性对照未验证(非通过):"
        + (f"{table_note};" if table_note else "")
        + f"{verdict};实测 rc={rc},输出 {combined[:200]!r}")


_ARM32LE_HEADER = (
    b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8   # e_ident:ELF32 小端
    + (2).to_bytes(2, "little")                       # e_type = ET_EXEC
    + (40).to_bytes(2, "little")                      # e_machine = EM_ARM
)


def _arm_binfmt_registered(table_dir: Path | None = None) -> tuple[bool | None, str]:
    """读测试进程可见的内核 binfmt_misc 表,判定是否注册 ARM32 小端转译。

    返回 (判定, 说明):True=表可读且有 enabled 条目按 magic/mask 匹配;
    False=表可读且无匹配(含全局 status=disabled);None=表不可读(测试
    进程与容器内核可能不同,如 Docker Desktop 非 WSL2 后端)。按 magic/
    mask 匹配,不依赖条目命名;只读,不修改任何条目。行为层面的最终裁决
    由 test_binfmt_independence_control 的裸跑探测承担——本函数是保守
    预检:宁可漏报"未注册",不误报(误报会让对照假通过)。
    """
    base = Path(table_dir) if table_dir is not None else Path("/proc/sys/fs/binfmt_misc")
    try:
        paths = sorted(base.iterdir())
    except OSError:
        return None, "宿主侧 binfmt_misc 表不可读"
    global_status = ""
    matched: list[str] = []
    for path in paths:
        try:
            text = path.read_text()
        except OSError:
            continue
        if path.name == "status":
            global_status = text.strip()
            continue
        if path.name == "register" or not text.startswith("enabled"):
            continue
        if _entry_matches_arm32le(text):
            matched.append(path.name)
    if global_status == "disabled":
        return False, "binfmt_misc 全局禁用"
    if matched:
        return True, "binfmt_misc 条目: " + ", ".join(matched)
    return False, "宿主侧 binfmt_misc 表可读且无 ARM 条目"


def _entry_matches_arm32le(entry_text: str) -> bool:
    """单条 binfmt_misc 条目是否匹配 ARM32 小端 ELF(按 magic/mask)。"""
    fields: dict[str, str] = {}
    for line in entry_text.splitlines()[1:]:
        key, _, value = line.partition(" ")
        fields[key.strip().rstrip(":")] = value.strip()
    magic_hex = fields.get("magic", "")
    if not magic_hex:
        return False  # 扩展名匹配条目与 ELF 无关
    try:
        magic = bytes.fromhex(magic_hex)
        mask = (bytes.fromhex(fields["mask"]) if fields.get("mask")
                else b"\xff" * len(magic))
        offset = int(fields.get("offset", "0"), 0)
    except ValueError:
        return False  # 形态异常的条目跳过匹配;误漏由行为探测兜底
    if len(mask) < len(magic):
        mask = mask.ljust(len(magic), b"\xff")  # 内核语义:缺省按 0xff
    segment = _ARM32LE_HEADER[offset:offset + len(magic)]
    if not segment:
        return True  # 探测头覆盖不到的偏移:保守当作可能匹配
    overlap = min(len(segment), len(magic))
    return bytes(a & b for a, b in zip(segment[:overlap], mask[:overlap])) \
        == magic[:overlap]


# ---------- 离线:binfmt 注册表解析(无 Docker,始终跑) ----------

# 本机 /proc/sys/fs/binfmt_misc 实测条目原样形状(2026-09-23;解析器夹具)。
_ARM_ENTRY = """enabled
interpreter /usr/bin/qemu-arm
flags: POCF
offset 0
magic 7f454c4601010100000000000000000002002800
mask ffffffffffffff00fffffffffffffffffeffffff
"""
_AARCH64_ENTRY = """enabled
interpreter /usr/bin/qemu-aarch64
flags: POCF
offset 0
magic 7f454c460201010000000000000000000200b700
mask ffffffffffffff00fffffffffffffffffeffffff
"""
_PYTHON_ENTRY = """enabled
interpreter /usr/bin/python3.13
flags:
offset 0
magic f30d0d0a
"""


def _write_binfmt_table(tmp_path: Path, entries: dict[str, str],
                        *, status: str = "enabled") -> Path:
    table = tmp_path / "binfmt_misc"
    table.mkdir(parents=True, exist_ok=True)
    (table / "register").write_text("", encoding="utf-8")
    (table / "status").write_text(status, encoding="utf-8")
    for name, text in entries.items():
        (table / name).write_text(text, encoding="utf-8")
    return table


def test_arm_binfmt_registered_matches_real_arm_entry(tmp_path: Path) -> None:
    verdict, note = _arm_binfmt_registered(
        _write_binfmt_table(tmp_path, {"arm": _ARM_ENTRY}))
    assert verdict is True and "arm" in note


def test_arm_binfmt_registered_ignores_non_arm_entries(tmp_path: Path) -> None:
    verdict, note = _arm_binfmt_registered(_write_binfmt_table(tmp_path, {
        "aarch64": _AARCH64_ENTRY,      # ELF64/e_machine=183:类或机器号不匹配
        "python3.13": _PYTHON_ENTRY,    # 无 mask(缺省 0xff):magic 不是 ELF
    }))
    assert verdict is False and "无 ARM 条目" in note


def test_arm_binfmt_registered_respects_disabled(tmp_path: Path) -> None:
    table = _write_binfmt_table(tmp_path, {"arm": _ARM_ENTRY}, status="disabled")
    verdict, note = _arm_binfmt_registered(table)
    assert verdict is False and "全局禁用" in note


def test_arm_binfmt_registered_ignores_per_entry_disabled(tmp_path: Path) -> None:
    verdict, _ = _arm_binfmt_registered(_write_binfmt_table(tmp_path, {
        "arm": _ARM_ENTRY.replace("enabled", "disabled", 1)}))
    assert verdict is False


def test_arm_binfmt_registered_unreadable_table_is_indeterminate(tmp_path: Path) -> None:
    verdict, note = _arm_binfmt_registered(tmp_path / "no-such-dir")
    assert verdict is None and "不可读" in note


def test_arm_binfmt_registered_partial_mask_pad_and_offset(tmp_path: Path) -> None:
    # mask 短于 magic:缺省按 0xff 补齐(内核语义)→ 仍判匹配
    short_mask = _ARM_ENTRY.replace(
        "mask ffffffffffffff00fffffffffffffffffeffffff", "mask ffffffffffffff00")
    verdict, _ = _arm_binfmt_registered(
        _write_binfmt_table(tmp_path / "a", {"arm": short_mask}))
    assert verdict is True
    # offset 大到探测头(ELF 头 20 字节)覆盖不到:保守判可能匹配,不当"未注册"
    far_offset = _ARM_ENTRY.replace("offset 0", "offset 64")
    verdict, _ = _arm_binfmt_registered(
        _write_binfmt_table(tmp_path / "b", {"arm": far_offset}))
    assert verdict is True


# ---------- 真实容器:基础镜像不回归(AC3) ----------

def test_base_image_no_qemu_and_tools_intact() -> None:
    """firm_audit/sandbox 保持零 qemu(结构性隔离:sandbox_verify 无法启动 QEMU),
    且原有工具入口健在;深层工具行为由既有 CLI 工具门控套件覆盖。"""
    base_image = _load_pins()["BASE_IMAGE"]
    if not docker_available(base_image):
        pytest.skip(f"基础镜像 {base_image} 不可用")
    rc, out, err = run_docker(
        base_image,
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

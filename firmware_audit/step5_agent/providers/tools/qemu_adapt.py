"""票 18:预定义环境适配模板(基础目录/配置文件/夹具/stdin + 有限 NVRAM 读取)。

本模块是适配声明的解析、校验、固化与记账形态的单一出处;会话工具
(qemu_session)在开启会话时调用,声明在会话期固化,执行期不可更改
(spec:"每次会话从原始目标和显式声明的适配材料干净重建")。

边界(ADR-0013 + 票 02/18 AC):
- 适配值逐项有来源:NVRAM 值的来源引用是必填声明,缺失即准备阻塞;
  测试夹具记 source="declared_test_input"(模型构造的测试输入),与
  "设备真实配置"(固件材料,带文件/行引用)分开,不互冒充。
- NVRAM 模板只覆盖 /dev/nvram 系已核实读取接口(nvram_get/bcm_nvram_get,
  票 02 三方反汇编一致;本票在真实 PRoot/QEMU 后端实测):适配桩
  (docker/nvram-shim)在 syscall 边界模拟缺失的内核驱动后端,真实固件库
  代码原样执行。set/unset/commit/getall 与 envram(MTD)系不在支持表。
- 未声明键:桩按固件缺失键语义返回 NULL 并把键名写入未决日志
  (运行目录内,宿主可读回);工具读回后在执行记录标注 gap——相关配置面
  行为不得作为设备真实行为结论,不伪造空值或成功。
- bind 目标路径保留字:/session、/dev、/tmp、/host-rootfs 前缀拒绝;
  bind 源固定为容器内已挂载材料,模型不能借声明开放未授权容器程序。
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import posixpath
import re
import shutil
from pathlib import Path

from .base import resolve_within

# ---- 适配桩身份(docker/nvram-shim/build_shim.sh 产物的钉值;漂移拒绝) ----

NVRAM_SHIM_BASENAME = "libnvram_shim.so"
NVRAM_SHIM_SHA256 = "d5bda54811bec49ca376ce4e7d2266feb48bc5e6f0907d36d421b17176170a15"
_SHIM_SOURCE = Path(__file__).resolve().parents[3] / "docker" / "nvram-shim" / NVRAM_SHIM_BASENAME

# 容器内固定形状(与 nvram_shim.c 的常量一一对应,改动必须两侧同步)。
ADAPT_MOUNT = "/session/adapt"
FIXTURES_MOUNT = "/session/fixtures"
RUNTIME_MOUNT = "/session/runtime"
NVRAM_IMAGE_BASENAME = "nvram.img"
NVRAM_UNRESOLVED_BASENAME = "nvram-unresolved.log"
NVRAM_LD_PRELOAD = f"{ADAPT_MOUNT}/{NVRAM_SHIM_BASENAME}"

# 会话内声明上限(防病态输入;超出即准备阻塞,不静默截断)。
MAX_FIXTURES = 32
MAX_FIXTURE_BYTES = 1 << 16
MAX_BINDS = 32
MAX_NVRAM_ENTRIES = 512          # 与 nvram_shim.c MAX_ENTRIES 一致
MAX_NVRAM_VALUE_BYTES = 256
# 映像总字节数上限,与 nvram_shim.c IMAGE_CAP 逐字配对:桩只装载前 64 KiB,
# 超出的已声明键会被静默截断为"未声明"——必须在接受声明前拒绝,不能靠
# 运行期 gap 兜底(声明在会话期固化的契约)。
NVRAM_IMAGE_MAX_BYTES = 65536
NVRAM_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# NVRAM 系库基名(票 02 三方 /dev/nvram 同协议库;预检闸门与家族判定共用)。
NVRAM_FAMILY_BASENAMES = ("libnvram.so", "libCfm.so", "libtpi.so")

# bind 目标保留前缀(guest 视角):/session 是后端挂载命名空间,/dev 是
# 固定设备绑定形状,/tmp 是会话运行目录本体,/host-rootfs 是执行边界。
_RESERVED_GUEST_PREFIXES = ("/session", "/dev", "/tmp", "/host-rootfs")


class AdaptationError(ValueError):
    """适配声明非法;消息区分原因,由会话工具转为准备阻塞。"""


# ---- NVRAM 支持表(票 02 + 票 18 实测;预检与会话共用,单一出处) ----

NVRAM_FAMILY = "dev_nvram"
NVRAM_SUPPORTED_READS = ("nvram_get", "bcm_nvram_get")
NVRAM_UNSUPPORTED_NOTE = (
    "set/unset/commit/getall 不在支持表(写副作用与驱动填充格式未放行);"
    "envram(MTD)系全家族未支持(票 02),不因同名库放行")
NVRAM_PROTOCOL_NOTE = (
    "驱动协议=票 02 反汇编(三方一致):read(fd,name,len+1) 返回 4 字节映像"
    "偏移即命中,其余返回值→NULL;模板桩只模拟该后端,真实固件库代码原样执行")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---- 声明解析 ----

def parse_fixtures(text: str) -> dict[str, bytes]:
    """夹具声明:`<name>=<base64(utf-8)>` 每行一条;来源一律 declared_test_input。"""
    items: dict[str, bytes] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        name, sep, payload = line.partition("=")
        name = name.strip()
        if not sep or not NAME_RE.fullmatch(name):
            raise AdaptationError(f"夹具名非法(须为 [A-Za-z0-9._-]): {name!r}")
        if name in items:
            raise AdaptationError(f"夹具名重复: {name}")
        try:
            content = base64.b64decode(payload.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AdaptationError(f"夹具 {name} 内容不是合法 base64: {exc}") from exc
        if len(content) > MAX_FIXTURE_BYTES:
            raise AdaptationError(
                f"夹具 {name} 超过单文件上限 {MAX_FIXTURE_BYTES} 字节")
        items[name] = content
    if len(items) > MAX_FIXTURES:
        raise AdaptationError(f"夹具数量超过上限 {MAX_FIXTURES}")
    return items


def parse_binds(text: str, root: Path, fixtures: dict[str, bytes]) -> list[dict]:
    """bind 声明:`ro:<guest>=extracted/<rel>` / `ro:<guest>=fixture/<name>` /
    `rw:<guest>=base/<name>` 每行一条。

    ro 源校验存在性与固件根归属;rw 基础目录自动创建在会话运行目录下。
    返回逐项声明(含来源与差异),执行期按容器路径换算 bind。
    """
    binds: list[dict] = []
    seen_guests: set[str] = set()
    seen_bases: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        head, sep, rest = line.partition(":")
        if not sep or head not in ("ro", "rw"):
            raise AdaptationError(
                f"bind 行必须是 ro:<guest>=<源> 或 rw:<guest>=base/<名>: {line!r}")
        guest, sep2, source = rest.partition("=")
        # normpath 折叠 .. 与冗余段(如 /a/../etc 折为 /etc):接受词形等价
        # 声明,但折叠后必须仍是根内规范路径,穿越段不得残留
        guest = posixpath.normpath(guest.strip())
        if not sep2 or not guest.startswith("/"):
            raise AdaptationError(f"bind 目标必须是 guest 内绝对路径: {rest!r}")
        if ".." in guest.split("/"):
            raise AdaptationError(f"bind 目标折叠后仍含 ..: {guest}")
        if any(guest == p or guest.startswith(p + "/")
               for p in _RESERVED_GUEST_PREFIXES):
            raise AdaptationError(
                f"bind 目标命中保留前缀(后端命名空间/设备/运行目录/执行边界): {guest}")
        if guest in seen_guests:
            raise AdaptationError(f"bind 目标重复: {guest}")
        seen_guests.add(guest)
        if head == "ro":
            kind, _, ref = source.partition("/")
            if kind == "extracted":
                rel = source[len("extracted/"):]
                resolved = resolve_within(root, rel) if rel else None
                if resolved is None or not resolved.exists():
                    raise AdaptationError(
                        f"bind 源不存在或越出固件根: {source}")
                digest = (sha256_bytes(resolved.read_bytes())
                          if resolved.is_file() else None)
                binds.append({"mode": "ro", "guest_path": guest,
                              "kind": "extracted", "ref": rel,
                              "sha256": digest})
            elif kind == "fixture":
                name = source[len("fixture/"):]
                if name not in fixtures:
                    raise AdaptationError(f"bind 源引用未声明夹具: {source}")
                binds.append({"mode": "ro", "guest_path": guest,
                              "kind": "fixture", "ref": name,
                              "sha256": sha256_bytes(fixtures[name])})
            else:
                raise AdaptationError(
                    f"ro bind 源必须是 extracted/<路径> 或 fixture/<名>: {source}")
        else:
            kind, _, name = source.partition("/")
            if kind != "base" or not name or not NAME_RE.fullmatch(name):
                raise AdaptationError(
                    f"rw bind 源必须是 base/<名>(可写基础目录): {source}")
            if name in seen_bases:
                raise AdaptationError(f"基础目录名重复: {name}")
            seen_bases.add(name)
            binds.append({"mode": "rw", "guest_path": guest,
                          "kind": "base", "ref": name, "sha256": None})
    if len(binds) > MAX_BINDS:
        raise AdaptationError(f"bind 数量超过上限 {MAX_BINDS}")
    return binds


def parse_nvram_declaration(values_text: str, sources_text: str) -> dict[str, dict]:
    """NVRAM 模板声明:值与来源两份 `key=value` / `key=<来源引用>` 行。

    逐项有来源是机械约束:任一值缺来源、或来源无对应值,都是准备阻塞——
    不伪造空值或成功(ADR-0013;票 18 AC)。
    """
    values: dict[str, str] = {}
    for raw in (values_text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not NVRAM_KEY_RE.fullmatch(key):
            raise AdaptationError(f"NVRAM 键名非法: {key!r}")
        if key in values:
            raise AdaptationError(f"NVRAM 键重复: {key}")
        if not value or len(value.encode("utf-8")) > MAX_NVRAM_VALUE_BYTES:
            raise AdaptationError(
                f"NVRAM {key} 的值缺失或超过 {MAX_NVRAM_VALUE_BYTES} 字节")
        values[key] = value
    sources: dict[str, str] = {}
    for raw in (sources_text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        key, sep, source = line.partition("=")
        key = key.strip()
        if not sep or not key:
            raise AdaptationError(f"NVRAM 来源行必须是 key=<来源引用>: {line!r}")
        if key in sources:
            raise AdaptationError(f"NVRAM 来源键重复: {key}")
        if not source.strip():
            raise AdaptationError(f"NVRAM {key} 的来源引用为空")
        sources[key] = source.strip()
    missing = sorted(set(values) - set(sources))
    orphan = sorted(set(sources) - set(values))
    if missing:
        raise AdaptationError(
            f"NVRAM 值缺来源引用(逐项有来源是硬约束): {', '.join(missing)}")
    if orphan:
        raise AdaptationError(
            f"NVRAM 来源引用没有对应值声明: {', '.join(orphan)}")
    if len(values) > MAX_NVRAM_ENTRIES:
        raise AdaptationError(f"NVRAM 值数量超过桩上限 {MAX_NVRAM_ENTRIES}")
    return {key: {"value": value, "source": sources[key]}
            for key, value in values.items()}


def build_nvram_image(values: dict[str, dict]) -> bytes:
    """模板映像:`k=v\\0` 串表(getall 同款格式,票 02),键序字典序确定。

    映像是声明值的固化形态,sha256 入台账;桩按条目起始偏移应答驱动协议。
    """
    ordered = sorted(values)
    chunks: list[bytes] = []
    for key in ordered:
        entry = f"{key}={values[key]['value']}".encode("utf-8")
        if b"\x00" in entry:
            raise AdaptationError(f"NVRAM {key} 的值含 NUL 字节")
        chunks.append(entry + b"\x00")
    image = b"".join(chunks)
    if len(image) > NVRAM_IMAGE_MAX_BYTES:
        # 桩只装载前 IMAGE_CAP 字节,超限条目会静默降级——声明期拒绝
        raise AdaptationError(
            f"NVRAM 模板映像共 {len(image)} 字节,超过桩装载上限 "
            f"{NVRAM_IMAGE_MAX_BYTES}(与 nvram_shim.c IMAGE_CAP 配对)")
    return image


# ---- 会话期固化 ----

def shim_artifact() -> Path:
    """库内适配桩产物路径;缺失即准备阻塞(不静默换桩)。"""
    if not _SHIM_SOURCE.is_file():
        raise AdaptationError(
            f"适配桩产物缺失: {_SHIM_SOURCE}(先运行 docker/nvram-shim/build_shim.sh)")
    digest = sha256_bytes(_SHIM_SOURCE.read_bytes())
    if digest != NVRAM_SHIM_SHA256:
        raise AdaptationError(
            "适配桩产物与钉值不一致(sha256 漂移,拒绝装配): "
            f"实际 {digest} 期望 {NVRAM_SHIM_SHA256};"
            "如为有意重建,请同步 NVRAM_SHIM_SHA256 并走评审")
    return _SHIM_SOURCE


def materialize(session_dir: Path, root: Path, *, fixtures: dict[str, bytes],
                binds: list[dict], nvram: dict[str, dict] | None) -> dict:
    """把声明固化为会话工件并返回台账形态(逐项来源/差异/身份)。

    - 夹具写 session_dir/fixtures/<name>(容器 ro 挂 /session/fixtures);
    - 基础目录建 session_dir/runtime/base/<name>(随运行目录 rw 挂载);
    - NVRAM:适配桩(钉值校验后复制)与模板映像写 session_dir/adapt
      (容器 ro 挂 /session/adapt),执行期经 PRoot bind 进 guest。
    覆盖固件根内已有路径的 bind 逐项记录被遮蔽原件(difference 台账)。
    """
    declaration: dict = {}
    if fixtures:
        fixtures_dir = session_dir / "fixtures"
        fixtures_dir.mkdir(parents=True, exist_ok=True)
        declaration["fixtures"] = [{
            "name": name, "sha256": sha256_bytes(content),
            "size_bytes": len(content), "source": "declared_test_input",
        } for name, content in sorted(fixtures.items())]
        for name, content in fixtures.items():
            (fixtures_dir / name).write_bytes(content)
    if binds:
        entries: list[dict] = []
        for bind in binds:
            entry = dict(bind)
            if bind["mode"] == "rw":
                (session_dir / "runtime" / "base" / bind["ref"]).mkdir(
                    parents=True, exist_ok=True)
            else:
                original = root / bind["guest_path"].lstrip("/")
                if original.exists():
                    entry["shadowed_original"] = {
                        "guest_path": bind["guest_path"],
                        "exists_in_firmware_root": True,
                        "sha256": (sha256_bytes(original.read_bytes())
                                   if original.is_file() else None),
                        "note": "模板 bind 覆盖固件根内已有路径;原件只读未动",
                    }
            entries.append(entry)
        declaration["binds"] = entries
    if nvram is not None:
        adapt_dir = session_dir / "adapt"
        adapt_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(shim_artifact(), adapt_dir / NVRAM_SHIM_BASENAME)
        image = build_nvram_image(nvram)
        (adapt_dir / NVRAM_IMAGE_BASENAME).write_bytes(image)
        declaration["nvram"] = {
            "family": NVRAM_FAMILY,
            "supported_reads": list(NVRAM_SUPPORTED_READS),
            "values_count": len(nvram),
            "values": {k: v["source"] for k, v in sorted(nvram.items())},
            "image_sha256": sha256_bytes(image),
            "shim_sha256": NVRAM_SHIM_SHA256,
            "shim": ("docker/nvram-shim(ARM32 LE,syscall 边界模拟 /dev/nvram "
                     "驱动后端;真实固件库代码原样执行)"),
            "driver_protocol": NVRAM_PROTOCOL_NOTE,
            "unsupported": NVRAM_UNSUPPORTED_NOTE,
            "unresolved_log": f"runtime/{NVRAM_UNRESOLVED_BASENAME}",
            "unresolved_semantics": ("未声明键:桩按固件缺失键语义应答 NULL,"
                                     "键名入未决日志;相关配置面行为不得作为"
                                     "设备真实行为结论"),
        }
    return declaration


# ---- 执行期换算 ----

def proot_binds(binds: list[dict], *, with_nvram: bool) -> list[str]:
    """执行期 PRoot bind 参数(容器路径:guest 路径;每次执行新建实例)。"""
    argv: list[str] = []
    for bind in binds:
        if bind["kind"] == "extracted":
            source = f"/session/firmware/{bind['ref']}"
        elif bind["kind"] == "fixture":
            source = f"{FIXTURES_MOUNT}/{bind['ref']}"
        else:
            source = f"{RUNTIME_MOUNT}/base/{bind['ref']}"
        argv += ["-b", f"{source}:{bind['guest_path']}"]
    if with_nvram:
        argv += ["-b", f"{ADAPT_MOUNT}/{NVRAM_SHIM_BASENAME}:{NVRAM_LD_PRELOAD}"]
        argv += ["-b", f"{ADAPT_MOUNT}/{NVRAM_IMAGE_BASENAME}:"
                       f"{ADAPT_MOUNT}/{NVRAM_IMAGE_BASENAME}"]
    return argv


def container_mounts(session_dir: Path, *, with_fixtures: bool,
                     with_nvram: bool) -> list[tuple[Path, str, str]]:
    """会话容器级挂载(开启时固化;逐执行 bind 由 proot_binds 换算)。"""
    mounts: list[tuple[Path, str, str]] = []
    if with_fixtures:
        mounts.append((session_dir / "fixtures", FIXTURES_MOUNT, "ro"))
    if with_nvram:
        mounts.append((session_dir / "adapt", ADAPT_MOUNT, "ro"))
    return mounts


def consume_unresolved_keys(runtime_dir: Path) -> list[str]:
    """读回并清除未决键日志(逐执行消费,避免会话内跨执行串账)。

    日志由适配桩追加写在运行目录(会话持久);缺失 = 无未决键,不是错误。
    """
    path = runtime_dir / NVRAM_UNRESOLVED_BASENAME
    if not path.is_file():
        return []
    keys: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key = line.strip()
        if key and key not in keys:
            keys.append(key)
    path.unlink()
    return keys


_ENVGRAM_PREFIX = "envram_"


def nvram_family_for_target(needed: list[str], undefined: list[str],
                            exported: list[str]) -> dict:
    """目标级 NVRAM 家族判定(票 18 口径;库基名只作闸门,家族看符号)。

    - undefined 含已核实读取接口 → dev_nvram(可解锁,仅实测接口);
    - undefined 含 envram_* → envram 系在用(未支持;相关调用运行期如实失败);
    - 两类并存 → mixed(模板覆盖 /dev/nvram 读取,envram 调用将失败);
    - NEEDED 命中 NVRAM 系基名但导入/导出符号都不能定家族 → unknown
      (维持不判定/阻塞,不因同名库放行);
    - NEEDED 无 NVRAM 系基名 → none(无需模板)。
    """
    libs = sorted({lib.split("/")[-1] for lib in needed
                   if lib.split("/")[-1] in NVRAM_FAMILY_BASENAMES})
    und_supported = sorted(set(undefined) & set(NVRAM_SUPPORTED_READS))
    und_envram = sorted({s for s in undefined if s.startswith(_ENVGRAM_PREFIX)})
    if not libs:
        return {"family": "none", "libs": [], "undefined_supported": [],
                "undefined_envram": [], "note": None}
    exported_set = set(exported)
    provider_confirmed = bool(exported_set & set(NVRAM_SUPPORTED_READS))
    if und_supported and und_envram:
        return {"family": "mixed", "libs": libs,
                "undefined_supported": und_supported,
                "undefined_envram": und_envram,
                "note": ("目标同时调用 /dev/nvram 系读取与 envram(MTD)系;"
                         "模板只覆盖前者,envram 调用将如实失败")}
    if und_supported:
        return {"family": NVRAM_FAMILY, "libs": libs,
                "undefined_supported": und_supported,
                "undefined_envram": [],
                "note": "导入已核实读取接口;"
                        + ("提供库导出符号印证" if provider_confirmed
                           else "提供库符号未能印证(仍按导入符号解锁实测接口)")}
    if und_envram:
        return {"family": "envram", "libs": libs,
                "undefined_supported": [],
                "undefined_envram": und_envram,
                "note": "目标只调用 envram(MTD)系;未支持族,不因同名库放行"}
    return {"family": "unknown", "libs": libs,
            "undefined_supported": [], "undefined_envram": [],
            "note": ("库基名命中 NVRAM 系但导入符号不可判定家族;"
                     "维持不判定/阻塞(票 18 口径)")}

"""票 05(qemu-user-mode-experiments):qemu_precheck 预检动词与工具契约。

两层接缝(spec.md Testing Decisions):
- 离线:手构最小 ELF 夹具 + Docker 替身(替换 _facility_check,零容器调用),
  覆盖参数契约、角色授权、结果分类枚举、路径边界、模板适用性、原始信息
  保留与限制句纪律;
- 真实:qemu-exec 镜像内真实预检 target/6(usr/sbin/nvram,ARM32 LE)与
  target/8(bin/busybox,MIPS32 BE)各一样本——缺镜像/缺样本 SKIP 并记录
  原因,不假绿。

预检红线(spec/ADR-0013/票 04 纪律,本文件逐条钉住):
- 不执行目标、不运行固件或其加载器、不创建会话(唯一容器调用是镜像内
  qemu 二进制自报版本,不触固件字节);
- 架构/解释器检查通过 ≠ 子进程链能力已验证(票 04:ARM 链受阻、根因未
  定论;报告不得宣称链可用);
- 未核实的失败根因不作定论,矩阵外架构只记"不在首批矩阵",不宣称永久
  不可行;
- sandbox_verify 路径结构性无法触达 QEMU 执行(基础镜像零 qemu,票 03)。
"""
from __future__ import annotations

import struct
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import (
    ReplayPolicy,
    ToolAuthorizationError,
    ToolContract,
    make_tools,
    tool_contracts,
    tool_names_for_role,
)
from firmware_audit.step5_agent.providers.tools.base import ToolContext
from firmware_audit.step5_agent.providers.tools.qemu_base import (
    PRECHECK_RESULT_CLASSES,
    QEMU_EXEC_IMAGE,
    QemuResultClass,
)
from firmware_audit.step5_agent.providers.tools.qemu_precheck import (
    ElfParseError,
    QemuPrecheckTool,
    parse_elf_runtime,
)
from firmware_audit.step5_agent.providers.tools.sandbox_verify import (
    _INTERPRETERS,
    SandboxVerifyTool,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PINS_PATH = REPO_ROOT / "firmware_audit" / "docker" / "qemu-exec" / "pins.env"

# 真实样本(票 01/03 实测代表二进制;workspace 工件,gitignored)
TGT6_SQUASH = (REPO_ROOT / "target/6/process/extracted/"
               "000000_DIR890LA1_FW111b02_20170519_beta01.bin.extracted/"
               "1C0094/squashfs-root")
TGT8_SQUASH = (REPO_ROOT / "target/8/process/extracted/"
               "000000_openwrt-19.07.0-ath79-generic-tplink_archer-c7-v2-"
               "squashfs-sysupgrade.bin.extracted/185BC4/squashfs-root")

TEST_TIMEOUT = 180


# ---------- ELF32 夹具构造(离线,零 Docker) ----------

_PT_LOAD, _PT_DYNAMIC, _PT_INTERP = 1, 2, 3
_DT_NULL, _DT_NEEDED, _DT_STRTAB = 0, 1, 5


def elf32_blob(*, machine: int, little: bool = True, interp: str | None = None,
               needed: list[str] | None = None,
               with_dynamic: bool = True) -> bytes:
    """最小 ELF32 执行镜像:PT_LOAD 全文件恒等映射 + 可选 PT_INTERP/PT_DYNAMIC。

    interp=None 且 needed=[] 且 with_dynamic=False → 纯静态形态。
    """
    needed = list(needed or [])
    end = "<" if little else ">"
    has_interp = interp is not None
    phnum = 1 + int(has_interp) + int(with_dynamic)
    ehsize, phentsize = 52, 32
    off = ehsize + phnum * phentsize

    interp_blob = b""
    if has_interp:
        interp_blob = interp.encode() + b"\x00"
        interp_off = off
        off += len(interp_blob)

    strtab_blob = b"\x00" + "".join(f"{n}\x00" for n in needed).encode()
    strtab_off = strtab_vaddr = off
    off += len(strtab_blob)

    name_offs: list[int] = []
    cur = 1
    for n in needed:
        name_offs.append(cur)
        cur += len(n) + 1

    dyn_parts = [struct.pack(end + "iI", _DT_NEEDED, o) for o in name_offs]
    if with_dynamic:
        dyn_parts.append(struct.pack(end + "iI", _DT_STRTAB, strtab_vaddr))
        dyn_parts.append(struct.pack(end + "iI", _DT_NULL, 0))
    dyn_blob = b"".join(dyn_parts)
    dyn_off = off

    loads_sz = dyn_off + len(dyn_blob)
    phdrs = [struct.pack(end + "IIIIIIII", _PT_LOAD, 0, 0, 0, loads_sz, loads_sz, 5, 0x1000)]
    if has_interp:
        phdrs.append(struct.pack(end + "IIIIIIII", _PT_INTERP, interp_off,
                                 interp_off, 0, len(interp_blob), 0, 4, 1))
    if with_dynamic:
        phdrs.append(struct.pack(end + "IIIIIIII", _PT_DYNAMIC, dyn_off,
                                 dyn_off, 0, len(dyn_blob), 0, 6, 4))

    ident = b"\x7fELF" + bytes([1, 1 if little else 2, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack(end + "HHIIIIIHHHHHH",
                               2, machine, 1, 0, ehsize, 0, 0,
                               ehsize, phentsize, phnum, 0, 0, 0)
    return ehdr + b"".join(phdrs) + interp_blob + strtab_blob + dyn_blob


def _fake_loader() -> bytes:
    return elf32_blob(machine=40)


@contextmanager
def stub_facility(*, available: bool = True,
                  version: str = "qemu-arm-static version 5.2.0"):
    """Docker 替身:替换 _facility_check,记录调用并返回固定设施状态。"""
    calls: list[str] = []

    def fake(self, qemu_binary: str) -> dict:
        calls.append(qemu_binary)
        return {
            "image": QEMU_EXEC_IMAGE,
            "qemu_binary": qemu_binary,
            "available": available,
            "version": version if available else None,
            "detail": "" if available else "镜像不可用(Docker 替身)",
            "check": "executed",
        }

    original = QemuPrecheckTool._facility_check
    QemuPrecheckTool._facility_check = fake
    try:
        yield calls
    finally:
        QemuPrecheckTool._facility_check = original


def _make_workspace(tmp: Path, *, blob: bytes,
                    loader: str | None, libs: dict[str, bytes]) -> tuple[Path, str, str]:
    """tmp 下建 extracted/fw/{target.elf, squashfs-root/lib/...};返回 (process_dir, file_ref, root_ref)。"""
    extracted = tmp / "extracted"
    fw_root = extracted / "fw" / "squashfs-root"
    (fw_root / "lib").mkdir(parents=True)
    (extracted / "fw" / "target.elf").write_bytes(blob)
    if loader is not None:
        loader_path = fw_root / loader.lstrip("/")
        loader_path.parent.mkdir(parents=True, exist_ok=True)
        loader_path.write_bytes(_fake_loader())
    for name, content in libs.items():
        (fw_root / "lib" / name).write_bytes(content)
    return tmp, "fw/target.elf", "fw/squashfs-root"


def _run_precheck(process_dir: Path, file_ref: str, firmware_root: str) -> object:
    tools = make_tools(ToolContext(process_dir=process_dir))
    return tools["qemu_precheck"].execute(file_ref=file_ref, firmware_root=firmware_root)


ARM_LE_LOADER = "/lib/ld-uClibc.so.0"


# ---------- 离线:解析器纯函数 ----------

def test_parse_elf_arm32le() -> list[str]:
    fails: list[str] = []
    info = parse_elf_runtime(elf32_blob(machine=40, interp=ARM_LE_LOADER,
                                        needed=["libnvram.so", "libc.so.0"]))
    if (info["bits"], info["endianness"], info["e_machine"]) != (32, "little", 40):
        fails.append(f"ARM32LE 三元组不符: {info}")
    if info["interp"] != ARM_LE_LOADER:
        fails.append(f"PT_INTERP 解析不符: {info['interp']}")
    if info["needed"] != ["libnvram.so", "libc.so.0"]:
        fails.append(f"DT_NEEDED 解析不符: {info['needed']}")
    return fails


def test_parse_elf_mips32be_and_static() -> list[str]:
    fails: list[str] = []
    be = parse_elf_runtime(elf32_blob(machine=8, little=False,
                                      interp="/lib/ld-musl-mips-sf.so.1",
                                      needed=["libgcc_s.so.1", "libc.so"]))
    if (be["bits"], be["endianness"], be["e_machine"]) != (32, "big", 8):
        fails.append(f"MIPS32BE 三元组不符: {be}")
    if be["interp"] != "/lib/ld-musl-mips-sf.so.1" or be["needed"] != ["libgcc_s.so.1", "libc.so"]:
        fails.append(f"MIPS32BE interp/needed 不符: {be}")
    static = parse_elf_runtime(elf32_blob(machine=40, with_dynamic=False))
    if static["interp"] is not None or static["needed"]:
        fails.append(f"静态形态应无 interp/needed: {static}")
    return fails


def test_parse_elf_rejects_garbage() -> list[str]:
    fails: list[str] = []
    for blob in (b"MZ garbage", b"", b"\x7fELFtrunc"):
        try:
            parse_elf_runtime(blob)
        except ElfParseError:
            continue
        fails.append(f"垃圾字节应抛 ElfParseError: {blob[:8]!r}")
    return fails


# ---------- 离线:参数契约(AC1) ----------

def test_precheck_params_contract() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        tools = make_tools(ToolContext(process_dir=Path(td)))
        t = tools["qemu_precheck"]
        # 结构化声明单一来源:必选参数 + JSON 骨架文档
        for name in ("file_ref", "firmware_root"):
            if not t.params.get(name, {}).get("required"):
                fails.append(f"{name} 应为必选参数: {t.params}")
        if "{" not in t.params_doc or "file_ref" not in t.params_doc:
            fails.append(f"params_doc 应含 JSON 骨架与参数名: {t.params_doc[:120]}")
        # 缺失必选 / 未知参数 / 类型错误 → 优雅错误
        r = t.execute()
        if r.ok or "缺失必选参数: file_ref, firmware_root" not in (r.error or ""):
            fails.append(f"缺失必选应优雅报错: {r.error}")
        r = t.execute(file_ref="a", firmware_root="b", argv0="sh")
        if r.ok or "未知参数 argv0" not in (r.error or ""):
            fails.append(f"未知参数应优雅报错: {r.error}")
        r = t.execute(file_ref=123, firmware_root="b")
        if r.ok or "类型错误" not in (r.error or ""):
            fails.append(f"类型错误应优雅报错: {r.error}")
    return fails


# ---------- 离线:结果分类枚举(AC3) ----------

def test_result_class_enum_is_spec_eight() -> list[str]:
    """八类失败分类 + 预检通过态 ok;预检只发出其子集。"""
    fails: list[str] = []
    expected_eight = {
        "normal_exit", "nonzero_exit", "target_signal", "timeout",
        "prep_blocked", "dependency_blocked", "facility_failure",
        "cleanup_uncertain",
    }
    values = {c.value for c in QemuResultClass}
    missing = expected_eight - values
    if missing:
        fails.append(f"枚举缺 spec 八类: {sorted(missing)}")
    if "ok" not in values:
        fails.append("枚举缺预检通过态 ok")
    if {c.value for c in PRECHECK_RESULT_CLASSES} - expected_eight:
        fails.append("预检子集只能是八类失败分类的子集")
    # 执行侧类不是预检子集(预检不执行目标)
    for exec_only in ("normal_exit", "nonzero_exit", "target_signal", "timeout",
                      "cleanup_uncertain"):
        if QemuResultClass(exec_only) in PRECHECK_RESULT_CLASSES:
            fails.append(f"执行侧分类 {exec_only} 不得进预检子集")
    return fails


# ---------- 离线:预检行为(Docker 替身,零容器调用) ----------

def test_precheck_happy_path_arm32le() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=elf32_blob(machine=40, interp=ARM_LE_LOADER,
                                      needed=["libc.so.0"]),
            loader=ARM_LE_LOADER, libs={"libc.so.0": _fake_loader()})
        with stub_facility() as calls:
            r = _run_precheck(ws, fref, rref)
        if not r.ok:
            fails.append(f"预检执行应成功: {r.error}")
            return fails
        d = r.data or {}
        if d.get("result_class") != "ok":
            fails.append(f"全条件满足应 ok, got {d.get('result_class')}: {d.get('blockers')}")
        if d.get("mode") != "precheck":
            fails.append("报告应显式标 mode=precheck(不执行不建会话)")
        arch = d.get("architecture") or {}
        if arch.get("qemu_binary") != "qemu-arm-static" or arch.get("matrix") != "first_batch":
            fails.append(f"架构档案不符: {arch}")
        if calls != ["qemu-arm-static"]:
            fails.append(f"设施核查应恰一次且查 qemu-arm-static: {calls}")
        if not (d.get("execution_facility") or {}).get("available"):
            fails.append(f"设施状态应可用: {d.get('execution_facility')}")
        # 限制句纪律:通过≠子进程链可用(票 04)
        joined = " ".join(d.get("limitations") or [])
        if "子进程链" not in joined:
            fails.append(f"limitations 必须声明子进程链未验证: {joined}")
        if "不执行" not in joined or "会话" not in joined:
            fails.append(f"limitations 必须声明不执行目标不创建会话: {joined}")
    return fails


def test_precheck_static_binary_ok() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=elf32_blob(machine=40, with_dynamic=False),
            loader=None, libs={})
        with stub_facility():
            r = _run_precheck(ws, fref, rref)
        d = r.data or {}
        if (d or {}).get("result_class") != "ok":
            fails.append(f"静态二进制应 ok(无加载器/依赖需求): {d}")
        interp = (d or {}).get("interpreter") or {}
        if interp.get("requested") is not None:
            fails.append(f"静态形态 interpreter.requested 应为 None: {interp}")
    return fails


def test_precheck_missing_loader_dependency_blocked() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=elf32_blob(machine=40, interp=ARM_LE_LOADER, needed=[]),
            loader=None, libs={})
        with stub_facility():
            r = _run_precheck(ws, fref, rref)
        d = r.data or {}
        if d.get("result_class") != "dependency_blocked":
            fails.append(f"缺加载器应 dependency_blocked: {d.get('result_class')}")
        if not any(b.get("check") == "interpreter" for b in d.get("blockers") or []):
            fails.append(f"阻塞项应含 interpreter 检查: {d.get('blockers')}")
    return fails


def test_precheck_missing_needed_lib_dependency_blocked() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=elf32_blob(machine=40, interp=ARM_LE_LOADER,
                                      needed=["libc.so.0", "libmissing.so"]),
            loader=ARM_LE_LOADER, libs={"libc.so.0": _fake_loader()})
        with stub_facility():
            r = _run_precheck(ws, fref, rref)
        d = r.data or {}
        if d.get("result_class") != "dependency_blocked":
            fails.append(f"缺 NEEDED 库应 dependency_blocked: {d.get('result_class')}")
        deps = d.get("dependencies") or {}
        if deps.get("missing") != ["libmissing.so"]:
            fails.append(f"missing 应精确记录缺失库: {deps.get('missing')}")
        # 原始信息保留不静默丢弃:完整 needed 清单 + 已解析映射仍在报告
        if deps.get("needed") != ["libc.so.0", "libmissing.so"]:
            fails.append(f"原始 needed 清单应保留: {deps.get('needed')}")
        if "libc.so.0" not in (deps.get("resolved") or {}):
            fails.append(f"已解析库映射应保留: {deps.get('resolved')}")
    return fails


def test_precheck_nvram_family_template_blocker() -> list[str]:
    """票 02 移交:NEEDED 含 NVRAM 系库 → 需模板注入;支持表未定稿(票 11)= 运行阻塞;
    /dev/nvram 系与 envram(MTD)系家族归属预检不判定(未核实不定论)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=elf32_blob(machine=40, interp=ARM_LE_LOADER,
                                      needed=["libnvram.so", "libc.so.0"]),
            loader=ARM_LE_LOADER,
            libs={"libnvram.so": _fake_loader(), "libc.so.0": _fake_loader()})
        with stub_facility():
            r = _run_precheck(ws, fref, rref)
        d = r.data or {}
        if d.get("result_class") != "dependency_blocked":
            fails.append(f"NVRAM 系需模板(未定稿)应 dependency_blocked: {d.get('result_class')}")
        tpl = d.get("template_applicability") or {}
        if "libnvram.so" not in (tpl.get("nvram_family_needed") or []):
            fails.append(f"模板适用性应记录 NVRAM 系库: {tpl}")
        detail = tpl.get("detail") or ""
        if "票 11" not in detail or "不判定" not in detail:
            fails.append(f"模板阻塞 detail 应含支持表未定稿与家族不判定: {detail}")
        # 库本身在固件根内找得到——阻塞原因必须归模板而非库缺失
        if "libnvram.so" not in (d.get("dependencies") or {}).get("resolved", {}):
            fails.append("libnvram.so 在根内存在,不得误报为库缺失")
    return fails


def test_precheck_unsupported_arch_prep_blocked_no_facility_call() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=elf32_blob(machine=8, little=True,  # MIPS 小端:矩阵外
                                      interp="/lib/ld-musl-mipsel.so.1",
                                      needed=["libc.so"]),
            loader="/lib/ld-musl-mipsel.so.1", libs={"libc.so": _fake_loader()})
        with stub_facility() as calls:
            r = _run_precheck(ws, fref, rref)
        d = r.data or {}
        if d.get("result_class") != "prep_blocked":
            fails.append(f"矩阵外架构应 prep_blocked: {d.get('result_class')}")
        arch = d.get("architecture") or {}
        if arch.get("matrix") != "unsupported":
            fails.append(f"矩阵外应标 unsupported: {arch}")
        detail = " ".join(b.get("detail", "") for b in d.get("blockers") or [])
        if "首批矩阵" not in detail or "不据此宣称" not in detail:
            fails.append(f"阻塞 detail 应指明首批矩阵口径并声明不外推: {detail}")
        if calls:
            fails.append(f"架构未入选时不得发起设施核查: {calls}")
    return fails


def test_precheck_not_elf_prep_blocked() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=b"#!/bin/sh\necho hi\n", loader=None, libs={})
        with stub_facility() as calls:
            r = _run_precheck(ws, fref, rref)
        d = r.data or {}
        if d.get("result_class") != "prep_blocked":
            fails.append(f"非 ELF 应 prep_blocked: {d.get('result_class')}")
        if calls:
            fails.append(f"非 ELF 不得发起设施核查: {calls}")
    return fails


def test_precheck_facility_failure() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=elf32_blob(machine=40, interp=ARM_LE_LOADER,
                                      needed=["libc.so.0"]),
            loader=ARM_LE_LOADER, libs={"libc.so.0": _fake_loader()})
        with stub_facility(available=False):
            r = _run_precheck(ws, fref, rref)
        d = r.data or {}
        if d.get("result_class") != "facility_failure":
            fails.append(f"设施不可用应 facility_failure: {d.get('result_class')}")
        # 静态检查照常完成并保留(不因设施失败静默丢弃)
        if (d.get("dependencies") or {}).get("needed") != ["libc.so.0"]:
            fails.append(f"设施失败时静态检查结果应保留: {d.get('dependencies')}")
    return fails


def test_precheck_path_boundary_no_execution() -> list[str]:
    """越界/缺失路径 → 准备阻塞;全程零容器调用(替身记录为空)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        (ws / "extracted" / "fw").mkdir(parents=True)
        tools = make_tools(ToolContext(process_dir=ws))
        t = tools["qemu_precheck"]
        with stub_facility() as calls:
            for kwargs in (
                {"file_ref": "../../etc/passwd", "firmware_root": "fw"},
                {"file_ref": "fw/target.elf", "firmware_root": "../../"},
                {"file_ref": "fw/absent.elf", "firmware_root": "fw"},
                {"file_ref": "fw/target.elf", "firmware_root": "fw/no-such-root"},
            ):
                (ws / "extracted" / "fw" / "target.elf").write_bytes(
                    elf32_blob(machine=40))
                r = t.execute(**kwargs)
                d = r.data or {}
                if r.ok is False and r.data is None:
                    fails.append(f"{kwargs} 应产出预检报告而非契约错误: {r.error}")
                elif d.get("result_class") != "prep_blocked":
                    fails.append(f"{kwargs} 应 prep_blocked: {d.get('result_class')}")
        if calls:
            fails.append(f"路径边界拦截不得发起任何容器调用: {calls}")
    return fails


def test_precheck_accepts_extracted_prefix_refs() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ws, fref, rref = _make_workspace(
            Path(td), blob=elf32_blob(machine=40, interp=ARM_LE_LOADER,
                                      needed=["libc.so.0"]),
            loader=ARM_LE_LOADER, libs={"libc.so.0": _fake_loader()})
        with stub_facility():
            r = _run_precheck(ws, f"extracted/{fref}", f"extracted/{rref}")
        d = r.data or {}
        if (d or {}).get("result_class") != "ok":
            fails.append(f"带 extracted/ 前缀的工具路径引用应放行(ADR-0008): {d}")
    return fails


# ---------- 离线:注册表角色授权(AC2) ----------

def test_precheck_registry_contract() -> list[str]:
    fails: list[str] = []
    contracts = tool_contracts()
    c = contracts.get("qemu_precheck")
    if c is None:
        return ["注册表缺 qemu_precheck"]
    if isinstance(c, ToolContract):
        if set(c.roles) != {"analysis", "verification"}:
            fails.append(f"qemu_precheck 角色应为 analysis/verification: {c.roles}")
        if c.replay_policy is not ReplayPolicy.READ_ONLY_IDEMPOTENT:
            fails.append(f"预检是只读幂等检查,重放策略应为 READ_ONLY_IDEMPOTENT: {c.replay_policy}")
    try:
        tool_names_for_role("recon")  # 未知角色校验的同时取浅层清单
    except ToolAuthorizationError:
        fails.append("tool_names_for_role('recon') 不应抛错")
    if "qemu_precheck" in tool_names_for_role("recon"):
        fails.append("recon 不得看见 qemu_precheck")
    try:
        authorize = __import__(
            "firmware_audit.step5_agent.providers.tools", fromlist=["authorize_tool"]
        ).authorize_tool
        authorize("recon", "qemu_precheck")
    except ToolAuthorizationError as exc:
        detail = str(exc)
        if "recon" not in detail or "qemu_precheck" not in detail:
            fails.append(f"拒绝文案应含角色与工具名: {detail}")
    else:
        fails.append("recon 调用 qemu_precheck 应被契约拒绝")
    for role in ("analysis", "verification"):
        if "qemu_precheck" not in tool_names_for_role(role):
            fails.append(f"{role} 应可见 qemu_precheck")
    with tempfile.TemporaryDirectory() as td:
        for role, want in (("recon", False), ("analysis", True), ("verification", True)):
            provisioned = make_tools(ToolContext(process_dir=Path(td)), role=role)
            if ("qemu_precheck" in provisioned) != want:
                fails.append(f"make_tools(role={role}) 对 qemu_precheck 的配置应为 {want}")
    return fails


def test_precheck_image_pin_matches_pins_env() -> list[str]:
    """工具常量 QEMU_EXEC_IMAGE 与 pins.env 钉值同源(防双写漂移,票 03 口径)。"""
    fails: list[str] = []
    if not PINS_PATH.is_file():
        return [f"缺少钉值文件 {PINS_PATH}"]
    pins = {}
    for line in PINS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            pins[key.strip()] = value.strip()
    expected = pins.get("QEMU_EXEC_IMAGE", "")
    if not expected:
        fails.append("pins.env 缺 QEMU_EXEC_IMAGE")
    elif QEMU_EXEC_IMAGE.split(":")[0] != expected.split(":")[0]:
        fails.append(f"QEMU_EXEC_IMAGE 常量 {QEMU_EXEC_IMAGE} 与 pins.env {expected} 不同源")
    return fails


# ---------- 离线:sandbox_verify 结构性隔离(AC2 后半,票 04 约束 4) ----------

def test_sandbox_verify_cannot_reach_qemu() -> list[str]:
    fails: list[str] = []
    # 解释器白名单只有三个脚本解释器,无任何 qemu 入口
    if not set(_INTERPRETERS.values()) <= {"python3", "node", "php"}:
        fails.append(f"sandbox_verify 解释器白名单漂移: {set(_INTERPRETERS.values())}")
    if any("qemu" in name for name in _INTERPRETERS):
        fails.append("sandbox_verify 白名单不得含 qemu 相关入口")
    # 参数面只有 code/language/timeout,不存在可指定镜像/入口/命令的参数
    if set(SandboxVerifyTool.params) != {"code", "language", "timeout"}:
        fails.append(f"sandbox_verify 参数面漂移: {set(SandboxVerifyTool.params)}")
    # 注册表:qemu 执行族与脚本复核是两个独立入口,授权互不重叠
    c = tool_contracts().get("sandbox_verify")
    if c is None:
        fails.append("注册表缺 sandbox_verify")
    elif "qemu_precheck" in set(c.roles):
        fails.append("sandbox_verify 契约不得覆盖 qemu 工具")
    return fails


def test_role_prompts_mention_precheck_scope() -> list[str]:
    """角色指令与工具契约一致(ADR-0013:工具说明解释适用场景)。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.host.analysis import ANALYSIS_SESSION_SYSTEM
    from firmware_audit.step5_agent.host.recon import RECON_SESSION_SYSTEM
    from firmware_audit.step5_agent.host.verification import (
        VERIFICATION_SESSION_SYSTEM,
    )
    if "qemu_precheck" not in ANALYSIS_SESSION_SYSTEM:
        fails.append("analysis 提示词应列明 qemu_precheck 及适用场景")
    if "qemu_precheck" not in VERIFICATION_SESSION_SYSTEM:
        fails.append("verification 提示词应列明 qemu_precheck")
    if "qemu_precheck" in RECON_SESSION_SYSTEM and "不可见" not in RECON_SESSION_SYSTEM:
        fails.append("recon 提示词提及 qemu_precheck 时必须声明不可见")
    return fails


# ---------- 真实:镜像内预检 target/6 + target/8 各一样本(门控) ----------

def _load_pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in PINS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        pins[key.strip()] = value.strip()
    return pins


def _require_exec_image() -> str:
    from firmware_audit.docker.docker_utils import docker_available

    image = _load_pins()["QEMU_EXEC_IMAGE"]
    if not docker_available(image):
        pytest.skip(
            f"Docker 或镜像 {image} 不可用(先运行 "
            "firmware_audit/docker/qemu-exec/build_image.sh 构建)")
    return image


def _require_sample(squash_root: Path, rel_bin: str) -> None:
    if not (squash_root / rel_bin).is_file():
        pytest.skip(f"预检样本二进制不存在(解包树缺失或不完整): {squash_root / rel_bin}")


def _precheck_real(squash_root: Path, rel_bin: str):
    image = _require_exec_image()
    _require_sample(squash_root, rel_bin)
    # squash_root = <target>/<N>/process/extracted/<pkg>.extracted/<offset>/squashfs-root
    process_dir = squash_root.parents[3]  # <target>/<N>/process
    root_rel = squash_root.relative_to(process_dir / "extracted")
    tools = make_tools(ToolContext(process_dir=process_dir))
    return tools["qemu_precheck"].execute(
        file_ref=(root_rel / rel_bin).as_posix(),
        firmware_root=root_rel.as_posix(),
    )


def test_real_precheck_tgt8_busybox_ready() -> None:
    """target/8 busybox(MIPS32 BE/musl):静态条件全过 → ok;不宣称链能力。"""
    image = _require_exec_image()
    r = _precheck_real(TGT8_SQUASH, "bin/busybox")
    assert r.ok, f"预检执行失败: {r.error}"
    d = r.data or {}
    assert d["result_class"] == "ok", f"blockers={d.get('blockers')}"
    arch = d["architecture"]
    assert arch["key"] == "mips32be" and arch["qemu_binary"] == "qemu-mips-static"
    assert arch["matrix"] == "first_batch"
    assert d["interpreter"]["requested"] == "/lib/ld-musl-mips-sf.so.1"
    assert d["interpreter"]["present"] is True
    assert d["dependencies"]["missing"] == []
    assert set(d["dependencies"]["needed"]) == {"libgcc_s.so.1", "libc.so"}
    assert d["execution_facility"]["available"] is True
    assert image in d["execution_facility"]["image"]
    # 限制句纪律(票 04 约束 1/2):通过≠子进程链已验证
    joined = " ".join(d["limitations"])
    assert "子进程链" in joined
    assert d["mode"] == "precheck"


def test_real_precheck_tgt6_nvram_template_blocker() -> None:
    """target/6 nvram(ARM32 LE/uClibc):静态条件全过,但 NEEDED libnvram.so
    需要 NVRAM 模板(支持表未定稿,票 11)→ dependency_blocked;
    报告保留原始 NEEDED,不宣称 ARM 子进程链可用。"""
    _require_exec_image()
    r = _precheck_real(TGT6_SQUASH, "usr/sbin/nvram")
    assert r.ok, f"预检执行失败: {r.error}"
    d = r.data or {}
    assert d["result_class"] == "dependency_blocked", f"blockers={d.get('blockers')}"
    arch = d["architecture"]
    assert arch["key"] == "arm32le" and arch["qemu_binary"] == "qemu-arm-static"
    assert d["interpreter"]["requested"] == "/lib/ld-uClibc.so.0"
    assert d["interpreter"]["present"] is True
    deps = d["dependencies"]
    assert deps["missing"] == [], f"库都在固件根内: {deps}"
    assert "libnvram.so" in deps["needed"]
    assert "libnvram.so" in deps["resolved"]
    tpl = d["template_applicability"]
    assert "libnvram.so" in tpl["nvram_family_needed"]
    assert "不判定" in tpl["detail"]
    joined = " ".join(d["limitations"])
    assert "子进程链" in joined
    assert "受阻" in joined or "未定论" in joined


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("parse_elf_arm32le", test_parse_elf_arm32le),
        ("parse_elf_mips32be_and_static", test_parse_elf_mips32be_and_static),
        ("parse_elf_rejects_garbage", test_parse_elf_rejects_garbage),
        ("precheck_params_contract", test_precheck_params_contract),
        ("result_class_enum_is_spec_eight", test_result_class_enum_is_spec_eight),
        ("precheck_happy_path_arm32le", test_precheck_happy_path_arm32le),
        ("precheck_static_binary_ok", test_precheck_static_binary_ok),
        ("precheck_missing_loader_dependency_blocked", test_precheck_missing_loader_dependency_blocked),
        ("precheck_missing_needed_lib_dependency_blocked", test_precheck_missing_needed_lib_dependency_blocked),
        ("precheck_nvram_family_template_blocker", test_precheck_nvram_family_template_blocker),
        ("precheck_unsupported_arch_prep_blocked_no_facility_call", test_precheck_unsupported_arch_prep_blocked_no_facility_call),
        ("precheck_not_elf_prep_blocked", test_precheck_not_elf_prep_blocked),
        ("precheck_facility_failure", test_precheck_facility_failure),
        ("precheck_path_boundary_no_execution", test_precheck_path_boundary_no_execution),
        ("precheck_accepts_extracted_prefix_refs", test_precheck_accepts_extracted_prefix_refs),
        ("precheck_registry_contract", test_precheck_registry_contract),
        ("precheck_image_pin_matches_pins_env", test_precheck_image_pin_matches_pins_env),
        ("sandbox_verify_cannot_reach_qemu", test_sandbox_verify_cannot_reach_qemu),
        ("role_prompts_mention_precheck_scope", test_role_prompts_mention_precheck_scope),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())

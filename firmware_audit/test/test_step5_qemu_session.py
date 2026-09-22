"""票 16(qemu-user-mode-experiments):qemu_execute 单发执行会话入口。

两层接缝(spec.md Testing Decisions):
- 离线:Docker 替身(monkeypatch qemu_session 命名空间的 docker 原语),
  覆盖参数契约、角色授权、预算归属(3 会话/角色+归属,第 4 个拒绝,角色与
  归属独立,env 覆盖与非法回落)、准备阻塞路径、结果分类映射、清理升级、
  argv/环境形状(mixed-mode/kill-on-exit/timeout 包裹/PROOT_TMP_DIR)、
  台账封存与损坏拒绝(零容器调用);
- 真实:firm_audit/qemu-exec:p540q1111 + target/6、target/8 解包树——
  真实 ARM 单发执行(顶层 + 原链)、命令注入型链路探针、/host-rootfs
  边界拒绝、超时分类、3+1 会话名额、停机封存(容器拆除)。缺依赖 SKIP
  并记录原因,不假绿。

纪律:不调用真实 LLM、不读取 GT、不改既有封存世代;动态结果不是漏洞结论。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import (
    ToolAuthorizationError,
    make_tools,
    tool_names_for_role,
)
from firmware_audit.step5_agent.providers.tools.base import ToolContext
from firmware_audit.step5_agent.providers.tools import qemu_session as qs
from firmware_audit.step5_agent.providers.tools.qemu_base import QEMU_EXEC_V2_IMAGE

REPO_ROOT = Path(__file__).resolve().parents[2]
TGT6_SQUASH = (REPO_ROOT / "target/6/process/extracted/"
               "000000_DIR890LA1_FW111b02_20170519_beta01.bin.extracted/"
               "1C0094/squashfs-root")
TGT8_SQUASH = (REPO_ROOT / "target/8/process/extracted/"
               "000000_openwrt-19.07.0-ath79-generic-tplink_archer-c7-v2-"
               "squashfs-sysupgrade.bin.extracted/185BC4/squashfs-root")


# ---------- Docker 替身 ----------

class FakeDocker:
    """会话原语替身:记录调用并按脚本回放;零真实容器。"""

    def __init__(self, *, exec_script: list[tuple[int, str, str]] | None = None,
                 labels: dict | None = {"fw.qemu.version": "11.1.1",
                                        "fw.proot.version": "5.4.0"},
                 count_queue: list[str] | None = None):
        self.calls: list[tuple[str, ...]] = []
        self.exec_results = list(exec_script or [])
        self.labels = labels
        self.count_queue = list(count_queue or [])
        self.removed: list[str] = []
        self.detached: list[list[str]] = []

    def run_detached(self, image, args, *, name, mounts=None, tmpfs=None,
                     entrypoint=None, network="none", read_only=False,
                     init=True, timeout=120):
        self.calls.append(("run_detached", image, name, tuple(sorted(
            (str(m[0]), m[1], m[2]) for m in (mounts or []))),
            tuple(tmpfs or []), read_only))
        return 0, f"cid-{name}\n", ""

    def exec(self, container, args, *, env=None, detach=False, timeout=300):
        if detach:
            self.detached.append(args)
            return 0, "", ""
        if args[:1] == ["/usr/local/bin/llscan"]:
            if args[1] == "count":
                answer = self.count_queue.pop(0) if self.count_queue else "0"
                return 0, answer + "\n", ""
            if args[1] == "cat":
                return 0, "pid=9 exe=/session/stub/prooted-9-XYZ cmd=qemu\n", ""
            if args[1] == "kill":
                return 0, "2\n", ""
        if args[:1] == ["/usr/bin/timeout"]:
            self.calls.append(("exec", tuple(args), tuple(sorted((env or {}).items()))))
            return self.exec_results.pop(0) if self.exec_results else (0, "", "")
        self.calls.append(("exec-other", tuple(args[:2])))
        return 0, "", ""

    def rm(self, container, *, timeout=60):
        self.removed.append(container)
        return 0, "", ""

    def image_labels(self, image):
        self.calls.append(("labels", image))
        return self.labels


@pytest.fixture
def fake_docker(monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(qs, "docker_run_detached", fake.run_detached)
    monkeypatch.setattr(qs, "docker_exec", fake.exec)
    monkeypatch.setattr(qs, "docker_rm", fake.rm)
    monkeypatch.setattr(qs, "docker_image_labels", fake.image_labels)
    return fake


def _tool(tmp: Path, role: str | None = "analysis"):
    ctx = ToolContext(process_dir=tmp)
    tools = make_tools(ctx, exclude=set(), role=role)
    return tools["qemu_execute"]


def _default_kwargs(**over):
    kwargs = dict(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                  investigation_ref="inv-1")
    kwargs.update(over)
    return kwargs


def _arm_workspace(tmp: Path) -> None:
    """最小 ARM 形态 ELF + 加载器(离线解析够用即可)。"""
    root = tmp / "extracted" / "fw"
    (root / "usr" / "sbin").mkdir(parents=True, exist_ok=True)
    (root / "lib").mkdir(exist_ok=True)
    blob = _elf32(machine=40, interp="/lib/ld-uClibc.so.0",
                  needed=["libc.so.0"])
    (root / "usr" / "sbin" / "nvram").write_bytes(blob)
    (root / "lib" / "ld-uClibc.so.0").write_bytes(_elf32(machine=40))
    (root / "lib" / "libc.so.0").write_bytes(_elf32(machine=40))


_DT_NULL, _DT_NEEDED, _DT_STRTAB = 0, 1, 5
_PT_LOAD, _PT_DYNAMIC, _PT_INTERP = 1, 2, 3


def _elf32(*, machine: int, little: bool = True, interp: str | None = None,
           needed: list[str] | None = None) -> bytes:
    import struct
    needed = list(needed or [])
    end = "<" if little else ">"
    has_interp = interp is not None
    phnum = 1 + int(has_interp) + int(bool(needed))
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
    name_offs, cur = [], 1
    for n in needed:
        name_offs.append(cur)
        cur += len(n) + 1
    dyn = b"".join([struct.pack(end + "iI", _DT_NEEDED, o) for o in name_offs]
                   + [struct.pack(end + "iI", _DT_STRTAB, strtab_vaddr),
                      struct.pack(end + "iI", _DT_NULL, 0)])
    dyn_off = off
    loads_sz = dyn_off + len(dyn)
    phdrs = [struct.pack(end + "IIIIIIII", _PT_LOAD, 0, 0, 0, loads_sz, loads_sz, 5, 0x1000)]
    if has_interp:
        phdrs.append(struct.pack(end + "IIIIIIII", _PT_INTERP, interp_off,
                                 interp_off, 0, len(interp_blob), 0, 4, 1))
    if needed:
        phdrs.append(struct.pack(end + "IIIIIIII", _PT_DYNAMIC, dyn_off,
                                 dyn_off, 0, len(dyn), 0, 6, 4))
    ident = b"\x7fELF" + bytes([1, 1 if little else 2, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack(end + "HHIIIIIHHHHHH",
                               2, machine, 1, 0, ehsize, 0, 0,
                               ehsize, phentsize, phnum, 0, 0, 0)
    return ehdr + b"".join(phdrs) + interp_blob + strtab_blob + dyn


# ---------- 离线:授权与参数契约 ----------

def test_registry_authorization() -> None:
    assert "qemu_execute" not in tool_names_for_role("recon")
    assert "qemu_execute" in tool_names_for_role("analysis")
    assert "qemu_execute" in tool_names_for_role("verification")
    try:
        make_tools(ToolContext(process_dir=Path("/tmp")), role="recon")
    except Exception:
        pass  # make_tools 对 recon 只是不构造
    with pytest.raises(ToolAuthorizationError):
        qs  # noqa: B018 — 占位保持 import 语义
        from firmware_audit.step5_agent.providers.tools import authorize_tool
        authorize_tool("recon", "qemu_execute")


def test_param_contract(tmp_path: Path, fake_docker: FakeDocker) -> None:
    tool = _tool(tmp_path)
    r = tool.execute()  # 缺全部必选
    assert r.ok is False and "缺失必选参数" in (r.error or "")
    r = tool.execute(file_ref="x", firmware_root="fw", investigation_ref="i",
                     bogus="1")
    assert r.ok is False and "未知参数" in (r.error or "")
    r = tool.execute(file_ref="x", firmware_root="fw", investigation_ref="i",
                     timeout_seconds="60")
    assert r.ok is False and "类型错误" in (r.error or "")
    assert fake_docker.calls == []


# ---------- 离线:预算归属 ----------

def test_quota_three_then_refusal(tmp_path: Path, fake_docker: FakeDocker,
                                  monkeypatch) -> None:
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    for i in range(3):
        r = tool.execute(**_default_kwargs())
        assert r.ok and r.data["result_class"] == "normal_exit", (i, r.data)
    r = tool.execute(**_default_kwargs())
    assert r.ok and r.data["result_class"] == "prep_blocked"
    assert r.data["refused"]["reason"] == "session_quota_exhausted"
    ledger = json.loads((tmp_path / "qemu_sessions" / "ledger.json")
                        .read_text(encoding="utf-8"))
    assert len(ledger["sessions"]) == 3 and len(ledger["refusals"]) == 1


def test_quota_role_and_scope_independent(tmp_path: Path, fake_docker: FakeDocker,
                                           monkeypatch) -> None:
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    _arm_workspace(tmp_path)
    analysis = _tool(tmp_path, role="analysis")
    verification = _tool(tmp_path, role="verification")
    for _ in range(3):
        assert analysis.execute(**_default_kwargs()).data["result_class"] == "normal_exit"
    # verification 名额独立;不同 investigation_ref 也独立
    r = verification.execute(**_default_kwargs())
    assert r.data["result_class"] == "normal_exit"
    r = analysis.execute(**_default_kwargs(investigation_ref="inv-2"))
    assert r.data["result_class"] == "normal_exit"


def test_quota_env_override_and_invalid_fallback(tmp_path: Path, fake_docker: FakeDocker,
                                                 monkeypatch) -> None:
    _arm_workspace(tmp_path)
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSIONS", "1")
    tool = _tool(tmp_path)
    assert tool.execute(**_default_kwargs()).data["result_class"] == "normal_exit"
    r = tool.execute(**_default_kwargs())
    assert r.data["result_class"] == "prep_blocked"  # 第 2 个拒绝
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSIONS", "x")
    r = tool.execute(**_default_kwargs(investigation_ref="inv-other"))
    assert r.data["session_budget"]["limit"] == 3  # 非法回落默认


# ---------- 离线:准备阻塞 ----------

def test_prep_blocked_paths(tmp_path: Path, fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    cases = [
        _default_kwargs(file_ref="../outside"),                       # 越界
        _default_kwargs(file_ref="fw/usr/sbin/missing"),              # 不存在
        _default_kwargs(file_ref="fw/lib/libc.so.0"),                 # 在根内 OK 的对照
    ]
    r = tool.execute(**cases[0])
    assert r.data["result_class"] == "prep_blocked"
    r = tool.execute(**cases[1])
    assert r.data["result_class"] == "prep_blocked"
    # args 引号非法
    r = tool.execute(**_default_kwargs(args='"unbalanced'))
    assert r.data["result_class"] == "prep_blocked"
    # env 行非法
    r = tool.execute(**_default_kwargs(env="NOEQUALS"))
    assert r.data["result_class"] == "prep_blocked"
    # cwd 越界
    r = tool.execute(**_default_kwargs(cwd="/a/../b"))
    assert r.data["result_class"] == "prep_blocked"
    assert fake_docker.calls == []  # 全部在容器创建前拒绝


# ---------- 离线:设施失败与分类映射 ----------

def test_facility_failure(tmp_path: Path, monkeypatch) -> None:
    _arm_workspace(tmp_path)
    fake = FakeDocker(labels=None)
    monkeypatch.setattr(qs, "docker_run_detached", fake.run_detached)
    monkeypatch.setattr(qs, "docker_exec", fake.exec)
    monkeypatch.setattr(qs, "docker_rm", fake.rm)
    monkeypatch.setattr(qs, "docker_image_labels", fake.image_labels)
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.ok and r.data["result_class"] == "facility_failure"
    assert fake.calls == [("labels", QEMU_EXEC_V2_IMAGE)]


@pytest.mark.parametrize("rc,out,err,want", [
    (0, "usage\n", "", "normal_exit"),
    (1, "", "guest err", "nonzero_exit"),
    (124, "", "", "timeout"),
    (137, "", "", "target_signal"),
    (139, "", "", "target_signal"),
    (255, "", "bad", "nonzero_exit"),
    (1, "", "proot error: bad cwd\nfatal error: see `proot --help`.", "prep_blocked"),
    (125, "", "docker failed", "facility_failure"),
])
def test_result_classification(tmp_path: Path, fake_docker: FakeDocker,
                               rc: int, out: str, err: str, want: str) -> None:
    _arm_workspace(tmp_path)
    fake_docker.exec_results = [(rc, out, err)]
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.data["result_class"] == want, (rc, r.data.get("result_class"))


# ---------- 离线:argv/环境形状与清理升级 ----------

def test_execution_shape(tmp_path: Path, fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs(args="get foo", env="FOO=bar",
                                       cwd="/tmp", timeout_seconds=90))
    assert r.data["result_class"] == "normal_exit"
    exec_calls = [c for c in fake_docker.calls if c[0] == "exec"]
    assert exec_calls, fake_docker.calls
    argv = exec_calls[0][1]
    assert argv[0] == "/usr/bin/timeout" and list(argv[1:4]) == ["-k", "5", "90"]
    joined = " ".join(argv)
    for needle in ("--mixed-mode on", "--kill-on-exit", "-r /session/firmware",
                   "-b /session/runtime:/tmp", "-b /dev/null",
                   "-w /tmp", "/usr/sbin/nvram", "get foo"):
        assert needle in joined, needle
    env = dict(exec_calls[0][2])
    assert env["PROOT_TMP_DIR"] == "/session/stub" and env["QEMU_STRACE"] == "1"
    assert env["FOO"] == "bar"
    # 观察者先于执行(detached watch)
    assert fake_docker.detached and fake_docker.detached[0][1] == "watch"
    # 封存:容器拆除 + 台账 sealed
    assert fake_docker.removed, "容器必须拆除"
    ledger = json.loads((tmp_path / "qemu_sessions" / "ledger.json")
                        .read_text(encoding="utf-8"))
    assert ledger["sessions"][0]["sealed"] is True
    assert ledger["sessions"][0]["declared"]["argv"] == ["get", "foo"]


def test_cleanup_escalation_and_leftover(tmp_path: Path, fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    fake_docker.count_queue = ["2", "0"]
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.data["cleanup"]["verdict"] == "clean_after_kill"
    # 残留不清:升级后仍 >0 → 容器拆除兜底
    fake_docker.count_queue = ["3", "3"]
    r = tool.execute(**_default_kwargs(investigation_ref="inv-2"))
    assert r.data["cleanup"]["verdict"] == "leftover"
    assert fake_docker.removed, "残留不明时必须拆容器"


def test_corrupt_ledger_refuses(tmp_path: Path, fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    sessions = tmp_path / "qemu_sessions"
    sessions.mkdir()
    (sessions / "ledger.json").write_text("{corrupt", encoding="utf-8")
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.ok is False and "台账损坏" in (r.error or "")
    assert fake_docker.calls == []


# ---------- 真实:ARM/MIPS 单发会话(门控) ----------

def _require_real():
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用"
                    "(先运行 firmware_audit/docker/qemu-exec-v2/build_image.sh)")
    if not TGT6_SQUASH.is_dir():
        pytest.skip(f"target/6 解包树缺失: {TGT6_SQUASH}")


def _real_workspace(tmp: Path) -> Path:
    """选择性复制最小固件子树到临时工作区(原件只读;会话写独立运行目录)。

    squashfs 树含设备节点等特殊文件,整树 copy 会炸;会话只需 shell/目标/库。
    """
    import shutil
    root = tmp / "extracted" / "fw"
    root.mkdir(parents=True, exist_ok=True)
    for rel in ("bin/busybox", "usr/sbin/nvram"):
        src = TGT6_SQUASH / rel
        if src.is_file():
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst, follow_symlinks=True)
    libdir = TGT6_SQUASH / "lib"
    if libdir.is_dir():
        shutil.copytree(libdir, root / "lib",
                        ignore=shutil.ignore_patterns("*.so.*.*"),
                        dirs_exist_ok=True, symlinks=False)
    return tmp


def test_real_arm_session_chain_boundary_and_quota(tmp_path: Path,
                                                   monkeypatch) -> None:
    _require_real()
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = _real_workspace(tmp_path)
    tool = _tool(ws, role="analysis")

    # ① 顶层单发:nvram usage(rc=0,固件指纹)
    r = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                     investigation_ref="case-real")
    d = r.data
    assert d["result_class"] == "normal_exit", d
    assert "usage: nvram" in (d["observation_excerpt"]["stdout"]["excerpt"]
                              + d["observation_excerpt"]["stderr"]["excerpt"])
    assert d["sealed"] is True and d["cleanup"]["verdict"] in ("clean", "clean_after_kill")
    assert d["backend"]["proot_version"] == "5.4.0"

    # ② 原链:固件 busybox sh 自主派生静态子
    r = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                     investigation_ref="case-real",
                     args="sh -c '/bin/busybox echo chain-child-real'")
    d = r.data
    assert d["result_class"] == "normal_exit", d
    assert "chain-child-real" in d["observation_excerpt"]["stdout"]["excerpt"]

    # ③ 命令注入型链路探针:注入子命令真实进入仿真(第 3 个会话,名额用满)
    r = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                     investigation_ref="case-real",
                     args="sh -c '/usr/sbin/nvram; /bin/busybox echo injected-child'")
    d = r.data
    assert d["result_class"] == "normal_exit", d
    assert "injected-child" in d["observation_excerpt"]["stdout"]["excerpt"]

    # ④ 名额:同角色同归属第 4 个会话被拒(不建容器、不产生会话)
    r = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                     investigation_ref="case-real", args="sh -c x")
    d = r.data
    assert d["result_class"] == "prep_blocked"
    assert d["refused"]["reason"] == "session_quota_exhausted"

    # ⑤ 边界:注入载荷借 /host-rootfs 执行容器原生 qemu → 拒绝(独立归属)
    r = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                     investigation_ref="case-boundary",
                     args="sh -c '/usr/sbin/nvram; "
                          "/host-rootfs/usr/local/bin/qemu-arm-static --version'")
    d = r.data
    assert d["result_class"] in ("nonzero_exit", "target_signal"), d
    assert "Invalid ELF image" in (d["observation_excerpt"]["stderr"]["excerpt"]
                                   + d["observation_excerpt"]["stdout"]["excerpt"])
    assert d["cleanup"]["verdict"] in ("clean", "clean_after_kill")
    assert d["sealed"] is True

    ledger = json.loads((ws / "qemu_sessions" / "ledger.json").read_text(encoding="utf-8"))
    used = [s["investigation_ref"] for s in ledger["sessions"]]
    assert used.count("case-real") == 3
    assert ledger["sessions"][-1]["sealed"] is True


def test_real_timeout_classification(tmp_path: Path, monkeypatch) -> None:
    _require_real()
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = _real_workspace(tmp_path)
    tool = _tool(ws, role="verification")
    r = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                     investigation_ref="case-timeout",
                     args="sh -c '/bin/busybox sleep 30'",
                     timeout_seconds=5)
    d = r.data
    assert d["result_class"] == "timeout", d
    assert d["sealed"] is True


def test_real_mips_non_shell_parent(tmp_path: Path, monkeypatch) -> None:
    """非 shell 父程序直接派生(MIPS busybox env 直接 exec 固件 ELF;
    真实固件二进制,非合成夹具——裸 11.1.1 下此场景 rc=126 无救回,
    PRoot 组合实测救回,证据 investigation/proot540-qemu1111-2026-09-22/logs/82)。"""
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用")
    if not TGT8_SQUASH.is_dir() or not (TGT8_SQUASH / "bin/busybox").is_file():
        pytest.skip(f"target/8 解包树缺失: {TGT8_SQUASH}")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    import shutil
    fw = tmp_path / "extracted" / "fw8"
    fw.mkdir(parents=True)
    shutil.copy2(TGT8_SQUASH / "bin/busybox", fw / "busybox", follow_symlinks=True)
    libdir = TGT8_SQUASH / "lib"
    if libdir.is_dir():
        shutil.copytree(libdir, fw / "lib", dirs_exist_ok=True, symlinks=False)
    tool = _tool(tmp_path, role="analysis")
    r = tool.execute(file_ref="fw8/busybox", firmware_root="fw8",
                     investigation_ref="case-mips",
                     args="env /busybox echo env-parent-mips-ok")
    d = r.data
    assert d["result_class"] == "normal_exit", d
    assert "env-parent-mips-ok" in d["observation_excerpt"]["stdout"]["excerpt"]

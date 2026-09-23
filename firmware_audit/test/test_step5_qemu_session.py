"""票 16/17(qemu-user-mode-experiments):qemu_execute 多步执行会话入口。

两层接缝(spec.md Testing Decisions):
- 离线:Docker 替身(monkeypatch qemu_session 命名空间的 docker 原语),
  覆盖参数契约、角色授权、会话名额(3 会话/角色+归属)、会话内执行次数
  (显式预算参数:Host 配置层 > env > 默认 4,来源入台账,超限拒绝)、
  多执行复用(session_id/keep_open/stop,同容器、逐执行清理验证、台账有序
  追加)、准备阻塞路径、结果分类映射、argv/环境形状、旧镜像身份漂移拒绝、
  以及中断注入(开启/执行/输出采集/停机各边界)与恢复语义(收割、中断即
  会话死亡、留档不进新会话、已持久化执行不重复扣名额)——零真实容器;
- 真实:firm_audit/qemu-exec:p540q1111 + target/6、target/8 解包树——
  真实 ARM 单发/原链/边界拒绝/超时、同一会话两次执行的状态连续(第一次写
  运行目录第二次可读)、新会话干净重建、会话内执行次数、遗留容器强制收割
  (中断即会话死亡)。缺依赖 SKIP 并记录原因,不假绿。

纪律:不调用真实 LLM、不读取 GT、不改既有封存世代;动态结果不是漏洞结论。
"""
from __future__ import annotations

import base64
import json
import shutil
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
from firmware_audit.step5_agent.providers.tools import qemu_adapt
from firmware_audit.step5_agent.providers.tools import qemu_session as qs
from firmware_audit.step5_agent.providers.tools.qemu_recovery import (
    reap_leftover_sessions,
    seal_open_sessions,
)
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
    """会话原语替身:记录调用并按脚本回放;零真实容器。

    exec_script 条目可为 (rc, out, err) 或异常实例(命中目标执行时抛出,
    模拟执行窗口内中断)。rm_results 逐次消费,模拟停机失败/容器缺失。
    """

    DEFAULT_LABELS = {
        "fw.qemu.version": "11.1.1",
        "fw.proot.version": "5.4.0",
        "fw.proot.patch.sha256": "d55abd0d8c0adb86d8a264368664fb4fbf0ea8273a27681119295bd126f41cdd",
        "fw.proot.execveat.patch.sha256": "d361d4b28c75029e89892a5283efcdddb99a89a0d752372b91bf07b1c98dae2e",
        "fw.boundary": "proot-mixed-mode-inherit+raw-execveat-deny+strip(deny-by-absence)",
    }
    _UNSET = object()

    def __init__(self, *, exec_script: list | None = None,
                 labels=_UNSET,
                 count_queue: list[str] | None = None,
                 rm_results: list[tuple[int, str, str]] | None = None):
        self.calls: list[tuple] = []
        self.exec_results = list(exec_script or [])
        # labels=None 表示镜像不可用(image_labels 返回 None);缺省 = 可用档案
        self.labels = self.DEFAULT_LABELS if labels is self._UNSET else labels
        self.count_queue = list(count_queue or [])
        self.rm_results = list(rm_results or [])
        self.removed: list[str] = []
        self.detached: list[list[str]] = []
        self.containers_started: list[str] = []
        self.stdin_sizes: list[int | None] = []

    def run_detached(self, image, args, *, name, mounts=None, tmpfs=None,
                     entrypoint=None, network="none", read_only=False,
                     init=True, timeout=120):
        self.calls.append(("run_detached", image, name, tuple(sorted(
            (str(m[0]), m[1], m[2]) for m in (mounts or []))),
            tuple(tmpfs or []), read_only))
        self.containers_started.append(name)
        return 0, f"cid-{name}\n", ""

    def exec(self, container, args, *, env=None, detach=False, timeout=300,
             stdin_bytes=None):
        if detach:
            self.detached.append(args)
            return 0, "", ""
        if args[:1] == ["/usr/local/bin/llscan"]:
            if args[1] == "count":
                answer = self.count_queue.pop(0) if self.count_queue else "0"
                return 0, answer + "\n", ""
            if args[1] == "cat":
                return 0, ("pid=9 exe=/session/stub/prooted-9-XYZ size=123 "
                           "sha256=" + "a" * 64 + " cmd=qemu\n"), ""
            if args[1] == "kill":
                self.calls.append(("exec-other", tuple(args[:2])))
                return 0, "2\n", ""
        if args[:1] == ["/usr/bin/timeout"]:
            self.calls.append(("exec", tuple(args), tuple(sorted((env or {}).items()))))
            self.stdin_sizes.append(len(stdin_bytes) if stdin_bytes is not None else None)
            if self.exec_results:
                item = self.exec_results.pop(0)
                if isinstance(item, BaseException):
                    raise item
                return item
            return (0, "", "")
        self.calls.append(("exec-other", tuple(args[:2])))
        return 0, "", ""

    def rm(self, container, *, timeout=60):
        self.removed.append(container)
        if self.rm_results:
            rc, out, err = self.rm_results.pop(0)
            return rc, out, err
        return 0, "", ""

    def image_identity(self, image):
        self.calls.append(("labels", image))
        return ({"image_id": "sha256:test-image", "labels": self.labels}
                if self.labels is not None else None)


@pytest.fixture
def fake_docker(monkeypatch):
    fake = FakeDocker()
    # 仅离线 Docker 替身测试未放行后端的生命周期，不提供真实执行旁路。
    monkeypatch.setattr(qs, "docker_run_detached", fake.run_detached)
    monkeypatch.setattr(qs, "docker_exec", fake.exec)
    monkeypatch.setattr(qs, "docker_rm", fake.rm)
    monkeypatch.setattr(qs, "docker_image_identity", fake.image_identity)
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


def _read_ledger(tmp: Path) -> dict:
    return json.loads((tmp / "qemu_sessions" / "ledger.json")
                      .read_text(encoding="utf-8"))


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
    from firmware_audit.step5_agent.providers.tools import authorize_tool
    with pytest.raises(ToolAuthorizationError):
        authorize_tool("recon", "qemu_execute")


def test_param_contract(tmp_path: Path, fake_docker: FakeDocker) -> None:
    tool = _tool(tmp_path)
    r = tool.execute(investigation_ref="i", bogus="1")
    assert r.ok is False and "未知参数" in (r.error or "")
    r = tool.execute(investigation_ref="i", timeout_seconds="60")
    assert r.ok is False and "类型错误" in (r.error or "")
    # 归属是 Host 注入语义:空归属拒绝记账(investigation_ref 可缺省)
    r = tool.execute(file_ref="x", firmware_root="fw")
    assert r.ok and r.data["result_class"] == "prep_blocked"
    assert "investigation_ref 缺失" in r.data["detail"]
    ledger = _read_ledger(tmp_path)
    assert ledger["sessions"] == [] and len(ledger["refusals"]) == 1
    assert fake_docker.calls == []


def test_verb_semantics_refuse_before_any_docker_call(
        tmp_path: Path, fake_docker: FakeDocker) -> None:
    """裸 stop / 裸执行(缺 file_ref)在容器创建前拒绝。"""
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    r = tool.execute(investigation_ref="i", stop=True)          # 无 session 无目标
    assert r.data["result_class"] == "prep_blocked"
    r = tool.execute(**_default_kwargs(file_ref=""))             # 执行调用缺目标
    assert r.data["result_class"] == "prep_blocked"
    r = tool.execute(**_default_kwargs(session_id="no-such"))    # 未知会话
    assert r.data["result_class"] == "prep_blocked"
    assert fake_docker.calls == []
    ledger = _read_ledger(tmp_path)
    assert ledger["sessions"] == [] and len(ledger["refusals"]) == 3


# ---------- 离线:会话名额(票 16 语义保持) ----------

def test_quota_three_then_refusal(tmp_path: Path, fake_docker: FakeDocker,
                                  monkeypatch) -> None:
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    for i in range(3):
        r = tool.execute(**_default_kwargs())
        assert r.ok and r.data["result_class"] == "normal_exit", (i, r.data)
        assert r.data["sealed"] is True  # 单发默认停机封存
    r = tool.execute(**_default_kwargs())
    assert r.ok and r.data["result_class"] == "prep_blocked"
    assert r.data["refused"]["reason"] == "session_quota_exhausted"
    ledger = _read_ledger(tmp_path)
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


def test_session_configuration_cannot_exceed_three(tmp_path: Path, fake_docker, monkeypatch):
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSIONS", "99")
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    for _ in range(3):
        assert tool.execute(**_default_kwargs()).data["result_class"] == "normal_exit"
    assert tool.execute(**_default_kwargs()).data["result_class"] == "prep_blocked"


# ---------- 离线:多执行会话(票 17 核心) ----------

def test_session_reuse_state_continuity_and_stop(tmp_path: Path,
                                                 fake_docker: FakeDocker) -> None:
    """同一会话两次执行:同容器、台账有序追加、仅停机封存。"""
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    r1 = tool.execute(**_default_kwargs(keep_open=True, args="set foo bar"))
    d1 = r1.data
    assert d1["result_class"] == "normal_exit"
    assert d1["sealed"] is False and d1["status"] == "running"
    session_id = d1["session_id"]
    assert not fake_docker.removed, "keep_open 会话不得拆除容器"

    r2 = tool.execute(**_default_kwargs(session_id=session_id, args="get foo"))
    d2 = r2.data
    assert d2["session_id"] == session_id
    assert d2["executions_total"] == 2
    assert not fake_docker.removed, "复用执行之间不得拆容器"
    # 同一容器:只开过一次,两次执行都在其中
    assert len(fake_docker.containers_started) == 1
    # 台账有序追加:两次执行各自带声明输入与输出 digest
    entry = next(s for s in _read_ledger(tmp_path)["sessions"]
                 if s["session_id"] == session_id)
    assert [e["seq"] for e in entry["executions"]] == [1, 2]
    assert entry["executions"][0]["declared"]["argv"] == ["set", "foo", "bar"]
    assert entry["executions"][1]["declared"]["argv"] == ["get", "foo"]
    assert entry["executions"][0]["execution"]["stdout_sha256"]
    assert entry["execution_budget"] == {"limit": 4, "source": "default", "used": 2}
    assert entry["status"] == "running"

    # 仅停机:不执行、拆容器、台账终态
    removed_before = len(fake_docker.removed)
    r3 = tool.execute(investigation_ref="inv-1", session_id=session_id, stop=True)
    d3 = r3.data
    assert d3["action"] == "session_stop"
    assert d3["sealed"] is True and d3["status"] == "sealed"
    assert d3["executions_total"] == 2
    assert len(fake_docker.removed) == removed_before + 1
    entry = next(s for s in _read_ledger(tmp_path)["sessions"]
                 if s["session_id"] == session_id)
    assert entry["status"] == "sealed" and entry["seal_kind"] == "agent_stop"
    assert len(entry["executions"]) == 2  # 停机不产生执行


def test_session_runtime_dir_is_per_session(tmp_path: Path, fake_docker: FakeDocker) -> None:
    """新会话干净重建:运行目录独立,不继承旧会话文件。"""
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    r1 = tool.execute(**_default_kwargs(keep_open=True))
    sid1 = r1.data["session_id"]
    (tmp_path / "qemu_sessions" / sid1 / "runtime" / "state.txt").write_text("x")
    r2 = tool.execute(**_default_kwargs(investigation_ref="inv-2"))
    sid2 = r2.data["session_id"]
    assert sid1 != sid2
    assert not (tmp_path / "qemu_sessions" / sid2 / "runtime" / "state.txt").exists()


def test_reuse_requires_same_scope_and_firmware_root(tmp_path: Path,
                                                     fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    sid = tool.execute(**_default_kwargs(keep_open=True)).data["session_id"]
    # 跨归属拒绝
    r = tool.execute(**_default_kwargs(session_id=sid, investigation_ref="inv-2"))
    assert r.data["result_class"] == "prep_blocked"
    # 跨角色拒绝
    other = _tool(tmp_path, role="verification")
    r = other.execute(**_default_kwargs(session_id=sid))
    assert r.data["result_class"] == "prep_blocked"
    # 固件根不一致拒绝(guest 根在开启时固化)
    r = tool.execute(**_default_kwargs(session_id=sid, firmware_root="other"))
    assert r.data["result_class"] == "prep_blocked"
    assert len(fake_docker.containers_started) == 1


def test_reuse_refused_after_seal(tmp_path: Path, fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    sid = tool.execute(**_default_kwargs()).data["session_id"]
    r = tool.execute(**_default_kwargs(session_id=sid))
    assert r.data["result_class"] == "prep_blocked"
    assert "封存" in r.data["detail"]


def test_per_execution_cleanup_between_executions(tmp_path: Path,
                                                  fake_docker: FakeDocker) -> None:
    """执行之间无目标进程存活:残留 → 连进程组 SIGKILL → 复扫,逐执行验证。"""
    _arm_workspace(tmp_path)
    fake_docker.count_queue = ["2", "0"]
    tool = _tool(tmp_path)
    r1 = tool.execute(**_default_kwargs(keep_open=True))
    sid = r1.data["session_id"]
    tool.execute(**_default_kwargs(session_id=sid))
    kill_positions = [i for i, c in enumerate(fake_docker.calls) if c == ("exec-other", ("/usr/local/bin/llscan", "kill"))]
    assert kill_positions, "第一次执行后必须升级清理"
    first_target = next(i for i, c in enumerate(fake_docker.calls) if c[0] == "exec")
    second_target = len(fake_docker.calls) - 1 - next(
        i for i, c in enumerate(reversed(fake_docker.calls)) if c[0] == "exec")
    assert first_target < kill_positions[0] < second_target, \
        "升级清理必须发生在两次执行之间"
    entry = next(s for s in _read_ledger(tmp_path)["sessions"]
                 if s["session_id"] == sid)
    assert entry["executions"][0]["cleanup"]["verdict"] == "clean_after_kill"
    assert entry["executions"][1]["cleanup"]["verdict"] == "clean"


# ---------- 离线:会话内执行次数(票 17 显式预算参数) ----------

def test_execution_quota_host_config_layer(tmp_path: Path, fake_docker: FakeDocker) -> None:
    """Host 配置层生效且来源入台账;对照/异常逐次计数;超限拒绝。"""
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    budget_kwargs = dict(investigation_ref="host-inv")
    r1 = tool.execute_for_scope(
        {k: v for k, v in _default_kwargs(keep_open=True, **budget_kwargs).items()
         if k != "investigation_ref"},
        investigation_ref="host-inv", remaining_seconds=None, max_executions=2)
    sid = r1.data["session_id"]
    assert r1.data["execution_budget"] == {"limit": 2, "source": "host_config",
                                           "used": 1}
    r2 = tool.execute_for_scope(
        {k: v for k, v in _default_kwargs(session_id=sid, **budget_kwargs).items()
         if k != "investigation_ref"},
        investigation_ref="host-inv", remaining_seconds=None, max_executions=2)
    assert r2.data["result_class"] == "normal_exit"  # 异常输入也逐次计数
    r3 = tool.execute_for_scope(
        {k: v for k, v in _default_kwargs(session_id=sid, **budget_kwargs).items()
         if k != "investigation_ref"},
        investigation_ref="host-inv", remaining_seconds=None, max_executions=2)
    assert r3.data["result_class"] == "prep_blocked"
    assert r3.data["refused"]["reason"] == "execution_quota_exhausted"
    ledger = _read_ledger(tmp_path)
    assert len(ledger["refusals"]) == 1
    assert ledger["refusals"][0]["reason"] == "execution_quota_exhausted"
    assert ledger["refusals"][0]["session_id"] == sid


def test_execution_quota_env_layer_and_fallback(tmp_path: Path, fake_docker: FakeDocker,
                                                monkeypatch) -> None:
    _arm_workspace(tmp_path)
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSION_EXECUTIONS", "1")
    tool = _tool(tmp_path)
    r1 = tool.execute(**_default_kwargs(keep_open=True))
    assert r1.data["execution_budget"] == {"limit": 1, "source": "environment",
                                           "used": 1}
    sid = r1.data["session_id"]
    r2 = tool.execute(**_default_kwargs(session_id=sid))
    assert r2.data["refused"]["reason"] == "execution_quota_exhausted"
    # 非法值回落默认 4
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSION_EXECUTIONS", "zero")
    r3 = tool.execute(**_default_kwargs(investigation_ref="inv-2"))
    assert r3.data["execution_budget"]["limit"] == 4
    assert r3.data["execution_budget"]["source"] == "default"


def test_execution_quota_zero_and_negative_env_invalid(tmp_path: Path,
                                                       fake_docker: FakeDocker,
                                                       monkeypatch) -> None:
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSION_EXECUTIONS", "0")
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.data["execution_budget"]["limit"] == 4  # 越界同非法,回落默认


# ---------- 离线:准备阻塞 ----------

def test_prep_blocked_paths(tmp_path: Path, fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs(file_ref="../outside"))
    assert r.data["result_class"] == "prep_blocked"
    r = tool.execute(**_default_kwargs(file_ref="fw/usr/sbin/missing"))
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
    monkeypatch.setattr(qs, "docker_image_identity", fake.image_identity)
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.ok and r.data["result_class"] == "facility_failure"
    assert fake.calls == [("labels", QEMU_EXEC_V2_IMAGE)]
    assert not (tmp_path / "qemu_sessions/ledger.json").exists()


def test_container_start_failure_seals_placeholder(tmp_path: Path, fake_docker,
                                                   monkeypatch) -> None:
    """容器启动失败:占位已记账(名额可审计),立即权威拆除并封存。"""
    _arm_workspace(tmp_path)
    monkeypatch.setattr(qs, "docker_run_detached",
                        lambda *a, **kw: (124, "", "docker timed out"))
    fake_docker.rm_results = [(1, "", "Error: No such container: fw-qemu-x")]
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.data["result_class"] == "facility_failure"
    assert r.data["sealed"] is True and r.data["status"] == "sealed"
    assert r.data["container_removal"]["verdict"] == "absent"
    assert fake_docker.removed, "开启超时也可能是容器已建,必须以 rm 结果为准"
    ledger = _read_ledger(tmp_path)
    assert len(ledger["sessions"]) == 1
    assert ledger["sessions"][0]["status"] == "sealed"


@pytest.mark.parametrize("rc,out,err,want", [
    (0, "usage\n", "", "normal_exit"),
    (1, "", "guest err", "nonzero_exit"),
    (124, "", "", "nonzero_exit"),
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
    assert r.data["chain"]["stub_identities"] == [{
        "pid": 9, "exe": "/session/stub/prooted-9-XYZ", "size_bytes": 123,
        "sha256": "a" * 64, "cmd": "qemu", "identity_complete": True,
    }]
    # Observation 文本如实反映台账事实(执行序号不渲染成 None)
    assert "第 1 次执行" in r.text
    assert "第 None 次执行" not in r.text
    # 封存:容器拆除 + 台账 sealed
    assert fake_docker.removed, "容器必须拆除"
    ledger = _read_ledger(tmp_path)
    session = ledger["sessions"][0]
    assert session["sealed"] is True
    assert session["executions"][0]["declared"]["argv"] == ["get", "foo"]
    assert r.data["declared"]["argv"] == ["get", "foo"]


def test_explicit_argv0_is_recorded_and_passed(tmp_path: Path, fake_docker: FakeDocker) -> None:
    """票 18:argv0 为绝对 guest 路径(多路复用 CGI 真实调用形态)——目标以
    同一文件身份 bind 到该路径执行;裸名字已不支持(PRoot 以命令路径为 argv[0])。"""
    _arm_workspace(tmp_path)
    result = _tool(tmp_path).execute(**_default_kwargs(
        argv0="/usr/sbin/nvram-wrapper", args="get foo"))
    assert result.data["declared"]["argv0"] == "/usr/sbin/nvram-wrapper"
    exec_call = next(call for call in fake_docker.calls if call[0] == "exec")
    argv = exec_call[1]
    # bind:同一目标呈现在 argv0 路径(只读执行视图,不改固件根)
    assert "/session/firmware/usr/sbin/nvram:/usr/sbin/nvram-wrapper" in argv
    # 命令 = argv0 路径;其后仅跟声明 argv(PRoot 以命令路径为 argv[0])
    assert "/usr/sbin/nvram-wrapper" in argv
    assert "get" in argv and "foo" in argv
    assert argv[-3:] == ("/usr/sbin/nvram-wrapper", "get", "foo")


def test_argv0_rejects_bare_name_and_shadowing(tmp_path: Path, fake_docker: FakeDocker) -> None:
    """裸名字 argv0(PRoot 下无法表达)与遮蔽固件根内已有文件均拒绝。"""
    _arm_workspace(tmp_path)
    r = _tool(tmp_path).execute(**_default_kwargs(argv0="nvram-wrapper"))
    assert r.data["result_class"] == "prep_blocked"
    assert "绝对路径" in r.data["detail"]
    assert not any(call[0] == "run_detached" for call in fake_docker.calls)
    r = _tool(tmp_path).execute(**_default_kwargs(
        argv0="/lib/ld-uClibc.so.0"))
    assert r.data["result_class"] == "prep_blocked"
    assert "遮蔽" in r.data["detail"]
    assert not any(call[0] == "run_detached" for call in fake_docker.calls)


def test_argv0_rejects_nul_injection(tmp_path: Path, fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    result = _tool(tmp_path).execute(**_default_kwargs(argv0="bad\x00name"))
    assert result.data["result_class"] == "prep_blocked"
    assert not any(call[0] == "run_detached" for call in fake_docker.calls)


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


def test_legacy_schema_one_ledger_refuses(tmp_path: Path, fake_docker: FakeDocker) -> None:
    """票 16 schema 1 台账不兼容:拒绝续写,不静默升级。"""
    _arm_workspace(tmp_path)
    sessions = tmp_path / "qemu_sessions"
    sessions.mkdir()
    (sessions / "ledger.json").write_text(
        json.dumps({"schema_version": 1, "sessions": [], "refusals": []}),
        encoding="utf-8")
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.ok is False and "版本不兼容" in (r.error or "")


# ---------- 离线:中断注入与恢复(票 17) ----------

def test_interrupt_during_execution_leaves_honest_running_state(
        tmp_path: Path, fake_docker: FakeDocker) -> None:
    """执行窗口内 Ctrl+C/SIGKILL:执行未发生就不入账,会话留在 running
    供恢复收割(Exception 拦不住 KeyboardInterrupt,与宿主中断同形)。"""
    _arm_workspace(tmp_path)
    fake_docker.exec_results = [KeyboardInterrupt("host died mid-exec")]
    tool = _tool(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        tool.execute(**_default_kwargs(keep_open=True))
    ledger = _read_ledger(tmp_path)
    entry = ledger["sessions"][0]
    assert entry["status"] == "running"
    assert entry["executions"] == [], "未完成的执行不得伪装为已持久化"
    assert not fake_docker.removed, "中断路径不即时拆容器(会话可能仍可用)"

    # 恢复路径:收割遗留容器,中断即会话死亡
    report = reap_leftover_sessions(tmp_path)
    assert entry["session_id"] in report["reaped"]
    assert fake_docker.removed == [f"fw-qemu-{entry['session_id']}"]
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "interrupted"
    assert entry["seal_kind"] == "recovery_reap"
    assert entry["sealed"] is True
    assert entry["cleanup"]["verdict"] == "container_removed"
    assert "不进入新会话" in entry["recovery"]["note"]

    # 死会话不可继续;新会话独立计数,已持久化执行(0 次)不重复扣名额
    r = tool.execute(**_default_kwargs(session_id=entry["session_id"]))
    assert r.data["result_class"] == "prep_blocked"
    assert "中断" in r.data["detail"]
    r2 = tool.execute(**_default_kwargs())
    assert r2.data["result_class"] == "normal_exit"
    assert r2.data["execution_budget"]["used"] == 1


def test_interrupt_after_execution_persisted_keeps_execution_counted(
        tmp_path: Path, fake_docker: FakeDocker, monkeypatch) -> None:
    """输出采集边界中断:执行已发生,事实与 digest 留档,恢复不重复计数。"""
    _arm_workspace(tmp_path)
    original = qs.docker_exec

    def broken_cat(container, args, **kwargs):
        if args[:2] == ["/usr/local/bin/llscan", "cat"]:
            raise OSError("snapshot read failed")
        return original(container, args, **kwargs)

    monkeypatch.setattr(qs, "docker_exec", broken_cat)
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs(keep_open=True))
    assert r.ok, "观测异常转为分类承载,不是工具崩溃"
    entry = _read_ledger(tmp_path)["sessions"][0]
    # 清理未确认 → 容器拆除兜底 + 封存(不得带不确定状态进入下次执行)
    assert entry["status"] == "sealed" and entry["sealed"] is True
    assert len(entry["executions"]) == 1
    assert entry["executions"][0]["execution"]["exit_code"] == 0
    assert entry["executions"][0]["result_class"] == "facility_failure"
    assert "输出采集" in entry["executions"][0]["result_note"]
    assert entry["execution_budget"]["used"] == 1

    # 已持久化执行留档;新会话执行次数从 0 起(不重复扣减)
    monkeypatch.setattr(qs, "docker_exec", original)  # 解除观测异常
    r2 = tool.execute(**_default_kwargs())
    assert r2.data["result_class"] == "normal_exit"
    assert r2.data["session_id"] != entry["session_id"]
    assert r2.data["execution_budget"]["used"] == 1
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert len(entry["executions"]) == 1, "旧会话执行记录不被触碰"


def test_interrupt_during_seal_marks_seal_failed_then_recovery_reaps(
        tmp_path: Path, fake_docker: FakeDocker) -> None:
    """停机边界中断:拆除未确认 → seal_failed(不伪装封存)→ 恢复强制收割。"""
    _arm_workspace(tmp_path)
    fake_docker.rm_results = [(1, "", "cannot remove: device busy")]
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs())
    assert r.data["result_class"] == "normal_exit"  # 执行结果不被停机失败覆盖
    assert r.data["sealed"] is False and r.data["status"] == "seal_failed"
    assert r.data["container_removal"]["verdict"] == "uncertain"
    sid = r.data["session_id"]
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "seal_failed"
    assert entry["cleanup"]["verdict"] == "uncertain"

    # seal_failed 会话不得复用执行;恢复收割确认拆除后封存终于完成
    r2 = tool.execute(**_default_kwargs(session_id=sid))
    assert r2.data["result_class"] == "prep_blocked"
    report = reap_leftover_sessions(tmp_path)
    assert sid in report["reaped"]
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "sealed"
    assert entry["seal_kind"] == "recovery_reap"
    assert entry["cleanup"]["verdict"] == "container_removed"


def test_recovery_treats_absent_container_as_clean(tmp_path: Path,
                                                   fake_docker: FakeDocker) -> None:
    """执行窗口中断且容器已缺席:absent 是已确认清理,不是不确定。"""
    _arm_workspace(tmp_path)
    fake_docker.exec_results = [KeyboardInterrupt("died before exec")]
    tool = _tool(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        tool.execute(**_default_kwargs(keep_open=True))
    fake_docker.rm_results = [(1, "", "Error: No such container: fw-qemu-x")]
    report = reap_leftover_sessions(tmp_path)
    assert report["reaped"] and not report["uncertain"]
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["cleanup"]["verdict"] == "absent"
    assert entry["sealed"] is True


def test_recovery_with_unreadable_ledger_is_loud_not_fatal(tmp_path: Path) -> None:
    sessions = tmp_path / "qemu_sessions"
    sessions.mkdir()
    (sessions / "ledger.json").write_text("{corrupt", encoding="utf-8")
    report = reap_leftover_sessions(tmp_path)
    assert report["unreadable"] and "损坏" in report["unreadable"]
    seal = seal_open_sessions(tmp_path, kind="host_finalize")
    assert seal["unreadable"]


def test_recovery_noop_without_sessions(tmp_path: Path) -> None:
    assert reap_leftover_sessions(tmp_path) == {
        "reaped": [], "uncertain": [], "unreadable": None}


def test_seal_open_sessions_force_seals_all_running(tmp_path: Path,
                                                    fake_docker: FakeDocker) -> None:
    """调查终态强制封存:全部开启会话停机,与 agent 自觉无关。"""
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    sid1 = tool.execute(**_default_kwargs(keep_open=True)).data["session_id"]
    sid2 = tool.execute(
        **_default_kwargs(investigation_ref="inv-2", keep_open=True)
    ).data["session_id"]
    report = seal_open_sessions(tmp_path, kind="host_finalize")
    assert sorted(report["sealed"]) == sorted([sid1, sid2])
    ledger = _read_ledger(tmp_path)
    assert all(s["status"] == "sealed" and s["seal_kind"] == "host_finalize"
               for s in ledger["sessions"])
    assert len(fake_docker.removed) == 2
    # 幂等:已封存会话不再触碰
    before = len(fake_docker.removed)
    seal_open_sessions(tmp_path, kind="host_finalize")
    assert len(fake_docker.removed) == before


def test_seal_open_sessions_records_failed_teardown(tmp_path: Path,
                                                    fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    sid = tool.execute(**_default_kwargs(keep_open=True)).data["session_id"]
    fake_docker.rm_results = [(1, "", "daemon unreachable")]
    report = seal_open_sessions(tmp_path, kind="host_interrupt")
    assert report["failed"] == [sid]
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "seal_failed"
    assert entry["seal_kind"] == "host_interrupt"
    assert entry["cleanup"]["verdict"] == "uncertain"


# ---------- 离线:Host 绑定与旧镜像身份 ----------

def test_host_binds_scope_and_remaining_time(tmp_path: Path, fake_docker: FakeDocker,
                                             monkeypatch) -> None:
    from firmware_audit.step5_agent.host.tooling import execute_tool
    from firmware_audit.step5_agent.host.budget import RunBudget
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    budget = RunBudget.load(tmp_path / "budget", persist=False)
    budget.resolved["max_active_seconds"] = 2.8
    for index in range(3):
        result = execute_tool(tool, _default_kwargs(investigation_ref=f"forged-{index}"),
                              investigation_ref="host-inv-1", budget=budget)
        assert result.data["declared"]["timeout_seconds"] <= 2
        assert result.data["investigation_ref"] == "host-inv-1"
    result = execute_tool(tool, _default_kwargs(investigation_ref="forged-4"),
                          investigation_ref="host-inv-1", budget=budget)
    assert result.data["refused"]["reason"] == "session_quota_exhausted"
    budget.resolved["max_active_seconds"] = 0.5
    before = len(fake_docker.calls)
    result = execute_tool(tool, _default_kwargs(), investigation_ref="host-inv-2", budget=budget)
    assert result.data["result_class"] == "prep_blocked"
    assert len(fake_docker.calls) == before


def test_host_passes_layered_execution_limit(tmp_path: Path, fake_docker: FakeDocker,
                                             monkeypatch) -> None:
    from firmware_audit.step5_agent.host.tooling import execute_tool
    from firmware_audit.step5_agent.host.budget import RunBudget
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSION_EXECUTIONS", "99")  # env 层被 Host 配置压住
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    budget = RunBudget.load(tmp_path / "budget", persist=False)
    budget.resolved["qemu_max_session_executions"] = 2
    result = execute_tool(tool, _default_kwargs(keep_open=True),
                          investigation_ref="host-inv", budget=budget)
    assert result.data["execution_budget"] == {
        "limit": 2, "source": "host_config", "used": 1}
    sid = result.data["session_id"]
    result = execute_tool(tool, _default_kwargs(session_id=sid),
                          investigation_ref="host-inv", budget=budget)
    assert result.data["executions_total"] == 2
    result = execute_tool(tool, _default_kwargs(session_id=sid),
                          investigation_ref="host-inv", budget=budget)
    assert result.data["refused"]["reason"] == "execution_quota_exhausted"


def test_old_snapshot_without_execution_limit_falls_back(tmp_path: Path, fake_docker,
                                                         monkeypatch) -> None:
    """票 16 世代快照无新键:Host 传 None,工具回落 env 并如实记录来源。"""
    from firmware_audit.step5_agent.host.tooling import execute_tool
    from firmware_audit.step5_agent.host.budget import RunBudget
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSION_EXECUTIONS", "1")
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    budget = RunBudget.load(tmp_path / "budget", persist=False)
    del budget.resolved["qemu_max_session_executions"]  # 模拟旧快照
    result = execute_tool(tool, _default_kwargs(keep_open=True),
                          investigation_ref="host-inv", budget=budget)
    assert result.data["execution_budget"]["source"] == "environment"
    assert result.data["execution_budget"]["limit"] == 1


@pytest.mark.parametrize("role", ["analysis", "verification"])
def test_stale_image_without_execveat_patch_blocks_before_session(tmp_path, monkeypatch, role):
    """旧镜像缺少 raw execveat deny 身份时不得创建执行会话。"""
    _arm_workspace(tmp_path)
    fake = FakeDocker(labels={"fw.qemu.version": "11.1.1", "fw.proot.version": "5.4.0"})
    monkeypatch.setattr(qs, "docker_image_identity", fake.image_identity)
    monkeypatch.setattr(qs, "docker_run_detached", fake.run_detached)
    monkeypatch.setattr(qs, "docker_exec", fake.exec)
    monkeypatch.setattr(qs, "docker_rm", fake.rm)
    result = _tool(tmp_path, role).execute(**_default_kwargs())
    assert result.data["result_class"] == "facility_failure"
    assert "execveat" in result.data["backend"]["detail"]
    assert not any(c[0] in ("run_detached", "exec") for c in fake.calls)
    assert not (tmp_path / "qemu_sessions/ledger.json").exists()


@pytest.mark.parametrize("label", [
    "fw.qemu.version", "fw.proot.version", "fw.proot.patch.sha256",
    "fw.proot.execveat.patch.sha256", "fw.boundary",
])
@pytest.mark.parametrize("role", ["analysis", "verification"])
def test_stale_image_with_any_backend_identity_drift_blocks_before_session(
    tmp_path, monkeypatch, role, label
):
    """raw deny 标签不能单独 bless 一个漂移的 PRoot/QEMU 后端。"""
    _arm_workspace(tmp_path)
    labels = dict(FakeDocker.DEFAULT_LABELS)
    labels[label] = "wrong"
    fake = FakeDocker(labels=labels)
    monkeypatch.setattr(qs, "docker_image_identity", fake.image_identity)
    monkeypatch.setattr(qs, "docker_run_detached", fake.run_detached)
    monkeypatch.setattr(qs, "docker_exec", fake.exec)
    monkeypatch.setattr(qs, "docker_rm", fake.rm)
    result = _tool(tmp_path, role=role).execute(**_default_kwargs())
    assert result.data["result_class"] == "facility_failure"
    assert label in result.data["backend"]["identity_mismatches"]
    assert fake.calls == [("labels", qs.QEMU_EXEC_V2_IMAGE)]
    assert not (tmp_path / "qemu_sessions/ledger.json").exists()


def test_scope_slug_collision_keeps_distinct_evidence(tmp_path, fake_docker):
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    first = tool.execute(**_default_kwargs(investigation_ref="inv/a"))
    second = tool.execute(**_default_kwargs(investigation_ref="inv?a"))
    assert first.data["session_id"] != second.data["session_id"]
    entries = _read_ledger(tmp_path)["sessions"]
    assert [s["investigation_ref"] for s in entries] == ["inv/a", "inv?a"]


def test_cleanup_removal_failure_overrides_success(tmp_path, fake_docker, monkeypatch):
    _arm_workspace(tmp_path)
    monkeypatch.setattr(qs, "docker_rm", lambda *a, **kw: (1, "", "daemon lost"))
    result = _tool(tmp_path).execute(**_default_kwargs())
    assert result.data["status"] == "seal_failed"
    assert result.data["sealed"] is False
    assert result.data["container_removal"]["verdict"] == "uncertain"
    assert result.data["execution"]["exit_code"] == 0


def test_post_start_exception_seals_uncertain_cleanup(tmp_path, fake_docker, monkeypatch):
    """观测边界异常:执行事实保留;清理未确认 → 立即销毁容器并封存(AC1/AC8)。"""
    _arm_workspace(tmp_path)
    original = qs.docker_exec
    def broken_snapshot(container, args, **kwargs):
        if args[:2] == ["/usr/local/bin/llscan", "cat"]:
            raise OSError("snapshot read failed")
        return original(container, args, **kwargs)
    monkeypatch.setattr(qs, "docker_exec", broken_snapshot)
    result = _tool(tmp_path).execute(**_default_kwargs(keep_open=True))
    assert result.data["result_class"] == "facility_failure"
    assert result.data["execution"]["exit_code"] == 0, "执行已发生,退出码保留"
    assert "清理未确认" in (result.data.get("detail") or "")
    # 清理无法确认 → 容器拆除兜底 + 封存,不得复用
    assert fake_docker.removed, "清理未确认必须拆容器"
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "sealed" and entry["sealed"] is True
    assert len(entry["executions"]) == 1
    # 封存后的会话不可继续
    monkeypatch.setattr(qs, "docker_exec", original)
    sid = entry["session_id"]
    refused = _tool(tmp_path).execute(**_default_kwargs(session_id=sid))
    assert refused.data["result_class"] == "prep_blocked"


def test_cleanup_leftover_in_reused_session_forces_seal(tmp_path, fake_docker):
    """残留未清(leftover)→ 销毁会话容器并封存;同容器不得继续执行(AC1/AC8)。"""
    _arm_workspace(tmp_path)
    fake_docker.count_queue = ["3", "3"]  # 升级击杀后仍残留
    tool = _tool(tmp_path)
    r = tool.execute(**_default_kwargs(keep_open=True))
    assert r.data["cleanup"]["verdict"] == "leftover"
    assert r.data["sealed"] is True and r.data["status"] == "sealed"
    assert "不得复用" in (r.data.get("detail") or "")
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "sealed"
    refused = tool.execute(**_default_kwargs(session_id=entry["session_id"]))
    assert refused.data["result_class"] == "prep_blocked"
    assert "封存" in refused.data["detail"]


def test_budget_exhausted_after_open_seals_fresh_session(tmp_path, fake_docker):
    """预算在开启后、启动前耗尽:目标未运行,新开单发会话立即封存。"""
    _arm_workspace(tmp_path)
    tool = _tool(tmp_path)
    remaining = iter((60, 0))  # 预备阶段还有预算,执行前耗尽
    r = tool.execute_for_scope(
        {"file_ref": "fw/usr/sbin/nvram", "firmware_root": "fw"},
        investigation_ref="inv-1",
        remaining_seconds=lambda: next(remaining))
    assert r.ok and r.data["result_class"] == "prep_blocked"
    assert r.data["sealed"] is True and r.data["status"] == "sealed"
    assert fake_docker.containers_started, "容器已开启(名额已占)"
    assert fake_docker.removed, "单发会话未执行也要封存拆除"
    ledger = _read_ledger(tmp_path)
    assert ledger["sessions"][0]["executions"] == []
    assert [r["reason"] for r in ledger["refusals"]] == ["budget_exhausted"]


def test_interrupt_at_open_boundary_leaves_reapable_placeholder(tmp_path, fake_docker,
                                                                monkeypatch):
    """AC9 开启边界中断:占位已入账,恢复路径按名收割(absent=确认清理)。"""
    _arm_workspace(tmp_path)
    def interrupt_start(*args, **kwargs):
        raise KeyboardInterrupt("host died at open")
    monkeypatch.setattr(qs, "docker_run_detached", interrupt_start)
    tool = _tool(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        tool.execute(**_default_kwargs(keep_open=True))
    ledger = _read_ledger(tmp_path)
    assert ledger["sessions"][0]["status"] == "running"
    assert not fake_docker.removed
    # 恢复:容器从未建成(rm 报 absent)= 确认清理;会话死亡
    fake_docker.rm_results = [(1, "", "Error: No such container: fw-qemu-x")]
    report = reap_leftover_sessions(tmp_path)
    assert report["reaped"] == [ledger["sessions"][0]["session_id"]]
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "interrupted"
    assert entry["cleanup"]["verdict"] == "absent"


# ---------- 离线:环境/依赖/输入身份(票 16 语义保持) ----------

@pytest.mark.parametrize("env", ["PROOT_NO_SECCOMP=1", "PROOT_TMP_DIR=/tmp",
                                  "QEMU_LD_PREFIX=/host-rootfs", "LD_PRELOAD=/tmp/x.so"])
def test_guest_environment_cannot_configure_native_backend(tmp_path, fake_docker, env):
    _arm_workspace(tmp_path)
    result = _tool(tmp_path).execute(**_default_kwargs(env=env))
    assert result.data["result_class"] == "prep_blocked"
    assert not any(c[0] == "run_detached" for c in fake_docker.calls)


def test_dependency_digest_does_not_read_outside_firmware(tmp_path, fake_docker):
    _arm_workspace(tmp_path)
    fw = tmp_path / "extracted/fw"
    external = tmp_path / "host-only-loader"
    external.write_text("not firmware")
    loader = fw / "lib/ld-uClibc.so.0"
    loader.unlink()
    loader.symlink_to(external)
    result = _tool(tmp_path).execute(**_default_kwargs())
    assert result.data["result_class"] == "dependency_blocked"
    assert not any(c[0] == "run_detached" for c in fake_docker.calls)


def test_input_digest_and_output_byte_count(tmp_path, fake_docker):
    import hashlib
    _arm_workspace(tmp_path)
    data = b"request=known"
    (tmp_path / "extracted/input.txt").write_bytes(data)
    fake_docker.exec_results = [(0, "中文", "")]
    result = _tool(tmp_path).execute(**_default_kwargs(input_ref="input.txt"))
    assert result.data["declared"]["input"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert result.data["execution"]["stdout_bytes"] == len("中文".encode())


@pytest.mark.parametrize("message,expected", [
    ("qemu-arm-static: Invalid ELF image for this architecture", "prep_blocked"),
    ("error while loading shared libraries: libfoo.so: cannot open shared object file", "dependency_blocked"),
])
def test_boundary_and_runtime_dependency_are_not_target_crashes(tmp_path, fake_docker, message, expected):
    _arm_workspace(tmp_path)
    fake_docker.exec_results = [(139, "", message)]
    result = _tool(tmp_path).execute(**_default_kwargs())
    assert result.data["result_class"] == expected
    assert result.data["execution"]["exit_code"] == 139


def test_fast_exit_124_is_not_a_timeout():
    kind, _, note = qs.QemuExecuteTool._classify(124, 0.1, 60, "", "")
    assert kind == "nonzero_exit"
    kind, _, _ = qs.QemuExecuteTool._classify(124, 60.2, 60, "", "")
    assert kind == "timeout"


def test_static_precheck_allows_execution_after_execveat_boundary(tmp_path, monkeypatch):
    _arm_workspace(tmp_path)
    from firmware_audit.step5_agent.providers.tools.qemu_precheck import QemuPrecheckTool
    monkeypatch.setattr(QemuPrecheckTool, "_facility_check", lambda *a: {"available": False})
    precheck = make_tools(ToolContext(process_dir=tmp_path), role="analysis")["qemu_precheck"]
    result = precheck.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw")
    assert result.data["execution_gate"]["allowed"] is True
    assert result.data["execution_gate"]["reason"] is None
    assert "尚未闭合" not in result.text
    assert not (tmp_path / "qemu_sessions").exists()


def test_session_pins_inspected_image_id(tmp_path, fake_docker):
    _arm_workspace(tmp_path)
    result = _tool(tmp_path).execute(**_default_kwargs())
    assert result.data["backend"]["image_id"] == "sha256:test-image"
    call = next(c for c in fake_docker.calls if c[0] == "run_detached")
    assert call[1] == "sha256:test-image"


# ---------- 票 18:环境适配模板(离线;Docker 替身) ----------

def test_adaptation_session_shape_and_ledger(tmp_path: Path, monkeypatch,
                                             fake_docker) -> None:
    """适配声明在开启时固化:容器挂载、逐执行 PRoot bind、LD_PRELOAD、
    台账逐项来源;复用会话携带适配参数被拒。"""
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = tmp_path / "ws"
    _arm_workspace(ws)
    (ws / "extracted" / "fw" / "etc").mkdir()
    (ws / "extracted" / "fw" / "etc" / "conntrack.conf").write_bytes(b"conf")
    tool = _tool(ws, role="analysis")
    fixture_b64 = base64.b64encode(b"tcp 6 ESTABLISHED src=10.0.0.1\n").decode()

    r = tool.execute(
        file_ref="fw/usr/sbin/nvram", firmware_root="fw",
        investigation_ref="case-adapt",
        adapt_binds=("rw:/var=base/varstate\n"
                     "ro:/proc/net/ip_conntrack=fixture/conntrack\n"
                     "ro:/etc/conntrack.conf=extracted/etc/conntrack.conf\n"),
        adapt_fixtures=f"conntrack={fixture_b64}",
        nvram_values="wan_wifi_ssid=testwlan\n",
        nvram_sources="wan_wifi_ssid=declared_test_input\n",
        keep_open=True)
    d = r.data
    assert d["result_class"] == "normal_exit", d
    session_id = d["session_id"]

    # 会话容器挂载:夹具与适配材料目录(ro)
    open_call = next(c for c in fake_docker.calls if c[0] == "run_detached")
    container_mounts = {m[1]: m[2] for m in open_call[3]}
    assert container_mounts["/session/fixtures"] == "ro"
    assert container_mounts["/session/adapt"] == "ro"

    # 目标执行 argv:逐执行 bind;LD_PRELOAD 经 exec_env 注入(替身逐字记录)
    exec_call = next(c for c in fake_docker.calls if c[0] == "exec")
    argv = " ".join(exec_call[1])
    assert "/session/runtime/base/varstate:/var" in argv
    assert "/session/fixtures/conntrack:/proc/net/ip_conntrack" in argv
    assert "/session/firmware/etc/conntrack.conf:/etc/conntrack.conf" in argv
    assert "/session/adapt/libnvram_shim.so:/session/adapt/libnvram_shim.so" in argv
    assert "/session/adapt/nvram.img:/session/adapt/nvram.img" in argv
    env_pairs = dict(exec_call[2])
    assert env_pairs.get("LD_PRELOAD") == "/session/adapt/libnvram_shim.so"

    # 台账:声明逐项来源与身份;适配桩产物已复制进会话 adapt 目录
    entry = _read_ledger(ws)["sessions"][0]
    adaptation = entry["adaptation"]
    assert adaptation["nvram"]["values_count"] == 1
    assert adaptation["nvram"]["values"] == {"wan_wifi_ssid": "declared_test_input"}
    assert len(adaptation["nvram"]["image_sha256"]) == 64
    assert adaptation["nvram"]["unsupported"].startswith("set/unset/commit")
    assert adaptation["fixtures"][0]["source"] == "declared_test_input"
    assert {b["kind"] for b in adaptation["binds"]} == {"base", "fixture", "extracted"}
    adapt_dir = ws / "qemu_sessions" / session_id / "adapt"
    assert (adapt_dir / "libnvram_shim.so").is_file()
    assert (adapt_dir / "nvram.img").read_bytes() == b"wan_wifi_ssid=testwlan\x00"
    assert (ws / "qemu_sessions" / session_id / "fixtures" / "conntrack") \
        .read_bytes().startswith(b"tcp 6")

    # 复用会话:不同声明拒绝(适配在会话期固化);相同声明幂等放行执行
    r2 = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                      investigation_ref="case-adapt", session_id=session_id,
                      nvram_values="k=different", nvram_sources="k=s")
    assert r2.data["result_class"] == "prep_blocked"
    assert "固化" in r2.data["detail"]
    # 含遮蔽型 extracted bind 的相同声明也必须幂等放行(派生记账字段
    # shadowed_original 不计入声明比较)
    r3 = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                      investigation_ref="case-adapt", session_id=session_id,
                      adapt_binds=("rw:/var=base/varstate\n"
                                   "ro:/proc/net/ip_conntrack=fixture/conntrack\n"
                                   "ro:/etc/conntrack.conf=extracted/etc/conntrack.conf\n"),
                      adapt_fixtures=f"conntrack={fixture_b64}",
                      nvram_values="wan_wifi_ssid=testwlan\n",
                      nvram_sources="wan_wifi_ssid=declared_test_input\n",
                      args="get wl0_ssid", use_strace=False)
    d3 = r3.data
    assert d3["result_class"] == "normal_exit", d3
    assert d3["execution"]["seq"] == 2
    assert d3["adaptation"]["binds"][2]["shadowed_original"]["sha256"] is not None
    # 相同声明 + stop=true:幂等通过并停机封存
    r4 = tool.execute(investigation_ref="case-adapt", session_id=session_id,
                      stop=True)
    assert r4.data["action"] == "session_stop"
    assert r4.data["sealed"] is True

    # 适配声明入报告
    assert d["adaptation"]["nvram"]["family"] == "dev_nvram"
    assert any("适配(会话期固化)" in line for line in (r.text or "").splitlines())


def test_adaptation_declaration_failures_refuse_before_open(
        tmp_path: Path, monkeypatch, fake_docker) -> None:
    """声明非法/NVRAM 值缺来源/桩钉值漂移:准备阻塞,不建容器不占名额。"""
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = tmp_path / "ws"
    _arm_workspace(ws)
    tool = _tool(ws, role="analysis")

    cases = [
        ({"adapt_binds": "ro:/tmp/x=fixture/a"}, "保留前缀"),
        ({"adapt_binds": "ro:/x=fixture/missing",
          "adapt_fixtures": "other=" + base64.b64encode(b"x").decode()}, "未声明夹具"),
        ({"nvram_values": "k=v"}, "缺来源引用"),
        ({"nvram_sources": "k=s"}, "没有对应值"),
    ]
    for over, why in cases:
        r = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                         investigation_ref=f"case-reject", **over)
        d = r.data
        assert d["result_class"] == "prep_blocked", (why, d)
        assert why in d["detail"], (why, d["detail"])
    assert _read_ledger(ws)["sessions"] == []
    assert fake_docker.containers_started == []

    # 桩钉值漂移:开启前拒绝,不装配
    r = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                     investigation_ref="case-drift",
                     nvram_values="k=v", nvram_sources="k=s")
    assert r.data["result_class"] == "normal_exit"
    monkeypatch.setattr(qemu_adapt, "NVRAM_SHIM_SHA256", "f" * 64)
    r = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                     investigation_ref="case-drift-2",
                     nvram_values="k=v", nvram_sources="k=s")
    assert r.data["result_class"] == "prep_blocked"
    assert "漂移" in r.data["detail"]
    sessions = _read_ledger(ws)["sessions"]
    assert all(s["investigation_ref"] == "case-drift" for s in sessions)


def test_nvram_unresolved_gap_recorded_and_consumed_per_execution(
        tmp_path: Path, monkeypatch, fake_docker) -> None:
    """未声明键:桩日志读回为执行级 gap;逐执行消费,不跨执行串账。"""
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = tmp_path / "ws"
    _arm_workspace(ws)
    tool = _tool(ws, role="analysis")

    real_exec = fake_docker.exec

    def exec_writing_log(container, args, *, env=None, detach=False,
                         timeout=300, stdin_bytes=None):
        if not detach and args[:1] == ["/usr/bin/timeout"]:
            for runtime in (ws / "qemu_sessions").glob("*/runtime"):
                (runtime / "nvram-unresolved.log").write_text(
                    "wl0_ssid\nhttp_passwd\n", encoding="utf-8")
        return real_exec(container, args, env=env, detach=detach,
                         timeout=timeout, stdin_bytes=stdin_bytes)

    monkeypatch.setattr(qs, "docker_exec", exec_writing_log)

    r = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                     investigation_ref="case-gap",
                     nvram_values="wan_ip=10.0.0.1\n",
                     nvram_sources="wan_ip=declared_test_input\n",
                     keep_open=True)
    d = r.data
    assert d["result_class"] == "normal_exit", d
    gaps = d["adaptation_gaps"]
    assert gaps["nvram_unresolved_keys"] == ["wl0_ssid", "http_passwd"]
    assert "不得作为设备真实行为结论" in gaps["note"]
    assert any("适配缺口" in line for line in (r.text or "").splitlines())
    ledger_entry = _read_ledger(ws)["sessions"][0]
    assert ledger_entry["executions"][0]["adaptation_gaps"] == gaps
    # 第二次执行:写入的键相同,但作为本次执行的新鲜 gap 记录(日志已重置)
    sid = d["session_id"]
    r2 = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                      investigation_ref="case-gap", session_id=sid)
    assert r2.data["adaptation_gaps"]["nvram_unresolved_keys"] == \
        ["wl0_ssid", "http_passwd"]
    assert _read_ledger(ws)["sessions"][0]["executions"][1]["adaptation_gaps"][
        "nvram_unresolved_keys"] == ["wl0_ssid", "http_passwd"]


def test_stdin_delivery_records_digest(tmp_path: Path, fake_docker) -> None:
    """stdin_ref:文件字节作为目标 stdin 送达;台账记 ref/sha256/字节数。"""
    ws = tmp_path / "ws"
    _arm_workspace(ws)
    (ws / "extracted" / "fw" / "post-body.txt").write_bytes(b"uid=admin&pwd=x")
    tool = _tool(ws, role="analysis")
    r = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                     investigation_ref="case-stdin", stdin_ref="fw/post-body.txt")
    d = r.data
    assert d["result_class"] == "normal_exit", d
    assert d["declared"]["stdin"]["ref"] == "fw/post-body.txt"
    assert d["declared"]["stdin"]["size_bytes"] == 15
    assert d["declared"]["stdin"]["sha256"] == \
        qs.sha256_text("uid=admin&pwd=x")
    assert fake_docker.stdin_sizes == [15]
    entry = _read_ledger(ws)["sessions"][0]
    assert entry["executions"][0]["declared"]["stdin"]["size_bytes"] == 15


def _require_real():
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用"
                    "(先运行 firmware_audit/docker/qemu-exec-v2/build_image.sh)")
    if not TGT6_SQUASH.is_dir():
        pytest.skip(f"target/6 解包树缺失: {TGT6_SQUASH}")


TGT7_SQUASH = (REPO_ROOT / "target/7/process/extracted/"
               "000002_partition_1.bin.extracted/0/squashfs-root")


def _copy_lib_tree(src_root: Path, dst_root: Path) -> None:
    """复制固件 lib 全目录(符号链接原样,常规文件按内容);原件只读。"""
    lib = src_root / "lib"
    if not lib.is_dir():
        return
    for item in lib.iterdir():
        dst = dst_root / "lib" / item.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        if item.is_symlink():
            shutil.copy2(item, dst, follow_symlinks=False)
        elif item.is_file():
            shutil.copy2(item, dst, follow_symlinks=True)


def _copy_rel(src_root: Path, dst_root: Path, rel: str) -> bool:
    src = src_root / rel
    if not (src.is_file() or src.is_symlink()):
        return False
    dst = dst_root / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst, follow_symlinks=True)
    return True


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
    assert d["result_class"] == "prep_blocked", d
    assert "Invalid ELF image" in (d["observation_excerpt"]["stderr"]["excerpt"]
                                   + d["observation_excerpt"]["stdout"]["excerpt"])
    assert d["cleanup"]["verdict"] in ("clean", "clean_after_kill")
    assert d["sealed"] is True

    ledger = json.loads((ws / "qemu_sessions" / "ledger.json").read_text(encoding="utf-8"))
    used = [s["investigation_ref"] for s in ledger["sessions"]]
    assert used.count("case-real") == 3
    assert ledger["sessions"][-1]["sealed"] is True


def test_real_session_state_continuity_cleanup_and_session_death(
        tmp_path: Path, monkeypatch) -> None:
    """票 17 核心:同一会话两次执行状态连续;新会话干净重建;封存即死亡。"""
    _require_real()
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = _real_workspace(tmp_path)
    tool = _tool(ws, role="verification")

    # ① 开会话 + 第一次执行:向运行目录(guest /tmp)写状态
    r1 = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                      investigation_ref="case-cont", keep_open=True,
                      args="sh -c '/bin/busybox echo session-state-ok > /tmp/state.txt'")
    d1 = r1.data
    assert d1["result_class"] == "normal_exit", d1
    assert d1["sealed"] is False and d1["status"] == "running"
    session_id = d1["session_id"]

    # ② 同一会话第二次执行:读回前序写入(状态跨执行积累)
    r2 = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                      investigation_ref="case-cont", session_id=session_id,
                      args="sh -c '/bin/busybox cat /tmp/state.txt'")
    d2 = r2.data
    assert d2["result_class"] == "normal_exit", d2
    assert "session-state-ok" in d2["observation_excerpt"]["stdout"]["excerpt"]
    assert d2["executions_total"] == 2

    ledger = json.loads((ws / "qemu_sessions" / "ledger.json").read_text(encoding="utf-8"))
    entry = next(s for s in ledger["sessions"] if s["session_id"] == session_id)
    # 同一容器:容器身份唯一;每次执行各自声明输入与输出 digest
    assert len({json.dumps(e["declared"]["argv"]) for e in entry["executions"]}) == 2
    assert entry["executions"][0]["execution"]["stdout_sha256"] != \
        entry["executions"][1]["execution"]["stdout_sha256"]
    # 执行之间无目标进程存活:两次执行的清理验证均为干净
    for execution in entry["executions"]:
        assert execution["cleanup"]["verdict"] in ("clean", "clean_after_kill"), execution["cleanup"]

    # 宿主侧:状态文件真实落在该会话的运行目录(不是 guest 幻觉)
    state_file = ws / "qemu_sessions" / session_id / "runtime" / "state.txt"
    assert state_file.read_text(encoding="utf-8", errors="replace").strip() == "session-state-ok"

    # ③ 仅停机:容器拆除封存
    r3 = tool.execute(investigation_ref="case-cont", session_id=session_id, stop=True)
    assert r3.data["action"] == "session_stop"
    assert r3.data["sealed"] is True and r3.data["status"] == "sealed"

    # ④ 封存即死亡:旧会话不可继续
    r4 = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                      investigation_ref="case-cont", session_id=session_id,
                      args="sh -c '/bin/busybox cat /tmp/state.txt'")
    assert r4.data["result_class"] == "prep_blocked"
    assert "封存" in r4.data["detail"]

    # ⑤ 新会话干净重建:不继承旧运行文件
    r5 = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                      investigation_ref="case-cont",
                      args="sh -c '/bin/busybox cat /tmp/state.txt'")
    d5 = r5.data
    assert d5["result_class"] == "nonzero_exit", d5
    assert "session-state-ok" not in (
        d5["observation_excerpt"]["stdout"]["excerpt"]
        + d5["observation_excerpt"]["stderr"]["excerpt"])
    assert d5["session_id"] != session_id


def test_real_in_session_execution_quota(tmp_path: Path, monkeypatch) -> None:
    _require_real()
    monkeypatch.setenv("STEP5_QEMU_MAX_SESSION_EXECUTIONS", "2")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = _real_workspace(tmp_path)
    tool = _tool(ws, role="analysis")
    r1 = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                      investigation_ref="case-quota", keep_open=True,
                      args="sh -c '/bin/busybox echo exec-1'")
    assert r1.data["result_class"] == "normal_exit"
    sid = r1.data["session_id"]
    r2 = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                      investigation_ref="case-quota", session_id=sid,
                      args="sh -c '/bin/busybox echo exec-2'")
    assert r2.data["result_class"] == "normal_exit"
    r3 = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                      investigation_ref="case-quota", session_id=sid,
                      args="sh -c '/bin/busybox echo exec-3'")
    assert r3.data["result_class"] == "prep_blocked"
    assert r3.data["refused"]["reason"] == "execution_quota_exhausted"
    ledger = json.loads((ws / "qemu_sessions" / "ledger.json").read_text(encoding="utf-8"))
    entry = next(s for s in ledger["sessions"] if s["session_id"] == sid)
    assert len(entry["executions"]) == 2
    assert entry["execution_budget"] == {"limit": 2, "source": "environment", "used": 2}
    assert [r["reason"] for r in ledger["refusals"]] == ["execution_quota_exhausted"]


def test_real_leftover_container_reaped_by_recovery(tmp_path: Path, monkeypatch) -> None:
    """Host 死亡现场:客户端调用已返回而容器存活;恢复路径强制收割。"""
    import subprocess
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用")
    if not TGT6_SQUASH.is_dir():
        pytest.skip(f"target/6 解包树缺失: {TGT6_SQUASH}")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = _real_workspace(tmp_path)
    tool = _tool(ws, role="verification")
    # 后台子孙探针:后台 sleep 与前台 sleep 同属容器 cgroup,
    # 恢复收割按容器权威拆除,一并处置(固件 busybox 无 setsid,主动
    # 脱离会话的专项探针受限,如实记录于票 17 Comments)。
    r = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                     investigation_ref="case-orphan", keep_open=True,
                     args="sh -c '/bin/busybox sleep 30 & /bin/busybox sleep 30'")
    assert r.data["status"] == "running", r.data
    session_id = r.data["session_id"]
    container = f"fw-qemu-{session_id}"

    def _docker_ps() -> str:
        probe = subprocess.run(
            ["docker", "ps", "--filter", f"name={container}",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        return probe.stdout

    assert container in _docker_ps(), "客户端调用返回后容器必须仍存活(遗留现场)"

    report = reap_leftover_sessions(ws)
    assert session_id in report["reaped"], report
    assert container not in _docker_ps(), "收割后容器必须真实消失"
    ledger = json.loads((ws / "qemu_sessions" / "ledger.json").read_text(encoding="utf-8"))
    entry = next(s for s in ledger["sessions"] if s["session_id"] == session_id)
    assert entry["status"] == "interrupted"
    assert entry["seal_kind"] == "recovery_reap"
    assert entry["sealed"] is True
    assert entry["cleanup"]["verdict"] == "container_removed"
    assert entry["executions"] and entry["executions"][0]["declared"]["argv"] == [
        "sh", "-c", "/bin/busybox sleep 30 & /bin/busybox sleep 30"]

    # 中断即会话死亡:不可继续,已持久化执行留档
    r2 = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                      investigation_ref="case-orphan", session_id=session_id,
                      args="sh -c x")
    assert r2.data["result_class"] == "prep_blocked"
    assert "中断" in r2.data["detail"]


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
    # 链存活期越过观察点(t+2s):快照应捕获 tracer/桩,短命子进程缺项由 note 明示
    assert d["chain"]["snapshot"], "存活链的 /proc 快照不应为空"
    assert "短命子进程" in d["chain"]["snapshot_note"]
    assert d["chain"]["stub_identities"]
    assert all(item["identity_complete"] for item in d["chain"]["stub_identities"])


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
    (fw / "bin").mkdir()
    shutil.copy2(TGT8_SQUASH / "bin/busybox", fw / "bin" / "busybox",
                 follow_symlinks=True)
    libdir = TGT8_SQUASH / "lib"
    if libdir.is_dir():
        shutil.copytree(libdir, fw / "lib", dirs_exist_ok=True, symlinks=False)
    tool = _tool(tmp_path, role="analysis")
    r = tool.execute(file_ref="fw8/bin/busybox", firmware_root="fw8",
                     investigation_ref="case-mips",
                     args="sh -c '/bin/busybox echo env-parent-mips-ok'")
    d = r.data
    assert d["result_class"] == "normal_exit", d
    assert "env-parent-mips-ok" in d["observation_excerpt"]["stdout"]["excerpt"]


def test_execution_knob_env_name_consistent_across_layers() -> None:
    """QEMU 预算旋钮的 env 名与默认值在 budget 层与工具层一致(分层不可互导,
    用测试钉住单一来源)。"""
    from firmware_audit.step5_agent.host.budget import (
        DEFAULT_BUDGET_CONFIG,
        ENV_KEYS,
        QEMU_MAX_SESSION_EXECUTIONS_KEY,
    )
    from firmware_audit.step5_agent.providers.tools.qemu_base import (
        DEFAULT_MAX_SESSION_EXECUTIONS,
        QEMU_MAX_SESSION_EXECUTIONS_ENV,
    )
    assert ENV_KEYS[QEMU_MAX_SESSION_EXECUTIONS_KEY] == QEMU_MAX_SESSION_EXECUTIONS_ENV
    assert (DEFAULT_BUDGET_CONFIG[QEMU_MAX_SESSION_EXECUTIONS_KEY]
            == DEFAULT_MAX_SESSION_EXECUTIONS)


# ---------- 票 18:真实通路与 NVRAM ABI(门控;真实 PRoot/QEMU 后端) ----------

def test_real_opkg_mipsbe_business_pathway_and_control(
        tmp_path: Path, monkeypatch) -> None:
    """票 18 选定业务通路(target/8 opkg,MIPS32 大端):固件原生包数据库
    → 已装包清单;正常对照(info 过滤同一配置)证明输入→输出真实处理。
    预检不计入该项验收;结果分类只是 Evidence,不构成漏洞结论。"""
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用")
    tgt8 = TGT8_SQUASH
    if not tgt8.is_dir():
        pytest.skip(f"target/8 解包树缺失: {tgt8}")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = tmp_path / "ws"
    root = ws / "extracted" / "fw"
    for rel in ("bin/opkg", "lib/libc.so", "lib/ld-musl-mips-sf.so.1",
                "lib/libgcc_s.so.1", "lib/libubox.so",
                "etc/opkg.conf", "usr/lib/opkg/status"):
        assert _copy_rel(tgt8, root, rel), f"固件子树缺失: {rel}"
    tool = _tool(ws, role="analysis")

    # ① 业务输出:固件原生 status 数据库 → 已装包清单
    r1 = tool.execute(file_ref="fw/bin/opkg", firmware_root="fw",
                      investigation_ref="case-opkg", keep_open=True,
                      args="list-installed", use_strace=False,
                      timeout_seconds=90,
                      adapt_binds="rw:/var/lock=base/varlock")
    d1 = r1.data
    assert d1["result_class"] == "normal_exit", d1
    out1 = d1["observation_excerpt"]["stdout"]["excerpt"]
    assert "busybox" in out1 and "base-files" in out1
    assert d1["adaptation"]["binds"][0]["mode"] == "rw"

    # ② 正常对照:同一固件配置,info 子命令过滤出单条记录
    r2 = tool.execute(file_ref="fw/bin/opkg", firmware_root="fw",
                      investigation_ref="case-opkg", session_id=d1["session_id"],
                      args="info busybox", use_strace=False, timeout_seconds=90,
                      adapt_binds="rw:/var/lock=base/varlock")
    d2 = r2.data
    assert d2["result_class"] == "normal_exit", d2
    out2 = d2["observation_excerpt"]["stdout"]["excerpt"]
    assert "Package: busybox" in out2 and "Version:" in out2
    # 输入不同 → 输出不同:两次都是真实业务处理,而非启动成功
    assert d2["executions_total"] == 2
    assert d2["declared"]["argv"] == ["info", "busybox"]


def test_real_t6_nvram_abi_known_missing_unknown(tmp_path: Path,
                                                 monkeypatch) -> None:
    """票 18 AC(target/6 通用接口):真实 libnvram 库经适配桩取得
    已声明值;缺失/未知键按固件缺失键语义返回 NULL 并记入未决 gap。"""
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用")
    if not TGT6_SQUASH.is_dir():
        pytest.skip(f"target/6 解包树缺失: {TGT6_SQUASH}")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = tmp_path / "ws"
    root = ws / "extracted" / "fw"
    assert _copy_rel(TGT6_SQUASH, root, "usr/sbin/nvram")
    _copy_lib_tree(TGT6_SQUASH, root)
    tool = _tool(ws, role="analysis")

    common = dict(nvram_values="wl0_ssid=fwtest_ssid\nrouter_mode=ap\n",
                  nvram_sources="wl0_ssid=declared_test_input\n"
                                "router_mode=declared_test_input\n")
    r1 = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                      investigation_ref="case-t6abi", keep_open=True,
                      use_strace=False, args="get wl0_ssid", **common)
    d1 = r1.data
    assert d1["result_class"] == "normal_exit", d1
    assert d1["observation_excerpt"]["stdout"]["excerpt"] == "wl0_ssid=fwtest_ssid\n"
    assert d1["adaptation"]["nvram"]["family"] == "dev_nvram"

    r2 = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                      investigation_ref="case-t6abi",
                      session_id=d1["session_id"],
                      use_strace=False, args="get router_mode", **common)
    d2 = r2.data
    assert d2["observation_excerpt"]["stdout"]["excerpt"] == "router_mode=ap\n"
    assert d2["adaptation_gaps"] is None

    # 缺失/未知键:真实库返回 NULL(空输出),键入未决日志,结果明示 gap
    r3 = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                      investigation_ref="case-t6abi",
                      session_id=d1["session_id"],
                      use_strace=False, args="get fwtest_missing_key", **common)
    d3 = r3.data
    assert d3["result_class"] == "normal_exit", d3
    assert d3["observation_excerpt"]["stdout"]["excerpt"] == ""
    gaps = d3["adaptation_gaps"]
    assert gaps is not None and gaps["nvram_unresolved_keys"] == ["fwtest_missing_key"]
    assert "不得作为设备真实行为结论" in gaps["note"]
    ledger_entry = _read_ledger(ws)["sessions"][0]
    assert ledger_entry["executions"][2]["adaptation_gaps"] == gaps


def test_real_t7_nvram_abi_and_envram_negative(tmp_path: Path,
                                               monkeypatch) -> None:
    """票 18 AC(target/7):真实固件库读取设备真实默认值
    (webroot_ro/nvram_default.cfg 为来源);envram(MTD)系未支持族
    不因同名库放行——真实 envram 代码对缺失 MTD 如实失败,模板值不泄漏。"""
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用")
    if not TGT7_SQUASH.is_dir():
        pytest.skip(f"target/7 解包树缺失: {TGT7_SQUASH}")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = tmp_path / "ws"
    root = ws / "extracted" / "fw"
    assert _copy_rel(TGT7_SQUASH, root, "bin/nvram")
    assert _copy_rel(TGT7_SQUASH, root, "bin/envram")
    _copy_lib_tree(TGT7_SQUASH, root)
    tool = _tool(ws, role="analysis")

    common = dict(nvram_values="lan_ifname=br0\nos_name=linux\n",
                  nvram_sources="lan_ifname=target/7 webroot_ro/nvram_default.cfg\n"
                                "os_name=target/7 webroot_ro/nvram_default.cfg\n")

    # ① 设备真实默认值经真实库读出
    r1 = tool.execute(file_ref="fw/bin/nvram", firmware_root="fw",
                      investigation_ref="case-t7abi", keep_open=True,
                      use_strace=False, args="get lan_ifname", **common)
    d1 = r1.data
    assert d1["result_class"] == "normal_exit", d1
    assert d1["observation_excerpt"]["stdout"]["excerpt"] == "lan_ifname=br0\n"

    # ② 缺失键 → NULL + gap
    r2 = tool.execute(file_ref="fw/bin/nvram", firmware_root="fw",
                      investigation_ref="case-t7abi",
                      session_id=d1["session_id"],
                      use_strace=False, args="get t7_missing_probe", **common)
    d2 = r2.data
    assert d2["observation_excerpt"]["stdout"]["excerpt"] == ""
    assert d2["adaptation_gaps"]["nvram_unresolved_keys"] == ["t7_missing_probe"]

    # ③ envram 负对照:同一模板值不得经 envram 系泄漏
    r3 = tool.execute(file_ref="fw/bin/envram", firmware_root="fw",
                      investigation_ref="case-t7envram",
                      use_strace=False, timeout_seconds=45,
                      args="get lan_ifname", **common)
    d3 = r3.data
    out3 = (d3["observation_excerpt"]["stdout"]["excerpt"]
            + d3["observation_excerpt"]["stderr"]["excerpt"])
    assert "read flash error" in out3, out3
    assert "br0" not in out3, "模板值不得经未支持族泄漏"
    assert d3["adaptation_gaps"] is None or \
        d3["adaptation_gaps"].get("nvram_unresolved_keys") is None


def test_real_t7_httpd_bcm_vendor_wrapper_consumes_template(
        tmp_path: Path, monkeypatch) -> None:
    """票 18 AC(target/7 厂商包装):httpd 启动期经真实 libCfm
    bcm_nvram_get 消费模板值(br0 出现在 SIOCGIFADDR ioctl 的业务逻辑中);
    常驻服务本身第一阶段不交付,进程按预算清理并如实分类。"""
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用")
    if not TGT7_SQUASH.is_dir():
        pytest.skip(f"target/7 解包树缺失: {TGT7_SQUASH}")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = tmp_path / "ws"
    root = ws / "extracted" / "fw"
    assert _copy_rel(TGT7_SQUASH, root, "bin/httpd")
    _copy_lib_tree(TGT7_SQUASH, root)
    tool = _tool(ws, role="analysis")
    r = tool.execute(file_ref="fw/bin/httpd", firmware_root="fw",
                     investigation_ref="case-t7bcm", use_strace=True,
                     timeout_seconds=15,
                     nvram_values="lan_ifname=br0\nos_name=linux\n",
                     nvram_sources="lan_ifname=target/7 webroot_ro/nvram_default.cfg\n"
                                   "os_name=target/7 webroot_ro/nvram_default.cfg\n")
    d = r.data
    # 常驻服务被预算击杀:target_signal/timeout 都是如实的分类
    assert d["result_class"] in ("target_signal", "timeout"), d
    stderr = d["observation_excerpt"]["stderr"]["excerpt"]
    assert "SIOCGIFADDR" in stderr and "br0" in stderr, stderr[:500]
    assert d["cleanup"]["verdict"] in ("clean", "clean_after_kill")
    # 台账:声明值与来源逐字可复查
    declared_nv = d["adaptation"]["nvram"]
    assert declared_nv["values"] == {
        "lan_ifname": "target/7 webroot_ro/nvram_default.cfg",
        "os_name": "target/7 webroot_ro/nvram_default.cfg"}


def test_real_t6_conntrack_cgi_honest_block(tmp_path: Path, monkeypatch) -> None:
    """票 18 选定的 t6 CGI 通路候选在真实后端的如实记录:会话门附件代码
    在输出前确定性 SIGSEGV(输入无关;动态崩溃不构成漏洞结论)。
    业务通路交付由 target/8 opkg 承担(见上文),本用例固化该阻塞证据。"""
    import base64 as b64
    from firmware_audit.docker.docker_utils import docker_available
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用")
    if not TGT6_SQUASH.is_dir():
        pytest.skip(f"target/6 解包树缺失: {TGT6_SQUASH}")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    ws = tmp_path / "ws"
    root = ws / "extracted" / "fw"
    assert _copy_rel(TGT6_SQUASH, root, "htdocs/cgibin")
    _copy_lib_tree(TGT6_SQUASH, root)
    tool = _tool(ws, role="analysis")
    conntrack = ("tcp      6 4294967295 ESTABLISHED src=192.168.0.100 "
                 "dst=192.168.0.1 sport=5000 dport=80 [ASSURED] use=1\n")
    sesscfg = "600\n8\n16\n1\n"
    r = tool.execute(
        file_ref="fw/htdocs/cgibin", firmware_root="fw",
        investigation_ref="case-conntrack", use_strace=True,
        argv0="/htdocs/web/conntrack.cgi",
        env="REQUEST_METHOD=GET\n"
            "SCRIPT_FILENAME=/htdocs/web/conntrack.cgi\n"
            "REQUEST_URI=/conntrack.cgi?NETWORK=192.168.0&MASK=24\n"
            "HTTP_COOKIE=uid=probeuid",
        adapt_binds=("rw:/var=base/var\n"
                     "ro:/proc/net/ip_conntrack=fixture/conntrack\n"
                     "ro:/var/session/sesscfg=fixture/sesscfg\n"),
        adapt_fixtures=(
            "conntrack=" + b64.b64encode(conntrack.encode()).decode() + "\n"
            "sesscfg=" + b64.b64encode(sesscfg.encode()).decode()),
        timeout_seconds=45)
    d = r.data
    # 会话门(argv0 分发、/var 会话存储、sesscfg 解析)真实运行过;
    # 在产出业务输出前 SIGSEGV——崩溃如实分类,不冒充业务输出
    stderr = (d["observation_excerpt"]["stderr"]["excerpt"]
              + d["observation_excerpt"]["stdout"]["excerpt"])
    assert "/var/session/1" in d["observation_excerpt"]["stderr"]["excerpt"] or \
        "/var/session" in stderr, stderr[:400]
    assert d["result_class"] in ("nonzero_exit", "target_signal"), d
    assert "<conntrack>" not in d["observation_excerpt"]["stdout"]["excerpt"]
    assert "uncaught target signal" in stderr or d["result_class"] == "target_signal"


def test_adaptation_mismatch_build_error_refuses_in_channel(
        tmp_path: Path, fake_docker) -> None:
    """复用会话的幂等比较会重建 NVRAM 映像:超装载上限的传入声明必须在
    refuse 通道拒绝(ok=True/prep_blocked/拒绝入台账),不得逃逸成异常。"""
    ws = tmp_path / "ws"
    _arm_workspace(ws)
    tool = _tool(ws, role="analysis")
    r1 = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                      investigation_ref="case-builderr", keep_open=True,
                      nvram_values="k=v", nvram_sources="k=s",
                      use_strace=False)
    d1 = r1.data
    assert d1["result_class"] == "normal_exit", d1
    oversized = "\n".join(f"k{i:03d}=" + "v" * 250 for i in range(500))
    sources = "\n".join(f"k{i:03d}=s" for i in range(500))
    r2 = tool.execute(file_ref="fw/usr/sbin/nvram", firmware_root="fw",
                      investigation_ref="case-builderr",
                      session_id=d1["session_id"],
                      nvram_values=oversized, nvram_sources=sources)
    assert r2.ok is True
    assert r2.data["result_class"] == "prep_blocked"
    assert "装载上限" in r2.data["detail"]
    ledger = _read_ledger(ws)
    assert any(ref["reason"] == "prep_blocked" and "装载上限" in ref["detail"]
               for ref in ledger["refusals"])

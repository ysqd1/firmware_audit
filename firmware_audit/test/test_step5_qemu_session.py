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

    def run_detached(self, image, args, *, name, mounts=None, tmpfs=None,
                     entrypoint=None, network="none", read_only=False,
                     init=True, timeout=120):
        self.calls.append(("run_detached", image, name, tuple(sorted(
            (str(m[0]), m[1], m[2]) for m in (mounts or []))),
            tuple(tmpfs or []), read_only))
        self.containers_started.append(name)
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
                return 0, ("pid=9 exe=/session/stub/prooted-9-XYZ size=123 "
                           "sha256=" + "a" * 64 + " cmd=qemu\n"), ""
            if args[1] == "kill":
                self.calls.append(("exec-other", tuple(args[:2])))
                return 0, "2\n", ""
        if args[:1] == ["/usr/bin/timeout"]:
            self.calls.append(("exec", tuple(args), tuple(sorted((env or {}).items()))))
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
    # 封存:容器拆除 + 台账 sealed
    assert fake_docker.removed, "容器必须拆除"
    ledger = _read_ledger(tmp_path)
    session = ledger["sessions"][0]
    assert session["sealed"] is True
    assert session["executions"][0]["declared"]["argv"] == ["get", "foo"]
    assert r.data["declared"]["argv"] == ["get", "foo"]


def test_explicit_argv0_is_recorded_and_passed(tmp_path: Path, fake_docker: FakeDocker) -> None:
    _arm_workspace(tmp_path)
    result = _tool(tmp_path).execute(**_default_kwargs(argv0="nvram-wrapper", args="get foo"))
    assert result.data["declared"]["argv0"] == "nvram-wrapper"
    exec_call = next(call for call in fake_docker.calls if call[0] == "exec")
    argv = exec_call[1]
    target_index = argv.index("/usr/sbin/nvram")
    assert argv[target_index + 1 : target_index + 4] == ("nvram-wrapper", "get", "foo")


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
    assert entry["status"] == "running"
    assert len(entry["executions"]) == 1
    assert entry["executions"][0]["execution"]["exit_code"] == 0
    assert entry["executions"][0]["result_class"] == "facility_failure"
    assert "输出采集" in entry["executions"][0]["result_note"]
    assert not fake_docker.removed, "观测异常不即时拆容器(会话仍可恢复/停机)"

    # 恢复:执行保留在台账(留档),收割容器;恢复后新会话执行次数从 0 起
    report = reap_leftover_sessions(tmp_path)
    assert entry["session_id"] in report["reaped"]
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "interrupted"
    assert entry["execution_budget"]["used"] == 1, "已持久化执行不因恢复重复扣减"
    assert len(entry["executions"]) == 1


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

    # seal_failed 会话不得复用执行;恢复收割成功后清理如实确认
    r2 = tool.execute(**_default_kwargs(session_id=sid))
    assert r2.data["result_class"] == "prep_blocked"
    report = reap_leftover_sessions(tmp_path)
    assert sid in report["reaped"]
    entry = _read_ledger(tmp_path)["sessions"][0]
    assert entry["status"] == "interrupted"
    assert entry["cleanup"]["verdict"] == "container_removed"


def test_recovery_treats_absent_container_as_clean(tmp_path: Path,
                                                   fake_docker: FakeDocker) -> None:
    """容器已不存在(开启前中断):absent 是已确认清理,不是不确定。"""
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


def test_post_start_exception_keeps_session_recoverable(tmp_path, fake_docker, monkeypatch):
    """观测边界异常:执行事实保留;keep_open 会话留在 running,停机路径仍可用。"""
    _arm_workspace(tmp_path)
    original = qs.docker_exec
    def broken_snapshot(container, args, **kwargs):
        if args[:2] == ["/usr/local/bin/llscan", "cat"]:
            raise OSError("snapshot read failed")
        return original(container, args, **kwargs)
    monkeypatch.setattr(qs, "docker_exec", broken_snapshot)
    result = _tool(tmp_path).execute(**_default_kwargs(keep_open=True))
    assert result.data["result_class"] == "facility_failure"
    assert result.data["status"] == "running", "观测异常不改变会话生命周期"
    assert result.data["execution"]["exit_code"] == 0
    entries = _read_ledger(tmp_path)["sessions"]
    assert entries[0]["status"] == "running"
    # 停机路径仍然可用:容器可拆、台账收口
    monkeypatch.setattr(qs, "docker_exec", original)
    sid = entries[0]["session_id"]
    sealed = _tool(tmp_path).execute(investigation_ref="inv-1",
                                     session_id=sid, stop=True)
    assert sealed.data["sealed"] is True
    assert _read_ledger(tmp_path)["sessions"][0]["status"] == "sealed"


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


# ---------- 真实:ARM/MIPS 会话(门控) ----------

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
    r = tool.execute(file_ref="fw/bin/busybox", firmware_root="fw",
                     investigation_ref="case-orphan", keep_open=True,
                     args="sh -c '/bin/busybox sleep 6'")
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
        "sh", "-c", "/bin/busybox sleep 6"]

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
                     argv0="sh", args="-c '/bin/busybox echo env-parent-mips-ok'")
    d = r.data
    assert d["result_class"] == "normal_exit", d
    assert "env-parent-mips-ok" in d["observation_excerpt"]["stdout"]["excerpt"]

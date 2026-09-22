"""qemu_execute:单次真实执行的会话入口(票 16;spec 预检/会话两组能力的会话侧)。

一次工具调用 = 一个只含一次执行的会话:开启会话(干净容器)→ 执行原固件
程序及其自主派生链 → Observation + 世代内台账 → 停机封存(容器拆除)。
多次执行、跨轮状态积累、Host 死亡后的持久恢复由票 17 完成。

边界(ADR-0013 + 票 16 组合验证,证据见
.scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/):
- 隔离边界是 Docker:断网、固件根只读挂载、只读容器根、独立可写运行目录、
  不挂 docker socket/其他 target;/host-rootfs 逃逸面由 proot --mixed-mode
  继承补丁(guest 派生树内原生 x86 ELF 的 execve 一律改写经 qemu 路由 → 架构
  不符 → 拒绝)+ raw execveat deny 补丁(QEMU tracee 早期返回 EACCES)+
  镜像剥离；正式镜像身份必须带已验收的补丁摘要。
- 每会话执行命令以容器内 timeout -k 包裹(默认 60s,硬上限 180s);清理验证
  用镜像内 llscan(/proc 扫描),升级清理(连进程组 SIGKILL)后仍有残留则
  拆容器;客户端退出不等于清理完成(N4:客户端死后链仍存活)。
- 身份三分:原固件(sha256)、PRoot/QEMU 后端(镜像 LABEL/BUILD-INFO)、
  prooted 装载桩(逐执行临时名)分开记录;链观测是"延时一次快照 + QEMU_STRACE
  辅助日志",短命子进程可能未入快照——缺项明示,不宣称完整执行链身份。
- 预算归属:每 (角色, investigation_ref) 独立最多 N 个会话(默认 3,env
  STEP5_QEMU_MAX_SESSIONS 覆盖,非法回落);同归属第 N+1 个拒绝;预检不占
  名额;失败不自动原样重试。
- Observation 只是 Evidence:正常退出/崩溃/超时都不构成漏洞成立或不存在。

ToolResult.ok 语义:会话报告成功产出即为 True(含各类阻塞与目标失败);
参数未过契约或设施不可用才 False/分类承载。分类看 data.result_class。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import time
import uuid
from pathlib import Path

from ....docker.docker_utils import (
    docker_exec,
    docker_image_identity,
    docker_rm,
    docker_run_detached,
)
from .base import AgentTool, ToolContext, ToolResult, resolve_within
from .cli_base import extracted_root
from .qemu_base import (
    QEMU_EXEC_V2_IMAGE,
    QEMU_ARCH_MATRIX,
    QemuArchProfile,
    QemuResultClass,
    qemu_exec_v2_label_mismatches,
    resolve_max_sessions,
)
from .qemu_precheck import ElfParseError, find_in_root, parse_elf_runtime

# 执行会话固定形状(票 16 组合验证结论,不做成参数):
_PROOT_BIN = "/usr/local/bin/proot"
_LLSCAN_BIN = "/usr/local/bin/llscan"
_GUEST_ROOT = "/session/firmware"
_GUEST_RUNTIME = "/session/runtime"
_GUEST_STUB = "/session/stub"          # prooted 装载桩(guest 视角不可见)
_GUEST_INPUT = "/session/input"        # 声明输入文件(只读绑定)
_DEVICE_BINDS = ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom")
# guest 默认 PATH 是声明的适配默认值(台账逐字记录,env 参数可覆盖);
# 固件 shell 以绝对路径派生链不受其影响(票 16 探针同款)。
_DEFAULT_GUEST_ENV = {"PATH": "/bin:/sbin:/usr/bin:/usr/sbin"}
_KILL_GRACE_SECONDS = 5
_DOCKER_OVERHEAD_SECONDS = 30
_OUTPUT_EXCERPT_CHARS = 6000
_STUB_SCAN_RE = re.compile(
    r"^pid=(?P<pid>\d+) exe=(?P<exe>\S+) size=(?P<size>\d+|-) "
    r"sha256=(?P<sha256>[0-9a-f]{64}|-) cmd=(?P<cmd>.*)$"
)


# 台账/报告固定限制句(措辞是 ADR-0012/0013 纪律落点,不得改写为能力宣称)
_LIMIT_EVIDENCE = ("动态执行 Observation 只是 Evidence:正常退出、崩溃、超时或"
                   "启动失败都不构成漏洞成立或不存在的依据。")
_LIMIT_SNAPSHOT = ("链身份观测 = 延时一次 /proc 快照 + QEMU_STRACE 辅助日志:"
                   "短命子进程可能未被快照捕获,不以快照或 cmdline 宣称完整执行链;"
                   "prooted-* 是逐执行装载桩,不是原固件或 qemu 原件。")
_LIMIT_SESSION = ("一次调用即一个只含一次执行的会话,结束时容器停机封存;"
                  "多次执行与跨轮状态由后续会话票支持。")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _slug(text: str, limit: int = 32) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", (text or "").strip())
    return (cleaned.strip("-") or "scope")[:limit]


def _parse_stub_identities(snapshot_text: str) -> list[dict]:
    """Extract independent size/digest identities for observed prooted-* stubs."""
    identities: list[dict] = []
    for raw_line in snapshot_text.splitlines():
        match = _STUB_SCAN_RE.match(raw_line.strip())
        if match is None or "/prooted-" not in match["exe"]:
            continue
        size = match["size"]
        digest = match["sha256"]
        identities.append({
            "pid": int(match["pid"]),
            "exe": match["exe"],
            "size_bytes": int(size) if size != "-" else None,
            "sha256": digest if digest != "-" else None,
            "cmd": match["cmd"],
            "identity_complete": size != "-" and digest != "-",
        })
    return identities


class SessionLedger:
    """世代内会话台账:追加式 JSON,原子落盘(单进程 Host 串行假设)。"""

    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {"schema_version": 1, "sessions": [], "refusals": []}
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if (isinstance(loaded, dict)
                        and loaded.get("schema_version") == 1
                        and isinstance(loaded.get("sessions"), list)
                        and isinstance(loaded.get("refusals"), list)):
                    self.data = loaded
                else:
                    raise ValueError("结构不符")
            except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
                raise LedgerError(f"会话台账损坏,拒绝冒然续写: {exc}") from exc

    def count(self, role: str, investigation_ref: str) -> int:
        return sum(1 for s in self.data["sessions"]
                   if s.get("role") == role
                   and s.get("investigation_ref") == investigation_ref)

    def add(self, kind: str, entry: dict) -> None:
        self.data[kind].append(entry)
        self._save()

    def replace(self, session_id: str, entry: dict) -> None:
        """把同 session_id 的占位记录替换为终态(找不到则追加,不静默丢)。"""
        for i, existing in enumerate(self.data["sessions"]):
            if existing.get("session_id") == session_id:
                self.data["sessions"][i] = entry
                self._save()
                return
        self.add("sessions", entry)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1),
                       encoding="utf-8")
        os.replace(tmp, self.path)


class LedgerError(RuntimeError):
    """台账结构损坏;拒绝在损坏台账上继续记账。"""


class QemuExecuteTool(AgentTool):
    name = "qemu_execute"
    description = (
        "在隔离会话中真实执行一次原固件程序及其自主派生链(PRoot+QEMU 后端),"
        "返回 Observation 与可核验证据后停机封存。仅当静态证据不足、确需观察"
        "真实程序行为时使用;调用即消耗一个会话名额(每调查/案卷有限),"
        "结果分类区分正常退出/非零/信号/超时/阻塞,不构成漏洞结论。"
    )
    params = {
        "file_ref": {"type": "str", "required": True,
                     "desc": "目标 ELF 工具路径(相对 extracted 根,可带 extracted/ 前缀;"
                             "必须位于 firmware_root 内)"},
        "firmware_root": {"type": "str", "required": True,
                          "desc": "固件根目录(相对 extracted 根;作为 guest 的 / 根)"},
        "investigation_ref": {"type": "str", "required": True,
                              "desc": "会话归属标识(当前调查/案卷 id);预算按角色+该标识独立计数"},
        "args": {"type": "str", "default": "",
                 "desc": "目标参数串;按 POSIX 引号规则切分后逐个传入(无 shell 参与)"},
        "argv0": {"type": "str", "default": "",
                  "desc": "目标 argv[0];为空时使用 guest 目标路径,不经过 shell"},
        "env": {"type": "str", "default": "",
                "desc": "额外环境变量,换行分隔的 K=V(值可含 =);不继承宿主环境"},
        "cwd": {"type": "str", "default": "/",
                "desc": "guest 工作目录(固件根内绝对路径或 /tmp)"},
        "input_ref": {"type": "str", "default": "",
                      "desc": "可选输入文件(extracted 内);只读绑定到 guest 的 /session/input"},
        "timeout_seconds": {"type": "int", "default": 60,
                            "desc": "单次执行预算秒数(默认 60,硬上限 180)"},
        "use_strace": {"type": "bool", "default": True,
                       "desc": "QEMU_STRACE=1 辅助链路日志(仅日志,不充当隔离或完整台账)"},
    }

    def execute_for_scope(self, arguments: dict, *, investigation_ref: str,
                          remaining_seconds) -> ToolResult:
        """Host 绑定实际调查/案卷及动态剩余预算，模型不能通过改名获得名额。"""
        self._remaining_seconds = remaining_seconds
        try:
            return self.execute(**{**arguments, "investigation_ref": investigation_ref})
        finally:
            self._remaining_seconds = None

    def _effective_timeout(self, requested: int) -> int:
        seconds = max(1, min(int(requested), 180))
        remaining = getattr(self, "_remaining_seconds", None)
        if remaining is not None:
            seconds = min(seconds, max(0, int(remaining())))
        return seconds

    # ---- 工具路径解析 ----

    def _resolve_extracted(self, ref: str) -> Path | None:
        r = (ref or "").strip().replace("\\", "/").removeprefix("extracted/")
        if r.startswith("/"):
            return None
        return resolve_within(extracted_root(self.ctx), r)

    # ---- 会话目录与台账 ----

    def _sessions_root(self) -> Path:
        gen = self.ctx.generation_dir
        base = gen if gen is not None else self.ctx.process_dir
        return Path(base) / "qemu_sessions"

    # ---- 设施身份 ----

    def _facility(self, qemu_binary: str) -> dict:
        identity = docker_image_identity(QEMU_EXEC_V2_IMAGE)
        if identity is None:
            return {"image": QEMU_EXEC_V2_IMAGE, "available": False,
                    "detail": (f"镜像 {QEMU_EXEC_V2_IMAGE} 不可用"
                               "(先运行 docker/qemu-exec-v2/build_image.sh)")}
        labels = identity["labels"]
        mismatches = qemu_exec_v2_label_mismatches(labels)
        execveat_patch = labels.get("fw.proot.execveat.patch.sha256")
        if mismatches:
            return {
                "image_id": identity["image_id"],
                "image": QEMU_EXEC_V2_IMAGE,
                "available": False,
                "qemu_binary": qemu_binary,
                "proot_version": labels.get("fw.proot.version"),
                "proot_execveat_patch_sha256": execveat_patch,
                "identity_mismatches": mismatches,
                "detail": "镜像执行后端身份不匹配: " + ", ".join(
                    f"{key}={value!r}" for key, value in mismatches.items()),
            }
        return {
            "image_id": identity["image_id"],
            "image": QEMU_EXEC_V2_IMAGE,
            "available": True,
            "qemu_binary": qemu_binary,
            "qemu_version": labels.get("fw.qemu.version"),
            "proot_version": labels.get("fw.proot.version"),
            "proot_patch": ("mixed_mode-inherit(" + labels.get("fw.proot.patch.sha256", "")[:12]
                            + ")+raw-execveat-deny(" + execveat_patch[:12] + ")"),
            "proot_execveat_patch_sha256": execveat_patch,
            "base_digest": labels.get("fw.base.digest"),
            "boundary": labels.get("fw.boundary"),
        }

    # ---- 会话主流程 ----

    def _run(self, *, file_ref: str, firmware_root: str, investigation_ref: str,
             args: str = "", argv0: str = "", env: str = "", cwd: str = "/", input_ref: str = "",
             timeout_seconds: int = 60, use_strace: bool = True) -> ToolResult:
        ledger = SessionLedger(self._sessions_root() / "ledger.json")
        role = self.role or "analysis"
        limit = resolve_max_sessions()

        def finish(report: dict, ok: bool = True) -> ToolResult:
            report.setdefault("limitations", [_LIMIT_EVIDENCE, _LIMIT_SNAPSHOT,
                                              _LIMIT_SESSION])
            return ToolResult(ok=ok, text=_render_text(report), data=report)

        def refuse(detail: str, kind=QemuResultClass.PREP_BLOCKED) -> ToolResult:
            ledger.add("refusals", {"role": role,
                                    "investigation_ref": investigation_ref,
                                    "reason": kind.value, "detail": detail})
            report["result_class"] = kind.value
            report["result_class_label"] = kind.label
            report["detail"] = detail
            return finish(report)

        report: dict = {"schema_version": 1, "tool": self.name,
                        "mode": "session_execute", "role": role,
                        "investigation_ref": investigation_ref}

        # 1) 预算归属:同 (角色, 归属) 第 N+1 个会话拒绝(不建容器)
        used = ledger.count(role, investigation_ref)
        report["session_budget"] = {"used": used, "limit": limit,
                                    "env_knob": "STEP5_QEMU_MAX_SESSIONS"}
        if used >= limit:
            refusal = {"role": role, "investigation_ref": investigation_ref,
                       "reason": "session_quota_exhausted",
                       "detail": f"同角色同归属已有 {used} 个会话(上限 {limit}),第 {used + 1} 个被拒绝"}
            ledger.add("refusals", refusal)
            report["result_class"] = QemuResultClass.PREP_BLOCKED.value
            report["result_class_label"] = QemuResultClass.PREP_BLOCKED.label
            report["refused"] = refusal
            return finish(report)

        # 2) 路径边界与静态启动条件(不运行目标;复用预检解析器)
        target = self._resolve_extracted(file_ref)
        root = self._resolve_extracted(firmware_root)
        if target is None or root is None:
            return refuse("目标或固件根路径越界/非法(须为 extracted/ 内相对路径)")
        if not root.is_dir():
            return refuse(f"固件根不存在或不是目录: {root}")
        if not target.is_file():
            return refuse(f"目标不存在或不是常规文件: {target}")
        try:
            target.relative_to(root)
        except ValueError:
            return refuse("目标必须位于 firmware_root 内(guest 根即固件根)")
        try:
            blob = target.read_bytes()
            elf = parse_elf_runtime(blob)
        except (OSError, ElfParseError) as exc:
            return refuse(f"ELF 解析失败: {exc}")
        profile: QemuArchProfile | None = QEMU_ARCH_MATRIX.get(
            (elf["bits"], elf["endianness"], elf["e_machine"]))
        if profile is None:
            return refuse(f"架构 ELF{elf['bits']} {elf['endianness']}-endian "
                                      f"e_machine={elf['e_machine']} 不在首批矩阵")

        # 3) 声明输入固化(参数面;无 shell 参与)
        try:
            argv_list = shlex.split(args or "")
        except ValueError as exc:
            return refuse(f"args 引号解析失败(POSIX 规则): {exc}")
        declared_argv0 = (argv0 or "").strip()
        if "\x00" in declared_argv0:
            return refuse("argv0 不得包含 NUL 字节")
        declared_env = dict(_DEFAULT_GUEST_ENV)
        for line in (env or "").splitlines():
            line = line.strip()
            if not line:
                continue
            key, sep, value = line.partition("=")
            if not sep or not key.strip():
                return refuse(f"env 行必须是 K=V: {line!r}")
            key = key.strip()
            if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                    or key.startswith(("PROOT_", "QEMU_", "LD_"))):
                return refuse(f"env 不允许后端控制变量或非法名称 {key!r}；请使用声明的 guest 输入")
            declared_env[key] = value
        guest_cwd = (cwd or "/").strip() or "/"
        if not guest_cwd.startswith("/") or ".." in guest_cwd.split("/"):
            return refuse(f"cwd 必须是 guest 内绝对路径且不含 ..: {cwd!r}")
        timeout_clamped = self._effective_timeout(timeout_seconds)
        if timeout_clamped < 1:
            return refuse("案例剩余活动预算不足 1 秒；请停止执行并收束调查")
        input_path: Path | None = None
        input_guest: str | None = None
        input_mount: tuple[Path, str, str] | None = None
        if input_ref.strip():
            input_path = self._resolve_extracted(input_ref)
            if input_path is None or not input_path.is_file():
                return refuse(f"input_ref 不存在或越界: {input_ref}")
            try:
                input_guest = "/" + input_path.relative_to(root).as_posix()
            except ValueError:
                # 固件根外的输入:单文件只读绑定挂到约定路径
                input_guest = _GUEST_INPUT
                input_mount = (input_path, _GUEST_INPUT, "ro")

        # 4) 设施与身份档案
        facility = self._facility(profile.qemu_binary)
        report["backend"] = facility
        if not facility.get("available"):
            report["result_class"] = QemuResultClass.FACILITY_FAILURE.value
            report["result_class_label"] = QemuResultClass.FACILITY_FAILURE.label
            return finish(report)

        digest_map = {"target": sha256_file(target)}
        try:
            dep_rels, deps_truncated = self._runtime_dependencies(root, elf)
        except ValueError as exc:
            return refuse(str(exc), QemuResultClass.DEPENDENCY_BLOCKED)
        for rel in dep_rels:
            digest_map[rel] = sha256_file(root / rel)

        # 5) 开启会话(干净容器;命名可追溯)
        seq = used + 1
        session_id = f"{role}-{_slug(investigation_ref)}-{seq:03d}-{uuid.uuid4().hex}"
        container_name = f"fw-qemu-{session_id}"
        session_dir = self._sessions_root() / session_id
        runtime_dir = session_dir / "runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        mounts = [(root, _GUEST_ROOT, "ro"), (runtime_dir, _GUEST_RUNTIME, "rw")]
        if input_mount is not None:
            mounts.append(input_mount)
        entry: dict = {
            "schema_version": 1,
            "session_id": session_id,
            "status": "running",
            "role": role,
            "investigation_ref": investigation_ref,
            "declared": {
                "target": {"ref": file_ref, "sha256": digest_map["target"],
                           "guest_path": "/" + target.relative_to(root).as_posix()},
                "firmware_root": {"ref": firmware_root},
                "argv": argv_list,
                "argv0": declared_argv0 or ("/" + target.relative_to(root).as_posix()),
                "env": declared_env,
                "cwd": guest_cwd,
                "input": ({"ref": input_ref, "guest_path": input_guest,
                           "sha256": sha256_file(input_path)}
                          if input_path is not None else None),
                "timeout_seconds": timeout_clamped,
                "use_strace": bool(use_strace),
            },
            "dependencies_sha256": {k: v for k, v in digest_map.items() if k != "target"},
            "backend": facility,
            "container": {"name": container_name},
        }
        if deps_truncated:
            entry["dependencies_search_truncated"] = (
                "固件根检索达上限后截断,依赖身份档案可能缺项(明示,不当缺失)")
        report["session_id"] = session_id
        # 占位记账先于执行:执行窗口内宿主客户端死亡也有名额记录与收割锚点
        # (容器名 fw-qemu-<session_id> 可按名收割;终态由 replace 回写)。
        ledger.add("sessions", entry)

        try:
            self._execute_session(entry, mounts, input_mount, session_dir)
        except Exception as exc:
            entry.update(result_class=QemuResultClass.FACILITY_FAILURE.value,
                         result_class_label=QemuResultClass.FACILITY_FAILURE.label,
                         facility_error=f"{type(exc).__name__}: {exc}")
        finally:
            # 包含启动超时、观察/落盘异常和 KeyboardInterrupt；Host 被 SIGKILL
            # 的恢复不属单次执行票，但启动前的占位保留收割锚点。
            try:
                rm_rc, _, rm_err = docker_rm(container_name, timeout=60)
            except Exception as exc:
                rm_rc, rm_err = 125, f"{type(exc).__name__}: {exc}"
            entry["container"]["removed"] = rm_rc == 0
            entry["sealed"] = rm_rc == 0
            entry["status"] = "sealed" if rm_rc == 0 else "seal_failed"
            entry["sealed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            if rm_rc != 0:
                entry["execution_result_class"] = entry.get("result_class")
                entry.update(result_class=QemuResultClass.CLEANUP_UNCERTAIN.value,
                             result_class_label=QemuResultClass.CLEANUP_UNCERTAIN.label)
                entry["cleanup"] = {"verdict": "uncertain", "detail": rm_err,
                                    "leftovers_after": None}
            else:
                entry.setdefault("cleanup", {"verdict": "container_removed",
                                             "leftovers_after": 0})
            ledger.replace(session_id, entry)

        report.update(entry)
        report["artifacts"] = {
            "session_dir": str(session_dir),
            "stdout": str(session_dir / "stdout.txt"),
            "stderr": str(session_dir / "stderr.txt"),
            "ledger": str(self._sessions_root() / "ledger.json"),
        }
        return finish(report)

    def _execute_session(self, entry: dict, mounts: list,
                         input_mount: tuple | None, session_dir: Path) -> None:
        """只负责一次容器执行/观察；调用方始终负责停机与终态记账。"""
        container_name = entry["container"]["name"]
        declared = entry["declared"]
        timeout_clamped = declared["timeout_seconds"]
        rc, cid_out, err = docker_run_detached(
            entry["backend"]["image_id"], ["infinity"],
            name=container_name,
            mounts=mounts,
            tmpfs=["/tmp:rw,noexec,nosuid,nodev", f"{_GUEST_STUB}:rw,exec,nosuid,nodev"],
            entrypoint="/bin/sleep",
            network="none", read_only=True, init=True, timeout=120)
        if rc != 0:
            entry["result_class"] = QemuResultClass.FACILITY_FAILURE.value
            entry["result_class_label"] = QemuResultClass.FACILITY_FAILURE.label
            entry["facility_error"] = (err or "").strip()[:400]
            return
        container_id = cid_out.strip().splitlines()[-1] if cid_out.strip() else container_name

        entry["container"]["id"] = container_id[:12]
        # 6) 观察者(docker exec -d;延时后写快照到 guest 不可见的 stub tmpfs)
        snapshot_guest = f"{_GUEST_STUB}/.proc-snapshot.txt"
        docker_exec(container_id, [_LLSCAN_BIN, "watch", "2", snapshot_guest],
                    detach=True, timeout=30)

        # 容器准备/哈希/观察器也消耗案例活动时间；实际执行前再次收紧。
        timeout_clamped = self._effective_timeout(timeout_clamped)
        entry["declared"]["timeout_seconds"] = timeout_clamped
        if timeout_clamped < 1:
            entry.update(result_class=QemuResultClass.PREP_BLOCKED.value,
                         result_class_label=QemuResultClass.PREP_BLOCKED.label,
                         detail="案例剩余活动预算不足 1 秒；未启动目标")
            return

        # 7) 单次执行(容器内 timeout -k 包裹 proot;直接 argv,无 shell)
        proot_argv = [
            "/usr/bin/timeout", "-k", str(_KILL_GRACE_SECONDS), str(timeout_clamped),
            _PROOT_BIN, "--mixed-mode", "on", "--kill-on-exit",
            "-q", f"/usr/local/bin/{entry['backend']['qemu_binary']}",
            "-r", _GUEST_ROOT,
            "-b", f"{_GUEST_RUNTIME}:/tmp",
        ]
        for dev in _DEVICE_BINDS:
            proot_argv += ["-b", dev]
        if input_mount is not None:
            proot_argv += ["-b", f"{_GUEST_INPUT}:{_GUEST_INPUT}"]
        proot_argv += ["-w", declared["cwd"],
                       declared["target"]["guest_path"], declared["argv0"]] + declared["argv"]
        exec_env = {**declared["env"], "PROOT_TMP_DIR": _GUEST_STUB}
        if declared["use_strace"]:
            exec_env["QEMU_STRACE"] = "1"
        exec_started = time.monotonic()
        rc, out, err = docker_exec(
            container_id, proot_argv, env=exec_env,
            timeout=timeout_clamped + _KILL_GRACE_SECONDS + _DOCKER_OVERHEAD_SECONDS)
        elapsed = round(time.monotonic() - exec_started, 3)
        (session_dir / "stdout.txt").write_text(out or "", encoding="utf-8", errors="replace")
        (session_dir / "stderr.txt").write_text(err or "", encoding="utf-8", errors="replace")
        entry["execution"] = {
            "elapsed_seconds": elapsed,
            "exit_code": rc,
            "stdout_sha256": hashlib.sha256((out or "").encode("utf-8", "replace")).hexdigest(),
            "stderr_sha256": hashlib.sha256((err or "").encode("utf-8", "replace")).hexdigest(),
            "stdout_bytes": len((out or "").encode("utf-8", "replace")),
            "stderr_bytes": len((err or "").encode("utf-8", "replace")),
        }

        # 8) 清理验证与升级(llscan 扫描;残留 → 连进程组 SIGKILL → 复扫 → 拆容器)
        cleanup = self._reap_and_verify(container_id)
        entry["cleanup"] = cleanup

        # 9) 链身份快照(guest 不可见文件经 llscan cat 读回;缺项明示)
        snap_rc, snapshot_text, _ = docker_exec(
            container_id, [_LLSCAN_BIN, "cat", snapshot_guest], timeout=30)
        if snap_rc == 0 and snapshot_text.strip():
            (session_dir / "proc-snapshot.txt").write_text(
                snapshot_text, encoding="utf-8", errors="replace")
            stub_identities = _parse_stub_identities(snapshot_text)
            entry["chain"] = {
                "snapshot": [line for line in snapshot_text.strip().splitlines()],
                "stub_identities": stub_identities,
                "stub_identity_note": (
                    "每个可见 prooted-* 装载桩均记录容器内文件大小和 SHA-256"
                    if stub_identities else
                    "快照未捕获 prooted-* 装载桩；没有把 /proc 快照当作完整身份证明"),
                "snapshot_note": ("延时一次快照,短命子进程可能未捕获;"
                                  "prooted-* 为装载桩(非固件/qemu 原件)"),
            }
        else:
            entry["chain"] = {"snapshot": [],
                              "stub_identities": [],
                              "stub_identity_note": "快照缺失，无法独立识别 prooted-* 装载桩",
                              "snapshot_note": "快照缺失(链先于观察点结束或观察失败),缺项明示"}

        if rc == 124 and elapsed >= (timeout_clamped + _KILL_GRACE_SECONDS
                                     + _DOCKER_OVERHEAD_SECONDS - 1):
            entry.update(result_class=QemuResultClass.FACILITY_FAILURE.value,
                         result_class_label=QemuResultClass.FACILITY_FAILURE.label,
                         facility_error="docker exec 宿主侧超时；目标执行结果未知")
            return
        result_class, label, note = self._classify(
            rc, elapsed, timeout_clamped, out or "", err or "")
        entry.update(result_class=result_class, result_class_label=label)
        if note:
            entry["result_note"] = note
        entry["observation_excerpt"] = self._excerpt(out or "", err or "")

    # ---- 分步辅助 ----

    @staticmethod
    def _runtime_dependencies(root: Path, elf: dict) -> tuple[list[str], bool]:
        """解释器 + NEEDED 库在固件根内的相对路径(身份档案用,不阻塞)。

        返回 (相对路径列表, 检索是否截断);截断由调用方写入台账条目,
        不得静默当缺失(find_in_root 红线)。
        """
        rels: list[str] = []
        truncated = False
        if elf.get("interp"):
            rel = elf["interp"].lstrip("/")
            interpreter = resolve_within(root, rel)
            if interpreter is None or not interpreter.is_file():
                raise ValueError("解释器缺失或越出固件根；请先运行 qemu_precheck 检查依赖")
            rels.append(interpreter.relative_to(root.resolve()).as_posix())
        for lib in elf.get("needed") or []:
            hit, trunc = find_in_root(root, lib.split("/")[-1])
            truncated = truncated or trunc
            if hit is not None:
                dependency = resolve_within(root, hit)
                if dependency is None or not dependency.is_file():
                    raise ValueError("依赖越出固件根；请先运行 qemu_precheck 检查依赖")
                rels.append(dependency.relative_to(root.resolve()).as_posix())
            elif not trunc:
                raise ValueError(f"依赖 {lib} 缺失；请先运行 qemu_precheck 检查依赖")
        return rels, truncated

    @staticmethod
    def _reap_and_verify(container_id: str) -> dict:
        """清理验证:llscan count → 残留则 kill(组) → 复扫;无法确认留给拆除。"""
        rc, out, err = docker_exec(container_id, [_LLSCAN_BIN, "count"], timeout=30)
        if rc != 0:
            return {"verdict": "unknown", "leftovers_after": None,
                    "detail": (f"清理扫描失败 rc={rc}: {(err or '').strip()[:200]}")}
        leftovers = int((out or "0").strip() or 0)
        if leftovers == 0:
            return {"verdict": "clean", "leftovers_after": 0}
        docker_exec(container_id, [_LLSCAN_BIN, "kill"], timeout=30)
        time.sleep(2)
        rc, out, err = docker_exec(container_id, [_LLSCAN_BIN, "count"], timeout=30)
        if rc != 0:
            return {"verdict": "unknown", "leftovers_after": None,
                    "detail": f"复扫失败 rc={rc}: {(err or '').strip()[:200]}"}
        after = int((out or "0").strip() or 0)
        return {"verdict": "clean_after_kill" if after == 0 else "leftover",
                "leftovers_after": after}

    @staticmethod
    def _classify(rc: int, elapsed: float, budget: int,
                  out: str, err: str) -> tuple[str, str, str | None]:
        # 容器/docker 层失败:目标从未运行,不得伪装为目标崩溃
        if rc == 125:
            return (QemuResultClass.FACILITY_FAILURE.value,
                    QemuResultClass.FACILITY_FAILURE.label,
                    (err or "").strip()[:300] or "docker exec 失败")
        # 日志分类是提示，不据此宣称目标从未运行或漏洞成立；原始 rc 保留。
        if rc != 0 and "Invalid ELF image for this architecture" in err:
            return (QemuResultClass.PREP_BLOCKED.value,
                    QemuResultClass.PREP_BLOCKED.label,
                    "日志提示执行架构/边界拒绝；不归为目标崩溃")
        if rc != 0 and ("error while loading shared libraries:" in err
                        or "can't load library" in err):
            return (QemuResultClass.DEPENDENCY_BLOCKED.value,
                    QemuResultClass.DEPENDENCY_BLOCKED.label,
                    "日志提示运行时依赖阻塞；请先运行 qemu_precheck 核查依赖")
        proot_fatal = ("proot error" in (err or "")
                       and "fatal error: see `proot --help`" in (err or ""))
        if proot_fatal and not out.strip():
            return (QemuResultClass.PREP_BLOCKED.value,
                    QemuResultClass.PREP_BLOCKED.label,
                    "proot 启动失败(目标未运行): " + (err or "").strip()[:300])
        if rc == 124 and elapsed >= budget:
            return (QemuResultClass.TIMEOUT.value,
                    QemuResultClass.TIMEOUT.label,
                    f"预算 {budget}s 触发(timeout rc=124,已等待 {elapsed:.1f}s)")
        if rc == 137:
            if elapsed >= budget * 0.9:
                note = (f"SIGKILL 语义(疑似 -k 兜底击杀,elapsed={elapsed:.1f}s"
                        f"≈预算 {budget}s)")
            else:
                note = f"SIGKILL 语义(提前于预算,elapsed={elapsed:.1f}s,外部击杀可能)"
            return (QemuResultClass.TARGET_SIGNAL.value,
                    QemuResultClass.TARGET_SIGNAL.label, note)
        if 128 < rc <= 159:
            return (QemuResultClass.TARGET_SIGNAL.value,
                    QemuResultClass.TARGET_SIGNAL.label,
                    f"目标信号 {rc - 128}(rc={rc})")
        if rc == 0:
            return QemuResultClass.NORMAL_EXIT.value, QemuResultClass.NORMAL_EXIT.label, None
        note = "guest 退出码 126/127:目标未找到或不可执行的 guest 侧语义" if rc in (126, 127) else None
        return (QemuResultClass.NONZERO_EXIT.value,
                QemuResultClass.NONZERO_EXIT.label, note)

    @staticmethod
    def _excerpt(out: str, err: str) -> dict:
        def cut(text: str) -> dict:
            if len(text) <= _OUTPUT_EXCERPT_CHARS:
                return {"excerpt": text, "truncated": False}
            head = int(_OUTPUT_EXCERPT_CHARS * 0.7)
            tail = _OUTPUT_EXCERPT_CHARS - head
            return {"excerpt": text[:head] + f"\n...[截断,省略 {len(text) - head - tail} 字符,全文见 artifacts]...\n" + text[-tail:],
                    "truncated": True, "total_chars": len(text)}
        return {"stdout": cut(out), "stderr": cut(err)}


def _render_text(report: dict) -> str:
    """会话报告 → LLM 可读 Observation(分类/身份/声明输入/输出摘录/清理/限制)。"""
    lines = [f"[qemu_execute] 会话 {report.get('session_id', '?')} 结果分类: "
             f"{report.get('result_class', '?')}({report.get('result_class_label', '?')})"]
    if report.get("refused"):
        lines.append(f"- 拒绝: {report['refused']['detail']}")
    if report.get("detail"):
        lines.append(f"- 阻塞: {report['detail']}")
    declared = report.get("declared") or {}
    if declared:
        tgt = declared.get("target") or {}
        lines.append(f"- 目标: {tgt.get('ref')} sha256={str(tgt.get('sha256'))[:16]}… "
                     f"guest 路径 {tgt.get('guest_path')}")
        lines.append(f"- 声明输入: argv0={declared.get('argv0')} argv={declared.get('argv')} cwd={declared.get('cwd')} "
                     f"env={list((declared.get('env') or {}).keys())} "
                     f"input={((declared.get('input') or {}) or {}).get('guest_path')}")
        lines.append(f"- 预算: {declared.get('timeout_seconds')}s(硬上限 180)"
                     + ("" if report.get("session_budget") is None
                        else f";会话名额 {report['session_budget']['used']}/{report['session_budget']['limit']}"))
    backend = report.get("backend") or {}
    if backend:
        lines.append(f"- 后端: {backend.get('image')} qemu={backend.get('qemu_version')} "
                     f"proot={backend.get('proot_version')} "
                     f"边界={backend.get('boundary')}")
    execution = report.get("execution") or {}
    if execution:
        lines.append(f"- 执行: rc={execution.get('exit_code')} "
                     f"耗时 {execution.get('elapsed_seconds')}s;输出 digest 已入台账")
    chain = report.get("chain") or {}
    if chain:
        lines.append(f"- 链观测: 快照 {len(chain.get('snapshot') or [])} 条;"
                     f"桩身份 {len(chain.get('stub_identities') or [])} 条;"
                     f"{chain.get('snapshot_note')}")
        if chain.get("stub_identity_note"):
            lines.append(f"    桩身份: {chain['stub_identity_note']}")
        for identity in (chain.get("stub_identities") or [])[:6]:
            lines.append(f"    stub pid={identity['pid']} exe={identity['exe']} "
                         f"size={identity['size_bytes']} sha256={identity['sha256']}")
        for line in (chain.get("snapshot") or [])[:6]:
            lines.append(f"    {line}")
    cleanup = report.get("cleanup") or {}
    if cleanup:
        lines.append(f"- 清理: {cleanup.get('verdict')}(残留 {cleanup.get('leftovers_after')})"
                     + (";容器已拆除封存" if report.get("sealed") else ";**容器拆除未确认**"))
    obs = report.get("observation_excerpt") or {}
    for name in ("stdout", "stderr"):
        part = obs.get(name) or {}
        if part.get("excerpt", "").strip():
            tag = "[截断]" if part.get("truncated") else ""
            lines.append(f"- {name}{tag}:")
            for text_line in part["excerpt"].strip().splitlines()[:24]:
                lines.append(f"    {text_line}")
    if report.get("result_note"):
        lines.append(f"- 注: {report['result_note']}")
    if report.get("artifacts"):
        lines.append(f"- 工件: {report['artifacts']['session_dir']}(台账 {report['artifacts']['ledger']})")
    lines.append("- 限制: " + " ".join(report.get("limitations") or []))
    return "\n".join(lines)

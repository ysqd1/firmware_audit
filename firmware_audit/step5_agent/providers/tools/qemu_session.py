"""qemu_execute:多步执行会话入口(票 16 单发贯通;票 17 会话制/预算/恢复)。

会话生命周期(ADR-0013 会话制):一次工具调用 = 一次声明执行。
- 不带 session_id:开启新会话(干净容器 + 干净运行目录)→ 执行一次 → 默认
  停机封存(单发特例,票 16 兼容);keep_open=true 保持会话开启,返回
  session_id 供后继执行复用。新会话干净重建,不继承旧会话运行文件。
- 带 session_id:在同一会话容器内再执行一次(每次执行新建 PRoot 实例),
  运行目录内前序执行写入的文件后继可读;执行之间无目标进程存活(逐执行
  清理验证),prooted 装载桩/后端残留不作为运行状态保留。
- stop=true:停机封存;带 session_id 且不带 file_ref 时为仅停机不执行。
- 会话内执行次数上限为显式预算参数(临时默认 4,最终由票 19 校准):
  Host 配置层(config.json 快照)> env(STEP5_QEMU_MAX_SESSION_EXECUTIONS)>
  默认,生效值与来源记入台账;超限拒绝,对照/异常/复现逐次计数。
- 会话名额归属不变:每 (角色, investigation_ref) 独立最多 N 个会话(默认
  3,STEP5_QEMU_MAX_SESSIONS 覆盖);预检不占名额;失败不自动原样重试。
- 调查终态(正常完成/预算耗尽/中断)由 Host 强制停机封存全部开启会话,
  Host 死亡后的恢复路径强制收割遗留容器(见 qemu_recovery)。中断即会话
  死亡:恢复不复活会话,运行产物仅留档,续跑开启新会话且已持久化执行
  不重复扣名额。

边界(ADR-0013 + 票 16 组合验证,证据见
.scratch/qemu-user-mode-experiments/investigation/proot540-qemu1111-2026-09-22/):
- 隔离边界是 Docker:断网、固件根只读挂载、只读容器根、独立可写运行目录、
  不挂 docker socket/其他 target;/host-rootfs 逃逸面由 proot --mixed-mode
  继承补丁(guest 派生树内原生 x86 ELF 的 execve 一律改写经 qemu 路由 → 架构
  不符 → 拒绝)+ raw execveat deny 补丁(QEMU tracee 早期返回 EACCES)+
  镜像剥离;正式镜像身份必须带已验收的补丁摘要。
- 每次执行以容器内 timeout -k 包裹(默认 60s,硬上限 180s);清理验证
  用镜像内 llscan(/proc 扫描),升级清理(连进程组 SIGKILL)后仍有残留则
  拆容器;客户端退出不等于清理完成(N4:客户端死后链仍存活)。
- 身份三分:原固件(sha256)、PRoot/QEMU 后端(镜像 LABEL/BUILD-INFO)、
  prooted 装载桩(逐执行临时名)分开记录;链观测是"延时一次快照 + QEMU_STRACE
  辅助日志",短命子进程可能未入快照——缺项明示,不宣称完整执行链身份。
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
    resolve_max_session_executions,
    resolve_max_sessions,
    timestamp,
)
from .qemu_precheck import ElfParseError, find_in_root, parse_elf_runtime

# 执行会话固定形状(票 16 组合验证结论,不做成参数):
_PROOT_BIN = "/usr/local/bin/proot"
LLSCAN_BIN = "/usr/local/bin/llscan"
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

# 会话工件目录名(工具与恢复路径共用的单一出处)。
SESSIONS_DIRNAME = "qemu_sessions"
LEDGER_SCHEMA_VERSION = 2


# 台账/报告固定限制句(措辞是 ADR-0012/0013 纪律落点,不得改写为能力宣称)
_LIMIT_EVIDENCE = ("动态执行 Observation 只是 Evidence:正常退出、崩溃、超时或"
                   "启动失败都不构成漏洞成立或不存在的依据。")
_LIMIT_SNAPSHOT = ("链身份观测 = 延时一次 /proc 快照 + QEMU_STRACE 辅助日志:"
                   "短命子进程可能未被快照捕获,不以快照或 cmdline 宣称完整执行链;"
                   "prooted-* 是逐执行装载桩,不是原固件或 qemu 原件。")
_LIMIT_SESSION = ("会话即执行名额单位:会话内运行目录状态跨执行积累,执行之间"
                  "无目标进程存活;调查终态由 Host 强制停机封存,中断即会话死亡,"
                  "恢复不复活会话。")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


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


def remove_session_container(name: str) -> tuple[str, str | None]:
    """停机封存的权威拆除;返回 (判定, 失败详情)。

    `docker rm -f` 是唯一权威:杀容器即杀 PRoot/QEMU 及全部派生(含后台/
    脱离进程组子孙);"No such container" 视为 absent(无容器可清理,不是
    不确定);其余失败一律 uncertain,交由恢复路径强制收割。
    """
    try:
        rc, _, err = docker_rm(name, timeout=60)
    except Exception as exc:  # 客户端/守护进程不可达也不是清理完成
        return "uncertain", f"{type(exc).__name__}: {exc}"
    if rc == 0:
        return "container_removed", None
    if "no such container" in (err or "").lower():
        return "absent", None
    return "uncertain", (err or "").strip()[:300]


class SessionLedger:
    """世代内会话台账:追加式 JSON,原子落盘(单进程 Host 串行假设)。

    schema 2(票 17):会话条目带 status 生命周期(running/sealed/
    seal_failed/interrupted)与 executions 有序数组——每次执行的声明输入、
    原始输出 digest、结果与清理逐条追加,保留 Verification 重放所需的
    执行序列。schema 1(票 16 单发)不兼容,拒绝在其上续写。
    """

    def __init__(self, path: Path):
        self.path = path
        self.data: dict = {"schema_version": LEDGER_SCHEMA_VERSION,
                           "sessions": [], "refusals": []}
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if (isinstance(loaded, dict)
                        and loaded.get("schema_version") == LEDGER_SCHEMA_VERSION
                        and isinstance(loaded.get("sessions"), list)
                        and isinstance(loaded.get("refusals"), list)):
                    self.data = loaded
                else:
                    raise ValueError("结构不符(或为票 16 schema 1 旧台账)")
            except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
                raise LedgerError(f"会话台账损坏或版本不兼容,拒绝冒然续写: {exc}") from exc

    def find(self, session_id: str) -> dict | None:
        for entry in self.data["sessions"]:
            if entry.get("session_id") == session_id:
                return entry
        return None

    def count(self, role: str, investigation_ref: str) -> int:
        return sum(1 for s in self.data["sessions"]
                   if s.get("role") == role
                   and s.get("investigation_ref") == investigation_ref)

    def add(self, kind: str, entry: dict) -> None:
        self.data[kind].append(entry)
        self._save()

    def replace(self, session_id: str, entry: dict) -> None:
        """把同 session_id 的记录回写为最新状态(找不到则追加,不静默丢)。"""
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


class _PrepError(Exception):
    """执行输入准备失败;kind 携带结果分类(依赖阻塞与准备阻塞分开)。"""

    def __init__(self, detail: str, kind: QemuResultClass = QemuResultClass.PREP_BLOCKED):
        super().__init__(detail)
        self.kind = kind


class QemuExecuteTool(AgentTool):
    name = "qemu_execute"
    description = (
        "在隔离会话中真实执行原固件程序及其自主派生链(PRoot+QEMU 后端),"
        "返回 Observation 与可核验证据。会话制:开启会话后可多次执行,运行"
        "目录内状态跨执行积累(keep_open/session_id),最后一次执行或不再"
        "需要时停机封存(stop);会话内执行次数有限,对照/异常/复现逐次计数;"
        "每次新会话消耗一个会话名额(每调查/案卷有限)。仅当静态证据不足、"
        "确需观察真实程序行为时使用;结果分类区分正常退出/非零/信号/超时/"
        "阻塞,不构成漏洞结论;调查结束时 Host 会强制停机封存全部会话。"
    )
    params = {
        "investigation_ref": {"type": "str", "default": "",
                              "desc": "会话归属标识;Host 运行中由 Host 注入真实调查/"
                                      "案卷 id(模型传入值被覆盖),预算按角色+该标识独立计数;"
                                      "仅独立演示需要显式填写"},
        "file_ref": {"type": "str", "required": False,
                     "desc": "目标 ELF 工具路径(相对 extracted 根,可带 extracted/ 前缀;"
                             "必须位于 firmware_root 内)。执行调用必填;仅停机"
                             "(session_id+stop=true)时省略"},
        "firmware_root": {"type": "str", "required": False,
                          "desc": "固件根目录(相对 extracted 根;作为 guest 的 / 根)。"
                                  "执行调用必填,且须与会话开启时一致(容器 guest 根已固化)"},
        "session_id": {"type": "str", "default": "",
                       "desc": "已有会话 id(来自本工具返回);空=开启新会话。复用时"
                               "运行目录内前序执行写入的文件可读"},
        "keep_open": {"type": "bool", "default": False,
                      "desc": "新会话执行后保持开启(返回 session_id 供后继执行);"
                              "默认单发即停机封存。对已有会话无效(复用保持开启,"
                              "直到 stop=true)"},
        "stop": {"type": "bool", "default": False,
                 "desc": "本次调用后停机封存会话;session_id+stop=true 且不带 "
                         "file_ref = 仅停机不执行"},
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
                          remaining_seconds, max_executions: int | None = None) -> ToolResult:
        """Host 绑定实际调查/案卷、动态剩余预算与会话内执行上限;模型不能
        通过改名获得名额或放大预算。"""
        self._remaining_seconds = remaining_seconds
        self._max_executions = max_executions
        try:
            return self.execute(**{**arguments, "investigation_ref": investigation_ref})
        finally:
            self._remaining_seconds = None
            self._max_executions = None

    def _effective_timeout(self, requested: int) -> int:
        seconds = max(1, min(int(requested), 180))
        remaining = getattr(self, "_remaining_seconds", None)
        if remaining is not None:
            seconds = min(seconds, max(0, int(remaining())))
        return seconds

    def _execution_limit(self) -> tuple[int, str]:
        """会话内执行次数上限及来源:Host 配置层 > env > 默认(票 17)。"""
        host_value = getattr(self, "_max_executions", None)
        if type(host_value) is int and host_value >= 1:
            return host_value, "host_config"
        return resolve_max_session_executions()

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
        return Path(base) / SESSIONS_DIRNAME

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

    def _run(self, *, investigation_ref: str = "", file_ref: str = "",
             firmware_root: str = "", session_id: str = "",
             keep_open: bool = False, stop: bool = False, args: str = "",
             argv0: str = "", env: str = "", cwd: str = "/",
             input_ref: str = "", timeout_seconds: int = 60,
             use_strace: bool = True) -> ToolResult:
        sessions_root = self._sessions_root()
        ledger = SessionLedger(sessions_root / "ledger.json")
        role = self.role or "analysis"
        session_id = (session_id or "").strip()
        wants_execution = bool((file_ref or "").strip())
        investigation_ref = (investigation_ref or "").strip()
        report: dict = {"schema_version": LEDGER_SCHEMA_VERSION, "tool": self.name,
                        "action": "execute", "role": role,
                        "investigation_ref": investigation_ref}

        def finish(ok: bool = True) -> ToolResult:
            report.setdefault("limitations",
                              [_LIMIT_EVIDENCE, _LIMIT_SNAPSHOT, _LIMIT_SESSION])
            return ToolResult(ok=ok, text=_render_text(report), data=report)

        def refuse(detail: str, kind=QemuResultClass.PREP_BLOCKED) -> ToolResult:
            ledger.add("refusals", {"role": role,
                                    "investigation_ref": investigation_ref,
                                    "session_id": session_id or None,
                                    "reason": kind.value, "detail": detail})
            report["result_class"] = kind.value
            report["result_class_label"] = kind.label
            report["detail"] = detail
            return finish()

        # ---- 0) 归属:Host 运行由 execute_for_scope 注入;空归属拒绝 ----
        if not investigation_ref:
            return refuse("investigation_ref 缺失:Host 运行由 Host 注入;"
                          "独立演示请显式填写归属标识")

        # ---- 1) 动词语义校验(不消耗任何名额) ----
        if stop and not session_id and not wants_execution:
            return refuse("stop=true 需要 session_id(停机已有会话);"
                          "开启新会话请提供 file_ref 与 firmware_root")
        if not wants_execution and not stop:
            return refuse("执行调用必须提供 file_ref 与 firmware_root;"
                          "仅停机请传 session_id 与 stop=true")
        existing = ledger.find(session_id) if session_id else None
        if session_id and existing is None:
            return refuse(f"会话不存在: {session_id}(id 逐字取自本工具返回)")
        if existing is not None:
            if (existing.get("role") != role
                    or existing.get("investigation_ref") != investigation_ref):
                return refuse("会话归属不匹配(角色/调查归属);不得操作他人会话")
            allowed = ("running", "seal_failed") if (stop and not wants_execution) \
                else ("running",)
            if existing.get("status") not in allowed:
                return refuse(_SESSION_DEAD_DETAIL.get(
                    existing.get("status"),
                    f"会话状态 {existing.get('status')!r} 不可继续"))

        # ---- 2) 仅停机:不执行,不占新名额 ----
        if not wants_execution:
            self._seal_session(ledger, existing, kind="agent_stop")
            report.update({"action": "session_stop", "session_id": session_id,
                           "sealed": existing.get("sealed"),
                           "status": existing.get("status"),
                           "cleanup": existing.get("cleanup"),
                           "executions_total": len(existing.get("executions") or []),
                           "execution_budget": existing.get("execution_budget")})
            return finish()

        # ---- 3) 执行输入准备(开启与复用共享;复用先校验固件根一致) ----
        root = self._resolve_extracted(firmware_root)
        if root is None or not root.is_dir():
            return refuse(f"固件根不存在或越界(须为 extracted/ 内目录): {firmware_root}")
        if existing is not None:
            stored_root = ((existing.get("firmware_root") or {}).get("path") or "")
            if stored_root and Path(stored_root) != root.resolve():
                return refuse("firmware_root 与会话开启时不一致;"
                              "会话容器的 guest 根在开启时已固化")
            entry = existing
            session_dir = sessions_root / session_id
        else:
            limit = resolve_max_sessions()
            used = ledger.count(role, investigation_ref)
            report["session_budget"] = {"used": used, "limit": limit,
                                        "env_knob": "STEP5_QEMU_MAX_SESSIONS"}
            if used >= limit:
                ledger.add("refusals", {
                    "role": role, "investigation_ref": investigation_ref,
                    "session_id": None, "reason": "session_quota_exhausted",
                    "detail": (f"同角色同归属已有 {used} 个会话(上限 {limit}),"
                               f"第 {used + 1} 个被拒绝")})
                report["result_class"] = QemuResultClass.PREP_BLOCKED.value
                report["result_class_label"] = QemuResultClass.PREP_BLOCKED.label
                report["refused"] = {"reason": "session_quota_exhausted",
                                     "detail": f"会话名额已用满({used}/{limit})"}
                return finish()
            entry = None  # 稍后在设施核查通过后开启

        try:
            prepared = self._prepare_execution(
                root=root, file_ref=file_ref, args=args, argv0=argv0, env=env,
                cwd=cwd, input_ref=input_ref, timeout_seconds=timeout_seconds,
                use_strace=use_strace)
        except _PrepError as exc:
            return refuse(str(exc), exc.kind)
        declared, target, input_mount, elf = prepared

        if existing is not None:
            exec_limit = entry.get("execution_budget") or {}
            if len(entry.get("executions") or []) >= int(exec_limit.get("limit") or 0):
                ledger.add("refusals", {
                    "role": role, "investigation_ref": investigation_ref,
                    "session_id": session_id,
                    "reason": "execution_quota_exhausted",
                    "detail": (f"会话 {session_id} 执行次数已达上限 "
                               f"{exec_limit.get('limit')}(对照/异常/复现逐次计数);"
                               "请新开会话(消耗会话名额)或停机收束")})
                report["result_class"] = QemuResultClass.PREP_BLOCKED.value
                report["result_class_label"] = QemuResultClass.PREP_BLOCKED.label
                report["refused"] = {"reason": "execution_quota_exhausted",
                                     "session_id": session_id,
                                     "detail": "会话内执行次数已达上限"}
                return finish()
            report["backend"] = entry.get("backend")
            container_ref = (entry["container"].get("id")
                             or entry["container"]["name"])
        else:
            # ---- 4) 开启会话:设施核查 → 干净容器 → 占位记账先于创建 ----
            facility = self._facility(declared["qemu_binary"])
            report["backend"] = facility
            if not facility.get("available"):
                report["result_class"] = QemuResultClass.FACILITY_FAILURE.value
                report["result_class_label"] = QemuResultClass.FACILITY_FAILURE.label
                return finish()
            exec_limit_value, exec_limit_source = self._execution_limit()
            seq = used + 1
            session_id = f"{role}-{_slug(investigation_ref)}-{seq:03d}-{uuid.uuid4().hex}"
            container_name = f"fw-qemu-{session_id}"
            session_dir = sessions_root / session_id
            entry = {
                "schema_version": LEDGER_SCHEMA_VERSION,
                "session_id": session_id,
                "status": "running",
                "role": role,
                "investigation_ref": investigation_ref,
                "firmware_root": {"ref": firmware_root,
                                  "path": str(root.resolve())},
                "backend": facility,
                "container": {"name": container_name},
                "execution_budget": {"limit": exec_limit_value,
                                     "source": exec_limit_source, "used": 0},
                "executions": [],
            }
            report["session_id"] = session_id
            # 运行目录先落盘再挂载(会话内跨执行状态的真实载体;新会话干净
            # 重建,不继承旧运行文件)。
            (session_dir / "runtime").mkdir(parents=True, exist_ok=True)
            # 占位记账先于容器创建:执行窗口内宿主死亡也有名额记录与
            # 容器名收割锚点(恢复路径按名强制收割)。
            ledger.add("sessions", entry)
            mounts = [(root, _GUEST_ROOT, "ro"),
                      (session_dir / "runtime", _GUEST_RUNTIME, "rw")]
            if input_mount is not None:
                mounts.append(input_mount)
            if not self._open_container(entry, mounts):
                # 开启失败:立即封存(rm 报 absent/uncertain,如实记录),
                # 名额已消耗(占位),不伪装成可继续的会话。
                self._seal_session(ledger, entry, kind="agent_stop")
                report["result_class"] = QemuResultClass.FACILITY_FAILURE.value
                report["result_class_label"] = QemuResultClass.FACILITY_FAILURE.label
                report.update({"sealed": entry.get("sealed"),
                               "status": entry.get("status"),
                               "container_removal": entry.get("cleanup")})
                return finish()
            container_ref = entry["container"]["id"]

        # ---- 5) 执行一次(逐执行:观察者/PRoot/清理验证/台账追加) ----
        exec_entry = self._execute_once(entry, ledger, session_dir,
                                        container=container_ref,
                                        declared=declared, input_mount=input_mount,
                                        root=root, target=target, elf=elf)
        if exec_entry is None:
            # 预算在启动前耗尽:目标未运行。本次新开的单发会话立即封存
            # (不留一个从未执行的活动会话);复用会话保持 running,交由
            # agent 后续重试或 Host 终态收口。
            if existing is None:
                self._seal_session(ledger, entry, kind="agent_stop")
                report.update({"result_class": QemuResultClass.PREP_BLOCKED.value,
                               "result_class_label": QemuResultClass.PREP_BLOCKED.label,
                               "detail": "案例剩余活动预算不足 1 秒;目标未启动,"
                                         "本次开启的会话已封存",
                               "sealed": entry.get("sealed"),
                               "status": entry.get("status"),
                               "container_removal": entry.get("cleanup")})
                ledger.add("refusals", {
                    "role": role, "investigation_ref": investigation_ref,
                    "session_id": session_id, "reason": "budget_exhausted",
                    "detail": "案例剩余活动预算不足 1 秒;未启动目标"})
                return finish()
            return refuse("案例剩余活动预算不足 1 秒;未启动目标,请收束调查")
        # 清理未确认(残留未清或观测异常):按边界销毁会话容器并封存,
        # 不得带着不确定的进程状态进入下一次执行(spec 清理兜底;AC1/AC8)。
        exec_cleanup_verdict = (exec_entry.get("cleanup") or {}).get("verdict")
        cleanup_unresolved = exec_cleanup_verdict in ("leftover", "unknown")
        report.update({"session_id": entry["session_id"],
                       "declared": declared,
                       "result_class": exec_entry.get("result_class"),
                       "result_class_label": exec_entry.get("result_class_label"),
                       "result_note": exec_entry.get("result_note"),
                       "execution": exec_entry.get("execution"),
                       "cleanup": exec_entry.get("cleanup"),
                       "chain": exec_entry.get("chain"),
                       "observation_excerpt": exec_entry.get("observation_excerpt"),
                       "executions_total": len(entry["executions"]),
                       "execution_budget": entry["execution_budget"]})

        # ---- 6) 会话去留:单发默认封存;keep_open/复用保持开启;
        #      清理未确认时无条件封存(容器拆除兜底) ----
        if stop or (existing is None and not keep_open) or cleanup_unresolved:
            self._seal_session(ledger, entry, kind="agent_stop")
            if cleanup_unresolved:
                report["detail"] = (
                    f"本次执行清理未确认(残留进程判定: {exec_cleanup_verdict}),"
                    "已销毁会话容器并封存;该会话不得复用,请以新会话继续")
        report.update({"sealed": entry.get("sealed", False),
                       "status": entry.get("status"),
                       # 容器拆除判定单列:与执行级清理验证(残留进程)分开,
                       # 都是事实,不互相覆盖。
                       "container_removal": entry.get("cleanup")})
        report["artifacts"] = {
            "session_dir": str(session_dir),
            "stdout": str(session_dir / f"exec-{exec_entry['seq']:03d}-stdout.txt"),
            "stderr": str(session_dir / f"exec-{exec_entry['seq']:03d}-stderr.txt"),
            "ledger": str(sessions_root / "ledger.json"),
        }
        return finish()

    # ---- 分步辅助:执行输入准备 ----

    def _prepare_execution(self, *, root: Path, file_ref: str, args: str,
                           argv0: str, env: str, cwd: str, input_ref: str,
                           timeout_seconds: int, use_strace: bool):
        """单次执行的声明输入固化(参数面;无 shell 参与)。

        返回 (declared, target, input_mount, elf);失败抛 _PrepError
        (kind 区分准备阻塞/依赖阻塞)。
        """
        target = self._resolve_extracted(file_ref)
        if target is None or not target.is_file():
            raise _PrepError(f"目标不存在或越界(须为 extracted/ 内文件): {file_ref}")
        try:
            target.relative_to(root)
        except ValueError:
            raise _PrepError("目标必须位于 firmware_root 内(guest 根即固件根)")
        try:
            blob = target.read_bytes()
            elf = parse_elf_runtime(blob)
        except (OSError, ElfParseError) as exc:
            raise _PrepError(f"ELF 解析失败: {exc}")
        profile: QemuArchProfile | None = QEMU_ARCH_MATRIX.get(
            (elf["bits"], elf["endianness"], elf["e_machine"]))
        if profile is None:
            raise _PrepError(f"架构 ELF{elf['bits']} {elf['endianness']}-endian "
                             f"e_machine={elf['e_machine']} 不在首批矩阵")
        try:
            argv_list = shlex.split(args or "")
        except ValueError as exc:
            raise _PrepError(f"args 引号解析失败(POSIX 规则): {exc}")
        declared_argv0 = (argv0 or "").strip()
        if "\x00" in declared_argv0:
            raise _PrepError("argv0 不得包含 NUL 字节")
        declared_env = dict(_DEFAULT_GUEST_ENV)
        for line in (env or "").splitlines():
            line = line.strip()
            if not line:
                continue
            key, sep, value = line.partition("=")
            if not sep or not key.strip():
                raise _PrepError(f"env 行必须是 K=V: {line!r}")
            key = key.strip()
            if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                    or key.startswith(("PROOT_", "QEMU_", "LD_"))):
                raise _PrepError(f"env 不允许后端控制变量或非法名称 {key!r};"
                                 "请使用声明的 guest 输入")
            declared_env[key] = value
        guest_cwd = (cwd or "/").strip() or "/"
        if not guest_cwd.startswith("/") or ".." in guest_cwd.split("/"):
            raise _PrepError(f"cwd 必须是 guest 内绝对路径且不含 ..: {cwd!r}")
        timeout_clamped = self._effective_timeout(timeout_seconds)
        if timeout_clamped < 1:
            raise _PrepError("案例剩余活动预算不足 1 秒;请停止执行并收束调查")
        input_path: Path | None = None
        input_guest: str | None = None
        input_mount: tuple[Path, str, str] | None = None
        if input_ref.strip():
            input_path = self._resolve_extracted(input_ref)
            if input_path is None or not input_path.is_file():
                raise _PrepError(f"input_ref 不存在或越界: {input_ref}")
            try:
                input_guest = "/" + input_path.relative_to(root).as_posix()
            except ValueError:
                # 固件根外的输入:单文件只读绑定挂到约定路径
                input_guest = _GUEST_INPUT
                input_mount = (input_path, _GUEST_INPUT, "ro")
        digest_map: dict[str, str] = {"target": sha256_file(target)}
        deps_truncated = False
        try:
            dep_rels, deps_truncated = self._runtime_dependencies(root, elf)
        except ValueError as exc:
            raise _PrepError(str(exc), QemuResultClass.DEPENDENCY_BLOCKED)
        for rel in dep_rels:
            digest_map[rel] = sha256_file(root / rel)
        guest_target = "/" + target.relative_to(root).as_posix()
        declared = {
            "target": {"ref": file_ref, "sha256": digest_map["target"],
                       "guest_path": guest_target},
            "argv": argv_list,
            "argv0": declared_argv0 or guest_target,
            "env": declared_env,
            "cwd": guest_cwd,
            "input": ({"ref": input_ref, "guest_path": input_guest,
                       "sha256": sha256_file(input_path)}
                      if input_path is not None else None),
            "timeout_requested_seconds": int(timeout_seconds),
            "timeout_seconds": timeout_clamped,
            "use_strace": bool(use_strace),
            "qemu_binary": profile.qemu_binary,
            "dependencies_sha256": {k: v for k, v in digest_map.items()
                                    if k != "target"},
        }
        if deps_truncated:
            declared["dependencies_search_truncated"] = (
                "固件根检索达上限后截断,依赖身份档案可能缺项(明示,不当缺失)")
        return declared, target, input_mount, elf

    # ---- 分步辅助:容器开启 ----

    def _open_container(self, entry: dict, mounts: list) -> bool:
        """创建会话常驻容器(干净、断网、只读根);失败写 facility_error。"""
        rc, cid_out, err = docker_run_detached(
            entry["backend"]["image_id"], ["infinity"],
            name=entry["container"]["name"],
            mounts=mounts,
            tmpfs=["/tmp:rw,noexec,nosuid,nodev",
                   f"{_GUEST_STUB}:rw,exec,nosuid,nodev"],
            entrypoint="/bin/sleep",
            network="none", read_only=True, init=True, timeout=120)
        if rc != 0:
            entry["facility_error"] = (err or "").strip()[:400]
            return False
        entry["container"]["id"] = (cid_out.strip().splitlines()[-1]
                                    if cid_out.strip()
                                    else entry["container"]["name"])[:12]
        return True

    # ---- 分步辅助:单次执行 ----

    def _execute_once(self, entry: dict, ledger: SessionLedger,
                      session_dir: Path, *, container: str, declared: dict,
                      input_mount: tuple | None, root: Path, target: Path,
                      elf: dict) -> dict | None:
        """会话内一次声明执行;执行事实先持久化,观测缺口如实补记。

        返回执行条目;返回 None = 未启动目标(案例剩余预算不足)。
        """
        timeout_clamped = self._effective_timeout(declared["timeout_seconds"])
        if timeout_clamped < 1:
            return None
        declared["timeout_seconds"] = timeout_clamped
        seq = len(entry.get("executions") or []) + 1
        exec_entry: dict = {"seq": seq, "declared": declared}
        # 观察者(docker exec -d;延时后写快照到 guest 不可见的 stub tmpfs;
        # 逐执行独立快照文件,桩名随本次 PRoot 实例变化)
        snapshot_guest = f"{_GUEST_STUB}/.proc-snapshot-exec-{seq:03d}.txt"
        docker_exec(container, [LLSCAN_BIN, "watch", "2", snapshot_guest],
                    detach=True, timeout=30)
        proot_argv = [
            "/usr/bin/timeout", "-k", str(_KILL_GRACE_SECONDS), str(timeout_clamped),
            _PROOT_BIN, "--mixed-mode", "on", "--kill-on-exit",
            "-q", f"/usr/local/bin/{declared['qemu_binary']}",
            "-r", _GUEST_ROOT,
            "-b", f"{_GUEST_RUNTIME}:/tmp",
        ]
        for dev in _DEVICE_BINDS:
            proot_argv += ["-b", dev]
        if input_mount is not None:
            proot_argv += ["-b", f"{_GUEST_INPUT}:{_GUEST_INPUT}"]
        proot_argv += ["-w", declared["cwd"],
                       declared["target"]["guest_path"], declared["argv0"]] \
            + declared["argv"]
        exec_env = {**declared["env"], "PROOT_TMP_DIR": _GUEST_STUB}
        if declared["use_strace"]:
            exec_env["QEMU_STRACE"] = "1"
        exec_started = time.monotonic()
        rc, out, err = docker_exec(
            container, proot_argv, env=exec_env,
            timeout=timeout_clamped + _KILL_GRACE_SECONDS + _DOCKER_OVERHEAD_SECONDS)
        elapsed = round(time.monotonic() - exec_started, 3)
        exec_entry["execution"] = {
            "seq": seq,
            "elapsed_seconds": elapsed,
            "exit_code": rc,
            "stdout_sha256": sha256_text(out or ""),
            "stderr_sha256": sha256_text(err or ""),
            "stdout_bytes": len((out or "").encode("utf-8", "replace")),
            "stderr_bytes": len((err or "").encode("utf-8", "replace")),
        }
        # 执行事实(声明输入 + 原始输出 digest)先于观测持久化:
        # 后续观测/落盘异常不抹掉已发生的执行,中断恢复也不重复计数。
        entry["executions"].append(exec_entry)
        entry["execution_budget"]["used"] = seq
        ledger.replace(entry["session_id"], entry)

        # 观测段:输出落盘、清理验证、链身份快照;异常记缺口不崩溃。
        observation_error: str | None = None
        try:
            (session_dir / f"exec-{seq:03d}-stdout.txt").write_text(
                out or "", encoding="utf-8", errors="replace")
            (session_dir / f"exec-{seq:03d}-stderr.txt").write_text(
                err or "", encoding="utf-8", errors="replace")
            exec_entry["cleanup"] = self._reap_and_verify(container)
            self._attach_chain_snapshot(exec_entry, container, session_dir,
                                        snapshot_guest)
        except Exception as exc:
            observation_error = f"{type(exc).__name__}: {exc}"
            exec_entry["observation_error"] = observation_error
            exec_entry["cleanup"] = {"verdict": "unknown", "leftovers_after": None,
                                     "detail": "观测异常,清理未验证(封存拆除兜底)"}
            exec_entry["chain"] = {"snapshot": [], "stub_identities": [],
                                   "stub_identity_note": "观测异常,快照未读取",
                                   "snapshot_note": "观测异常,缺项明示"}

        if rc == 124 and elapsed >= (timeout_clamped + _KILL_GRACE_SECONDS
                                     + _DOCKER_OVERHEAD_SECONDS - 1):
            exec_entry.update(result_class=QemuResultClass.FACILITY_FAILURE.value,
                              result_class_label=QemuResultClass.FACILITY_FAILURE.label,
                              result_note="docker exec 宿主侧超时;目标执行结果未知")
        elif observation_error is not None:
            exec_entry.update(
                result_class=QemuResultClass.FACILITY_FAILURE.value,
                result_class_label=QemuResultClass.FACILITY_FAILURE.label,
                result_note=f"输出采集/清理验证异常(执行已发生,退出码保留): "
                            f"{observation_error}")
        else:
            result_class, label, note = self._classify(
                rc, elapsed, timeout_clamped, out or "", err or "")
            exec_entry.update(result_class=result_class, result_class_label=label)
            if note:
                exec_entry["result_note"] = note
            exec_entry["observation_excerpt"] = self._excerpt(out or "", err or "")
        ledger.replace(entry["session_id"], entry)
        return exec_entry

    def _attach_chain_snapshot(self, exec_entry: dict, container: str,
                               session_dir: Path, snapshot_guest: str) -> None:
        """链身份快照(guest 不可见文件经 llscan cat 读回;缺项明示)。"""
        snap_rc, snapshot_text, _ = docker_exec(
            container, [LLSCAN_BIN, "cat", snapshot_guest], timeout=30)
        seq = exec_entry["seq"]
        if snap_rc == 0 and snapshot_text.strip():
            (session_dir / f"exec-{seq:03d}-proc-snapshot.txt").write_text(
                snapshot_text, encoding="utf-8", errors="replace")
            stub_identities = _parse_stub_identities(snapshot_text)
            exec_entry["chain"] = {
                "snapshot": [line for line in snapshot_text.strip().splitlines()],
                "stub_identities": stub_identities,
                "stub_identity_note": (
                    "每个可见 prooted-* 装载桩均记录容器内文件大小和 SHA-256"
                    if stub_identities else
                    "快照未捕获 prooted-* 装载桩;没有把 /proc 快照当作完整身份证明"),
                "snapshot_note": ("延时一次快照,短命子进程可能未捕获;"
                                  "prooted-* 为装载桩(非固件/qemu 原件)"),
            }
        else:
            exec_entry["chain"] = {"snapshot": [],
                                   "stub_identities": [],
                                   "stub_identity_note": "快照缺失，无法独立识别 prooted-* 装载桩",
                                   "snapshot_note": "快照缺失(链先于观察点结束或观察失败),缺项明示"}

    # ---- 分步辅助:停机封存 ----

    def _seal_session(self, ledger: SessionLedger, entry: dict, *, kind: str) -> None:
        """停机封存单个会话:容器权威拆除 → 台账终态(失败如实留 seal_failed)。"""
        name = (entry.get("container") or {}).get("name") or ""
        verdict, detail = remove_session_container(name) if name else ("absent", None)
        entry["cleanup"] = {"verdict": verdict, "detail": detail}
        entry["sealed"] = verdict in ("container_removed", "absent")
        entry["status"] = "sealed" if entry["sealed"] else "seal_failed"
        entry["seal_kind"] = kind
        entry["sealed_at"] = timestamp()
        ledger.replace(entry["session_id"], entry)

    # ---- 清理验证与分类(执行侧) ----

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
        rc, out, err = docker_exec(container_id, [LLSCAN_BIN, "count"], timeout=30)
        if rc != 0:
            return {"verdict": "unknown", "leftovers_after": None,
                    "detail": (f"清理扫描失败 rc={rc}: {(err or '').strip()[:200]}")}
        leftovers = int((out or "0").strip() or 0)
        if leftovers == 0:
            return {"verdict": "clean", "leftovers_after": 0}
        docker_exec(container_id, [LLSCAN_BIN, "kill"], timeout=30)
        time.sleep(2)
        rc, out, err = docker_exec(container_id, [LLSCAN_BIN, "count"], timeout=30)
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


# 中断/封存后会话的拒绝文案(中断即会话死亡,旧会话不可继续)。
_SESSION_DEAD_DETAIL = {
    "sealed": "会话已停机封存,不可继续执行(新会话独立计数,不继承运行文件)",
    "interrupted": ("会话已因中断死亡:恢复不复活会话,运行产物仅留档;"
                    "续跑请开启新会话(已持久化的执行不重复扣名额)"),
    "seal_failed": "会话容器拆除未确认,不得继续执行;恢复路径将强制收割",
}


def _render_text(report: dict) -> str:
    """会话报告 → LLM 可读 Observation(分类/身份/声明输入/输出摘录/清理/限制)。"""
    lines = [f"[qemu_execute] 会话 {report.get('session_id', '?')} "
             f"动作 {report.get('action', 'execute')} 结果分类: "
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
        lines.append(f"- 声明输入: argv0={declared.get('argv0')} argv={declared.get('argv')} "
                     f"cwd={declared.get('cwd')} "
                     f"env={list((declared.get('env') or {}).keys())} "
                     f"input={((declared.get('input') or {}) or {}).get('guest_path')}")
        lines.append(f"- 执行预算: {declared.get('timeout_seconds')}s(硬上限 180)"
                     + ("" if report.get("execution_budget") is None else
                        f";会话内执行 {report['execution_budget'].get('used')}/"
                        f"{report['execution_budget'].get('limit')}"
                        f"(来源 {report['execution_budget'].get('source')})"))
    if report.get("session_budget") is not None:
        lines.append(f"- 会话名额: {report['session_budget']['used']}/"
                     f"{report['session_budget']['limit']}")
    backend = report.get("backend") or {}
    if backend:
        lines.append(f"- 后端: {backend.get('image')} qemu={backend.get('qemu_version')} "
                     f"proot={backend.get('proot_version')} "
                     f"边界={backend.get('boundary')}")
    execution = report.get("execution") or {}
    if execution:
        lines.append(f"- 执行: rc={execution.get('exit_code')} "
                     f"耗时 {execution.get('elapsed_seconds')}s;"
                     f"声明输入、输出 digest 与结果已按序追加进会话台账(第 "
                     f"{execution.get('seq')} 次执行)")
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
    removal = report.get("container_removal") or {}
    if cleanup:
        lines.append(f"- 清理: {cleanup.get('verdict')}(残留 {cleanup.get('leftovers_after')})")
    if removal:
        lines.append(f"- 容器: {removal.get('verdict')}"
                     + (";会话已停机封存" if report.get("sealed")
                        else ";**拆除未确认,封存未完成**"))
    elif report.get("action") == "execute" and report.get("status") == "running":
        lines.append("- 会话: 保持开启(传 session_id 继续执行;调查终态由 Host 强制封存)")
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

"""QEMU 执行工具族共享基座(票 05 起;边界见 ADR-0013 与 spec.md)。

镜像:firm_audit/qemu-exec(票 03 派生层,pins.env 钉值)。与 cli_base 的
SANDBOX_IMAGE 同款常量先例,漂移由 test_step5_qemu_precheck 对 pins.env 校验。

结果分类枚举是 spec《结果分类》八类的单一出处:预检(票 05)与执行侧动词
(后续票)共用同一词汇表,预检只发出 PRECHECK_RESULT_CLASSES 子集,通过态
OK 不属于八类失败分类。执行侧五类(normal_exit/nonzero_exit/target_signal/
timeout/cleanup_uncertain)在本票只定义不发出。

架构矩阵是"档案"不是能力承诺:第一批以 ARM32 小端与 MIPS32 大端为目标
(spec);observed_notes 只记录票 01/04 实测观察并标注来源,不据此宣称
任何架构的子进程链可用(票 04:ARM 链受阻、根因未定论)。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# 执行镜像(票 16 产物;钉 tag 不漂移,与票 03 的 5.2 历史镜像完全独立)。
# 镜像 = PRoot 5.4.0(+mixed_mode 继承补丁)+ QEMU 11.1.1 静态双架构 +
# 形状隔离剥离(bookworm-slim digest 钉定),构建见 docker/qemu-exec-v2/。
QEMU_EXEC_V2_IMAGE = "firm_audit/qemu-exec:p540q1111"

# 正式镜像的 raw execveat deny 补丁身份。会话/预检拒绝缺失或漂移的镜像，
# 但不再以永久字符串闸阻断已完成验收的后端。
QEMU_EXECVEAT_PATCH_SHA256 = (
    "d361d4b28c75029e89892a5283efcdddb99a89a0d752372b91bf07b1c98dae2e"
)

# 历史镜像(票 03,QEMU 5.2/Debian 包)——仅作对照保留,产品工具不再使用。
QEMU_EXEC_IMAGE = "firm_audit/qemu-exec:latest"

# ELF e_machine 常量(首批矩阵只用到这两个)
EM_ARM = 40
EM_MIPS = 8


class QemuResultClass(str, Enum):
    """spec 结果分类八类(失败类)+ 预检通过态 OK。"""

    OK = "ok"                                   # 预检通过(非八类,预检专用)
    NORMAL_EXIT = "normal_exit"                 # 正常退出(执行侧)
    NONZERO_EXIT = "nonzero_exit"               # 非零退出(执行侧)
    TARGET_SIGNAL = "target_signal"             # 目标信号/崩溃(执行侧)
    TIMEOUT = "timeout"                         # 超时(执行侧)
    PREP_BLOCKED = "prep_blocked"               # 准备阻塞
    DEPENDENCY_BLOCKED = "dependency_blocked"   # 运行时依赖阻塞
    FACILITY_FAILURE = "facility_failure"       # 执行设施失败
    CLEANUP_UNCERTAIN = "cleanup_uncertain"     # 清理不确定(执行侧)

    @property
    def label(self) -> str:
        return QEMU_RESULT_CLASS_LABELS[self]


# 预检只发出的失败分类子集(八类之预检侧;OK 通过态单列)
PRECHECK_RESULT_CLASSES = frozenset({
    QemuResultClass.PREP_BLOCKED,
    QemuResultClass.DEPENDENCY_BLOCKED,
    QemuResultClass.FACILITY_FAILURE,
})

QEMU_RESULT_CLASS_LABELS: dict["QemuResultClass", str] = {
    QemuResultClass.OK: "预检通过",
    QemuResultClass.NORMAL_EXIT: "正常退出",
    QemuResultClass.NONZERO_EXIT: "非零退出",
    QemuResultClass.TARGET_SIGNAL: "目标信号/崩溃",
    QemuResultClass.TIMEOUT: "超时",
    QemuResultClass.PREP_BLOCKED: "准备阻塞",
    QemuResultClass.DEPENDENCY_BLOCKED: "运行时依赖阻塞",
    QemuResultClass.FACILITY_FAILURE: "执行设施失败",
    QemuResultClass.CLEANUP_UNCERTAIN: "清理不确定",
}


@dataclass(frozen=True)
class QemuArchProfile:
    """矩阵条目 = 命名档案 + 带来源的实测观察;不是能力承诺。"""

    key: str            # arm32le / mips32be
    name: str           # 人读架构名
    qemu_binary: str    # 执行镜像内对应静态 qemu 二进制
    observed_notes: str # 票 01/04 实测观察(带票号来源;不写成通用规则)


# 首批架构矩阵(spec:ARM32 小端/uClibc 与 MIPS32 大端/musl 为目标)。
# 矩阵外(含 MIPS 小端/ARM 大端/64 位)不在此列——预检记"不在首批矩阵",
# 不据此宣称该架构永久不可行。
# observed_notes 为票 16 组合验证(PRoot 5.4.0 + QEMU 11.1.1,2026-09-22)实测:
# investigation/proot540-qemu1111-2026-09-22/logs/82-matrix.txt、90-mmpatch-verify.txt。
QEMU_ARCH_MATRIX: dict[tuple[int, str, int], QemuArchProfile] = {
    (32, "little", EM_ARM): QemuArchProfile(
        key="arm32le", name="ARM32 little-endian", qemu_binary="qemu-arm-static",
        observed_notes=("票 16 组合实测(PRoot 5.4.0 + QEMU 11.1.1,2026-09-22):"
                        "target/6 顶层与原 sh 派生链(动态/静态子)均真实进入仿真;"
                        "实测不代表所有 ARM 程序可运行")),
    (32, "big", EM_MIPS): QemuArchProfile(
        key="mips32be", name="MIPS32 big-endian", qemu_binary="qemu-mips-static",
        observed_notes=("票 16 组合实测(PRoot 5.4.0 + QEMU 11.1.1,2026-09-22):"
                        "target/8 顶层与派生链、busybox env 直接派生均真实进入仿真"
                        "(无需 QEMU_LD_PREFIX);实测不代表所有 MIPS 程序可运行")),
}


# ---- 会话预算(票 16:每 Investigation/Case 独立最多 3 个会话) ----

QEMU_SESSION_SCHEMA_VERSION = 1
DEFAULT_MAX_SESSIONS_PER_SCOPE = 3
QEMU_MAX_SESSIONS_ENV = "STEP5_QEMU_MAX_SESSIONS"


def resolve_max_sessions(env: dict[str, str] | None = None) -> int:
    """同角色同归属的会话上限:默认 3(ADR-0013 由 4 收紧),env 层可覆盖。

    缺失/非法/越界(≤0)回落默认——与 STEP5_*_MAX_ITERS 的 resolver 同口径;
    正式 QEMU 预算块并入 RunBudget 分层解析由票 17 收口,本 resolver 只覆盖
    会话名额这一个旋钮。
    """
    import os
    raw = (os.environ if env is None else env).get(QEMU_MAX_SESSIONS_ENV)
    if raw is None or not str(raw).strip():
        return DEFAULT_MAX_SESSIONS_PER_SCOPE
    try:
        value = int(str(raw).strip())
    except ValueError:
        return DEFAULT_MAX_SESSIONS_PER_SCOPE
    if value < 1:
        return DEFAULT_MAX_SESSIONS_PER_SCOPE
    return min(value, DEFAULT_MAX_SESSIONS_PER_SCOPE)

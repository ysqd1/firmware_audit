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

# 执行镜像(票 03 产物;ENTRYPOINT 保持基座值,调用侧显式覆盖)
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
QEMU_ARCH_MATRIX: dict[tuple[int, str, int], QemuArchProfile] = {
    (32, "little", EM_ARM): QemuArchProfile(
        key="arm32le", name="ARM32 little-endian", qemu_binary="qemu-arm-static",
        observed_notes=("票 01/04 实测:target/6 顶层程序经 -L 前缀可运行;"
                        "子进程链当前受阻,根因未定论")),
    (32, "big", EM_MIPS): QemuArchProfile(
        key="mips32be", name="MIPS32 big-endian", qemu_binary="qemu-mips-static",
        observed_notes=("票 01/04 实测:target/8 顶层程序经 -L 前缀可运行;"
                        "子进程链需 QEMU_LD_PREFIX 环境适配(实测可行)")),
}

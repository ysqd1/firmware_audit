"""文件魔数嗅探与解包决策(纯函数层,无 Docker/网络)。

引导式解包器的决策核心。按"读文件头 4KB → sniff_magic → preclassify /
rule_decision"的链路工作,全部为纯函数,可单测。

责任边界(2026-08-13 评审定稿,勿破坏):
    preclassify  = 快速二分: 把"确定性的"送走(fdt→skip, elf/pe/text→product),
                   其余一律交 rule_decision。绝不在此裁决容器。
    rule_decision = 容器裁决者: 对 preclassify 筛剩下的,识别出容器魔数→continue,
                   无容器签名→finalize(留树;不透明文件的字符串审计由 Step5 strings_query 兜底)。
    二者无重叠: preclassify 输出的 product 绝不包含容器;rule_decision 只处理
    preclassify 筛剩下的。单测锁定此边界(test_step1_guided.py)。

对齐表(2026-09-10,票01):路由与 binwalk 签名库可解集对齐的声明在
align_table.py(厂商加密固件 SHRS 被 finalize 的教训),sniff_magic/rule_decision
共同消费;为什么不"全交 binwalk"的三条理由(静默失败/容器成本/fdt 旧疾)见该模块
docstring。
"""
from __future__ import annotations

import math

from .align_table import ALIGN_TABLE, ALIGN_NAMES

# --- 魔数表: (魔数 bytes, 名称)。按重要性排序,命中返回名称列表。 ---
# fdt 大/小端最前(part05 61.6 万条目的根因,必须先于一切拦截)
_MAGIC_TABLE: list[tuple[bytes, str]] = [
    (b"\xd0\x0d\xfe\xed", "fdt_be"),        # 设备树 blob,大端
    (b"\xed\xfe\x0d\xd0", "fdt_le"),        # 设备树 blob,小端
    (b"\x7fELF",          "elf"),           # ELF 可执行/库
    (b"MZ",               "pe"),            # PE/DOS 可执行
    (b"ANDROID!",         "bootimg"),       # Android boot image
    (b"VNDRBOOT",         "vendor_boot"),   # Android vendor boot
    (b"\x27\x05\x19\x56", "uimage"),        # U-Boot uImage,大端
    (b"\x56\x19\x05\x27", "uimage"),        # U-Boot uImage,小端
    (b"\x1f\x8b",         "gzip"),
    (b"\xfd7zXZ\x00",     "xz"),
    (b"\x5d\x00\x00\x00", "lzma"),          # 4 字节防误报(仅 5d 00 00 太宽)
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"BZh",              "bzip2"),
    (b"\x30\x37\x30\x37", "cpio"),          # "0707"(newc/odc 共用前缀)
    (b"070701",           "cpio_newc"),
    (b"070702",           "cpio_newc"),
    (b"070707",           "cpio_odc"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", "7z"),
    (b"PK\x03\x04",       "zip"),
    (b"PK\x05\x06",       "zip"),
    (b"PK\x07\x08",       "zip"),
    (b"hsqs",             "squashfs"),      # squashfs 大端
    (b"sqsh",             "squashfs"),      # squashfs 小端
    (b"\x85\x19",         "jffs2"),         # JFFS2 大端魔数
    (b"\x31\x18\x10\x06", "ubifs"),         # UBI 文件系统
    (b"UBI#",             "ubi"),           # UBI 卷
    (b"\x45\x3d\xcd\x28", "cramfs"),        # cramfs 小端
    (b"\x28\xcd\x3d\x45", "cramfs"),        # cramfs 大端
]

# 需在偏移处校验的魔数(非 0 偏移)
_OFFSET_MAGIC_TABLE: list[tuple[int, bytes, str]] = [
    (0x438, b"\x53\xef", "ext4"),           # ext 超级块魔数 0xEF53 LE
    (257,   b"ustar",    "tar"),
    (510,   b"\x55\xaa", "fat"),            # FAT 引导扇区 55AA
]

# 文本启发式:可打印占比阈值
_TEXT_PRINTABLE_RATIO = 0.9

# 无签名 finalize 的 reason 唯一出处:rule_decision 产出,extract_guided 的
# 深层复扫触发条件消费(票04)。改文案必须走本常量——字面量散落会让触发
# 判断与产出静默脱钩。
FINALIZE_UNSIGNED_REASON = "无容器签名,留树(字符串审计可用 Step5 strings_query 兜底)"


def sniff_magic(data: bytes, fname: str = "") -> list[str]:
    """嗅探文件头(前 4KB)命中魔数列表;无命中走文本启发式。

    Args:
        data: 文件头字节(建议读前 4096 字节;少于此长度按实际)
        fname: 文件名(可选,当前仅作日志/未来扩展,不影响判定)

    Returns:
        命中的魔数名称列表;无魔数命中且内容像文本 → ["text"];
        无魔数命中且不像文本 → []。
    """
    sigs: list[str] = []
    for magic, name in _MAGIC_TABLE:
        if data.startswith(magic):
            sigs.append(name)
    for off, magic, name in _OFFSET_MAGIC_TABLE:
        if len(data) > off and data[off : off + len(magic)] == magic:
            sigs.append(name)
    # 对齐表(binwalk 可解集路由声明):offset 0 条目与 _MAGIC_TABLE 同语义,
    # 非 0 条目与 _OFFSET_MAGIC_TABLE 同语义;命中名即 binwalk 签名名
    for name, off, magic, _note in ALIGN_TABLE:
        if len(data) > off and data[off : off + len(magic)] == magic:
            sigs.append(name)
    if not sigs and _looks_like_text(data):
        sigs.append("text")
    return sigs


def _looks_like_text(data: bytes) -> bool:
    """文本启发式:无 NUL + 可打印字符(含空白)占比 > 阈值。"""
    if not data:
        return False
    if b"\x00" in data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) > _TEXT_PRINTABLE_RATIO


def shannon_entropy(data: bytes) -> float:
    """Shannon 熵(0-8)。分诊用,建议采样前 64KB。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


# --- 决策函数 ---

def preclassify(sigs: list[str], fname: str = "") -> str:
    """快速二分:确定性的送走,其余交 rule_decision。

    返回:
        "skip"     → fdt(硬规则,永不分解,part05 根因)
        "product"  → ELF/PE/text(直接 finalize,不交 rule_decision)
        "container"→ 其余一切(含未知/无签名),交 rule_decision 裁决

    重要: 不得把"可能是容器"的提前归 product。压缩流/bootimg/fs 镜像
    在这里一律走 container 分支,由 rule_decision 决定 continue 还是 finalize。
    """
    if any(s in ("fdt_be", "fdt_le") for s in sigs):
        return "skip"
    if any(s in ("elf", "pe", "text") for s in sigs):
        return "product"
    return "container"


def rule_decision(sigs: list[str], fname: str = "", depth: int = 0) -> tuple[str, str]:
    """容器裁决者:对 preclassify 筛剩下的文件决定继续解 or 留树。

    Args:
        sigs: sniff_magic 结果
        fname: 文件名(日志/未来扩展)
        depth: 当前深度(供日志)

    Returns:
        (action, reason):
            ("skip", ...)     → fdt,硬跳过
            ("finalize", ...) → ELF/文本 或 无容器签名(留树,字符串审计由 Step5 strings_query 兜底)
            ("continue", ...) → 识别出的容器(压缩流/固件容器/fs 镜像)
    """
    if any(s in ("fdt_be", "fdt_le") for s in sigs):
        return "skip", "fdt 设备树,硬跳过(part05 根因)"

    if any(s in ("elf", "pe", "text") for s in sigs):
        return "finalize", "ELF/PE/文本,不需继续解"

    # 核心容器集(标准格式)+ 对齐表(binwalk 可解集路由声明,SHRS 等厂商格式)
    container_sigs = {
        "gzip", "xz", "lzma", "lz4", "zstd", "bzip2",          # 压缩流
        "cpio", "cpio_newc", "cpio_odc", "tar", "7z", "zip",   # 归档
        "squashfs", "cramfs", "jffs2", "ubifs", "ubi",         # fs 镜像
        "ext4", "fat",                                          # 磁盘文件系统
        "bootimg", "vendor_boot", "uimage",                     # 固件容器
    } | ALIGN_NAMES
    hit = [s for s in sigs if s in container_sigs]
    if hit:
        return "continue", f"容器签名 {','.join(hit)},继续解包"
    return "finalize", FINALIZE_UNSIGNED_REASON

"""规模闸门与开关:默认值唯一出处 + env 覆盖解析(2026-09-08 票 03;2026-09-10
票 04 增深层复扫阈值/开关,并由数值闸门扩展到 bool 开关)。

闸门历史出处(已收敛到本模块,别处不得再定义第二份默认值):
  - Step0 分区提取上限 50 GiB(原 step0_preprocess._PARTITION_MAX_SIZE_GB
    与 step0_split_img 的参数默认 50.0 两处重复)
  - Step1 单次解包产出上限 50000(原 step1_guided_extract.MAX_FILES_PER_EXTRACTION)
  - Step1 全树文件数上限 200000(原 step1_guided_extract.MAX_TOTAL_FILES)
  - Step1 深层复扫体积阈值 4 MiB(票04,双例校准见 DEEP_RESCAN_MIN_BYTES 注)

env 约定(对齐 STEP5_*_MAX_ITERS / runner.resolve_max_iters 先例):
  - 消费点解析而非 import 时固化:改 env 后下一次调用即生效,模块常量
    不被污染(测试可逐用例设/删 env)
  - 缺失/空白 → 静默回落默认;非法(不可解析/非正数/非法布尔值)→ 回落
    默认并打一次告警(同值去重,防逐文件消费点刷屏)
"""
from __future__ import annotations

import math
import os
from collections.abc import Callable

# Step0:rootfs/recovery 分区提取上限(超过视为"超大分区"跳过——几百 GB 的
# APP rootfs 提取会耗尽磁盘且 binwalk 仍会爆炸)。ext4 直读分区不受此闸门
# 约束(魔数触发不看大小,见 step0_ext4_read)。
PARTITION_MAX_SIZE_GB = 50.0

# Step1:单次解包产出上限,超过即删除该次产物(防 fdt 类爆炸,最坏=空目录)
MAX_FILES_PER_EXTRACTION = 50000

# Step1:全树文件数上限,超过停止新增解包(防总规模失控)
MAX_TOTAL_FILES = 200000

# Step1:深层复扫体积阈值——无签名 finalize 且 ≥ 阈值时,binwalk -e -M 全偏移
# 复扫一次(票04)。默认 4MiB 是双例校准值(2026-09-10 实测):target/1 树
# ≥1MiB 无签名文件 32 个(mp3/模型,零复扫价值,纯烧容器),≥4MiB 仅 3 个;
# target/4 待解内核 17MiB(复扫目标本体,任何阈值都命中)。校准数据见
# .scratch/binwalk-extractable-align/issues/04。
DEEP_RESCAN_MIN_BYTES = 4 * 1024 * 1024

# 告警去重:同 (env 名, 原始值) 只提示一次;模块级可变状态仅影响打印,不影响返回值
_invalid_warned: set[tuple[str, str]] = set()


def _resolve_positive(name: str, default: int | float,
                      convert: Callable[[str], int | float]) -> int | float:
    """env 值 → 正的有限数;缺失/空白静默回落,非法/非正数回落并告警一次。

    nan/inf 必须拦:nan 的比较恒 False,混进大小闸门会让守卫静默失效
    (size > nan 永不成立);inf 则等于无上限。
    """
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        v = convert(raw)
    except ValueError:
        v = None
    if v is None or not math.isfinite(v) or v <= 0:
        key = (name, raw)
        if key not in _invalid_warned:
            _invalid_warned.add(key)
            print(f"[配置] 警告: {name}={raw!r} 非法(需正数),"
                  f"回落默认 {default}")
        return default
    return v


def resolve_partition_max_size_gb() -> float:
    """env STEP0_PARTITION_MAX_SIZE_GB 覆盖分区提取上限(默认 50 GiB)。"""
    return _resolve_positive("STEP0_PARTITION_MAX_SIZE_GB",
                             PARTITION_MAX_SIZE_GB, float)


def resolve_max_files_per_extraction() -> int:
    """env STEP1_MAX_FILES_PER_EXTRACTION 覆盖单次解包产出上限(默认 50000)。"""
    return _resolve_positive("STEP1_MAX_FILES_PER_EXTRACTION",
                             MAX_FILES_PER_EXTRACTION, int)


def resolve_max_total_files() -> int:
    """env STEP1_MAX_TOTAL_FILES 覆盖全树文件数上限(默认 200000)。"""
    return _resolve_positive("STEP1_MAX_TOTAL_FILES",
                             MAX_TOTAL_FILES, int)


def resolve_deep_rescan_min_bytes() -> int:
    """env STEP1_DEEP_RESCAN_MIN_BYTES 覆盖深层复扫体积阈值(默认 4MiB)。"""
    return _resolve_positive("STEP1_DEEP_RESCAN_MIN_BYTES",
                             DEEP_RESCAN_MIN_BYTES, int)


# STEP1_DEEP_RESCAN 的显式开/关词表;其余任何值按非法处理(回落默认 + 告警一次),
# 与本模块"非法值回落并告警"约定一致,不做静默 fail-open
_FALSY = {"0", "false", "no", "off"}
_TRUTHY = {"1", "true", "yes", "on"}


def resolve_deep_rescan_enabled() -> bool:
    """env STEP1_DEEP_RESCAN 深层复扫开关(默认开)。"""
    return _resolve_flag("STEP1_DEEP_RESCAN", True)


def _resolve_flag(name: str, default: bool) -> bool:
    """bool env 解析:缺失/空白→默认;真值/假值词表→开/关;非法→默认+告警一次。"""
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    if raw in _FALSY:
        return False
    if raw in _TRUTHY:
        return True
    key = (name, raw)
    if key not in _invalid_warned:
        _invalid_warned.add(key)
        print(f"[配置] 警告: {name}={raw!r} 非法"
              f"(开: {sorted(_TRUTHY)},关: {sorted(_FALSY)}),回落默认 {default}")
    return default

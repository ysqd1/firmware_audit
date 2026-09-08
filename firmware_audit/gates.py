"""三道规模闸门:默认值唯一出处 + env 覆盖解析(2026-09-08 票 03)。

闸门历史出处(已收敛到本模块,别处不得再定义第二份默认值):
  - Step0 分区提取上限 50 GiB(原 step0_preprocess._PARTITION_MAX_SIZE_GB
    与 step0_split_img 的参数默认 50.0 两处重复)
  - Step1 单次解包产出上限 50000(原 step1_guided_extract.MAX_FILES_PER_EXTRACTION)
  - Step1 全树文件数上限 200000(原 step1_guided_extract.MAX_TOTAL_FILES)

env 约定(对齐 STEP5_*_MAX_ITERS / runner.resolve_max_iters 先例):
  - 消费点解析而非 import 时固化:改 env 后下一次调用即生效,模块常量
    不被污染(测试可逐用例设/删 env)
  - 缺失/空白 → 静默回落默认;非法(不可解析/非正数)→ 回落默认并打
    一次告警(同值去重,防逐文件消费点刷屏)
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

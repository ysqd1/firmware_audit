"""三道规模闸门 env 解析单测(工单 03:.scratch/step0-fs-extract/issues/03-config-env.md)。

验收对照:
  - STEP0_PARTITION_MAX_SIZE_GB(默认 50)/ STEP1_MAX_TOTAL_FILES(默认 200000)/
    STEP1_MAX_FILES_PER_EXTRACTION(默认 50000):env 覆盖生效、缺省回落默认、
    非法值回落默认并提示
  - 非法告警同值去重(消费点逐文件调用不刷屏)

消费点接线(step0/step1 模块确实调解析器)在 test_step0_split.py /
test_step1_guided.py 各有集成断言;本文件只测解析函数本身。

用法:
    python -m firmware_audit.test.test_gates
"""
from __future__ import annotations

import io
from contextlib import redirect_stdout
import os

from .. import gates
from ..gates import (
    MAX_FILES_PER_EXTRACTION,
    MAX_TOTAL_FILES,
    PARTITION_MAX_SIZE_GB,
    resolve_max_files_per_extraction,
    resolve_max_total_files,
    resolve_partition_max_size_gb,
)

_ENV_NAMES = ("STEP0_PARTITION_MAX_SIZE_GB", "STEP1_MAX_TOTAL_FILES",
              "STEP1_MAX_FILES_PER_EXTRACTION")


class _EnvScope:
    """临时设/删闸门 env,退出恢复原值;进出清告警去重集,隔离用例。"""

    def __init__(self, **values):
        self.values = values
        self._saved: dict[str, str | None] = {}

    def __enter__(self):
        for k in _ENV_NAMES:
            self._saved[k] = os.environ.get(k)
            os.environ.pop(k, None)
        gates._invalid_warned.clear()
        for k, v in self.values.items():
            if v is not None:
                os.environ[k] = v

    def __exit__(self, *exc):
        for k, old in self._saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old
        gates._invalid_warned.clear()
        return False


def _run_quiet(fn):
    """调用解析函数并捕获 stdout,返回 (结果, 打印文本)。"""
    buf = io.StringIO()
    with redirect_stdout(buf):
        v = fn()
    return v, buf.getvalue()


def test_defaults_when_missing() -> list[str]:
    """缺省(三个 env 全不存在)→ 三道闸门回落内置默认,类型正确。"""
    fails: list[str] = []
    with _EnvScope():
        gb, out = _run_quiet(resolve_partition_max_size_gb)
        if gb != PARTITION_MAX_SIZE_GB or not isinstance(gb, float):
            fails.append(f"分区上限缺省应回落 {PARTITION_MAX_SIZE_GB}(float),got {gb!r}")
        if out:
            fails.append(f"缺省不应打印告警,got {out!r}")

        total, out = _run_quiet(resolve_max_total_files)
        if total != MAX_TOTAL_FILES or not isinstance(total, int):
            fails.append(f"全树上限缺省应回落 {MAX_TOTAL_FILES}(int),got {total!r}")
        if out:
            fails.append(f"缺省不应打印告警,got {out!r}")

        per, out = _run_quiet(resolve_max_files_per_extraction)
        if per != MAX_FILES_PER_EXTRACTION or not isinstance(per, int):
            fails.append(f"单次上限缺省应回落 {MAX_FILES_PER_EXTRACTION}(int),got {per!r}")
        if out:
            fails.append(f"缺省不应打印告警,got {out!r}")
    return fails


def test_env_override_takes_effect() -> list[str]:
    """合法 env 值生效(浮点/整数/带空白均可)。"""
    fails: list[str] = []
    with _EnvScope(STEP0_PARTITION_MAX_SIZE_GB=" 250.5 ",
                   STEP1_MAX_TOTAL_FILES="300000",
                   STEP1_MAX_FILES_PER_EXTRACTION="7"):
        gb, out = _run_quiet(resolve_partition_max_size_gb)
        if gb != 250.5:
            fails.append(f"STEP0_PARTITION_MAX_SIZE_GB=250.5 应生效,got {gb!r}")
        if out:
            fails.append(f"合法值不应打印告警,got {out!r}")
        total, _ = _run_quiet(resolve_max_total_files)
        if total != 300000:
            fails.append(f"STEP1_MAX_TOTAL_FILES=300000 应生效,got {total!r}")
        per, _ = _run_quiet(resolve_max_files_per_extraction)
        if per != 7:
            fails.append(f"STEP1_MAX_FILES_PER_EXTRACTION=7 应生效,got {per!r}")
    return fails


def test_invalid_falls_back_with_notice() -> list[str]:
    """非法值(不可解析/非正数/整数闸门给小数)→ 回落默认并打印含 env 名的告警。"""
    fails: list[str] = []
    cases = [
        ("STEP0_PARTITION_MAX_SIZE_GB", "abc", resolve_partition_max_size_gb,
         PARTITION_MAX_SIZE_GB),
        ("STEP0_PARTITION_MAX_SIZE_GB", "0", resolve_partition_max_size_gb,
         PARTITION_MAX_SIZE_GB),
        ("STEP0_PARTITION_MAX_SIZE_GB", "-5", resolve_partition_max_size_gb,
         PARTITION_MAX_SIZE_GB),
        # nan 的比较恒 False、inf 等于无上限,都必须按非法回落(防闸门静默失效)
        ("STEP0_PARTITION_MAX_SIZE_GB", "nan", resolve_partition_max_size_gb,
         PARTITION_MAX_SIZE_GB),
        ("STEP0_PARTITION_MAX_SIZE_GB", "inf", resolve_partition_max_size_gb,
         PARTITION_MAX_SIZE_GB),
        ("STEP0_PARTITION_MAX_SIZE_GB", "-inf", resolve_partition_max_size_gb,
         PARTITION_MAX_SIZE_GB),
        ("STEP1_MAX_TOTAL_FILES", "inf", resolve_max_total_files, MAX_TOTAL_FILES),
        ("STEP1_MAX_TOTAL_FILES", "abc", resolve_max_total_files, MAX_TOTAL_FILES),
        ("STEP1_MAX_TOTAL_FILES", "-1", resolve_max_total_files, MAX_TOTAL_FILES),
        ("STEP1_MAX_TOTAL_FILES", "12.5", resolve_max_total_files, MAX_TOTAL_FILES),
        ("STEP1_MAX_FILES_PER_EXTRACTION", "x", resolve_max_files_per_extraction,
         MAX_FILES_PER_EXTRACTION),
        ("STEP1_MAX_FILES_PER_EXTRACTION", "0", resolve_max_files_per_extraction,
         MAX_FILES_PER_EXTRACTION),
    ]
    for name, raw, fn, default in cases:
        with _EnvScope(**{name: raw}):
            v, out = _run_quiet(fn)
            if v != default:
                fails.append(f"{name}={raw!r} 应回落默认 {default},got {v!r}")
            if name not in out or raw not in out:
                fails.append(f"{name}={raw!r} 应回落并告警,输出: {out!r}")
    return fails


def test_blank_is_silent_default() -> list[str]:
    """空白 env 视同缺失:回落默认且不告警(与'非法值提示'区分)。"""
    fails: list[str] = []
    for name, fn, default in (
        ("STEP0_PARTITION_MAX_SIZE_GB", resolve_partition_max_size_gb,
         PARTITION_MAX_SIZE_GB),
        ("STEP1_MAX_TOTAL_FILES", resolve_max_total_files, MAX_TOTAL_FILES),
        ("STEP1_MAX_FILES_PER_EXTRACTION", resolve_max_files_per_extraction,
         MAX_FILES_PER_EXTRACTION),
    ):
        with _EnvScope(**{name: "   "}):
            v, out = _run_quiet(fn)
            if v != default:
                fails.append(f"{name} 空白应回落 {default},got {v!r}")
            if out:
                fails.append(f"{name} 空白不应告警,got {out!r}")
    return fails


def test_invalid_warning_deduped() -> list[str]:
    """同一非法值多次解析只告警一次(消费点逐文件调用不刷屏);换值再告警。"""
    fails: list[str] = []
    with _EnvScope(STEP1_MAX_TOTAL_FILES="abc"):
        _, out1 = _run_quiet(resolve_max_total_files)
        _, out2 = _run_quiet(resolve_max_total_files)
        _, out3 = _run_quiet(resolve_max_total_files)
        count = (out1 + out2 + out3).count("STEP1_MAX_TOTAL_FILES")  # 累计输出
        if count != 1:
            fails.append(f"同值 3 次解析应只告警 1 次,got {count} 次"
                         f"(输出: {(out1 + out2 + out3)!r})")
        os.environ["STEP1_MAX_TOTAL_FILES"] = "xyz"
        _, out4 = _run_quiet(resolve_max_total_files)
        if "xyz" not in out4:
            fails.append(f"换非法值应再告警,got {out4!r}")
    return fails


def test_main() -> int:
    failures = 0
    groups = [
        ("缺省回落默认", test_defaults_when_missing()),
        ("env 覆盖生效", test_env_override_takes_effect()),
        ("非法值回落并提示", test_invalid_falls_back_with_notice()),
        ("空白视同缺失", test_blank_is_silent_default()),
        ("非法告警去重", test_invalid_warning_deduped()),
    ]
    for name, fl in groups:
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())

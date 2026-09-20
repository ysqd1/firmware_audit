"""票05 回归:解包全程原件原位保全(工作副本化)。

不变量(票 binwalk-extractable-align/05):
  - 引导解包对任何候选(含顶层固件)的所有终态——成功/空产出/失败/
    超限/中断恢复——都不移动、不消耗原件,SHA-256 逐字节不变;
  - extractor 拿到的是独立工作副本,它消费副本不伤原件;
  - 工作副本在解包调用返回后清理,不滞留树内;
  - manifest 各终态如实记录工作副本(renamed_to)与原件原位
    (preserved_original),不再出现"文件被动过但 manifest 无去向"。
"""
from __future__ import annotations

import contextlib
import hashlib
import itertools
import tempfile
from pathlib import Path

from ..step1 import step1_guided_extract
from ..step1.step1_guided_extract import (
    extract_guided,
    _binwalk_extract_one,
    _load_manifest,
)

_GZ = b"\x1f\x8b" + b"\x00" * 60  # gzip 魔数 → 容器 continue

_uid = itertools.count()  # test_main 直跑时各测试共用 tmp_path,目录名防撞


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


class ConsumingExtractor:
    """模拟真实 binwalk -e:成功后消费输入文件,产出 1 个 ELF。"""

    def __init__(self):
        self.calls: list[str] = []

    def __call__(self, path: Path, seq: int, parent: Path):
        self.calls.append(path.name)
        path.unlink(missing_ok=True)  # binwalk 吃掉递给它的输入
        d = parent / f"{seq:06d}_{path.name}.extracted"
        d.mkdir(parents=True, exist_ok=True)
        (d / "app.elf").write_bytes(b"\x7fELF" + b"\x00" * 60)
        return [d / "app.elf"], "ok"


def test_success_preserves_original(tmp_path: Path) -> list[str]:
    """成功路径:extractor 消费输入,原件仍原位原字节。"""
    fails: list[str] = []
    root = tmp_path / "t1"
    root.mkdir()
    fw = root / "fw.bin"
    fw.write_bytes(_GZ)
    digest = _sha(fw)
    fake = ConsumingExtractor()
    extract_guided(fw, root / "out", max_depth=2, extractor=fake,
                   check_docker=False)
    if not fw.is_file():
        fails.append("成功路径:原位固件被移动/消费(票05 不变量破坏)")
    elif _sha(fw) != digest:
        fails.append("成功路径:原位固件字节变化")
    if not list((root / "out").rglob("app.elf")):
        fails.append("成功路径:产物缺失(副本化不得改变产物)")
    return fails


def _run_status(tmp_path: Path, tag: str, status: str):
    root = tmp_path / f"{tag}{next(_uid)}"
    root.mkdir()
    fw = root / "fw.bin"
    fw.write_bytes(_GZ)
    digest = _sha(fw)

    def fake(path: Path, seq: int, parent: Path):
        return [], status

    extract_guided(fw, root / "out", max_depth=2, extractor=fake,
                   check_docker=False)
    return fw, digest, _load_manifest(root / "out")


def test_non_ok_states_preserve_original(tmp_path: Path) -> list[str]:
    """empty/failed/over_guard:原件仍原位原字节。"""
    fails: list[str] = []
    for tag, st in (("e", "empty"), ("f", "failed"), ("o", "over_guard")):
        fw, digest, _man = _run_status(tmp_path, tag, st)
        if not fw.is_file():
            fails.append(f"{st}: 原位固件丢失")
        elif _sha(fw) != digest:
            fails.append(f"{st}: 原位固件字节变化")
    return fails


def test_manifest_records_working_copy_on_all_states(tmp_path: Path) -> list[str]:
    """非 ok 终态也要记 renamed_to + preserved_original(堵记账缺口)。"""
    fails: list[str] = []
    for tag, st in (("e", "empty"), ("f", "failed"), ("o", "over_guard")):
        _fw, _digest, man = _run_status(tmp_path, tag, st)
        rec = man.get("fw.bin")
        if not rec:
            fails.append(f"{st}: manifest 无记录")
            continue
        if not rec.get("renamed_to"):
            fails.append(f"{st}: manifest 缺 renamed_to(工作副本去向)")
        if not rec.get("preserved_original"):
            fails.append(f"{st}: manifest 缺 preserved_original(原件原位)")
    return fails


def test_working_copy_cleaned_after_extract(tmp_path: Path) -> list[str]:
    """真实 extractor(直调,假 docker 不消费):副本用完即清,原件不动。"""
    fails: list[str] = []
    ws = tmp_path / "ws"
    ws.mkdir()
    fw = ws / "blob.bin"
    fw.write_bytes(_GZ)
    digest = _sha(fw)

    def fake_run_docker(image, args, mounts=None, env=None, timeout=0, **kw):
        return 0, "", ""  # binwalk 空转、不消费、无产出 → 走 7z 兜底仍空

    old = step1_guided_extract.run_docker
    step1_guided_extract.run_docker = fake_run_docker
    try:
        files, status = _binwalk_extract_one(fw, 0, ws)
    finally:
        step1_guided_extract.run_docker = old
    if status != "empty":
        fails.append(f"无产出应 empty,got {status}")
    if (ws / "_wc_000000_blob.bin").exists():
        fails.append("工作副本未清理(滞留树内)")
    if not fw.is_file() or _sha(fw) != digest:
        fails.append("原件被移动/改变")
    return fails


def test_crash_residue_cleaned_original_preserved(tmp_path: Path) -> list[str]:
    """中断残留(副本在树、manifest 未记):入口清残留,原件保全,恰好解一次。"""
    fails: list[str] = []
    root = tmp_path / "crash"
    root.mkdir()
    fw = root / "fw.bin"
    fw.write_bytes(_GZ)
    digest = _sha(fw)
    residue = root / "_wc_000000_fw.bin"
    residue.write_bytes(_GZ)  # 崩溃残留:manifest 落盘前的工作副本
    calls: list[str] = []

    def fake(path: Path, seq: int, parent: Path):
        calls.append(path.name)
        d = parent / f"{seq:06d}_{path.name}.extracted"
        d.mkdir(parents=True, exist_ok=True)
        (d / "out.bin").write_bytes(b"x")
        return [d / "out.bin"], "ok"

    extract_guided(root, root, max_depth=2, extractor=fake,
                   check_docker=False, scan_tree=True)
    if not fw.is_file() or _sha(fw) != digest:
        fails.append("中断场景:原件丢失/变化")
    if residue.exists():
        fails.append("崩溃残留副本未被入口清理")
    if len(calls) != 1:
        fails.append(f"残留副本不应被重复入队,应恰好解 1 次,实际 {calls}")
    return fails


def test_resume_after_consumption_no_reextraction(tmp_path: Path) -> list[str]:
    """消费后重跑:零重复解包,原件仍在。"""
    fails: list[str] = []
    root = tmp_path / "t5"
    root.mkdir()
    fw = root / "fw.bin"
    fw.write_bytes(_GZ)
    digest = _sha(fw)
    extract_guided(fw, root / "out", max_depth=2, extractor=ConsumingExtractor(),
                   check_docker=False)
    fake2 = ConsumingExtractor()
    extract_guided(fw, root / "out", max_depth=2, extractor=fake2,
                   check_docker=False)
    if fake2.calls:
        fails.append(f"重跑又调 extractor: {fake2.calls}")
    if not fw.is_file() or _sha(fw) != digest:
        fails.append("重跑后原件丢失/变化")
    return fails


def test_scan_tree_preserves_in_tree_original(tmp_path: Path) -> list[str]:
    """scan_tree:树内容器原件保全;重跑零重复解包。"""
    fails: list[str] = []
    tree = tmp_path / "tree"
    tree.mkdir()
    gz = tree / "data.gz"
    gz.write_bytes(_GZ)
    digest = _sha(gz)
    extract_guided(tree, tree, max_depth=2, extractor=ConsumingExtractor(),
                   check_docker=False, scan_tree=True)
    if not gz.is_file():
        fails.append("scan_tree:树内容器原件被移动/消费")
    elif _sha(gz) != digest:
        fails.append("scan_tree:树内容器原件字节变化")
    fake2 = ConsumingExtractor()
    extract_guided(tree, tree, max_depth=2, extractor=fake2,
                   check_docker=False, scan_tree=True)
    if fake2.calls:
        fails.append(f"scan_tree 重跑又解包: {fake2.calls}")
    return fails


def test_main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="test_step1_original_") as tmp:
        tmp_path = Path(tmp)
        groups = [
            ("成功路径原件保全", test_success_preserves_original(tmp_path)),
            ("非 ok 终态原件保全", test_non_ok_states_preserve_original(tmp_path)),
            ("manifest 全终态记账", test_manifest_records_working_copy_on_all_states(tmp_path)),
            ("工作副本用后即清", test_working_copy_cleaned_after_extract(tmp_path)),
            ("中断残留清理+原件保全", test_crash_residue_cleaned_original_preserved(tmp_path)),
            ("消费后重跑零重复", test_resume_after_consumption_no_reextraction(tmp_path)),
            ("scan_tree 原件保全", test_scan_tree_preserves_in_tree_original(tmp_path)),
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

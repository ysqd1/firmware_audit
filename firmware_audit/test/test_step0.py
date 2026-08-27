"""Step0 预解压单元测试。

验证 preprocess() 对归档类/单文件压缩/其他三类固件的分流:
  - 归档类(.tar.xz/.tar.gz/.zip)→ 解出文件系统,skip_binwalk=True
  - 单文件压缩(.gz/.bz2/.xz)→ 解出单文件,skip_binwalk=False
  - 其他(.bin/.img)→ 原样返回,skip_binwalk=False

磁盘镜像(分区表)的分流测试在 test_step0_split.py。

用法:
    python firmware_audit/test/test_step0.py
    python -m firmware_audit.test.test_step0
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from pathlib import Path

from ..step0.step0_preprocess import preprocess


def _make_tar_xz(path: Path, entries: dict[str, bytes]) -> None:
    """构造一个 .tar.xz,内含 entries 映射的 {rel_path: content}。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:xz") as t:
        for rel, content in entries.items():
            info = tarfile.TarInfo(rel)
            info.size = len(content)
            t.addfile(info, io.BytesIO(content))
    path.write_bytes(buf.getvalue())


def _make_tar_gz(path: Path, entries: dict[str, bytes]) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for rel, content in entries.items():
            info = tarfile.TarInfo(rel)
            info.size = len(content)
            t.addfile(info, io.BytesIO(content))
    path.write_bytes(buf.getvalue())


def _make_zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as z:
        for rel, content in entries.items():
            z.writestr(rel, content)


def _make_gz(path: Path, content: bytes) -> None:
    path.write_bytes(gzip.compress(content))


def _make_bz2(path: Path, content: bytes) -> None:
    path.write_bytes(bz2.compress(content))


def test_tar_xz_archive_skips_binwalk(tmp_path) -> list[str]:
    """归档类 .tar.xz → 解出文件系统到 extracted/,skip_binwalk=True。"""
    fails: list[str] = []
    fw = tmp_path / "fw.tar.xz"
    _make_tar_xz(fw, {"etc/passwd": b"root:x:0:0", "home/unitree/app.sh": b"#!/bin/sh"})
    extracted = tmp_path / "extracted"

    out, skip = preprocess(fw, extracted)

    if not skip:
        fails.append("归档 .tar.xz 应 skip_binwalk=True")
    if out != [extracted]:
        fails.append(f"归档应返回 [extracted 目录],实际 {out}")
    if not (extracted / "etc" / "passwd").is_file():
        fails.append("etc/passwd 未解压出来")
    if not (extracted / "home" / "unitree" / "app.sh").is_file():
        fails.append("home/unitree/app.sh 未解压出来")
    return fails


def test_tar_gz_archive_skips_binwalk(tmp_path) -> list[str]:
    """归档类 .tar.gz → 同上。"""
    fails: list[str] = []
    fw = tmp_path / "fw.tar.gz"
    _make_tar_gz(fw, {"a.txt": b"hello"})
    extracted = tmp_path / "extracted"

    out, skip = preprocess(fw, extracted)

    if not skip:
        fails.append("归档 .tar.gz 应 skip_binwalk=True")
    if not (extracted / "a.txt").is_file():
        fails.append("a.txt 未解压出来")
    return fails


def test_zip_archive_skips_binwalk(tmp_path) -> list[str]:
    """归档类 .zip → 同上。"""
    fails: list[str] = []
    fw = tmp_path / "fw.zip"
    _make_zip(fw, {"dir/x.bin": b"\x00\x01"})
    extracted = tmp_path / "extracted"

    out, skip = preprocess(fw, extracted)

    if not skip:
        fails.append("归档 .zip 应 skip_binwalk=True")
    if not (extracted / "dir" / "x.bin").is_file():
        fails.append("dir/x.bin 未解压出来")
    return fails


def test_gz_single_passes_to_binwalk(tmp_path) -> list[str]:
    """单文件压缩 .gz → 解出单文件到 process/ 根(extracted_dir.parent),skip_binwalk=False。"""
    fails: list[str] = []
    fw = tmp_path / "disk.img.gz"
    content = b"\x00\x01\x02" * 100
    _make_gz(fw, content)
    extracted = tmp_path / "extracted"

    out, skip = preprocess(fw, extracted)

    if skip:
        fails.append("单文件压缩 .gz 不应 skip_binwalk")
    expected = tmp_path / "disk.img"  # 中间文件落 process/ 根,非 extracted/ 内
    if out != [expected]:
        fails.append(f"单文件压缩应解出 [{expected}],实际 {out}")
    if out[0].read_bytes() != content:
        fails.append("解压内容不一致")
    return fails


def test_bz2_single_passes_to_binwalk(tmp_path) -> list[str]:
    """单文件压缩 .bz2 → 同上。"""
    fails: list[str] = []
    fw = tmp_path / "firmware.bin.bz2"
    content = b"ELF" + b"\x00" * 200
    fw.write_bytes(bz2.compress(content))
    extracted = tmp_path / "extracted"

    out, skip = preprocess(fw, extracted)

    if skip:
        fails.append("单文件压缩 .bz2 不应 skip_binwalk")
    expected = tmp_path / "firmware.bin"
    if out != [expected]:
        fails.append(f"单文件压缩应解出 [{expected}],实际 {out}")
    if out[0].read_bytes() != content:
        fails.append("解压内容不一致")
    return fails


def test_xz_single_passes_to_binwalk(tmp_path) -> list[str]:
    """单文件压缩 .xz → 同上。"""
    fails: list[str] = []
    fw = tmp_path / "firmware.bin.xz"
    content = b"U-Boot" + b"\x00" * 100
    fw.write_bytes(lzma.compress(content))
    extracted = tmp_path / "extracted"

    out, skip = preprocess(fw, extracted)

    if skip:
        fails.append("单文件压缩 .xz 不应 skip_binwalk")
    expected = tmp_path / "firmware.bin"
    if out != [expected]:
        fails.append(f"单文件压缩应解出 [{expected}],实际 {out}")
    if out[0].read_bytes() != content:
        fails.append("解压内容不一致")
    return fails


def test_other_ext_passes_through(tmp_path) -> list[str]:
    """其他扩展名(.bin/.img) → 原样返回,skip_binwalk=False。"""
    fails: list[str] = []
    fw = tmp_path / "firmware.bin"
    fw.write_bytes(b"\x00" * 10)
    extracted = tmp_path / "extracted"

    out, skip = preprocess(fw, extracted)

    if skip:
        fails.append("非压缩 .bin 不应 skip_binwalk")
    if out != [fw]:
        fails.append(f"非压缩应原样返回,实际 {out}")
    return fails


def main() -> int:
    import tempfile
    from pathlib import Path

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        groups = [
            ("tar.xz 归档跳过", test_tar_xz_archive_skips_binwalk(tmp)),
            ("tar.gz 归档跳过", test_tar_gz_archive_skips_binwalk(tmp)),
            ("zip 归档跳过", test_zip_archive_skips_binwalk(tmp)),
            ("gz 单文件交binwalk", test_gz_single_passes_to_binwalk(tmp)),
            ("bz2 单文件交binwalk", test_bz2_single_passes_to_binwalk(tmp)),
            ("xz 单文件交binwalk", test_xz_single_passes_to_binwalk(tmp)),
            ("其他原样返回", test_other_ext_passes_through(tmp)),
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
    raise SystemExit(main())

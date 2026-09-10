"""对齐表单测:厂商魔数路由 + 漂移守护(票01)。

覆盖:
  - 对齐表新签名(shrs/trx/romfs/zlib/yaffs 等)→ 识别命中 + 容器裁决 continue
  - 偏移锚定条目(iso9660@0x8001 / uefi_pi_volume@40 / efigpt@510)
  - 既有格式行为回归(gzip continue / fdt skip / text product / ELF product)
  - 忽略清单语义:S-record 文本仍走 text→product(不被路由)
  - 引导解包循环:SHRS 候选交 fake extractor,fdt 永不进 extractor
  - 漂移守护(Docker 门控):镜像可解集 ⊆ 对齐表 ∪ 忽略清单 ∪ 既有名映射
"""
from __future__ import annotations

import sys
from pathlib import Path

from ..step1.file_magic import sniff_magic, preclassify, rule_decision
from ..step1.align_table import ALIGN_TABLE, ALIGN_NAMES, IGNORE_LIST

try:
    import pytest
except ImportError:  # 独立模式(python -m)无 pytest
    pytest = None


def test_align_signatures_route_to_binwalk() -> list[str]:
    """对齐表代表条目:识别命中 + 容器裁决 continue(SHRS 是 target/4 病根本尊)。"""
    fails: list[str] = []
    cases = [
        (b"SHRS" + b"\x00" * 64, "shrs"),
        (b"HDR0" + b"\x00" * 64, "trx"),
        (b"-rom1fs-" + b"\x00" * 64, "romfs"),
        (b"x\x9c" + b"\xab" * 64, "zlib"),
        (b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff" + b"\x00" * 16, "yaffs"),
        (b"\x00\xd5\x08\x00" + b"\x00" * 64, "arcadyan"),
    ]
    for head, want in cases:
        sigs = sniff_magic(head)
        if want not in sigs:
            fails.append(f"{want} 魔数应命中,实际 {sigs}")
            continue
        pc = preclassify(sigs)
        if pc != "container":
            fails.append(f"{want} 应交容器裁决,实际 {pc}")
            continue
        action, reason = rule_decision(sigs)
        if action != "continue" or want not in reason:
            fails.append(f"{want} 应 continue 且理由含签名名,实际 {(action, reason)!r}")
    return fails


def test_align_offset_anchored_entries() -> list[str]:
    """偏移锚定条目:iso9660@0x8001 / uefi_pi_volume@40 / efigpt@510。"""
    fails: list[str] = []

    def _head(off: int, magic: bytes) -> bytes:
        return b"\x00" * off + magic + b"\x00" * 32

    iso = sniff_magic(_head(0x8001, b"\x01CD001\x01\x00"))
    if "iso9660" not in iso:
        fails.append(f"iso9660 应在偏移 0x8001 命中,实际 {iso}")
    fv = sniff_magic(_head(40, b"_FVH"))
    if "uefi_pi_volume" not in fv:
        fails.append(f"uefi_pi_volume 应在偏移 40 命中,实际 {fv}")
    gpt = sniff_magic(_head(510, b"\x55\xaaEFI PART"))
    if "efigpt" not in gpt:
        fails.append(f"efigpt 应在偏移 510 命中,实际 {gpt}")
    # 偏移不足时不误报
    if "iso9660" in sniff_magic(b"\x01CD001\x01\x00" + b"\x00" * 16):
        fails.append("短于 0x8001 的文件不应命中 iso9660")
    return fails


def test_existing_formats_unchanged() -> list[str]:
    """既有 33 项格式行为回归:对齐是纯增量。"""
    fails: list[str] = []
    # gzip 仍 continue
    a, r = rule_decision(sniff_magic(b"\x1f\x8b" + b"\x00" * 60))
    if a != "continue" or "gzip" not in r:
        fails.append(f"gzip 路由回归: {(a, r)!r}")
    # fdt 仍 skip
    a2, r2 = rule_decision(sniff_magic(b"\xd0\x0d\xfe\xed" + b"\x00" * 60))
    if a2 != "skip":
        fails.append(f"fdt 硬跳过回归: {(a2, r2)!r}")
    # ELF 仍 product(finalize)
    a3, _ = rule_decision(sniff_magic(b"\x7fELF" + b"\x00" * 60))
    if a3 != "finalize":
        fails.append(f"ELF product 回归: {a3}")
    # 未知二进制仍 finalize 留树
    a4, _ = rule_decision(sniff_magic(b"\xde\xad\xbe\xef" * 16))
    if a4 != "finalize":
        fails.append(f"未知魔数仍应 finalize: {a4}")
    return fails


def test_ignore_list_semantics() -> list[str]:
    """忽略清单语义:S-record 文本仍走 text→product(不被对齐表抢路由)。"""
    fails: list[str] = []
    srec = b"S00300004844521B\nS10700000000F0\n"
    sigs = sniff_magic(srec)
    if sigs != ["text"]:
        fails.append(f"S-record 应按文本启发式判 text,实际 {sigs}")
    a, _ = rule_decision(sigs)
    if a != "finalize":
        fails.append(f"S-record 应 finalize(product 语义),实际 {a}")
    # 忽略名单里的签名绝不在对齐表中(dt 与 mbr 类冲突防护)
    align_names = ALIGN_NAMES
    overlap = {n for n, _ in IGNORE_LIST} & align_names
    if overlap:
        fails.append(f"签名同时出现在对齐表与忽略清单: {sorted(overlap)}")
    return fails


def test_extract_guided_routes_shrs(tmp_path: Path) -> list[str]:
    """引导解包循环:SHRS 候选交 extractor(注入 fake)——对齐表消费的端到端证据。"""
    fails: list[str] = []
    from ..step1.step1_guided_extract import extract_guided

    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"SHRS" + b"\x00" * 256)

    called: list[str] = []

    def fake_extractor(path: Path, seq: int, parent: Path):
        called.append(path.name)
        return [], "fake"

    extract_guided(fw, tmp_path / "extracted", extractor=fake_extractor,
                   check_docker=False)
    if "fw.bin" not in called:
        fails.append(f"SHRS 候选应交 extractor(fake 记录),实际 {called}")
    return fails


def test_align_table_covers_binwalk_extractable() -> list[str]:
    """漂移守护(Docker 门控):镜像可解签名集 ⊆ 对齐表 ∪ 忽略清单 ∪ 既有名映射。

    target/4 病根的复发开关:binwalk 镜像升级引入新可解签名而表未跟时,本测试变红。
    """
    from firmware_audit.docker.docker_utils import docker_available

    fails: list[str] = []
    image = "binwalk"
    if not docker_available(image):
        if pytest is not None:
            pytest.skip(f"Docker 或镜像 {image} 不可用")
        print(f"[SKIP] Docker 或镜像 {image} 不可用")
        return fails

    import subprocess

    proc = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "binwalk", image, "-L"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120,
    )
    if proc.returncode != 0:
        fails.append(f"binwalk -L 失败: {(proc.stderr or '')[:200]}")
        return fails

    # 既有识别表条目 → binwalk 签名名的映射(漂移覆盖记账,仅此测试消费)
    alias = {
        "7z": "7zip", "bzip2": "bzip2", "cpio": "cpio", "cpio_newc": "cpio",
        "cpio_odc": "cpio", "cramfs": "cramfs", "ext4": "ext", "fat": "fat",
        "gzip": "gzip", "jffs2": "jffs2", "lz4": "lz4", "lzma": "lzma",
        "squashfs": "squashfs", "tar": "tarball", "uimage": "uimage",
        "ubi": "ubi", "ubifs": "ubifs", "xz": "xz", "zip": "zip", "zstd": "zstd",
    }
    covered = ALIGN_NAMES | {n for n, _ in IGNORE_LIST} | set(alias.values())

    extractable: set[str] = set()
    for line in proc.stdout.splitlines():
        if not line.strip() or line.startswith("-") or "Signature Description" in line \
                or line.strip().startswith("Total"):
            continue
        tokens = line.split()
        if len(tokens) < 3:
            continue
        name, util = tokens[-2], tokens[-1]
        if util.isdigit():
            continue  # "Total/Extractable signatures: N" 尾巴
        if util != "None":
            extractable.add(name)

    unaligned = extractable - covered
    if unaligned:
        fails.append(
            f"binwalk 可解签名未入对齐表/忽略清单(镜像升级后表落后,target/4 病根): "
            f"{sorted(unaligned)};请补对齐表条目或在 IGNORE_LIST 登记理由")
    return fails


def test_main() -> int:
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        groups = [
            ("对齐签名路由", test_align_signatures_route_to_binwalk),
            ("偏移锚定条目", test_align_offset_anchored_entries),
            ("既有格式回归", test_existing_formats_unchanged),
            ("忽略清单语义", test_ignore_list_semantics),
            ("SHRS 路由循环", lambda: test_extract_guided_routes_shrs(Path(td))),
            ("漂移守护(Docker 门控)", test_align_table_covers_binwalk_extractable),
        ]
        for name, fn in groups:
            fl = fn()
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

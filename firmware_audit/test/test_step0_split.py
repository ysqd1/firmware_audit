"""Step0 磁盘镜像分区单元测试。

构造小型 GPT 磁盘镜像,验证:
  - is_disk_image 检测(GPT/非镜像)
  - parse_partitions 分区表解析(名称/偏移/大小)
  - should_extract 分流(kernel/small 提取,超大 rootfs/userdata 跳过)
  - extract_partitions_from_image 提取内容一致性
  - preprocess 对磁盘镜像(及 .img.bz2 压缩镜像)走分区路径返回多文件

用法:
    python -m firmware_audit.test.test_step0_split
"""
from __future__ import annotations

import bz2
import os
import struct
import zlib
from pathlib import Path

from ..step0 import step0_preprocess
from ..step0.step0_split_img import (
    is_disk_image,
    parse_partitions_manual,  # 单测测手写解析(含 CRC 强校验,不依赖 Docker)
    detect_partition_kind,
    should_extract,
    extract_partitions_from_image,
    _partitions_from_sfdisk_json,  # sfdisk JSON 纯函数解析(可单测)
)

SECTOR = 512
DATA_START_LBA = 40  # 标准 GPT first_usable
NUM_ENTRIES = 128
ENTRY_SIZE = 128


def make_gpt_image(path: Path, partitions: list[tuple[str, bytes]]) -> list[dict]:
    """构造**完整合法**的 GPT 磁盘镜像,返回 [(name, offset, size), ...] 预期。

    partitions: [(分区名, 分区内容 bytes), ...],内容按序放入数据区。
    写出**主 + 备份双 GPT 头 + 双条目数组**(标准 GPT 布局,CRC 全部正确)。
    为什么必须双头: sfdisk(libfdisk)只有主备份双头都有效才识别为 gpt,
    缺备份头会退化为 dos 标签(实测)——单测镜像不完整会导致交叉验证误拒。
    """
    entries = []
    data_lba = DATA_START_LBA
    for name, data in partitions:
        first = data_lba
        last = first + (len(data) - 1) // SECTOR
        entries.append((name, first, last, data))
        data_lba = last + 1
    # 布局: [MBR] [主GPT头] [主条目数组 32扇区] [分区数据...]
    #        [备份条目数组 32扇区] [备份GPT头]
    # 备份数组 = 128×128B = 32 扇区;备份头 = 1 扇区
    # 备份数组起始 = max(数据末尾, 主数组末尾 34),不得与数据/主数组重叠
    backup_lba = max(data_lba, 2 + 32) + 32
    total_lba = backup_lba + 1
    img = bytearray(total_lba * SECTOR)

    # LBA0: MBR + 保护性分区条目
    mbr = bytearray(SECTOR)
    mbr[510:512] = b"\x55\xaa"
    mbr[450] = 0xEE  # protective type
    struct.pack_into("<I", mbr, 454, 1)
    struct.pack_into("<I", mbr, 458, total_lba - 1)
    img[0:SECTOR] = mbr

    # 条目数组(主 + 备,内容相同,CRC 覆盖整个数组)
    entries_blob = bytearray(NUM_ENTRIES * ENTRY_SIZE)
    for i, (name, first, last, _) in enumerate(entries):
        off = i * ENTRY_SIZE
        e = bytearray(ENTRY_SIZE)
        e[0:16] = b"\xaa\xbb" + b"\x00" * 14            # type GUID 非零
        e[16:32] = b"\xcc\xdd" + b"\x00" * 14           # unique GUID
        struct.pack_into("<Q", e, 32, first)
        struct.pack_into("<Q", e, 40, last)
        e[56:56 + len(name) * 2] = name.encode("utf-16le")
        entries_blob[off:off + ENTRY_SIZE] = e
    entries_crc = zlib.crc32(bytes(entries_blob)) & 0xffffffff

    def _build_header(current_lba, backup_lba_, entries_lba):
        """构造 GPT 头(current_lba/backup_lba/entries_lba 可变的备份头也用它)。"""
        h = bytearray(SECTOR)
        h[0:8] = b"EFI PART"
        struct.pack_into("<I", h, 8, 0x00010000)
        struct.pack_into("<I", h, 12, 92)
        struct.pack_into("<Q", h, 24, current_lba)
        struct.pack_into("<Q", h, 32, backup_lba_)
        struct.pack_into("<Q", h, 40, DATA_START_LBA)   # first usable
        struct.pack_into("<Q", h, 48, total_lba - 34)   # last usable
        h[56:72] = b"\x11" * 16                         # disk GUID
        struct.pack_into("<Q", h, 72, entries_lba)
        struct.pack_into("<I", h, 80, NUM_ENTRIES)
        struct.pack_into("<I", h, 84, ENTRY_SIZE)
        struct.pack_into("<I", h, 88, entries_crc)
        h[16:20] = b"\x00\x00\x00\x00"                  # header CRC 置零
        crc = zlib.crc32(bytes(h[:92])) & 0xffffffff
        struct.pack_into("<I", h, 16, crc)
        return h

    img[SECTOR:2 * SECTOR] = _build_header(1, backup_lba, 2)              # 主头
    img[2 * SECTOR:2 * SECTOR + len(entries_blob)] = entries_blob          # 主条目数组
    img[backup_lba * SECTOR:backup_lba * SECTOR + len(entries_blob)] = entries_blob  # 备份条目数组
    img[total_lba * SECTOR - SECTOR:total_lba * SECTOR] = _build_header(backup_lba, 1, backup_lba - 32)  # 备份头

    # 分区数据
    for name, first, last, data in entries:
        img[first * SECTOR:first * SECTOR + len(data)] = data

    path.write_bytes(bytes(img))
    return [{"name": n, "offset": f * SECTOR, "size": (l - f + 1) * SECTOR}
            for n, f, l, _ in entries]


def test_is_disk_image_true(tmp_path) -> list[str]:
    """GPT 磁盘镜像应被识别为磁盘镜像。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("APP", b"A" * (SECTOR * 4))])
    if not is_disk_image(img):
        fails.append("GPT 镜像应 is_disk_image=True")
    return fails


def test_is_disk_image_false(tmp_path) -> list[str]:
    """无分区表的普通文件不应识别为磁盘镜像(保持旧行为交 binwalk)。"""
    fails: list[str] = []
    plain = tmp_path / "fw.bin"
    plain.write_bytes(b"\x00" * 1024)
    if is_disk_image(plain):
        fails.append("无分区表文件不应 is_disk_image=True")
    short = tmp_path / "tiny.bin"
    short.write_bytes(b"\x00" * 10)
    if is_disk_image(short):
        fails.append("不足 512B 文件不应 is_disk_image=True")
    return fails


def test_parse_partitions(tmp_path) -> list[str]:
    """分区表解析:名称/偏移/大小应正确。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    parts = make_gpt_image(img, [
        ("APP", b"A" * (SECTOR * 10)),
        ("A_kernel", b"K" * (SECTOR * 3)),
        ("UDA", b"U" * (SECTOR * 2)),
    ])

    parsed = parse_partitions_manual(img)
    if len(parsed) != 3:
        fails.append(f"应解析出 3 个分区,实际 {len(parsed)}")
        return fails
    for got, exp in zip(parsed, parts):
        if got["name"] != exp["name"]:
            fails.append(f"分区名 {got['name']} != {exp['name']}")
        if got["offset"] != exp["offset"]:
            fails.append(f"{exp['name']} 偏移 {got['offset']} != {exp['offset']}")
        if got["size"] != exp["size"]:
            fails.append(f"{exp['name']} 大小 {got['size']} != {exp['size']}")
    return fails


def test_should_extract_rules() -> list[str]:
    """提取规则:kernel/small/medium 必提,dtb/reserved/超大 rootfs/userdata 跳过。"""
    fails: list[str] = []
    G = 1024 * 1024 * 1024
    # 必提(esp 显式 kind 后必须在列,否则掉出 small 兜底)
    for kind in ("bootloader", "kernel", "esp", "small", "medium"):
        if not should_extract(kind, 1 * G, 50.0):
            fails.append(f"{kind} 应提取")
    # 类型筛选:dtb/reserved 默认不提取(纯噪声分区,见 SKIP_AUDIT_KINDS)
    for kind in ("dtb", "reserved"):
        if should_extract(kind, 100 * 1024 * 1024, 50.0):
            fails.append(f"{kind} 应默认跳过")
    # 小 rootfs 提,超大 rootfs 跳
    if not should_extract("rootfs", 10 * G, 50.0):
        fails.append("10GB rootfs 应提取")
    if should_extract("rootfs", 200 * G, 50.0):
        fails.append("200GB rootfs 应跳过(防爆炸)")
    # userdata 永远跳
    if should_extract("userdata", 1 * G, 50.0):
        fails.append("userdata 应跳过")
    # max_size 调大可提取超大 rootfs
    if not should_extract("rootfs", 200 * G, 300.0):
        fails.append("调大 max_size 后 200GB rootfs 应可提取")
    return fails


def test_detect_partition_kind_priority() -> list[str]:
    """kind 判定优先级:dtb/reserved 先于 kernel 命中,esp 显式识别。"""
    fails: list[str] = []
    cases = [
        ("A_kernel-dtb", 1024, "dtb"),            # 含 kernel 但必须判 dtb
        ("B_kernel-dtb", 1024, "dtb"),
        ("A_reserved_on_user", 31 * 1024 * 1024, "reserved"),  # 否则落 small
        ("reserved", 479 * 1024 * 1024, "reserved"),            # 否则落 medium
        ("esp", 64 * 1024 * 1024, "esp"),        # 否则落 small 兜底
        ("esp_alt", 64 * 1024 * 1024, "esp"),
        ("A_kernel", 128 * 1024 * 1024, "kernel"),
        ("recovery", 80 * 1024 * 1024, "recovery"),
        ("APP", 1024, "rootfs"),
        ("tiny_unknown", 1024, "small"),
    ]
    for name, size, want in cases:
        got = detect_partition_kind(name, 0, size)
        if got != want:
            fails.append(f"{name}({size}) → {got},期望 {want}")
    return fails


def test_preprocess_cleans_skipped_kind(tmp_path) -> list[str]:
    """被筛类型(dtb)的旧产物应被自动清理,且新提取不再包含它。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("A_kernel-dtb", b"D" * (SECTOR * 2)),
                         ("A_kernel", b"K" * (SECTOR * 4))])
    extracted = tmp_path / "extracted"

    # 模拟旧版本提取:extract_all=True 时 dtb 分区已落盘
    old = extract_partitions_from_image(img, tmp_path, max_size_gb=50.0,
                                        extract_all=True)
    if len(old) != 2:
        fails.append("extract_all 应提取 2 个分区")
        return fails
    dtb_file = tmp_path / "part01_A_kernel-dtb.img"
    if not dtb_file.is_file():
        fails.append("旧产物 part01_A_kernel-dtb.img 应存在")
        return fails
    # 模拟 main.py 已把分区 move 进子工作区
    sub = tmp_path / "part01_A_kernel-dtb"
    sub.mkdir(parents=True)
    (sub / "fileinfo.json").write_text("{}", encoding="utf-8")

    # 新版本默认筛选:dtb 被筛,旧产物(文件+子工作区)自动清理
    out, skip = step0_preprocess.preprocess(img, extracted)

    if skip:
        fails.append("磁盘镜像不应 skip_binwalk")
    if len(out) != 1 or out[0].name != "part02_A_kernel.img":
        fails.append(f"应只返回 part02_A_kernel.img,实际 {[o.name for o in out]}")
        return fails
    if dtb_file.exists():
        fails.append("被筛分区的旧文件未清理")
    if sub.exists():
        fails.append("被筛分区的旧子工作区未清理")
    return fails


def test_extract_partitions_from_image(tmp_path) -> list[str]:
    """提取分区:文件内容应与镜像内原始数据一致。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    app_data = b"A" * (SECTOR * 10)
    kernel_data = b"K" * (SECTOR * 3)
    make_gpt_image(img, [("APP", app_data), ("A_kernel", kernel_data)])

    out_dir = tmp_path / "parts"
    extracted = extract_partitions_from_image(img, out_dir, max_size_gb=50.0)

    # APP 10 扇区(5KB) < 50GB → 提取;A_kernel 必提
    if len(extracted) != 2:
        fails.append(f"应提取 2 个分区,实际 {len(extracted)}")
        return fails
    by_name = {Path(e["file"]).name: e for e in extracted}
    if "part01_APP.img" not in by_name:
        fails.append("未提取 part01_APP.img")
    if "part02_A_kernel.img" not in by_name:
        fails.append("未提取 part02_A_kernel.img")
        return fails
    if Path(by_name["part01_APP.img"]["file"]).read_bytes() != app_data:
        fails.append("APP 分区内容不一致")
    if Path(by_name["part02_A_kernel.img"]["file"]).read_bytes() != kernel_data:
        fails.append("A_kernel 分区内容不一致")
    return fails


def test_preprocess_disk_image_returns_parts(tmp_path) -> list[str]:
    """preprocess 对磁盘镜像:返回分区文件列表,skip_binwalk=False。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("APP", b"A" * (SECTOR * 5)), ("UDA", b"U" * (SECTOR * 2))])
    extracted = tmp_path / "extracted"

    out, skip = step0_preprocess.preprocess(img, extracted)

    if skip:
        fails.append("磁盘镜像不应 skip_binwalk")
    if len(out) != 1:
        fails.append(f"APP 提取 + UDA 跳过 = 1 个分区,实际 {len(out)}")
        return fails
    if out[0].name != "part01_APP.img":
        fails.append(f"分区文件名应为 part01_APP.img,实际 {out[0].name}")
    # 分区文件直接落 process/ 根(extracted_dir.parent),无 partitions/ 中转目录
    if not (tmp_path / "part01_APP.img").is_file():
        fails.append("分区文件未写入 process/ 根")
    return fails


def test_preprocess_bz2_disk_image(tmp_path) -> list[str]:
    """.img.bz2 压缩磁盘镜像:先解压再分区(模拟 g1-nx-j6.1.img.bz2 场景)。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("A_kernel", b"K" * (SECTOR * 4)), ("UDA", b"U" * 1024)])
    fw = tmp_path / "disk.img.bz2"
    fw.write_bytes(bz2.compress(img.read_bytes()))
    extracted = tmp_path / "extracted"

    out, skip = step0_preprocess.preprocess(fw, extracted)

    if skip:
        fails.append("压缩镜像不应 skip_binwalk")
    if len(out) != 1:
        fails.append(f"应提取 1 个分区(A_kernel),实际 {len(out)}")
        return fails
    if not out[0].name.endswith("A_kernel.img"):
        fails.append(f"应提取 A_kernel 分区,实际 {out[0].name}")
    return fails


def test_preprocess_reuse_existing(tmp_path) -> list[str]:
    """已提取的分区应复用(不重新提取),且子工作区中的文件也能被识别。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("A_kernel", b"K" * (SECTOR * 4)), ("UDA", b"U" * 1024)])
    extracted = tmp_path / "extracted"

    out1, skip1 = step0_preprocess.preprocess(img, extracted)
    # 模拟 main.py:把分区 move 进子工作区 process/<分区名>/
    sub = tmp_path / "part01_A_kernel"
    sub.mkdir(parents=True)
    dst = sub / out1[0].name
    out1[0].rename(dst)
    mtime_before = dst.stat().st_mtime

    out2, skip2 = step0_preprocess.preprocess(img, extracted)

    if skip2:
        fails.append("第二次 preprocess 不应 skip_binwalk")
    if len(out2) != 1:
        fails.append("第二次应识别 1 个分区")
        return fails
    if out2[0] != dst:
        fails.append(f"第二次应复用子工作区文件 {dst},实际 {out2[0]}")
    if dst.stat().st_mtime != mtime_before:
        fails.append("复用不应重写文件(mtime 变化说明重新提取了)")
    return fails


def test_gpt_header_crc_corrupt_rejected(tmp_path) -> list[str]:
    """GPT 头 CRC 被破坏 → 分区表不可信,parse 返回 []。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("APP", b"A" * (SECTOR * 4))])
    data = bytearray(img.read_bytes())
    data[512 + 16] ^= 0xFF  # 破坏 header CRC 的一个字节
    img.write_bytes(bytes(data))

    parsed = parse_partitions_manual(img)
    if parsed != []:
        fails.append(f"头 CRC 损坏应拒绝,实际返回 {len(parsed)} 个分区")
    return fails


def test_entries_crc_corrupt_rejected(tmp_path) -> list[str]:
    """分区条目数组 CRC 被破坏 → parse 返回 []。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("APP", b"A" * (SECTOR * 4))])
    data = bytearray(img.read_bytes())
    data[1024 + 60] ^= 0xFF  # 破坏第一条目名字区(条目数组 CRC 会不匹配)
    img.write_bytes(bytes(data))

    parsed = parse_partitions_manual(img)
    if parsed != []:
        fails.append(f"条目 CRC 损坏应拒绝,实际返回 {len(parsed)} 个分区")
    return fails


def test_partition_truncated_flag(tmp_path) -> list[str]:
    """分区超出文件末尾(被截断的镜像)→ truncated=True 而非静默错误。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("APP", b"A" * (SECTOR * 10)), ("UDA", b"U" * (SECTOR * 2))])
    # 截断文件:只保留 APP 前 5 扇区 → APP truncated,UDA 完全超界被跳过
    data = bytearray(img.read_bytes())
    img.write_bytes(bytes(data[:(DATA_START_LBA + 5) * SECTOR]))

    parsed = parse_partitions_manual(img)
    app = [p for p in parsed if p["name"] == "APP"]
    uda = [p for p in parsed if p["name"] == "UDA"]
    if not app:
        fails.append("APP 分区应仍被解析")
        return fails
    if not app[0]["truncated"]:
        fails.append("APP 超出文件末尾应标 truncated=True")
    if uda:
        fails.append("UDA 偏移超出文件末尾应被跳过(不返回)")
    return fails


def test_partition_kind_conflict(tmp_path) -> list[str]:
    """身份交叉验证:名字说 rootfs 但签名 unknown → kind_conflict=True。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    # 内容全零 → 签名 unknown;名字含 rootfs → 期望 ext4/squashfs 等 → 冲突
    make_gpt_image(img, [("rootfs_test", b"\x00" * (SECTOR * 4))])

    parsed = parse_partitions_manual(img)
    if len(parsed) != 1:
        fails.append(f"应解析出 1 个分区,实际 {len(parsed)}")
        return fails
    if not parsed[0]["kind_conflict"]:
        fails.append(f"rootfs 分区签名 unknown 应标记 kind_conflict,"
                     f"实际签名 {parsed[0]['signatures']}")
    return fails


def test_extract_verified_flag(tmp_path) -> list[str]:
    """提取成功的分区应带 verified=True(回读校验通过)。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    make_gpt_image(img, [("APP", b"A" * (SECTOR * 10)), ("A_kernel", b"K" * (SECTOR * 3))])

    out_dir = tmp_path / "parts"
    extracted = extract_partitions_from_image(img, out_dir, max_size_gb=50.0)

    if len(extracted) != 2:
        fails.append(f"应提取 2 个分区,实际 {len(extracted)}")
        return fails
    for e in extracted:
        if not e.get("verified"):
            fails.append(f"{e['file']} 应 verified=True")
        # 回读内容一致(在既有测试已断言,这里补 verified 标志)
    return fails


def test_sfdisk_json_gpt(tmp_path) -> list[str]:
    """_partitions_from_sfdisk_json 解析 GPT JSON:name/offset/size 正确。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 200000)  # 200KB 足够容纳分区
    stdout = '''{
      "partitiontable": {
        "label": "gpt", "id": "X", "device": "/data.img",
        "unit": "sectors", "sectorsize": 512,
        "partitions": [
          {"node": "/data.img1", "start": 40, "size": 100, "type": "t1", "name": "APP"},
          {"node": "/data.img2", "start": 140, "size": 50, "type": "t2", "name": "A_kernel"}
        ]
      }
    }'''
    parts = _partitions_from_sfdisk_json(stdout, img)
    if not parts:
        fails.append("应解析出分区")
        return fails
    if len(parts) != 2:
        fails.append(f"应有 2 分区,实际 {len(parts)}")
        return fails
    p0, p1 = parts
    if p0["name"] != "APP" or p0["offset"] != 40 * 512 or p0["size"] != 100 * 512:
        fails.append(f"APP 解析错误: {p0}")
    if p1["name"] != "A_kernel" or p1["offset"] != 140 * 512:
        fails.append(f"A_kernel 解析错误: {p1}")
    return fails


def test_sfdisk_json_mbr(tmp_path) -> list[str]:
    """MBR(dos)JSON:无 name,type 是 hex 串 → 分区名回退 partition_N。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 200000)
    stdout = '''{
      "partitiontable": {
        "label": "dos", "id": "0x00000000", "device": "/data.img",
        "unit": "sectors", "sectorsize": 512,
        "partitions": [
          {"node": "/data.img1", "start": 63, "size": 200, "type": "83"}
        ]
      }
    }'''
    parts = _partitions_from_sfdisk_json(stdout, img)
    if not parts:
        fails.append("MBR 应解析出分区")
        return fails
    if parts[0]["name"] != "partition_1":
        fails.append(f"MBR 无 name 应回退 partition_1,实际 {parts[0]['name']}")
    if parts[0]["offset"] != 63 * 512:
        fails.append(f"MBR offset 错误: {parts[0]}")
    return fails


def test_sfdisk_json_none(tmp_path) -> list[str]:
    """无分区表/解析失败 → 返回 None(触发回退手写解析)。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 10000)
    # label 不是 gpt/dos
    if _partitions_from_sfdisk_json('{"partitiontable": {"label": "unknown"}}', img) is not None:
        fails.append("未知 label 应返回 None")
    # 非法 JSON
    if _partitions_from_sfdisk_json("not json", img) is not None:
        fails.append("非法 JSON 应返回 None")
    # 无 partitions 数组
    if _partitions_from_sfdisk_json('{"partitiontable": {"label": "gpt"}}', img) is not None:
        fails.append("无 partitions 应返回 None")
    # 空镜像(stat 0)
    empty = tmp_path / "empty.img"
    empty.write_bytes(b"")
    if _partitions_from_sfdisk_json(
        '{"partitiontable": {"label": "gpt", "partitions": [{"start": 0, "size": 1}]}}',
        empty) is not None:
        fails.append("空镜像分区应被跳过(超界)→ None")
    return fails


def test_extract_gate_env_consumed(tmp_path) -> list[str]:
    """STEP0_PARTITION_MAX_SIZE_GB 消费接线(工单 03):未显式传
    max_size_gb 时按 env 判限——闸门收紧 rootfs 跳过、放宽则提取。"""
    fails: list[str] = []
    env_name = "STEP0_PARTITION_MAX_SIZE_GB"
    img = tmp_path / "gate.img"
    # APP → kind rootfs;30 扇区 = 15360B
    make_gpt_image(img, [("APP", b"A" * (SECTOR * 30))])
    old = os.environ.get(env_name)
    try:
        os.environ[env_name] = "0.00001"   # ≈10.7KB < 15KB → 超限跳过
        got = extract_partitions_from_image(img, tmp_path / "out_tight")
        if got:
            fails.append(f"闸门收紧后 15KB rootfs 应跳过,got {[e['file'] for e in got]}")
        os.environ[env_name] = "1"         # 1GB → 放行
        got = extract_partitions_from_image(img, tmp_path / "out_loose")
        if len(got) != 1:
            fails.append(f"闸门放宽后应提取 1 个分区,got {len(got)}")
    finally:
        if old is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old
    return fails


def test_preprocess_partition_gate_env(tmp_path) -> list[str]:
    """同闸门在 preprocess 主路径生效:收紧 → 无分区产出、整盘回退 binwalk;
    放宽 → 返回分区文件条目。"""
    fails: list[str] = []
    env_name = "STEP0_PARTITION_MAX_SIZE_GB"
    img = tmp_path / "gate2.img"
    make_gpt_image(img, [("APP", b"A" * (SECTOR * 30))])
    old = os.environ.get(env_name)
    try:
        os.environ[env_name] = "0.00001"
        proc = tmp_path / "proc_tight"
        inputs, skip = step0_preprocess.preprocess(img, proc / "extracted")
        if inputs != [img] or skip:
            fails.append(f"闸门收紧应无分区产出、回退整盘,got ({inputs}, {skip})")
        os.environ[env_name] = "1"
        proc2 = tmp_path / "proc_loose"
        inputs2, skip2 = step0_preprocess.preprocess(img, proc2 / "extracted")
        if len(inputs2) != 1 or "APP" not in inputs2[0].name or skip2:
            fails.append(f"闸门放宽应返回 APP 分区条目,got ({inputs2}, {skip2})")
    finally:
        if old is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old
    return fails


def test_sfdisk_json_truncated(tmp_path) -> list[str]:
    """分区超出文件末尾 → truncated=True(截断标记)。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 50000)  # 50KB
    stdout = '''{
      "partitiontable": {
        "label": "gpt", "sectorsize": 512,
        "partitions": [
          {"node": "/data.img1", "start": 10, "size": 500, "name": "BIG"}
        ]
      }
    }'''
    # start=10 → offset 5120;size=500 → 256000 > 50000,超尾 → truncated
    parts = _partitions_from_sfdisk_json(stdout, img)
    if not parts:
        fails.append("应解析出分区")
        return fails
    if not parts[0]["truncated"]:
        fails.append(f"超出文件末尾应 truncated=True,实际 {parts[0]}")
    return fails


def test_main() -> int:
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        groups = [
            ("is_disk_image 检测", test_is_disk_image_true(tmp) + test_is_disk_image_false(tmp)),
            ("分区表解析", test_parse_partitions(tmp)),
            ("提取规则", test_should_extract_rules()),
            ("kind判定优先级", test_detect_partition_kind_priority()),
            ("被筛分区清理", test_preprocess_cleans_skipped_kind(tmp)),
            ("分区提取一致性", test_extract_partitions_from_image(tmp)),
            ("preprocess 磁盘镜像", test_preprocess_disk_image_returns_parts(tmp)),
            ("preprocess 压缩镜像", test_preprocess_bz2_disk_image(tmp)),
            ("复用已提取分区", test_preprocess_reuse_existing(tmp)),
            ("GPT头CRC损坏拒绝", test_gpt_header_crc_corrupt_rejected(tmp)),
            ("条目CRC损坏拒绝", test_entries_crc_corrupt_rejected(tmp)),
            ("超界分区截断标记", test_partition_truncated_flag(tmp)),
            ("身份签名冲突标记", test_partition_kind_conflict(tmp)),
            ("提取回读校验标记", test_extract_verified_flag(tmp)),
            ("sfdisk JSON GPT解析", test_sfdisk_json_gpt(tmp)),
            ("sfdisk JSON MBR解析", test_sfdisk_json_mbr(tmp)),
            ("sfdisk JSON 无表/失败", test_sfdisk_json_none(tmp)),
            ("sfdisk JSON 截断标记", test_sfdisk_json_truncated(tmp)),
            ("分区闸门env接线·提取", test_extract_gate_env_consumed(tmp)),
            ("分区闸门env接线·preprocess", test_preprocess_partition_gate_env(tmp)),
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

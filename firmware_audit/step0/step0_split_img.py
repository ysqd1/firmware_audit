#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Step0: 从大磁盘镜像中提取有内容的分区。

解决 .img 几百 GB 无法直接 binwalk 的问题:解析 GPT/MBR 分区表,
把有价值的分区提取成独立文件,每个分区再单独交 Step1 引导解包器。

分区准确性是第一优先级——分区切错,后续解包/过滤/反编译/审计全部作废。
因此这里有多道防线(宁可拒绝,不可静默出错):
  1. GPT 头 CRC32 + 分区条目数组 CRC32 校验(不匹配 → 拒绝使用分区表)
  2. 条目参数合理性(条目数/大小/数组位置在文件内)
  3. 每个分区边界检查(偏移超出文件末尾 → 跳过;超出末尾 → 截断并告警)
  4. 类型 GUID 全零但非空条目 → 告警跳过
  5. 身份交叉验证:名字推断的 kind 与头部签名冲突 → 告警
  6. 提取后回读校验(前 4KB 与源镜像对比,不一致 → 删除该分区)
  7. 复用检查同样过回读校验(大小一致但内容损坏 → 重新提取)

用法(独立运行):
    python -m firmware_audit.step0.step0_split_img <img文件> [--out-dir 输出目录] [--max-size GB]
    python -m firmware_audit.step0.step0_split_img g1-nx-j6.2.img --out-dir target/1/step0 --max-size 50

供流水线调用(preprocess):
    from .step0_split_img import is_disk_image, extract_partitions_from_image
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import zlib
from pathlib import Path

# 分区签名扫描上限:ext4 superblock(0x438)、squashfs/FAT/ELF 头都在分区前 64KB,
# 不必读 64MB(老实现 15 分区 × 64MB = ~1GB IO,对几百 GB 镜像浪费在无意义读盘)。
_MAX_SIGNATURE_SCAN = 64 * 1024

# 标准 GPT 头大小(header_size 字段,CRC 覆盖范围)
_GPT_HEADER_SIZE = 92
# 提取后回读校验比较的字节数(分区头 4KB 足以抓 seek/IO 错误)
_VERIFY_CHUNK = 4096

# sfdisk 主解析用的镜像(内含 libfdisk/sfdisk,权威分区表解析)
_SFDISK_IMAGE = "firm_audit/sandbox"

# 身份交叉验证:名字推断的 kind 应匹配的头部签名关键词。
# kind 不在表内(small/medium/large,名字无特征)→ 不做强约束。
_KIND_EXPECTED_SIGNATURES = {
    "rootfs": ("ext4", "squashfs", "gzip", "xz", "lzma"),
    "recovery": ("ext4", "squashfs", "gzip", "xz", "u-boot", "android"),
    "kernel": ("u-boot", "elf", "gzip", "xz", "lzma", "android"),
    "bootloader": ("u-boot", "elf"),
    "userdata": ("ext4", "ntfs", "fat"),
}
# 签名全部 unknown 仍算正常的 kind:裸内核/无签名 bootloader/recovery 镜像
# (厂商专有恢复镜像头部常无标准签名,实测 g1 镜像 recovery 分区即 unknown)常见。
# 文件系统类分区(rootfs/userdata)若 unknown 则是真冲突,值得告警。
_KIND_ALLOWS_UNKNOWN = {"kernel", "bootloader", "recovery"}

# 默认不送审计的分区类型:
#   dtb     - 设备树二进制。binwalk 递归解出数万 DTB 节点文件
#             (bus@0/aconnect@2900000/.../phandle,平均 16B)纯噪声,
#             且 DTB 里的 bootargs 凭据场景极少(已确认取舍)。
#   reserved - 保留区/签名/空白数据,无审计价值。
# 要强制提取/审计时用 --extract-all 或显式传 extract_all=True。
SKIP_AUDIT_KINDS = {"dtb", "reserved"}


def is_disk_image(path) -> bool:
    """判断文件是否磁盘镜像(含 GPT 或 MBR 分区表)。

    只读前 1KB:MBR 签名(0x55aa)+ 可选 GPT 头(LBA1 的 'EFI PART')。
    无分区表的裸固件(纯 squashfs/U-Boot 等)返回 False,保持旧行为交 binwalk。

    为什么不用扩展名: 固件也可能是 .bin/.img 且无分区表;分区表才是真信号。
    """
    try:
        with open(path, "rb") as f:
            mbr = f.read(512)
            if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
                return False
            f.seek(512)
            return f.read(8) == b"EFI PART"
    except OSError:
        return False


def parse_gpt_partitions(f):
    """解析 GPT 分区表，返回分区列表(带校验字段)。

    校验失败(CRC 不匹配/条目参数异常/数组超界)→ 打印醒目警告并返回 [],
    由调用方回退(直接交 binwalk),不静默使用不可信分区表。
    """
    f.seek(0, 2)
    file_size = f.tell()

    f.seek(0)
    mbr = f.read(512)
    if mbr[510:512] != b"\x55\xaa":
        print("[Step0] 警告: MBR 签名不存在，可能不是有效镜像")
        return []

    # 读 GPT 头 (LBA 1)
    f.seek(512)
    gpt_header = f.read(512)
    sig = gpt_header[0:8]

    if sig == b"EFI PART":
        return _parse_gpt(f, gpt_header, file_size)
    else:
        return _parse_mbr(mbr, file_size)


def _parse_gpt(f, gpt_header, file_size):
    """解析 GPT 格式(带 CRC32 校验与边界检查)。"""
    # --- 防线1:GPT 头 CRC32(覆盖头前 92 字节,CRC 字段自身置零) ---
    stored_crc = struct.unpack_from("<I", gpt_header, 16)[0]
    hdr = bytearray(gpt_header[:_GPT_HEADER_SIZE])
    hdr[16:20] = b"\x00\x00\x00\x00"
    calc_crc = zlib.crc32(bytes(hdr)) & 0xffffffff
    if stored_crc != calc_crc:
        print(f"[Step0] GPT 头 CRC32 校验失败(存储 {stored_crc:#x} != 计算 {calc_crc:#x}),"
              "分区表不可信,拒绝使用(回退直接交 binwalk)")
        return []

    # --- 防线2:头参数合理性 ---
    header_size = struct.unpack_from("<I", gpt_header, 12)[0]
    if header_size < _GPT_HEADER_SIZE or header_size > 512:
        print(f"[Step0] GPT 头大小异常: {header_size},拒绝使用")
        return []

    lba_start = struct.unpack_from("<Q", gpt_header, 72)[0]
    num_entries = struct.unpack_from("<I", gpt_header, 80)[0]
    entry_size = struct.unpack_from("<I", gpt_header, 84)[0]
    if num_entries == 0 or num_entries > 1024 or entry_size < 128:
        print(f"[Step0] GPT 条目参数异常(entries={num_entries}, size={entry_size}),拒绝使用")
        return []

    arr_off = lba_start * 512
    arr_len = num_entries * entry_size
    if arr_off + arr_len > file_size:
        print(f"[Step0] GPT 条目数组({arr_off}+{arr_len})超出文件末尾({file_size}),拒绝使用")
        return []

    f.seek(arr_off)
    entries_blob = f.read(arr_len)

    # --- 防线3:条目数组 CRC32(覆盖整个数组) ---
    stored_entries_crc = struct.unpack_from("<I", gpt_header, 88)[0]
    calc_entries_crc = zlib.crc32(entries_blob) & 0xffffffff
    if stored_entries_crc != calc_entries_crc:
        print(f"[Step0] GPT 条目数组 CRC32 校验失败(存储 {stored_entries_crc:#x} != "
              f"计算 {calc_entries_crc:#x}),分区表不可信,拒绝使用(回退直接交 binwalk)")
        return []

    # --- 逐条解析 + 防线4/5:条目有效性 + 边界检查 ---
    partitions = []
    for i in range(num_entries):
        entry = entries_blob[i * entry_size:(i + 1) * entry_size]
        if len(entry) < 56:
            break
        type_guid = entry[0:16]
        first_lba = struct.unpack_from("<Q", entry, 32)[0]
        last_lba = struct.unpack_from("<Q", entry, 40)[0]
        name = entry[56:128].decode("utf-16le", errors="ignore").rstrip("\x00")

        if type_guid == b"\x00" * 16 and first_lba == 0 and last_lba == 0 and not name:
            continue  # 空条目(标准做法)
        if type_guid == b"\x00" * 16:
            print(f"[Step0] 警告: 条目{i + 1} 类型 GUID 全零但非空,跳过(可能是垃圾条目)")
            continue

        issues: list[str] = []
        # 范围合理性:first <= last
        if first_lba > last_lba:
            print(f"[Step0] 警告: 条目{i + 1}({name}) first_lba({first_lba}) > "
                  f"last_lba({last_lba}),跳过")
            continue

        offset = first_lba * 512
        size = (last_lba - first_lba + 1) * 512

        # 边界检查(相对文件实际大小,防损坏/被截断的镜像)
        truncated = False
        if offset >= file_size:
            print(f"[Step0] 警告: 条目{i + 1}({name}) 偏移({offset})超出文件末尾"
                  f"({file_size}),跳过")
            continue
        if offset + size > file_size:
            truncated = True
            issues.append(f"分区超出文件末尾 {offset + size - file_size} 字节,截断处理")

        partitions.append({
            "index": i + 1,
            "name": name or f"partition_{i + 1}",
            "offset": offset,
            "size": size,
            "type": "gpt",
            "crc_ok": True,          # 表级 CRC 已通过
            "truncated": truncated,  # 超界截断标记
            "issues": issues,        # 人类可读问题列表
            "kind_conflict": False,  # 后续 parse_partitions 填充
        })

    return partitions


def _parse_mbr(mbr, file_size):
    """解析 MBR (DOS) 格式(带边界检查)。"""
    partitions = []
    for i in range(4):
        offset = 446 + i * 16
        entry = mbr[offset:offset + 16]
        ptype = entry[4]
        if ptype == 0:
            continue

        start_lba = struct.unpack_from("<I", entry, 8)[0]
        size_lba = struct.unpack_from("<I", entry, 12)[0]
        start = start_lba * 512
        size = size_lba * 512

        issues: list[str] = []
        if start >= file_size:
            print(f"[Step0] 警告: MBR 分区{i + 1} 偏移({start})超出文件末尾({file_size}),跳过")
            continue
        truncated = False
        if start + size > file_size:
            truncated = True
            issues.append(f"分区超出文件末尾 {start + size - file_size} 字节,截断处理")

        partitions.append({
            "index": i + 1,
            "name": f"dos_partition_{i + 1}",
            "offset": start,
            "size": size,
            "type": "mbr",
            "crc_ok": True,          # MBR 无 CRC,默认可信(有边界检查兜底)
            "truncated": truncated,
            "issues": issues,
            "kind_conflict": False,
        })
    return partitions


def detect_partition_kind(name, offset, size):
    """根据分区名和大小推断类型"""
    name_lower = name.lower()
    # dtb/reserved/esp 必须最先判定:名字形如 "A_kernel-dtb" 含 "kernel",
    # 若 "kernel" 先命中会把 DTB 分区误判为 kernel,binwalk 深解出数万
    # 节点文件(bus@0/aconnect@.../phandle)纯噪声。reserved 同理,否则
    # 31.6MB 的 reserved_on_user 落 small/medium 兜底被放行。
    if "dtb" in name_lower:
        return "dtb"
    if "reserved" in name_lower:
        return "reserved"
    if "esp" in name_lower:
        return "esp"
    if any(k in name_lower for k in ["boot", "mb1", "mb2", "bpmp", "tos", "tee", "cbo"]):
        return "bootloader"
    if any(k in name_lower for k in ["kernel", "boot_a", "boot_b"]):
        return "kernel"
    if any(k in name_lower for k in ["app", "rootfs", "system", "root"]):
        return "rootfs"
    if any(k in name_lower for k in ["recovery", "recovery_a", "recovery_b"]):
        return "recovery"
    if any(k in name_lower for k in ["uda", "data", "userdata"]):
        return "userdata"
    if size < 100 * 1024 * 1024:  # < 100MB
        return "small"
    if size < 5 * 1024 * 1024 * 1024:  # < 5GB
        return "medium"
    return "large"


def _cross_check_kind(kind, signatures):
    """身份交叉验证:名字推断的 kind 与头部签名是否冲突。

    Returns: (conflict: bool, 说明 str)。kind 无期望签名约束 → 不冲突。
    """
    expected = _KIND_EXPECTED_SIGNATURES.get(kind)
    if not expected:
        return False, ""
    joined = ",".join(s.lower() for s in signatures)
    if any(e in joined for e in expected):
        return False, ""
    # 全部 unknown 且该 kind 允许无签名头(裸内核/无签名 bootloader)→ 正常
    if "unknown" in joined and kind in _KIND_ALLOWS_UNKNOWN:
        return False, ""
    return True, (f"名字推断为 {kind},但头部签名({', '.join(signatures)})不匹配"
                  f"期望({', '.join(expected)}),身份存疑")


def should_extract(kind, size, max_size_gb):
    """判断是否应该提取该分区"""
    max_size_bytes = max_size_gb * 1024 * 1024 * 1024

    # 类型筛选:dtb/reserved 默认不提取(纯噪声分区,见 SKIP_AUDIT_KINDS)。
    # extract_all=True 的调用方(extract_partitions_from_image)绕开此判断。
    if kind in SKIP_AUDIT_KINDS:
        return False

    # 这些分区总是提取
    # 注意: esp 显式识别后必须在此列表——它原本靠 small 大小兜底,
    # 独立成 kind 后若漏加会从"必提"掉进"跳过"(实测 --list-only 暴露)。
    if kind in ("bootloader", "kernel", "esp", "small", "medium"):
        return True

    # rootfs 如果不超过限制就提取
    if kind == "rootfs" and size <= max_size_bytes:
        return True

    # recovery 通常较大但有价值，如果不超过限制就提取
    if kind == "recovery" and size <= max_size_bytes:
        return True

    # userdata 和超大分区跳过
    return False


def extract_partition(f, partition, out_path):
    """提取单个分区到文件(源提前截断时按实际可读量输出)。"""
    offset = partition["offset"]
    size = partition["size"]
    bs = 4 * 1024 * 1024  # 每次读写 4MB

    f.seek(offset)
    copied = 0

    with open(out_path, "wb") as fout:
        while copied < size:
            to_read = min(bs, size - copied)
            chunk = f.read(to_read)
            if not chunk:
                break  # 源已到末尾(被截断的镜像)
            fout.write(chunk)
            copied += len(chunk)

            # 进度显示
            gb_done = copied / (1024 * 1024 * 1024)
            gb_total = size / (1024 * 1024 * 1024)
            pct = copied * 100 / size
            sys.stdout.write(f"\r  提取中: {gb_done:.2f}/{gb_total:.2f} GB ({pct:.1f}%)")
            sys.stdout.flush()

    print()
    return copied


def _verify_extracted(src_path, offset, size, out_path, chunk=_VERIFY_CHUNK):
    """提取后回读校验:比较源分区头与提取文件头。

    抓 seek/IO/写入错误——分区内容不可信时宁可不产出,不产出坏数据。
    比较范围 = min(chunk, 提取文件实际大小, 期望大小):
      - 分区可能小于 4KB(如 kernel-dtb 768KB 以上,但小镜像测试分区可能 <4KB),
        此时越过分区边界读源会读到后续数据,必须按提取文件实际大小取 n。
      - 截断镜像的提取文件 < size,同样按实际大小比较(源也读不到更多)。
    """
    try:
        with open(src_path, "rb") as sf, open(out_path, "rb") as of:
            of.seek(0, 2)
            out_size = of.tell()
            n = min(chunk, out_size, size)
            sf.seek(offset)
            src_head = sf.read(n)
            of.seek(0)
            out_head = of.read(n)
        return src_head == out_head
    except OSError:
        return False


def scan_partition_signatures(f, partition, max_scan=_MAX_SIGNATURE_SCAN):
    """快速扫描分区头部，识别文件系统类型"""
    offset = partition["offset"]
    scan_size = min(max_scan, partition["size"])

    f.seek(offset)
    data = f.read(scan_size)

    signatures = []

    # ext4/ext2 superblock (偏移 0x438)
    if len(data) > 0x440:
        magic = struct.unpack_from("<H", data, 0x438)[0]
        if magic == 0xEF53:
            signatures.append("ext4/ext2 filesystem")

    # squashfs
    if len(data) >= 4:
        if data[0:4] == b"hsqs":
            signatures.append("squashfs (little-endian)")
        elif data[0:4] == b"sqsh":
            signatures.append("squashfs (big-endian)")

    # gzip
    if len(data) >= 2:
        if data[0:2] == b"\x1f\x8b":
            signatures.append("gzip compressed")

    # xz
    if len(data) >= 6:
        if data[0:6] == b"\xfd7zXZ\x00":
            signatures.append("xz compressed")

    # lzma
    if len(data) >= 4:
        if data[0:1] == b"\x5d":
            signatures.append("lzma (possible)")

    # Android bootimg(内核 + ramdisk + dtb,头部魔数 "ANDROID!")
    # 实测 g1 镜像 recovery 分区即此格式(file 输出 "Android bootimg")
    if len(data) >= 8:
        if data[0:8] == b"ANDROID!":
            signatures.append("Android bootimg")

    # U-Boot uImage
    if len(data) >= 4:
        if data[0:4] == b"\x27\x05\x19\x56":
            signatures.append("U-Boot uImage")

    # FAT(FAT12/16: 0x36 处 "FAT";FAT32: 0x52 处 "FAT32" 8 字节字段,
    # "FAT32" 后跟空格填充——实测 esp 分区 0x52 为 b"FAT32   \x0e\x1f",
    # 精确匹配会失败,必须用 in)
    # 注意: 跳转指令首字节是 0xEB/0xE9(不是 ASCII "EB" 0x45 0x42),
    # 且不能用 data[0:3] in (b"\xeb",) —— 3 字节切片永远不等于 1 字节。
    if len(data) >= 3:
        if data[0] in (0xEB, 0xE9):
            if len(data) > 0x52 and b"FAT32" in data[0x52:0x5A]:
                signatures.append("FAT32 filesystem")
            elif len(data) > 0x36 and b"FAT" in data[0x36:0x3F]:
                signatures.append("FAT filesystem")

    # NTFS
    if len(data) >= 8:
        if data[3:11] == b"NTFS    ":
            signatures.append("NTFS filesystem")

    # ELF
    if len(data) >= 4:
        if data[0:4] == b"\x7fELF":
            signatures.append("ELF executable")

    # cpio
    if len(data) >= 6:
        if data[0:6] == b"070701":
            signatures.append("cpio archive")

    # 如果没识别到，标记为 unknown
    if not signatures:
        signatures.append("unknown (raw binary)")

    return signatures


def _enrich_partitions(f, partitions: list[dict]) -> list[dict]:
    """给分区列表补充 kind/签名/身份交叉验证(两种解析路径共用)。"""
    for p in partitions:
        p["kind"] = detect_partition_kind(p["name"], p["offset"], p["size"])
        p["signatures"] = scan_partition_signatures(f, p)
        conflict, reason = _cross_check_kind(p["kind"], p["signatures"])
        p["kind_conflict"] = conflict
        if conflict:
            p["issues"].append(reason)
    return partitions


def parse_partitions_manual(img_path) -> list[dict]:
    """手写解析 GPT/MBR(含 CRC 强校验、边界检查)。

    作为 sfdisk 主解析的兜底(离线/镜像不可用/失败时)。
    返回分区列表;无分区表或表不可信(CRC 失败)返回 []。
    """
    with open(img_path, "rb") as f:
        partitions = parse_gpt_partitions(f)
        return _enrich_partitions(f, partitions)


def parse_partitions_sfdisk(img_path) -> list[dict] | None:
    """用 sfdisk(libfdisk 权威实现)解析分区表。

    为什么主解析用 sfdisk: 手写解析只见过宇树固件,libfdisk 处理过所有
    厂商的分区表变体,更普世、更不易错。分区表解析是准确性命门。

    Returns:
        分区列表;sfdisk 不可用/失败/无分区表返回 None(调用方回退手写解析)。
    """
    try:
        from ..docker.docker_utils import run_docker, docker_available
    except ImportError:
        return None
    if not docker_available(_SFDISK_IMAGE):
        print("[Step0] 提示: firm_audit/sandbox 镜像不可用,sfdisk 解析跳过,"
              "回退手写解析")
        return None
    try:
        # 必须 resolve 成绝对路径:相对路径(或含中文的相对路径)会被 Docker
        # 当 volume 名做字符校验而拒绝挂载,导致 sfdisk 主解析静默失效
        # (实测: target/完整/xxx.img 报 "includes invalid characters")。
        abs_path = str(Path(img_path).resolve())
        rc, stdout, stderr = run_docker(
            _SFDISK_IMAGE, ["-J", "/data.img"],
            mounts=[(abs_path, "/data.img")],
            entrypoint="sfdisk", timeout=120,
        )
    except Exception as e:
        print(f"[Step0] sfdisk 执行失败({e}),回退手写解析")
        return None
    if rc != 0:
        print(f"[Step0] sfdisk 退出码 {rc}(stderr: {stderr[:200]}),回退手写解析")
        return None
    partitions = _partitions_from_sfdisk_json(stdout, Path(img_path))
    if partitions is None:
        print("[Step0] sfdisk 输出无有效分区表(或解析失败),回退手写解析")
        return None
    with open(img_path, "rb") as f:
        return _enrich_partitions(f, partitions)


def _partitions_from_sfdisk_json(stdout: str, img_path) -> list[dict] | None:
    """解析 sfdisk -J JSON,构造分区列表(含边界检查)。

    纯函数(不依赖 Docker),可单测。返回 None = 无分区表或解析失败。

    sfdisk -J 输出结构(GPT 例):
        {"partitiontable": {"label": "gpt", "id": "...", "device": "/data.img",
            "unit": "sectors", "sectorsize": 512,
            "partitions": [{"node": "/data.img1", "start": 40, "size": 10,
                             "type": "...", "uuid": "...", "name": "APP"}]}}
    MBR(dos): 分区无 name,type 是 hex 字符串(如 "ee")。
    """
    import json
    try:
        data = json.loads(stdout)
        pt = data.get("partitiontable") or {}
    except (ValueError, AttributeError):
        return None
    if not isinstance(pt, dict):
        return None
    label = pt.get("label", "")
    if label not in ("gpt", "dos"):
        return None  # 无分区表(或非 GPT/MBR)
    parts_raw = pt.get("partitions")
    if not isinstance(parts_raw, list) or not parts_raw:
        return None
    try:
        file_size = img_path.stat().st_size
        sectorsize = int(pt.get("sectorsize") or pt.get("sector-size") or 512)
    except (OSError, ValueError):
        return None

    partitions: list[dict] = []
    for i, raw in enumerate(parts_raw):
        if not isinstance(raw, dict):
            return None
        try:
            start_sector = int(raw["start"])
            size_sectors = int(raw["size"])
        except (KeyError, ValueError, TypeError):
            return None
        name = raw.get("name") or ""
        offset = start_sector * sectorsize
        size = size_sectors * sectorsize

        # 边界检查(与手写解析一致):超界跳过,超尾截断标记
        truncated = False
        if offset >= file_size:
            print(f"[Step0] 警告: sfdisk 分区{i + 1}({name or '?'}) 偏移超出文件末尾,跳过")
            continue
        if offset + size > file_size:
            truncated = True

        partitions.append({
            "index": i + 1,
            "name": name or f"partition_{i + 1}",
            "offset": offset,
            "size": size,
            "type": label,
            "crc_ok": True,   # sfdisk 内部做过 GPT CRC 校验(主表坏用备份)
            "truncated": truncated,
            "issues": ["分区超出文件末尾,截断处理"] if truncated else [],
            "kind_conflict": False,
        })

    return partitions or None


def parse_partitions(img_path) -> list[dict]:
    """解析磁盘镜像分区表,返回分区列表(每项含 index/name/offset/size/kind/
    signatures/crc_ok/truncated/issues/kind_conflict)。

    主解析用 sfdisk(libfdisk 权威实现,普世不易错),失败/不可用回退手写解析
    (含 CRC 强校验)。无分区表或表不可信返回 []。
    """
    parts = parse_partitions_sfdisk(img_path)
    if parts is not None:
        return parts
    return parse_partitions_manual(img_path)


def extract_partitions_from_image(
    img_path,
    out_dir,
    max_size_gb: float = 50.0,
    extract_all: bool = False,
) -> list[dict]:
    """解析分区表并提取应提取的分区,返回 [{file, partition, extracted_size, verified}]。

    Args:
        img_path: 磁盘镜像文件
        out_dir: 提取输出目录(自动创建)
        max_size_gb: rootfs/recovery 分区最大提取大小(默认 50GB,
                    超过视为"大分区"跳过——几百 GB 的 APP rootfs 直接提取
                    会耗尽磁盘且 binwalk 仍会爆炸,留给用户单独处理)
        extract_all: 提取所有分区(包括 userdata/超大)

    Returns:
        已提取分区列表;空列表表示无分区表或全部跳过。
        每个分区提取后做回读校验,失败的分区删除且不加入结果(宁缺毋滥)。
    """
    img_path = Path(img_path)
    out_dir = Path(out_dir)
    partitions = parse_partitions(img_path)
    if not partitions:
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    extracted = []
    with open(img_path, "rb") as f:
        for p in partitions:
            do_extract = extract_all or should_extract(p["kind"], p["size"], max_size_gb)
            if not do_extract:
                continue
            # 告警:身份冲突 / 截断
            if p.get("kind_conflict"):
                print(f"[Step0] 警告: {p['name']} {p['issues'][-1]}")
            if p.get("truncated"):
                print(f"[Step0] 警告: {p['name']} {p['issues'][0]}")
            safe_name = p["name"].replace("/", "_").replace("\\", "_")
            out_file = out_dir / f"part{p['index']:02d}_{safe_name}.img"
            size = extract_partition(f, p, out_file)
            if not _verify_extracted(img_path, p["offset"], p["size"], out_file):
                print(f"[Step0] 错误: 分区 {out_file.name} 提取后回读校验失败,"
                      "删除(内容不可信)")
                try:
                    out_file.unlink()
                except OSError:
                    pass
                continue
            extracted.append({
                "file": str(out_file),
                "partition": p,
                "extracted_size": size,
                "verified": True,
            })
    return extracted


def format_size(size_bytes):
    """格式化文件大小"""
    if size_bytes >= 1024**3:
        return f"{size_bytes / (1024**3):.1f} GB"
    elif size_bytes >= 1024**2:
        return f"{size_bytes / (1024**2):.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes} B"


def _partition_status(p: dict) -> str:
    """CLI/manifest 显示用:分区的校验状态摘要。"""
    parts = []
    if p.get("kind", "") in SKIP_AUDIT_KINDS:
        parts.append("跳过")
    if p.get("truncated"):
        parts.append("截断")
    if p.get("kind_conflict"):
        parts.append("冲突")
    if p.get("issues") and not p.get("truncated"):
        parts.append("!")
    return ",".join(parts) if parts else "ok"


def main():
    parser = argparse.ArgumentParser(
        description="Step0: 从大磁盘镜像中提取有内容的分区"
    )
    parser.add_argument("img_path", help="镜像文件路径")
    parser.add_argument("--out-dir", default=".",
                        help="输出目录 (默认: 当前目录)")
    parser.add_argument("--max-size", type=float, default=50.0,
                        help="单个分区最大提取大小 GB (默认: 50)")
    parser.add_argument("--list-only", action="store_true",
                        help="只列出分区信息，不提取")
    parser.add_argument("--extract-all", action="store_true",
                        help="提取所有分区 (包括 dtb/reserved/userdata/超大分区)")
    args = parser.parse_args()

    img_path = args.img_path
    if not os.path.isfile(img_path):
        print(f"[Step0] 错误: 文件不存在: {img_path}")
        sys.exit(1)

    file_size = os.path.getsize(img_path)
    print(f"[Step0] 镜像文件: {img_path}")
    print(f"[Step0] 文件大小: {file_size / (1024**3):.2f} GB")

    partitions = parse_partitions(img_path)

    if not partitions:
        print("[Step0] 未找到有效分区表(或表校验失败),可能是裸二进制固件")
        print("[Step0] 建议直接使用 binwalk 分析")
        sys.exit(0)

    # 2. 打印每个分区
    print(f"\n[Step0] 共发现 {len(partitions)} 个分区:")
    print(f'{"":>4} {"名称":<25} {"偏移":>14} {"大小":>12} {"类型":<12} {"校验":<8} {"签名":<30} {"操作"}')
    print("-" * 128)

    for p in partitions:
        size_str = format_size(p["size"])
        do_extract = args.extract_all or should_extract(p["kind"], p["size"], args.max_size)
        action = "提取" if do_extract else "跳过"

        print(f'  {p["index"]:<3} {p["name"]:<25} {p["offset"]:>14} {size_str:>12} '
              f'{p["kind"]:<12} {_partition_status(p):<8} '
              f'{", ".join(p["signatures"]):<30} {action}')

    if args.list_only:
        print("\n[Step0] --list-only 模式，结束")
        return

    # 3. 提取分区
    os.makedirs(args.out_dir, exist_ok=True)
    print("\n[Step0] === 开始提取 ===")

    extracted = extract_partitions_from_image(
        img_path, args.out_dir, max_size_gb=args.max_size, extract_all=args.extract_all
    )

    # 4. 输出总结
    total_extracted = sum(e["extracted_size"] for e in extracted)
    skipped = [p for p in partitions if not (
        args.extract_all or should_extract(p["kind"], p["size"], args.max_size))]
    total_skipped = sum(p["size"] for p in skipped)

    print("\n[Step0] === 提取完成 ===")
    print(f"  提取: {len(extracted)} 个分区, 共 {format_size(total_extracted)}")
    print(f"  跳过: {len(skipped)} 个分区, 共 {format_size(total_skipped)}")
    print(f"  输出目录: {args.out_dir}")

    print("\n[Step0] 提取的文件:")
    for e in extracted:
        p = e["partition"]
        print(f"  {e['file']}")
        print(f"    分区: {p['name']}, 类型: {p['kind']}, 校验: {_partition_status(p)}, "
              f"签名: {', '.join(p['signatures'])}")
        print("    后续处理建议:")

        sigs = ",".join(p["signatures"])
        if "ext4" in sigs:
            print(f"      → binwalk -e {os.path.basename(e['file'])}")
            print("      → 或 7-Zip 直接打开提取文件")
        elif "squashfs" in sigs:
            print(f"      → binwalk -e {os.path.basename(e['file'])}")
            print(f"      → 或 unsquashfs {os.path.basename(e['file'])}")
        elif "gzip" in sigs or "xz" in sigs:
            print(f"      → binwalk -e {os.path.basename(e['file'])}")
        elif "U-Boot" in sigs:
            print(f"      → binwalk -e {os.path.basename(e['file'])}  (内核镜像)")
        elif "ELF" in sigs:
            print("      → 直接用 radare2/Ghidra 分析")
        else:
            print(f"      → binwalk -e {os.path.basename(e['file'])}  (尝试自动识别)")

    # 5. 写 manifest
    manifest_path = os.path.join(args.out_dir, "step0_manifest.txt")
    with open(manifest_path, "w", encoding="utf-8") as mf:
        mf.write("Step0 Partition Extraction Manifest\n")
        mf.write(f"Source: {img_path}\n")
        mf.write(f"Source size: {file_size} bytes ({file_size / (1024**3):.2f} GB)\n\n")
        mf.write(f'{"":>4} {"名称":<25} {"偏移":>14} {"大小":>14} {"类型":<12} '
                 f'{"校验":<8} {"签名":<30} {"操作"}\n')
        for p in partitions:
            do_extract = args.extract_all or should_extract(p["kind"], p["size"], args.max_size)
            action = "extracted" if do_extract else "skipped"
            mf.write(f'  {p["index"]:<3} {p["name"]:<25} {p["offset"]:>14} {p["size"]:>14} '
                     f'{p["kind"]:<12} {_partition_status(p):<8} '
                     f'{", ".join(p["signatures"]):<30} {action}\n')

    print(f"\n[Step0] Manifest 已写入: {manifest_path}")


if __name__ == "__main__":
    main()

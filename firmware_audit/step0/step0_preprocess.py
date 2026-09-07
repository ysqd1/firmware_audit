"""Step0 - 预解压(宿主 Python,不依赖 Docker)。

在 binwalk 之前用宿主标准库解压固件外层常见压缩,避开 binwalk 解压层
偶发 bug(实测同一固件两次解包结果不同),提升确定性与可复现性。

分流:
  - 归档类(.zip/.tar/.tar.gz/.tar.bz2/.tar.xz/.tgz)→ 解出完整文件系统,
    skip_binwalk=True(main.py 对解压树跑引导解包器 scan_tree 继续解嵌套容器)
  - 单文件压缩(.gz/.bz2/.xz)→ 解出单个文件(可能仍是固件容器),
    skip_binwalk=False(交 Step1 引导解包器单文件模式)
  - 磁盘镜像(含 GPT/MBR 分区表,如 .img)→ 分区提取,每个分区独立
    交 Step1 引导解包器。为什么必须分区: 几百 GB 的整盘镜像直接进 binwalk
    会爆炸(扫描整盘 + 递归解包 OOM/超时),先按分区表切成小文件。
  - 其他(.bin 等)→ 原样返回,skip_binwalk=False
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

from .step0_split_img import (
    is_disk_image,
    parse_partitions,
    should_extract,
    extract_partition,
    _verify_extracted,
    SKIP_AUDIT_KINDS,
)
import contextlib

# 归档类:解出文件系统,跳过 binwalk
_ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")
# 单文件压缩:解出单文件,仍交引导解包器
_SINGLE_COMPRESS_EXTS = (".gz", ".bz2", ".xz")

# rootfs/recovery 分区提取上限:超过视为"超大分区"跳过(几百 GB 的 APP
# rootfs 提取会耗尽磁盘且 binwalk 仍会爆炸)。需要时可调大或单独处理。
_PARTITION_MAX_SIZE_GB = 50.0


def _safe_extract_zip(src: Path, dest: Path) -> None:
    """安全解压 zip:拒绝 zip-slip(../ 越界)与符号链接,且不覆盖已有文件。"""
    with zipfile.ZipFile(src) as z:
        for info in z.infolist():
            name = info.filename
            if name.startswith("/") or ".." in name.split("/"):
                print(f"[Step0] 安全拦截: 跳过 zip 越界项 {name!r}")
                continue
            target = dest / name
            if not target.resolve().is_relative_to(dest.resolve()):
                print(f"[Step0] 安全拦截: 跳过 zip 越界项 {name!r}")
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            # external_attr 高 16 位存 Unix mode;create_system==3 只说明
            # "zip 由 Unix 系统创建",不等于符号链接(误判会拒掉整个 zip)
            if stat.S_ISLNK(info.external_attr >> 16):
                print(f"[Step0] 安全拦截: 跳过 zip 符号链接 {name!r}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src_f, open(target, "wb") as dst_f:
                shutil.copyfileobj(src_f, dst_f)


def _safe_extract_tar(src: Path, dest: Path) -> None:
    """安全解压 tar:拒绝 tar-slip(../)与绝对路径,拒绝符号链接,不覆盖已有文件。"""
    with tarfile.open(src) as t:
        for member in t.getmembers():
            name = member.name
            if name.startswith("/") or ".." in name.split("/"):
                print(f"[Step0] 安全拦截: 跳过 tar 越界项 {name!r}")
                continue
            target = dest / name
            if not target.resolve().is_relative_to(dest.resolve()):
                print(f"[Step0] 安全拦截: 跳过 tar 越界项 {name!r}")
                continue
            if member.issym() or member.islnk():
                print(f"[Step0] 安全拦截: 跳过 tar 符号链接 {name!r}")
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with t.extractfile(member) as src_f, open(target, "wb") as dst_f:
                if src_f is not None:
                    shutil.copyfileobj(src_f, dst_f)


def _decompress_archive(src: Path, dest: Path) -> Path:
    """解归档到 dest,返回解压根目录(== dest)。安全提取,拒绝 zip-slip/tar-slip。"""
    dest.mkdir(parents=True, exist_ok=True)
    if src.suffix.lower() == ".zip":
        _safe_extract_zip(src, dest)
    else:
        _safe_extract_tar(src, dest)
    return dest


def _decompress_single(src: Path, dest_dir: Path) -> Path:
    """解单文件压缩,输出到 dest_dir/<basename去压缩后缀>。

    .gz/.bz2/.xz 解出的单文件内容可能仍含固件容器(squashfs 等)或磁盘镜像
    (如 g1-nx-j6.1.img.bz2 解出 256GB .img),故返回该文件交分区/继续解。
    注意: dest_dir 传 extracted_dir.parent(process/ 根)——单文件压缩解出的
    是"中间固件文件",与分区文件同级;归档解出的文件系统才进 process/extracted/。
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = src.name
    for ext in _SINGLE_COMPRESS_EXTS:
        if name.lower().endswith(ext):
            name = name[: -len(ext)]
            break
    out = dest_dir / name

    if src.suffix.lower() == ".gz":
        opener = gzip.open
    elif src.suffix.lower() == ".bz2":
        opener = bz2.open
    else:
        opener = lzma.open
    with opener(src, "rb") as fin, open(out, "wb") as fout:
        shutil.copyfileobj(fin, fout)
    return out


def _find_existing_part(out_dir: Path, name: str, size: int) -> Path | None:
    """在 process/ 根及分区子工作区 process/<stem>/ 中找已提取的同名同大小分区。"""
    stem = Path(name).stem
    for cand in (out_dir / stem / name, out_dir / name):
        try:
            if cand.is_file() and cand.stat().st_size == size:
                return cand
        except OSError:
            continue
    return None


def _cleanup_skipped_part(out_dir: Path, index: int, name: str) -> None:
    """删除被筛类型分区(dtb/reserved)的旧产物,保持目录与筛选规则一致。

    旧产物位置与提取命名一致(见 _extract_partitions): process/ 根分区
    文件(out_dir/part<NN>_<name>.img)与分区子工作区(out_dir/part<NN>_<name>/,
    含 extracted/analysis/fileinfo.json,整体删除)。
    用户确认自动清理: 不删会让残留目录误导"已处理过"。删除仅限流水线
    产物路径,不碰固件与分区源文件。
    """
    safe_name = name.replace("/", "_").replace("\\", "_")
    part_name = f"part{index:02d}_{safe_name}.img"
    for cand in (out_dir / Path(part_name).stem, out_dir / part_name):
        if not cand.exists():
            continue
        try:
            if cand.is_dir():
                shutil.rmtree(cand)
            else:
                cand.unlink()
            print(f"[Step0] 清理被筛分区旧产物: {cand}")
        except OSError as e:
            print(f"[Step0] 清理失败({cand.name}): {e}")


def _extract_partitions(img: Path, target_dir: Path) -> list[Path]:
    """磁盘镜像分区提取,返回提取出的分区文件列表(可能为空)。

    target_dir 是 process/(extracted_dir.parent);分区文件直接落 process/ 根,
    main.py 随即把每个分区 move 进 process/<分区名>/ 子工作区。

    准确性命门: 每个分区提取后做回读校验(源头 4KB vs 提取文件头),不一致
    的分区宁可不产出(删除)也不输出坏数据——分区错,下游全废。
    复用同样过回读校验:大小一致但内容损坏的旧文件会被重提。
    """
    out_dir = target_dir
    try:
        partitions = parse_partitions(img)
    except Exception as e:
        print(f"[Step0] 分区表解析失败({img.name}): {e},回退直接交 binwalk")
        return []
    if not partitions:
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    files: list[Path] = []
    try:
        with open(img, "rb") as f:
            for p in partitions:
                if not should_extract(p["kind"], p["size"], _PARTITION_MAX_SIZE_GB):
                    # 类型被筛(dtb/reserved):顺带清理旧产物,避免残留误导
                    if p["kind"] in SKIP_AUDIT_KINDS:
                        _cleanup_skipped_part(out_dir, p["index"], p["name"])
                    continue
                # 告警:身份冲突 / 截断(有问题也要让用户看到,但不中断流程)
                if p.get("kind_conflict"):
                    print(f"[Step0] 警告: {p['name']} {p['issues'][-1]}")
                if p.get("truncated"):
                    print(f"[Step0] 警告: {p['name']} {p['issues'][0]}")
                safe_name = p["name"].replace("/", "_").replace("\\", "_")
                part_file = out_dir / f"part{p['index']:02d}_{safe_name}.img"
                # 复用:main.py 会把分区 move 进子工作区 process/<stem>/,
                # 两处都查,避免已处理的分区被重复提取(几百 GB 镜像重复 IO 很痛)。
                # 复用得过回读校验:大小一致但内容损坏的旧文件必须重新提取。
                existing = _find_existing_part(out_dir, part_file.name, p["size"])
                if existing is not None:
                    if _verify_extracted(img, p["offset"], p["size"], existing):
                        print(f"[Step0] 复用已提取分区: {existing.name}")
                        files.append(existing)
                        continue
                    print(f"[Step0] 已存在分区 {existing.name} 回读校验失败,重新提取")
                    with contextlib.suppress(OSError):
                        existing.unlink()
                extract_partition(f, p, part_file)
                if not _verify_extracted(img, p["offset"], p["size"], part_file):
                    print(f"[Step0] 错误: 分区 {part_file.name} 提取后回读校验失败,"
                          "删除(内容不可信)")
                    with contextlib.suppress(OSError):
                        part_file.unlink()
                    continue
                files.append(part_file)
    except Exception as e:
        print(f"[Step0] 分区提取失败({img.name}): {e},回退直接交 binwalk")
        return []

    if not files:
        print(f"[Step0] {img.name} 有分区表但无分区被提取(均为超大分区/空表),"
              "回退直接交 binwalk")
        return []
    print(f"[Step0] 磁盘镜像 {img.name} 已提取 {len(files)} 个分区到 {out_dir}:")
    for fp in files:
        print(f"  - {fp.name} ({fp.stat().st_size / 1024 / 1024:.1f} MB)")
    return files


def preprocess(firmware_path: Path, extracted_dir: Path) -> tuple[list[Path], bool]:
    """预解压固件,返回 (binwalk 输入文件列表, 是否跳过 binwalk)。

    Args:
        firmware_path: _find_firmware 识别出的固件文件
        extracted_dir: Step1 输出目录(process/extracted)
                      (单文件压缩的中间产物与分区文件落在 extracted_dir.parent,
                      即 process/ 根)

    Returns:
        (inputs, skip_binwalk):
            skip_binwalk=True  → inputs[0] 已是解压出的文件系统,直接进 Step2
            skip_binwalk=False → inputs 是需 binwalk 继续解的文件列表
                                 (单个固件 = [文件];磁盘镜像 = 各分区文件)

    解压失败(损坏/权限)不崩:打印错误并返回 ([firmware_path], False) 兜底,
    让 binwalk 尝试,保持"失败不崩"原则。
    """
    firmware_path = Path(firmware_path)
    extracted_dir = Path(extracted_dir)
    name = firmware_path.name.lower()

    try:
        if name.endswith(_ARCHIVE_EXTS):
            root = _decompress_archive(firmware_path, extracted_dir)
            print(f"[Step0] 归档 {firmware_path.name} 已解压到 {extracted_dir},跳过 binwalk")
            return [root], True
        if name.endswith(_SINGLE_COMPRESS_EXTS):
            # 解压出的中间文件放 process/ 根(extracted_dir.parent),与分区文件同级
            out = _decompress_single(firmware_path, extracted_dir.parent)
            print(f"[Step0] 单文件压缩 {firmware_path.name} 已解压为 {out.name}")
            # 解压出的单文件可能是磁盘镜像(如 256GB .img),继续走分区检查
            if is_disk_image(out):
                parts = _extract_partitions(out, extracted_dir.parent)
                if parts:
                    return parts, False
            return [out], False
    except Exception as e:
        print(f"[Step0] 解压失败({firmware_path.name}): {e},回退交 binwalk")
        return [firmware_path], False

    # 非常见压缩:先查磁盘镜像(几百 GB .img 直接 binwalk 会爆炸),
    # 有分区表 → 分区提取;无分区表 → 原样交 binwalk(裸固件)。
    if is_disk_image(firmware_path):
        parts = _extract_partitions(firmware_path, extracted_dir.parent)
        if parts:
            return parts, False
    print(f"[Step0] {firmware_path.name} 非磁盘镜像,直接交 binwalk")
    return [firmware_path], False

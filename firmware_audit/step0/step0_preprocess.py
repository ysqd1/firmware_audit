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
    例外: 命中 ext4 超级块魔数(0xEF53)的分区走直读(step0_ext4_read,
    debugfs/mount 双后端),不经 dd+binwalk 直接产出文件树 + Step1 完成标记
    ——不看大小(超大 rootfs 靠它救活);返回条目里这类分区是子工作区
    目录(非 .img 文件),main.py 按目录识别直接递归。
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
    format_size,
    is_disk_image,
    parse_partitions,
    should_extract,
    extract_partition,
    _verify_extracted,
    _find_existing_part,
    GATED_KINDS,
    SKIP_AUDIT_KINDS,
)
from .step0_ext4_read import STEP1_DONE_MARKER, direct_read_ext4, is_ext4_partition
from ..gates import resolve_partition_max_size_gb
import contextlib

# 归档类:解出文件系统,跳过 binwalk
_ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz")
# 单文件压缩:解出单文件,仍交引导解包器
_SINGLE_COMPRESS_EXTS = (".gz", ".bz2", ".xz")


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


def partition_skip_message(p: dict, max_size_gb: float) -> str:
    """非 ext4 分区被闸门/策略跳过时的日志行(票 02:主 rootfs 曾无声消失)。

    大小闸门只管辖 GATED_KINDS(rootfs/recovery;bootloader/kernel/esp/
    small/medium 恒提取,userdata/无特征大分区按策略跳过)——受闸门管辖而
    超限的分区打醒目告警并附 env 指引;其余策略性跳过打普通提示行。凡是
    走到闸门判定的分区,跳过必留日志。dtb/reserved 类型筛在调用方更早分支
    (带旧产物清理打印),不经本消息。ext4 分区在调用方先于闸门判魔数直读,
    天然不触发本消息。
    """
    if p["kind"] in GATED_KINDS:
        return (f"[Step0] 告警: 分区 {p['name']}({format_size(p['size'])},"
                f"{p['kind']})超过提取上限 {max_size_gb:g} GB,跳过——"
                "该分区内容将不进流水线;如需调整: env STEP0_PARTITION_MAX_SIZE_GB"
                "(ext4 分区不受此限,魔数命中即自动直读)")
    return (f"[Step0] 跳过分区 {p['name']}({format_size(p['size'])},{p['kind']}):"
            "按类型策略不提取(如需审计可用 python -m firmware_audit.step0."
            "step0_split_img --extract-all 单独提取)")


def _extract_partitions(img: Path, target_dir: Path) -> list[Path] | None:
    """磁盘镜像分区提取,返回分区条目列表(可能为空或 None)。

    target_dir 是 process/(extracted_dir.parent);分区文件直接落 process/ 根,
    main.py 随即把每个分区 move 进 process/<分区名>/ 子工作区。

    返回值三态:
      - 非空 list:.img 文件(非 ext4 分区,交 Step1 引导解包器)与/或子工作区
        目录(ext4 直读产物,extracted/ + .step1_done 已就位);main.py 按
        目录/文件分流递归。
      - []:无分区表(或表不可信),调用方回退直接交 binwalk(旧行为)。
      - None:有分区表但所有分区均未产出且含 ext4 直读失败——调用方必须
        终止而非回退:把几百 GB 整盘镜像交 binwalk 正是分区提取要防的爆炸。

    准确性命门: 每个分区提取后做回读校验(源头 4KB vs 提取文件头),不一致
    的分区宁可不产出(删除)也不输出坏数据——分区错,下游全废。
    复用同样过回读校验:大小一致但内容损坏的旧文件会被重提。

    ext4 直读失败(缺 debugfs/mount 无免密 sudo/文件系统损坏)不崩:响亮
    告警后跳过该分区,批次里其余分区照常处理(逐分区 try 隔离异常)。
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
    # 每镜像解析一次闸门(env STEP0_PARTITION_MAX_SIZE_GB,默认 50;只管辖
    # 非 ext4 的 dd 老路径——ext4 直读不看大小)
    max_size_gb = resolve_partition_max_size_gb()
    entries: list[Path] = []
    direct_read_failed = False
    try:
        with open(img, "rb") as f:
            for p in partitions:
                # 类型筛选(dtb/reserved 纯噪声)对 ext4 直读同样生效
                if p["kind"] in SKIP_AUDIT_KINDS:
                    # 类型被筛(dtb/reserved):顺带清理旧产物,避免残留误导
                    _cleanup_skipped_part(out_dir, p["index"], p["name"])
                    continue
                # ext4 魔数命中 → 直读,不看大小(spec 决策:大小闸门只管非 ext4
                # 的 dd 老路径;超大 rootfs 正是直读要救的对象)
                ext4 = is_ext4_partition(f, p)
                if not ext4 and not should_extract(p["kind"], p["size"], max_size_gb):
                    # 票 02:被跳过的分区必须留下含名/大小/上限的告警,不允许
                    # 主 rootfs 无声消失(target/3 事故)
                    print(partition_skip_message(p, max_size_gb))
                    continue
                # 告警:身份冲突 / 截断(有问题也要让用户看到,但不中断流程)
                if p.get("kind_conflict"):
                    print(f"[Step0] 警告: {p['name']} {p['issues'][-1]}")
                if p.get("truncated"):
                    print(f"[Step0] 警告: {p['name']} {p['issues'][0]}")
                safe_name = p["name"].replace("/", "_").replace("\\", "_")
                stem = f"part{p['index']:02d}_{safe_name}"

                if ext4:
                    ws = out_dir / stem
                    marker = ws / "extracted" / STEP1_DONE_MARKER
                    if marker.is_file():
                        print(f"[Step0] ext4 分区 {p['name']} 直读产物已存在,断点复用: {ws.name}")
                        entries.append(ws)
                        continue
                    print(f"[Step0] ext4 分区 {p['name']}({p['size'] / 1024 ** 3:.1f} GB)"
                          "命中 0xEF53 魔数,直读文件树(不经 dd+binwalk)")
                    # 逐分区 try:直读内部非 OSError 异常也不许炸掉整批分区
                    try:
                        ok, reason = direct_read_ext4(img, p, ws, f)
                    except Exception as e:
                        ok, reason = False, f"直读异常:{e}"
                    if ok:
                        entries.append(ws)
                    else:
                        direct_read_failed = True
                        print(f"[Step0] 告警: 分区 {p['name']} 直读失败:{reason};"
                              "跳过该分区,批次继续(其余分区不受影响)")
                    continue

                part_file = out_dir / f"{stem}.img"
                # 复用:main.py 会把分区 move 进子工作区 process/<stem>/,
                # 两处都查,避免已处理的分区被重复提取(几百 GB 镜像重复 IO 很痛)。
                # 复用得过回读校验:大小一致但内容损坏的旧文件必须重新提取。
                existing = _find_existing_part(out_dir, part_file.name, p["size"])
                if existing is not None:
                    if _verify_extracted(img, p["offset"], p["size"], existing):
                        print(f"[Step0] 复用已提取分区: {existing.name}")
                        entries.append(existing)
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
                entries.append(part_file)
    except Exception as e:
        print(f"[Step0] 分区提取失败({img.name}): {e},回退直接交 binwalk")
        return []

    if not entries:
        if direct_read_failed:
            print(f"[Step0] 错误: {img.name} 所有分区均未产出(含 ext4 直读失败),"
                  "不回退整盘 binwalk(会爆炸),交由调用方终止")
            return None
        print(f"[Step0] {img.name} 有分区表但无分区被提取(均为超大分区/空表),"
              "回退直接交 binwalk")
        return []
    print(f"[Step0] 磁盘镜像 {img.name} 已处理 {len(entries)} 个分区到 {out_dir}:")
    for fp in entries:
        if fp.is_dir():
            print(f"  - {fp.name}/ (ext4 直读树,含 .step1_done)")
        else:
            print(f"  - {fp.name} ({fp.stat().st_size / 1024 / 1024:.1f} MB)")
    return entries


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
                if parts is None:
                    return [], False
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
        if parts is None:
            # 有分区表但所有分区均未产出(含 ext4 直读失败):整盘交 binwalk
            # 会爆炸,返回空输入交调用方响亮终止
            return [], False
    print(f"[Step0] {firmware_path.name} 非磁盘镜像,直接交 binwalk")
    return [firmware_path], False

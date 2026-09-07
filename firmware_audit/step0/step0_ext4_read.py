"""Step0 ext4 分区直读(双后端:debugfs 默认 / mount 快路)。

对磁盘镜像中命中 ext4 超级块魔数(0xEF53,复用 step1/file_magic 既有检测)的
分区,不交 dd+binwalk,直接读出文件树落到该分区子工作区的 ``extracted/`` 并写
Step1 完成标记(``.step1_done``)——与现有分区递归落点同构,下游 Step2-5 零改动。
取代 2026-09-06 的手工旁路(loop-mount + tar + tarfile + 手写标记 + 外部驱动)。

触发判定只看魔数、不看分区大小(spec 决策:大小写统一,无双重标准参数);
dtb/reserved 纯噪声分区的类型筛选仍然生效(在调用方 step0_preprocess 里)。

双后端(env ``STEP0_EXT4_BACKEND``,缺省/非法值回落 debugfs):
    debugfs - 宿主原生 e2fsprogs,用户态读 ext4,零特权、不可信镜像不进内核、
              无 Docker 依赖。需先提取分区文件作为 debugfs 输入,直读成功后删除。
    mount   - 快路:``sudo -n mount -o ro,noload,loop,offset=N`` 挂载后 tar 管道
              拷贝,不产生分区中间文件。需免密 sudo;无免密时 sudo -n 立即失败,
              响亮报错(不挂死不静默)。

两后端共同语义:
    - lost+found 固化排除(文件系统修复垃圾,无审计价值);
    - 符号链接原样保留(usrmerge:/bin→usr/bin、悬空链接均不丢——当年 tarfile
      filter="data" 旁路丢链接的教训);
    - 落 links.jsonl 清单(rel→target,每行一个 JSON 对象,悬空链接也在列);
    - 直读成功以 ``extracted/.step1_done`` 为断点标记:已存在则整分区跳过;
    - 失败不崩:返回 (False, 原因),调用方响亮告警并跳过该分区、批次继续。

约束:debugfs -R 的命令串按空白分词,目标路径不能含空格(运行时有响亮守卫;
含空格请用 mount 后端)。安全边界:与 mount/binwalk 老路径一致,镜像内容被视为
操作者自有的待审数据(实机镜像已同时交给内核挂载/Docker 解包);ext4 目录项
穿越名经实测被 e2fsprogs 净化(write 阶段即剥掉 ../ 前缀,rdump 不外逃)。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..step1.file_magic import sniff_magic
from .step0_split_img import (
    _find_existing_part,
    _verify_extracted,
    extract_partition,
)

# Step1 完成标记:与 main.py 的 _STEP1_DONE_MARKER 同名同语义(直读即视同 Step1 完成)
STEP1_DONE_MARKER = ".step1_done"
# 直读产物里的符号链接清单(分区子工作区根,与 extracted/ 同级,不进审计树)
LINKS_MANIFEST = "links.jsonl"
# ext4 超级块魔数偏移(分区头 0x438 处 0xEF53 小端);读 0x440 字节足够 sniff
_EXT4_SB_READ = 0x440


def is_ext4_partition(f, partition: dict) -> bool:
    """分区数据头命中 ext4 超级块魔数(0xEF53)→ True(纯读判,不提取)。

    复用 file_magic.sniff_magic 的 0x438 偏移检测(spec:复用既有检测);
    ext2/ext3/ext4 共用该魔数,debugfs 对三者都能读,统一按 ext 家族处理。
    """
    try:
        f.seek(partition["offset"])
        head = f.read(_EXT4_SB_READ)
    except OSError:
        return False
    return "ext4" in sniff_magic(head)


def resolve_backend() -> str:
    """解析 STEP0_EXT4_BACKEND:debugfs(默认)/ mount;非法值响警回落默认。"""
    raw = (os.environ.get("STEP0_EXT4_BACKEND") or "").strip().lower()
    if not raw:
        return "debugfs"
    if raw in ("debugfs", "mount"):
        return raw
    print(f"[Step0] 警告: STEP0_EXT4_BACKEND={raw!r} 非法(可选 debugfs/mount),"
          "回落默认 debugfs")
    return "debugfs"


def _run(cmd: list[str]) -> tuple[int, str, str]:
    """subprocess 薄封装(测试 seam:monkeypatch 本函数断言命令拼装)。"""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except OSError as e:
        return 127, "", str(e)


def _run_pipe(cmd_src: list[str], cmd_dst: list[str]) -> tuple[int, str]:
    """跑一条管道 cmd_src | cmd_dst(测试 seam)。src 失败不启动 dst。"""
    try:
        p_src = subprocess.Popen(cmd_src, stdout=subprocess.PIPE)
        p_dst = subprocess.run(cmd_dst, stdin=p_src.stdout, capture_output=True)
        p_src.stdout.close()
        p_src.wait()
        if p_src.returncode != 0:
            return p_src.returncode, ""
        return p_dst.returncode, (p_dst.stderr or b"").decode("utf-8", "replace")
    except OSError as e:
        return 127, str(e)


def direct_read_ext4(
    img: Path, partition: dict, ws_dir: Path, f=None
) -> tuple[bool, str]:
    """直读一个 ext4 分区到 ws_dir/extracted/ 并写 Step1 标记。

    Args:
        img: 磁盘镜像路径(mount 后端直接用它 + offset;debugfs 后端提取分区)
        partition: parse_partitions 产出的分区 dict(offset/size/index/name)
        ws_dir: 分区子工作区目录(process/partNN_<name>/)
        f: 已打开镜像的二进制句柄(debugfs 后端提取分区用;None 则自行打开)

    Returns:
        (ok, reason):ok=False 时 reason 是给人看的失败原因(调用方响亮打印)。
    """
    backend = resolve_backend()
    extracted = ws_dir / "extracted"
    # 残树清理:上次直读中断留下的部分树必须清掉重读,防新旧混装
    if extracted.exists():
        shutil.rmtree(extracted, ignore_errors=True)
    ws_dir.mkdir(parents=True, exist_ok=True)
    # 预建 extracted/:mount 后端 tar -C 需要目标已存在(debugfs rdump 会自建)
    extracted.mkdir(parents=True, exist_ok=True)

    if backend == "mount":
        return _read_via_mount(img, partition, ws_dir, extracted)
    return _read_via_debugfs(img, partition, ws_dir, extracted, f)


# --- debugfs 后端(默认:用户态、零特权、无 Docker) ---

def _read_via_debugfs(
    img: Path, partition: dict, ws_dir: Path, extracted: Path, f=None
) -> tuple[bool, str]:
    debugfs = shutil.which("debugfs")
    if not debugfs:
        return False, ("本机无 debugfs(e2fsprogs)。请安装(e.g. apt install e2fsprogs),"
                       "或改用 STEP0_EXT4_BACKEND=mount(需免密 sudo)")
    if f is None:
        with open(img, "rb") as fh:
            return _read_via_debugfs(img, partition, ws_dir, extracted, fh)

    out_dir = ws_dir.parent
    safe_name = str(partition["name"]).replace("/", "_").replace("\\", "_")
    part_file = out_dir / f"part{partition['index']:02d}_{safe_name}.img"

    # 分区中间文件:debugfs 需要独立分区文件(不支持镜像内偏移)。复用已提取的
    # (上次直读中断的场景),否则提取 + 回读校验——与 dd 老路径同一套防线。
    existing = _find_existing_part(out_dir, part_file.name, partition["size"])
    if existing is not None:
        if _verify_extracted(img, partition["offset"], partition["size"], existing):
            print(f"[Step0] 复用已提取分区: {existing.name}")
            part_file = existing
        else:
            print(f"[Step0] 已存在分区 {existing.name} 回读校验失败,重新提取")
            existing.unlink(missing_ok=True)
    if not part_file.exists():
        extract_partition(f, partition, part_file)
        if not _verify_extracted(img, partition["offset"], partition["size"], part_file):
            part_file.unlink(missing_ok=True)
            return False, "分区提取后回读校验失败(内容不可信),已删除中间文件"

    extracted.parent.mkdir(parents=True, exist_ok=True)
    # debugfs -R 命令串按空白分词,路径含空格会静默解错位置——响亮拒绝
    for pth in (extracted, part_file):
        if any(ch.isspace() for ch in str(pth)):
            return False, (f"路径含空白字符,debugfs 后端不支持:{pth}。"
                           "请改用 STEP0_EXT4_BACKEND=mount 或移动到无空格路径")
    cmd = [debugfs, "-R", f"rdump / {extracted.resolve()}", str(part_file.resolve())]
    rc, stdout, stderr = _run(cmd)
    if rc != 0:
        return False, (f"debugfs rdump 失败(rc={rc}):{stderr.strip()[:200] or stdout.strip()[:200]}")

    ok, reason = _finalize_tree(ws_dir, extracted)
    if ok:
        # 树已独立落盘,255GB 级中间文件不再有价值,删除省盘
        part_file.unlink(missing_ok=True)
        print(f"[Step0] 直读完成,已删除分区中间文件 {part_file.name}")
    return ok, reason


# --- mount 后端(快路:需免密 sudo,不产生分区中间文件) ---

def _read_via_mount(img: Path, partition: dict, ws_dir: Path, extracted: Path) -> tuple[bool, str]:
    img_abs = str(Path(img).resolve())
    mnt = tempfile.mkdtemp(prefix=".ext4_mnt_", dir=ws_dir)
    mounted = False
    try:
        cmd_mount = [
            "sudo", "-n", "mount",
            "-o", f"ro,noload,loop,offset={partition['offset']}",
            img_abs, mnt,
        ]
        rc, stdout, err = _run(cmd_mount)
        if rc != 0:
            return False, _mount_fail_reason("mount", rc, err)
        mounted = True

        # tar 管道拷贝:src 侧 sudo(镜像内 root 属主文件非 sudo 读不了),
        # dst 侧当前用户(非 root tar 自动把属主落成解包者,下游可读);
        # GNU tar 原样保留符号链接(含 usrmerge 绝对/相对链接,不丢)。
        cmd_src = ["sudo", "-n", "tar", "-C", mnt,
                   "--exclude=./lost+found", "-cf", "-", "."]
        cmd_dst = ["tar", "-C", str(extracted), "-xf", "-"]
        rc, err = _run_pipe(cmd_src, cmd_dst)
        if rc != 0:
            return False, f"tar 拷贝失败(rc={rc}):{err.strip()[:200]}"
        return _finalize_tree(ws_dir, extracted)
    finally:
        if mounted:
            _run(["sudo", "-n", "umount", mnt])
        shutil.rmtree(mnt, ignore_errors=True)


def _mount_fail_reason(stage: str, rc: int, stderr: str) -> str:
    detail = (stderr or "").strip().splitlines()
    detail = detail[-1] if detail else f"退出码 {rc}"
    if "password" in detail.lower() or "sudo" in detail.lower():
        return (f"mount 快路需要免密 sudo,但失败:{detail}。"
                "请配置免密(如 sudo visudo)或改用默认 debugfs 后端")
    return f"mount {stage} 失败(rc={rc}):{detail}"


# --- 两后端共同收尾:lost+found 排除 / links.jsonl / Step1 标记 ---

def _finalize_tree(ws_dir: Path, extracted: Path) -> tuple[bool, str]:
    """校验树非空,排除 lost+found,落 links.jsonl 清单,写 Step1 完成标记。"""
    if not extracted.is_dir() or not any(extracted.iterdir()):
        return False, "直读后 extracted/ 为空(文件系统损坏或空分区)"

    lost_found = extracted / "lost+found"
    if lost_found.exists():
        shutil.rmtree(lost_found, ignore_errors=True)

    links = []
    for path in extracted.rglob("*"):
        # pathlib 递归不跟随目录符号链接:usrmerge(/bin→usr/bin)不会成环,
        # 悬空链接 is_symlink() 仍为 True,照常入清单
        if path.is_symlink():
            links.append({
                "rel": path.relative_to(extracted).as_posix(),
                "target": os.readlink(path),
            })
    links_path = ws_dir / LINKS_MANIFEST
    with open(links_path, "w", encoding="utf-8") as mf:
        for item in links:
            mf.write(json.dumps(item, ensure_ascii=False) + "\n")

    (extracted / STEP1_DONE_MARKER).write_text("ok", encoding="utf-8")
    print(f"[Step0] ext4 直读完成: {extracted}({len(links)} 条符号链接清单 → {LINKS_MANIFEST})")
    return True, ""

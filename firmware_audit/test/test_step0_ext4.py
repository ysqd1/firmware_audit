"""Step0 ext4 分区直读测试(工单 01:debugfs 默认 / mount 快路)。

验收对照(.scratch/step0-fs-extract/issues/01-ext4-direct-read.md):
  - 合成 GPT+ext4 镜像(零特权 fixture:mke2fs -d 填充 + 纯 Python GPT 布局)
    喂入 preprocess():ext4 分区直读出文件树 + 完成标记,非 ext4 分区不触发直读
  - 默认后端 debugfs 真跑(合成镜像小,秒级);mount 后端与缺省的命令拼装有假
    subprocess 断言;mount 无免密 sudo 报错明确;本机无 debugfs 报错并跳过该分区、
    批次继续
  - lost+found 不出现在产物树;符号链接(含 usrmerge/悬空)在产物树中保留;
    links.jsonl 清单生成且可解析
  - 直读产物落点与现有分区递归同构:run_pipeline 对单 ext4 分区合成镜像端到端
    跑通 Step2-3(--no-step5)

fixture 依赖宿主 mke2fs/debugfs(e2fsprogs);缺失时 fixture 级测试 SKIP,
纯函数测试(魔数触发/env 解析)不受影响。

用法:
    python -m firmware_audit.test.test_step0_ext4
"""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..step0 import step0_ext4_read
from ..step0.step0_ext4_read import direct_read_ext4, is_ext4_partition, resolve_backend
from ..step0 import step0_preprocess
from .test_step0_split import SECTOR, make_gpt_image

try:
    import pytest
except ImportError:  # 独立模式(python -m)无 pytest
    pytest = None

_TOOLS_MISSING = [t for t in ("mke2fs", "debugfs") if shutil.which(t) is None]


def _skip_if_no_tools() -> bool:
    """fixture 级测试的工具门控:pytest 下 SKIP,独立模式下静默放行(算过)。"""
    if not _TOOLS_MISSING:
        return False
    if pytest is not None:
        pytest.skip(f"宿主缺 {'/'.join(_TOOLS_MISSING)}(e2fsprogs),ext4 fixture 测试跳过")
    print(f"[SKIP] 宿主缺 {'/'.join(_TOOLS_MISSING)},ext4 fixture 测试跳过")
    return True


# --- fixture 构造(零特权:os.symlink + mke2fs -d + 纯 Python GPT 布局) ---

def _make_ext4_content(srcdir: Path) -> None:
    """直读行为定义的内容树:常规文件 + usrmerge 符号链接 + 悬空链接。"""
    (srcdir / "etc").mkdir(parents=True)
    (srcdir / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/bash\n",
                                           encoding="utf-8")
    (srcdir / "home" / "unitree").mkdir(parents=True)
    (srcdir / "home" / "unitree" / "app.sh").write_text("#!/bin/sh\necho hi\n",
                                                        encoding="utf-8")
    (srcdir / "usr" / "bin").mkdir(parents=True)
    (srcdir / "usr" / "bin" / "tool").write_text("#!/bin/sh\nexit 0\n",
                                                 encoding="utf-8")
    os.symlink("usr/bin", srcdir / "bin")                      # usrmerge 相对链接
    os.symlink("nonexistent.so", srcdir / "usr" / "libdummy")  # 悬空链接


def _make_ext4_fs(img_path: Path, srcdir: Path) -> None:
    """mke2fs -d 从目录零特权合成 ext4 文件系统镜像(含自动 lost+found)。"""
    subprocess.run(
        ["mke2fs", "-F", "-q", "-t", "ext4", "-b", "1024", "-d", str(srcdir),
         str(img_path), "8192"],
        check=True, capture_output=True,
    )


def _make_gpt_ext4_image(img_path: Path, with_kernel: bool = True) -> None:
    """GPT 磁盘镜像:分区1 = APP(ext4 文件系统);with_kernel 时加裸数据分区2。"""
    build = img_path.parent
    srcdir = build / "ext4_src"
    srcdir.mkdir(parents=True, exist_ok=True)
    _make_ext4_content(srcdir)
    fs_img = build / "fs.img"
    _make_ext4_fs(fs_img, srcdir)
    partitions = [("APP", fs_img.read_bytes())]
    if with_kernel:
        # 注意: 裸数据分区在完整流水线里 Step2 过滤后为空 → sys.exit(1)(票 02
        # 的"空分区杀整批"问题,本票不修)。端到端测试必须传 with_kernel=False。
        partitions.append(("A_kernel", b"K" * (SECTOR * 4)))
    make_gpt_image(img_path, partitions)
    fs_img.unlink()
    shutil.rmtree(srcdir, ignore_errors=True)


# --- 触发判定(纯函数,不依赖宿主工具) ---

def test_is_ext4_partition_magic() -> list[str]:
    """触发判定有单测:0x438 魔数命中/不命中/数据过短。"""
    fails: list[str] = []
    # 命中:偏移 0x438 处 0xEF53 小端(53 ef)
    hit = b"\x00" * 0x438 + b"\x53\xef" + b"\x00" * 6
    if not is_ext4_partition(io.BytesIO(hit), {"offset": 0}):
        fails.append("0x438 处 53 ef 应命中 ext4 魔数")
    # 不命中:同长度全零
    if is_ext4_partition(io.BytesIO(b"\x00" * 0x440), {"offset": 0}):
        fails.append("全零数据不应命中 ext4 魔数")
    # 不命中:数据不足 0x438(小分区/垃圾头)
    if is_ext4_partition(io.BytesIO(b"\x53\xef" * 4), {"offset": 0}):
        fails.append("不足 0x438 字节的数据不应命中 ext4 魔数")
    # 分区内偏移:魔数在 partition offset 之后
    img = b"\xff" * 512 + b"\x00" * 0x438 + b"\x53\xef" + b"\x00" * 6
    if not is_ext4_partition(io.BytesIO(img), {"offset": 512}):
        fails.append("分区偏移 512 处的魔数应命中")
    return fails


def test_backend_env_resolution() -> list[str]:
    """STEP0_EXT4_BACKEND:缺省/非法值回落 debugfs,mount 显式生效。"""
    fails: list[str] = []
    env_name = "STEP0_EXT4_BACKEND"
    old = os.environ.get(env_name)
    try:
        os.environ.pop(env_name, None)
        if resolve_backend() != "debugfs":
            fails.append("缺省应回落 debugfs")
        os.environ[env_name] = "bogus"
        if resolve_backend() != "debugfs":
            fails.append("非法值应回落 debugfs(不崩不静默换后端)")
        os.environ[env_name] = "MOUNT"
        if resolve_backend() != "mount":
            fails.append("mount(大小写不敏感)应生效")
    finally:
        if old is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old
    return fails


# --- preprocess 集成:直读真跑(debugfs 默认后端) ---

def test_preprocess_ext4_direct_read(tmp_path) -> list[str]:
    """合成 GPT+ext4 镜像喂入 preprocess():ext4 直读出树+标记,非 ext4 不触发。"""
    if _skip_if_no_tools():
        return []
    fails: list[str] = []
    tmp_path = tmp_path / "direct"  # 独立模式 main() 共享 tmp,各测试隔离
    tmp_path.mkdir(exist_ok=True)
    img = tmp_path / "disk.img"
    _make_gpt_ext4_image(img)
    extracted = tmp_path / "extracted"

    out = step0_preprocess.preprocess(img, extracted)[0]

    if len(out) != 2:
        fails.append(f"应返回 2 个分区条目(APP 直读目录 + A_kernel 文件),实际 {out}")
        return fails
    ws, kernel = out
    if not ws.is_dir() or ws.name != "part01_APP":
        fails.append(f"ext4 分区应返回子工作区目录 part01_APP,实际 {ws}")
        return fails
    if kernel.name != "part02_A_kernel.img" or not kernel.is_file():
        fails.append(f"非 ext4 分区应返回分区文件 part02_A_kernel.img,实际 {kernel}")

    tree = ws / "extracted"
    # 直读产物:文件树 + Step1 完成标记
    if not (tree / ".step1_done").is_file():
        fails.append("extracted/.step1_done 完成标记缺失")
    if not (tree / "etc" / "passwd").is_file():
        fails.append("etc/passwd 未直读出来")
    if not (tree / "home" / "unitree" / "app.sh").is_file():
        fails.append("home/unitree/app.sh 未直读出来")
    if not (tree / "usr" / "bin" / "tool").is_file():
        fails.append("usr/bin/tool 未直读出来")
    # lost+found 固化排除
    if (tree / "lost+found").exists():
        fails.append("lost+found 不应出现在产物树")
    # 符号链接原样保留(usrmerge 形态 + 悬空)
    bin_link = tree / "bin"
    if not bin_link.is_symlink() or os.readlink(bin_link) != "usr/bin":
        fails.append(f"usrmerge 链接 bin → usr/bin 应保留,实际 {bin_link}")
    dangling = tree / "usr" / "libdummy"
    if not dangling.is_symlink() or os.readlink(dangling) != "nonexistent.so":
        fails.append(f"悬空链接 usr/libdummy 应保留,实际 {dangling}")
    # links.jsonl 清单(rel→target)生成且可解析
    links_file = ws / "links.jsonl"
    if not links_file.is_file():
        fails.append("links.jsonl 清单未生成")
    else:
        entries = {}
        for line in links_file.read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            entries[item["rel"]] = item["target"]
        if entries.get("bin") != "usr/bin":
            fails.append(f"links.jsonl 应含 bin→usr/bin,实际 {entries}")
        if entries.get("usr/libdummy") != "nonexistent.so":
            fails.append(f"links.jsonl 应含 usr/libdummy→nonexistent.so,实际 {entries}")
    # debugfs 中间分区文件已删除,非 ext4 分区无直读副作用
    if (tmp_path / "part01_APP.img").exists():
        fails.append("直读成功后分区中间文件 part01_APP.img 应删除")
    if (tmp_path / "part02_A_kernel").exists():
        fails.append("非 ext4 分区不应产生子工作区/直读产物")
    return fails


def test_preprocess_ext4_resume(tmp_path) -> list[str]:
    """标记已存在 → 断点复用直读产物,不再调 debugfs(模拟其消失也应成功)。"""
    if _skip_if_no_tools():
        return []
    fails: list[str] = []
    tmp_path = tmp_path / "resume"  # 独立模式 main() 共享 tmp,各测试隔离
    tmp_path.mkdir(exist_ok=True)
    img = tmp_path / "disk.img"
    _make_gpt_ext4_image(img)
    extracted = tmp_path / "extracted"
    step0_preprocess.preprocess(img, extracted)

    real_which = shutil.which
    shutil.which = lambda name: None if name == "debugfs" else real_which(name)
    try:
        out = step0_preprocess.preprocess(img, extracted)[0]
    finally:
        shutil.which = real_which

    ws = [p for p in out if p.is_dir()]
    if len(ws) != 1 or ws[0].name != "part01_APP":
        fails.append(f"断点复用应仍返回 part01_APP 子工作区,实际 {out}")
        return fails
    if not (ws[0] / "extracted" / "etc" / "passwd").is_file():
        fails.append("断点复用不应破坏既有直读树")
    return fails


def test_no_debugfs_skips_partition_batch_continues(tmp_path) -> list[str]:
    """本机无 debugfs:明确报错并跳过该分区,批次继续(非 ext4 照常提取)。"""
    if _skip_if_no_tools():
        return []
    fails: list[str] = []
    tmp_path = tmp_path / "nodesk"  # 独立模式 main() 共享 tmp,各测试隔离
    tmp_path.mkdir(exist_ok=True)
    img = tmp_path / "disk.img"
    _make_gpt_ext4_image(img)
    extracted = tmp_path / "extracted"

    real_which = shutil.which
    shutil.which = lambda name: None if name == "debugfs" else real_which(name)
    try:
        out = step0_preprocess.preprocess(img, extracted)[0]
        # 报错信息本身也要"明确":点名 debugfs 并给出路(装包/mount 快路)
        ok, reason = direct_read_ext4(
            img, {"index": 3, "name": "X", "offset": 0, "size": 1024},
            tmp_path / "part03_X")
    finally:
        shutil.which = real_which

    if [p.name for p in out] != ["part02_A_kernel.img"]:
        fails.append(f"无 debugfs 时 ext4 分区应被跳过、A_kernel 照常,实际 {out}")
    if ok or "debugfs" not in reason:
        fails.append(f"无 debugfs 报错应失败且点名 debugfs,实际 ok={ok} reason={reason!r}")
    return fails


def test_debugfs_backend_command_assembly(tmp_path) -> list[str]:
    """缺省后端 debugfs:rdump 命令拼装有假 subprocess 断言(无需真 debugfs)。"""
    fails: list[str] = []
    region = b"K" * 8192
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 512 + region)  # 分区数据区在 offset=512
    partition = {"index": 1, "name": "APP", "offset": 512, "size": len(region)}
    ws = tmp_path / "part01_APP"
    # 预置分区中间文件(复用路径:模拟上次直读中断的遗留)
    part_file = tmp_path / "part01_APP.img"
    part_file.write_bytes(region)

    calls: list[list[str]] = []

    def fake_run(cmd):
        calls.append(cmd)
        # 模拟 debugfs rdump 侧真解出树
        dest = Path(cmd[2][len("rdump / "):])
        (dest / "etc").mkdir(parents=True)
        (dest / "etc" / "passwd").write_text("root:x:0:0\n", encoding="utf-8")
        return 0, "", ""

    real_which = shutil.which
    orig_run = step0_ext4_read._run
    shutil.which = lambda name: "/usr/sbin/debugfs" if name == "debugfs" else real_which(name)
    step0_ext4_read._run = fake_run
    try:
        ok, reason = direct_read_ext4(img, partition, ws)
    finally:
        step0_ext4_read._run = orig_run
        shutil.which = real_which

    if not ok:
        fails.append(f"debugfs 后端假 subprocess 下应成功,实际失败:{reason}")
        return fails
    if len(calls) != 1:
        fails.append(f"应恰好一次 debugfs rdump 调用,实际 {len(calls)}: {calls}")
        return fails
    cmd = calls[0]
    if cmd[0] != "/usr/sbin/debugfs" or cmd[1] != "-R":
        fails.append(f"应以 debugfs -R 形式调用,实际 {cmd}")
    if cmd[2] != f"rdump / {(ws / 'extracted').resolve()}":
        fails.append(f"rdump 应把 / 解到 extracted/,实际 {cmd[2]!r}")
    if cmd[3] != str(part_file.resolve()):
        fails.append(f"rdump 源应为分区中间文件绝对路径,实际 {cmd[3]!r}")
    # 产物与中间文件清理
    if not (ws / "extracted" / ".step1_done").is_file():
        fails.append("debugfs 后端应写 Step1 完成标记")
    if not (ws / "extracted" / "etc" / "passwd").is_file():
        fails.append("debugfs 后端 rdump 产物应落 extracted/")
    if not (ws / "links.jsonl").is_file():
        fails.append("debugfs 后端应生成 links.jsonl")
    if part_file.exists():
        fails.append("直读成功后分区中间文件应删除")
    return fails


def test_all_partitions_failed_no_binwalk_fallback(tmp_path) -> list[str]:
    """有分区表但直读全失败:返回空输入(不把整盘镜像交 binwalk 爆炸)。"""
    if _skip_if_no_tools():
        return []
    fails: list[str] = []
    tmp_path = tmp_path / "nofallback"  # 独立模式 main() 共享 tmp,各测试隔离
    tmp_path.mkdir(exist_ok=True)
    img = tmp_path / "disk.img"
    _make_gpt_ext4_image(img, with_kernel=False)  # 单 ext4 分区,失败即零产出

    real_which = shutil.which
    shutil.which = lambda name: None if name == "debugfs" else real_which(name)
    try:
        out, skip = step0_preprocess.preprocess(img, tmp_path / "extracted")
    finally:
        shutil.which = real_which

    if out != [] or skip:
        fails.append(f"直读全失败应返回 ([], False) 不回退 binwalk,实际 {out}, skip={skip}")
    return fails


# --- mount 后端(假 subprocess 断言命令拼装,真 mount 需 root 不进常规测试) ---

def test_mount_backend_command_assembly(tmp_path) -> list[str]:
    """STEP0_EXT4_BACKEND=mount:mount/tar 管道/umount 命令拼装有假 subprocess 断言。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 4096)
    partition = {"index": 1, "name": "APP", "offset": 40 * 512, "size": 2048}
    ws = tmp_path / "part01_APP"

    calls: list[list[str]] = []
    real_pipe = step0_ext4_read._run_pipe

    def fake_run(cmd):
        calls.append(cmd)
        return 0, "", ""

    def fake_pipe(cmd_src, cmd_dst):
        calls.append(cmd_src)
        calls.append(cmd_dst)
        # 模拟 tar 侧真解出内容(不含 lost+found——由 --exclude 保证)
        extracted = Path(cmd_dst[cmd_dst.index("-C") + 1])
        (extracted / "etc").mkdir(parents=True)
        (extracted / "etc" / "passwd").write_text("root:x:0:0\n", encoding="utf-8")
        return 0, ""

    orig_run, orig_pipe = step0_ext4_read._run, step0_ext4_read._run_pipe
    env_name = "STEP0_EXT4_BACKEND"
    old_env = os.environ.get(env_name)
    step0_ext4_read._run = fake_run
    step0_ext4_read._run_pipe = fake_pipe
    os.environ[env_name] = "mount"
    try:
        ok, reason = direct_read_ext4(img, partition, ws)
    finally:
        step0_ext4_read._run, step0_ext4_read._run_pipe = orig_run, orig_pipe
        if old_env is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old_env

    if not ok:
        fails.append(f"mount 后端假 subprocess 下应成功,实际失败:{reason}")
        return fails
    if len(calls) != 4:
        fails.append(f"应恰好 mount + tar 管道×2 + umount 四次调用,实际 {len(calls)}: {calls}")
        return fails
    cmd_mount, cmd_src, cmd_dst, cmd_umount = calls
    if cmd_mount[:3] != ["sudo", "-n", "mount"]:
        fails.append(f"mount 应走 sudo -n(无免密立即失败不挂死),实际 {cmd_mount}")
    opts = cmd_mount[4] if len(cmd_mount) > 4 else ""
    for token in ("ro", "noload", "loop", f"offset={partition['offset']}"):
        if token not in opts:
            fails.append(f"mount 选项应含 {token},实际 {opts}")
    if cmd_mount[5] != str(img.resolve()):
        fails.append(f"mount 源应为镜像绝对路径,实际 {cmd_mount}")
    mnt = cmd_mount[6]
    if cmd_src[:3] != ["sudo", "-n", "tar"] or "--exclude=./lost+found" not in cmd_src:
        fails.append(f"tar 源侧应 sudo -n + 排除 lost+found,实际 {cmd_src}")
    if cmd_src[3:5] != ["-C", mnt] or cmd_src[-1] != ".":
        fails.append(f"tar 源侧应从挂载点打包整树,实际 {cmd_src}")
    if cmd_dst[0] != "tar" or cmd_dst[1:3] != ["-C", str(ws / "extracted")]:
        fails.append(f"tar 目标侧应解到 extracted/,实际 {cmd_dst}")
    if cmd_umount[:3] != ["sudo", "-n", "umount"] or cmd_umount[3] != mnt:
        fails.append(f"最后一步应 sudo -n umount 挂载点,实际 {cmd_umount}")
    # 产物:树 + 标记 + 空链接清单(mount 假树无符号链接)
    if not (ws / "extracted" / ".step1_done").is_file():
        fails.append("mount 后端应写 Step1 完成标记")
    if not (ws / "extracted" / "etc" / "passwd").is_file():
        fails.append("mount 后端 tar 管道产物应落 extracted/")
    links_file = ws / "links.jsonl"
    if not links_file.is_file():
        fails.append("mount 后端应生成 links.jsonl(可为空清单)")
    elif links_file.read_text(encoding="utf-8").strip() != "":
        fails.append("无符号链接的树 links.jsonl 应为空文件")
    if (ws / "extracted" / "lost+found").exists():
        fails.append("lost+found 不应出现在产物树")
    return fails


def test_mount_backend_umount_called(tmp_path) -> list[str]:
    """mount 成功路径最后必须 umount(挂载点不残留)。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 4096)
    partition = {"index": 1, "name": "APP", "offset": 512, "size": 2048}
    ws = tmp_path / "part01_APP"

    calls: list[list[str]] = []

    def fake_run(cmd):
        calls.append(cmd)
        return 0, "", ""

    def fake_pipe(cmd_src, cmd_dst):
        extracted = Path(cmd_dst[cmd_dst.index("-C") + 1])
        (extracted / "marker.txt").write_text("x", encoding="utf-8")
        return 0, ""

    orig_run, orig_pipe = step0_ext4_read._run, step0_ext4_read._run_pipe
    env_name = "STEP0_EXT4_BACKEND"
    old_env = os.environ.get(env_name)
    step0_ext4_read._run = fake_run
    step0_ext4_read._run_pipe = fake_pipe
    os.environ[env_name] = "mount"
    try:
        direct_read_ext4(img, partition, ws)
    finally:
        step0_ext4_read._run, step0_ext4_read._run_pipe = orig_run, orig_pipe
        if old_env is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old_env

    if not any(c[:3] == ["sudo", "-n", "umount"] for c in calls):
        fails.append(f"mount 成功后必须 umount,实际调用 {calls}")
    for c in calls:
        if c[0] == "sudo" and c[1] != "-n":
            fails.append(f"所有 sudo 调用必须 -n(无免密立即失败不挂死): {c}")
    return fails


def test_mount_backend_no_passwordless_sudo(tmp_path) -> list[str]:
    """mount 无免密 sudo:报错信息明确(不挂死不静默),分区不产标记。"""
    fails: list[str] = []
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 4096)
    partition = {"index": 1, "name": "APP", "offset": 512, "size": 2048}
    ws = tmp_path / "part01_APP"

    def fake_run(cmd):
        return 1, "", "sudo: a password is required"

    orig_run, orig_pipe = step0_ext4_read._run, step0_ext4_read._run_pipe
    env_name = "STEP0_EXT4_BACKEND"
    old_env = os.environ.get(env_name)
    step0_ext4_read._run = fake_run
    os.environ[env_name] = "mount"
    try:
        ok, reason = direct_read_ext4(img, partition, ws)
    finally:
        step0_ext4_read._run, step0_ext4_read._run_pipe = orig_run, orig_pipe
        if old_env is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old_env

    if ok:
        fails.append("无免密 sudo 时直读必须失败")
    if "sudo" not in reason or "debugfs" not in reason:
        fails.append(f"报错应指明 sudo 问题并给 debugfs 退路,实际:{reason}")
    if (ws / "extracted" / ".step1_done").exists():
        fails.append("失败的直读不应写 Step1 完成标记")
    return fails


# --- 端到端:直读落点与分区递归同构(工单验收 #4) ---

def test_run_pipeline_single_ext4_partition_e2e(tmp_path) -> list[str]:
    """main 流水线对单 ext4 分区合成镜像:直读 + 分区递归跑通(--no-step5)。

    ADR-0011 后流水线为 Step0→1→5:断言到"解包树就位"为止(Step5 已跳过)。
    """
    if _skip_if_no_tools():
        return []
    fails: list[str] = []
    target = tmp_path / "tgt9"
    target.mkdir()
    # 单 ext4 分区合成镜像(工单验收 #4 原文口径)
    _make_gpt_ext4_image(target / "single_ext4.img", with_kernel=False)

    from ..main import run_pipeline

    run_pipeline(target, run_step5=False)

    sub = target / "process" / "part01_APP"
    if not sub.is_dir():
        fails.append(f"单 ext4 分区应产生分区子工作区 {sub}")
        return fails
    if not (sub / "extracted" / ".step1_done").is_file():
        fails.append("子工作区 extracted/.step1_done 缺失(直读标记未生效)")
    if not (sub / "extracted" / "etc" / "passwd").is_file():
        fails.append("子工作区直读树缺 etc/passwd")
    if not (sub / "links.jsonl").is_file():
        fails.append("子工作区 links.jsonl 缺失")
    if (sub / "fileinfo.json").exists():
        fails.append("fileinfo.json 已退役,不应再产出")
    return fails


def main() -> int:
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        groups = [
            ("魔数触发判定", test_is_ext4_partition_magic()),
            ("后端env解析", test_backend_env_resolution()),
            ("preprocess直读真跑", test_preprocess_ext4_direct_read(tmp)),
            ("直读断点复用", test_preprocess_ext4_resume(tmp)),
            ("无debugfs跳过分区", test_no_debugfs_skips_partition_batch_continues(tmp)),
            ("直读全失败不回退binwalk", test_all_partitions_failed_no_binwalk_fallback(tmp)),
            ("debugfs命令拼装", test_debugfs_backend_command_assembly(tmp)),
            ("mount命令拼装", test_mount_backend_command_assembly(tmp)),
            ("mount必umount", test_mount_backend_umount_called(tmp)),
            ("mount无免密sudo", test_mount_backend_no_passwordless_sudo(tmp)),
            ("单分区端到端", test_run_pipeline_single_ext4_partition_e2e(tmp)),
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

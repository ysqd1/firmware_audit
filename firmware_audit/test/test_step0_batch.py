"""Step0 分区批次行为测试(闸门跳过告警 + 双分区批次端到端)。

验收对照(.scratch/step0-fs-extract/issues/02-batch-failure-behavior.md 及
ADR-0011 退役后的新语义):
  - 非直读路径上,分区超限被跳过时输出含分区名/大小/上限的告警行
    (ext4 分区不受闸门约束,天然不触发此告警)
  - 双 ext4 分区合成镜像:两个分区各自完成解包(--no-step5),整体退出码 0
    (ADR-0011 后无 Step2 过滤,原"空分区跳过"语义消亡——每个解出的树
    都直接进 Step5,批次不再有过滤性跳过)

fixture 策略(复用工单 01 的合成镜像套路):
  - 告警行为:纯 Python GPT 布局 + env 压低 STEP0_PARTITION_MAX_SIZE_GB,
    小分区即触发闸门,不造 50GB 稀疏文件
  - 双分区批次:双 ext4 分区(APP 正常内容 / RECROOTFS 只含 SDK 路径
    usr/share/doc)——ext4 直读产物不经 Docker,测试确定

用法:
    python -m firmware_audit.test.test_step0_batch
"""
from __future__ import annotations

import contextlib
import io
import os
import shutil
from pathlib import Path

from ..step0 import step0_preprocess
from ..step0.step0_preprocess import partition_skip_message
from ..main import main as main_cli, run_pipeline
from .test_step0_split import make_gpt_image
from .test_step0_ext4 import _make_ext4_fs, _skip_if_no_tools

try:
    import pytest
except ImportError:  # 独立模式(python -m)无 pytest
    pytest = None


# --- 闸门跳过告警:消息构造(纯函数) ---

def test_partition_skip_message() -> list[str]:
    """告警行必含分区名/大小/上限;userdata/large 策略跳过打提示不谎称超限。"""
    fails: list[str] = []
    # rootfs 超限:含分区名/大小/上限/env 指引的醒目告警
    msg = partition_skip_message(
        {"name": "APP", "kind": "rootfs", "size": 238 * 1024 ** 3}, 50.0)
    for token in ("告警", "APP", "rootfs", "238.0 GB", "50 GB",
                  "STEP0_PARTITION_MAX_SIZE_GB"):
        if token not in msg:
            fails.append(f"rootfs 超限告警应含 {token!r},实际: {msg}")
    # recovery 超限同告警口径
    msg_rec = partition_skip_message(
        {"name": "REC", "kind": "recovery", "size": 60 * 1024 ** 3}, 50.0)
    if "告警" not in msg_rec or "50 GB" not in msg_rec:
        fails.append(f"recovery 超限应同样告警并带上限,实际: {msg_rec}")
    # userdata/large:策略性跳过,提示行不谎称"超过上限"
    for kind in ("userdata", "large"):
        msg_kind = partition_skip_message(
            {"name": "UDA", "kind": kind, "size": 8 * 1024 ** 3}, 50.0)
        if "UDA" not in msg_kind or kind not in msg_kind or "跳过" not in msg_kind:
            fails.append(f"{kind} 跳过应含分区名/类型且非静默,实际: {msg_kind}")
        if "超过提取上限" in msg_kind:
            fails.append(f"{kind} 跳过未触发大小闸门,不应谎称超限: {msg_kind}")
    return fails


# --- 闸门跳过告警:preprocess 集成(env 压低闸门,非 ext4 分区触发) ---

def test_oversize_partition_skip_warns(tmp_path) -> list[str]:
    """非 ext4 分区超限被跳过:输出告警行(名/大小/上限),其余分区照常提取。"""
    fails: list[str] = []
    tmp_path = tmp_path / "gate"  # 独立模式 main() 共享 tmp,各测试隔离
    tmp_path.mkdir(exist_ok=True)
    img = tmp_path / "disk.img"
    # APP=2MB 裸数据(kind=rootfs,非 ext4)压过 0.001GB(≈1MB)闸门;
    # A_kernel 恒提取(kind=kernel 不受闸门管辖)
    make_gpt_image(img, [
        ("APP", b"X" * (2 * 1024 * 1024)),
        ("A_kernel", b"K" * 2048),
    ])

    env_name = "STEP0_PARTITION_MAX_SIZE_GB"
    old_env = os.environ.get(env_name)
    buf = io.StringIO()
    try:
        os.environ[env_name] = "0.001"
        with contextlib.redirect_stdout(buf):
            out = step0_preprocess._extract_partitions(img, tmp_path / "process")
    finally:
        if old_env is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old_env

    log = buf.getvalue()
    for token in ("告警", "APP", "0.001 GB"):
        if token not in log:
            fails.append(f"超限跳过应输出含 {token!r} 的告警行,实际日志缺该词")
    if [p.name for p in out] != ["part02_A_kernel.img"]:
        fails.append(f"超限 APP 应被跳过、A_kernel 照常提取,实际 {out}")
    if (tmp_path / "process" / "part01_APP.img").exists():
        fails.append("被闸门跳过的分区不应留下提取产物")
    return fails


# --- 双分区批次集成(--no-step5,整体退出码 0) ---

def _make_two_ext4_partitions_image(img_path: Path) -> None:
    """双 ext4 分区 GPT 镜像:APP 正常 / RECROOTFS 只含 SDK 路径。

    RECROOTFS 的内容树非空(直读成功、写标记),全部落在搜索过滤名单
    (usr/share)——ADR-0011 前它会被 Step2 过滤为 0 而跳过;退役后每个
    解出的树都直接进 Step5,本用例验证"树内容不决定批次命运"。
    ext4 直读不经 Docker,测试确定。
    """
    build = img_path.parent
    plan = [
        ("APP", {"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
                 "home/unitree/app.sh": "#!/bin/sh\necho hi\n"}),
        ("RECROOTFS", {"usr/share/doc/junk.txt": "build noise\n"}),
    ]
    parts: list[tuple[str, bytes]] = []
    for name, files in plan:
        srcdir = build / f"src_{name}"
        srcdir.mkdir(parents=True, exist_ok=True)
        for rel, text in files.items():
            target = srcdir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        fs_img = build / f"{name}.ext4"
        _make_ext4_fs(fs_img, srcdir)
        parts.append((name, fs_img.read_bytes()))
        fs_img.unlink()
        shutil.rmtree(srcdir, ignore_errors=True)
    make_gpt_image(img_path, parts)


def test_two_partition_batch_e2e(tmp_path) -> list[str]:
    """双分区:各自完成解包(--no-step5 跳过审计),退出码 0,无 fileinfo 产物。"""
    if _skip_if_no_tools():
        return []
    fails: list[str] = []
    tmp_path = tmp_path / "batch"  # 独立模式 main() 共享 tmp,各测试隔离
    tmp_path.mkdir(exist_ok=True)
    target = tmp_path / "tgt"
    target.mkdir()
    _make_two_ext4_partitions_image(target / "disk.img")

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = main_cli([str(target), "--no-step5"])
    except SystemExit as e:
        fails.append(f"双分区批次不应失败(仍 SystemExit({e.code}))")
        return fails

    if rc != 0:
        fails.append(f"整体退出码应为 0,实际 {rc}")
    log = buf.getvalue()

    # 两个分区都完成解包(ADR-0011:无 Step2,树内容不决定批次命运)
    for name in ("part01_APP", "part02_RECROOTFS"):
        sub = target / "process" / name
        if not (sub / "extracted" / ".step1_done").is_file():
            fails.append(f"{name} 的直读标记缺失(分区未完成解包)")
    if not (target / "process" / "part01_APP" / "extracted" / "etc" / "passwd").is_file():
        fails.append("part01_APP 解包树缺 etc/passwd")
    # fileinfo.json 概念退役:流水线不再产出
    if (target / "process" / "part01_APP" / "fileinfo.json").exists():
        fails.append("fileinfo.json 已退役,不应再产出")
    if "所有分区审计完成" not in log:
        fails.append(f"批次末应有完成汇总: {log[-300:]}")
    return fails


# --- 分区子工作区:直接跑 run_pipeline(单分区递归路径) ---

def test_partition_subworkspace_pipeline(tmp_path) -> list[str]:
    """分区子工作区(workspace=分区目录本身)走 run_pipeline --no-step5 不崩。"""
    fails: list[str] = []
    tmp_path = tmp_path / "sub"
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "extracted" / "etc").mkdir(parents=True)
    (tmp_path / "extracted" / "etc" / "passwd").write_text(
        "root:x:0:0\n", encoding="utf-8")
    (tmp_path / "extracted" / ".step1_done").write_text("ok", encoding="utf-8")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run_pipeline(tmp_path, workspace=tmp_path, run_step5=False)
    log = buf.getvalue()
    if "跳过 Step1" not in log:
        fails.append(f"应识别已有解包跳过 Step1: {log[-300:]}")
    if "跳过 Step5" not in log:
        fails.append(f"--no-step5 应跳过 Step5: {log[-300:]}")
    return fails


def main() -> int:
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        groups = [
            ("闸门跳过告警消息", test_partition_skip_message()),
            ("超限跳过告警集成", test_oversize_partition_skip_warns(tmp)),
            ("双分区批次e2e", test_two_partition_batch_e2e(tmp)),
            ("分区子工作区流水线", test_partition_subworkspace_pipeline(tmp)),
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

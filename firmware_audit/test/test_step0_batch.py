"""Step0 分区批次失败行为测试(工单 02:跳过必告警 / 空分区不杀整批)。

验收对照(.scratch/step0-fs-extract/issues/02-batch-failure-behavior.md):
  - 非直读路径上,分区超限被跳过时输出含分区名/大小/上限的告警行
    (ext4 分区不受闸门约束,天然不触发此告警)
  - 分区递归中单分区 Step2 过滤为 0 文件:记录(分区名+原因)并继续其余分区;
    批次结束时汇总哪些分区被跳过;顶层(非分区)固件过滤为空仍终止
  - 空分区跳过判定为小决策点(main.empty_filter_action),有秒级单测
  - 两分区合成镜像(一空一正常)集成测试:--no-step5 下正常分区完成、
    空分区被记录、整体退出码 0

fixture 策略(复用工单 01 的合成镜像套路):
  - 告警行为:纯 Python GPT 布局 + env 压低 STEP0_PARTITION_MAX_SIZE_GB,
    小分区即触发闸门,不造 50GB 稀疏文件
  - 空分区批次:双 ext4 分区(APP 正常内容 / RECROOTFS 只含黑名单路径
    usr/share/doc → Step2 过滤为 0)——ext4 直读产物不经 Docker,测试确定

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
from ..main import empty_filter_action, main as main_cli, run_pipeline
from .test_step0_split import make_gpt_image
from .test_step0_ext4 import _make_ext4_fs, _skip_if_no_tools

try:
    import pytest
except ImportError:  # 独立模式(python -m)无 pytest
    pytest = None


# --- 决策点:空分区跳过判定(秒级纯函数) ---

def test_empty_filter_action() -> list[str]:
    """小决策点:分区批次内跳过续批,顶层单固件终止(语义保持不变)。"""
    fails: list[str] = []
    action, reason = empty_filter_action(True)
    if action != "skip":
        fails.append(f"分区模式应判定 skip,实际 {action!r}")
    if not reason:
        fails.append("skip 分支应携带原因(供日志记录分区名+原因)")
    action_top, reason_top = empty_filter_action(False)
    if action_top != "terminate":
        fails.append(f"顶层模式应判定 terminate(语义不变),实际 {action_top!r}")
    if "Step2 过滤后无文件" not in reason_top:
        fails.append(f"terminate 原因应保持原终止文案口径,实际 {reason_top!r}")
    return fails


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


# --- 两分区批次集成(一空一正常,--no-step5,整体退出码 0) ---

def _make_two_ext4_partitions_image(img_path: Path) -> None:
    """双 ext4 分区 GPT 镜像:APP 正常 / RECROOTFS 只含黑名单路径。

    RECROOTFS 的内容树非空(直读成功、写标记),但全部落在 Step2 黑名单
    (usr/share)→ 过滤为 0 文件,即工单语境的"空分区"(RECROOTFS 原型是
    target/3 解出空树的分区)。ext4 直读不经 Docker,测试确定。
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
    """一空一正常双分区:正常分区完成、空分区被记录、批次汇总、退出码 0。"""
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
        fails.append(f"空分区不应杀死整批(仍 SystemExit({e.code}))")
        return fails

    if rc != 0:
        fails.append(f"整体退出码应为 0,实际 {rc}")
    log = buf.getvalue()

    # 正常分区:完整走完 Step2-4(fileinfo.json 产出)
    sub_ok = target / "process" / "part01_APP"
    if not (sub_ok / "fileinfo.json").is_file():
        fails.append("正常分区 part01_APP 未产出 fileinfo.json(未完成审计)")
    else:
        from ..models import load_fileinfos
        rels = {fi.rel_path.replace("\\", "/")
                for fi in load_fileinfos(sub_ok / "fileinfo.json")}
        if "etc/passwd" not in rels:
            fails.append(f"part01_APP 的 fileinfo 应含 etc/passwd,实际 {sorted(rels)}")
    # 空分区:直读产物在(标记/树),但不再进入 Step3-4,无 fileinfo.json
    sub_empty = target / "process" / "part02_RECROOTFS"
    if not (sub_empty / "extracted" / ".step1_done").is_file():
        fails.append("空分区 part02_RECROOTFS 的直读标记缺失(前置直读未发生)")
    if (sub_empty / "fileinfo.json").exists():
        fails.append("被跳过的空分区不应产出 fileinfo.json")
    # 记录与汇总:分区名+原因进日志,批次结束有跳过清单
    if "part02_RECROOTFS" not in log or "过滤" not in log:
        fails.append("空分区跳过应有含分区名+原因的记录行")
    if "批次汇总" not in log or "part02_RECROOTFS" not in log:
        fails.append("批次结束应汇总被跳过的分区清单")
    return fails


# --- 顶层(非分区)固件过滤为空:语义不变,仍终止 ---

def test_top_level_empty_filter_terminates(tmp_path) -> list[str]:
    """顶层单固件(zip 只含黑名单路径)过滤为空 → sys.exit(1) 语义保持。"""
    fails: list[str] = []
    import zipfile
    tmp_path = tmp_path / "top"  # 独立模式 main() 共享 tmp,各测试隔离
    tmp_path.mkdir(exist_ok=True)
    target = tmp_path / "tgt"
    target.mkdir()
    with zipfile.ZipFile(target / "fw.zip", "w") as z:
        z.writestr("usr/share/doc/junk.txt", "noise\n")

    buf = io.StringIO()
    exited = False
    try:
        with contextlib.redirect_stdout(buf):
            run_pipeline(target, run_step5=False)
    except SystemExit as e:
        exited = True
        if e.code != 1:
            fails.append(f"顶层过滤为空应 sys.exit(1),实际退出码 {e.code!r}")
    if not exited:
        fails.append("顶层(非分区)固件过滤为空仍应终止,实际正常返回")
    if "Step2 过滤后无文件" not in buf.getvalue():
        fails.append(f"终止原因应保持原口径'Step2 过滤后无文件',日志: "
                     f"{buf.getvalue()[-300:]!r}")
    return fails


def main() -> int:
    import tempfile

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        groups = [
            ("空分区跳过决策点", test_empty_filter_action()),
            ("闸门跳过告警消息", test_partition_skip_message()),
            ("超限跳过告警集成", test_oversize_partition_skip_warns(tmp)),
            ("双分区批次e2e", test_two_partition_batch_e2e(tmp)),
            ("顶层空过滤仍终止", test_top_level_empty_filter_terminates(tmp)),
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

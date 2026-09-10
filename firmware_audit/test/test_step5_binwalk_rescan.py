"""票02 binwalk_rescan 幽灵扫描修复 execute 层单测(离线,mock 容器)。

只测外部行为(spec binwalk-extractable-align Testing Decisions):给定
工作区状态与工具入参,断言 ToolResult 的 ok/text/error 与"接口边界本身"
(run_docker 是否被调、镜像/挂载/entrypoint/断网)。覆盖:
  - 不存在文件 → ok=False 引导文案("文件不在解包树"+list_files 指引),
    零容器调用(宿主预检);目录目标 → "不是常规文件"同款拒绝
  - stderr 打开/读取失败标记 → ok=False 如实回喂(v3 幽灵扫描实测坑:
    打不开目标 rc=0 也拦)
  - 正常识别路径回归:ok=True 签名汇总 + data;rc!=0 失败不变;
    真扫过的"0 命中"(干净 stderr)仍合法

mock 补丁点:binwalk_rescan 命名空间的 run_docker / docker_available
(工具模块顶层 import,补丁即生效);替身用共享 ReplaySpy + patched。
先例:test_step5_r2_tools 替身模式。
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import binwalk_rescan as br
from firmware_audit.step5_agent.providers.tools.base import ToolContext
from firmware_audit.step5_agent.providers.tools.binwalk_rescan import (
    BinwalkRescanTool,
)
from firmware_audit.test.replay_spy import ReplaySpy, patched


def _make_ctx(root: Path) -> ToolContext:
    """最小工作区:extracted/fw.bin 存在(内容任意,mock 容器不真读)。"""
    (root / "extracted").mkdir(parents=True, exist_ok=True)
    (root / "extracted" / "fw.bin").write_bytes(b"FWBIN" + b"\x00" * 64)
    return ToolContext(process_dir=root)


def _install(spy: ReplaySpy):
    """补丁 run_docker + docker_available(强制可用),返回恢复函数。"""
    return patched(br, run_docker=spy, docker_available=lambda image: True)


def test_missing_file_guides_without_container() -> list[str]:
    """不存在文件 → 宿主预检 ok=False 引导文案,零容器调用(票02 验收1)。"""
    fails: list[str] = []
    spy = ReplaySpy()
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "extracted" / "sub").mkdir(parents=True, exist_ok=True)
            ctx = _make_ctx(root)
            t = BinwalkRescanTool(ctx)
            r = t.execute(file_ref="ghost/missing.bin")
            if r.ok or "文件不在解包树" not in (r.error or ""):
                fails.append(f"缺失文件应引导性拒绝: {r.error}")
            elif "list_files" not in (r.error or ""):
                fails.append(f"错误文案应指引 list_files: {r.error}")
            # 目录目标:存在但不是扫描对象,同样拒绝且零容器
            rd = t.execute(file_ref="sub")
            if rd.ok or "不是常规文件" not in (rd.error or ""):
                fails.append(f"目录目标应拒绝: {rd.error}")
            # 越界仍按原语义拒绝(回归)
            r2 = t.execute(file_ref="../../etc/passwd")
            if r2.ok or "非法路径" not in (r2.error or ""):
                fails.append(f"越界应拒绝: {r2.error}")
    finally:
        restore()
    if spy.calls:
        fails.append(f"预检拒绝路径不应触发容器: {spy.calls}")
    return fails


def test_stderr_failure_blocked_even_on_rc0() -> list[str]:
    """v3 幽灵扫描实测坑:打不开目标 rc=0、失败只打 stderr → ok=False 如实回喂。"""
    fails: list[str] = []
    cases = [
        (0, "Analyzed 1 file (0 hits)\n",
         "Failed to open/read /analysis/ghost.bin"),
        (0, "", "failed to open /analysis/ghost.bin"),
    ]
    for rc, out, err in cases:
        spy = ReplaySpy((rc, out, err))
        restore = _install(spy)
        try:
            with tempfile.TemporaryDirectory() as td:
                ctx = _make_ctx(Path(td))
                r = BinwalkRescanTool(ctx).execute(file_ref="fw.bin")
        finally:
            restore()
        if r.ok:
            fails.append(f"rc={rc} stderr 失败标记应拦: {r.text[:120]}")
        elif "/analysis/ghost.bin" not in (r.error or ""):
            fails.append(f"错误应如实回喂 stderr 原文(含目标与失败原因): {r.error}")
    return fails


def test_normal_scan_regression() -> list[str]:
    """正常识别路径行为不变:签名汇总 + data;接口边界(镜像/挂载/断网)不回退。"""
    fails: list[str] = []
    out = ("DECIMAL\tHEX\tDESCRIPTION\n"
           "1048576\t0x100000\tSquashFS filesystem, little endian, version 4.0\n")
    spy = ReplaySpy((0, out, ""))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            r = BinwalkRescanTool(ctx).execute(file_ref="fw.bin")
    finally:
        restore()
    if not r.ok:
        fails.append(f"正常识别应 ok: {r.error}")
        return fails
    if "签名复扫" not in r.text or "SquashFS" not in r.text:
        fails.append(f"text 应汇总签名: {r.text[:160]}")
    if not (r.data or {}).get("output"):
        fails.append(f"data 应带 output 原文: {r.data}")
    c = spy.last
    if c["args"][0] != "binwalk" or c["kwargs"].get("entrypoint") != "binwalk":
        fails.append(f"镜像/entrypoint 应回归不变: {c}")
    if c["kwargs"].get("network") != "none" or c["kwargs"].get("timeout") != 300:
        fails.append(f"断网与超时应保持: {c}")
    mounts = c["kwargs"].get("mounts") or []
    if not mounts or mounts[0][2] != "ro" or not str(mounts[0][0]).endswith("extracted"):
        fails.append(f"extracted 只读挂载应保持: {mounts}")
    if list(c["args"][1]) != ["/analysis/fw.bin"]:
        fails.append(f"目标容器路径应为 /analysis/fw.bin: {c['args']}")
    return fails


def test_clean_zero_hits_still_ok() -> list[str]:
    """真扫过(rc=0、stderr 干净)的 0 命中仍合法——修复不得误伤既有语义。"""
    fails: list[str] = []
    spy = ReplaySpy((0, "", ""))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            r = BinwalkRescanTool(ctx).execute(file_ref="fw.bin")
    finally:
        restore()
    if not r.ok or "无签名命中" not in r.text:
        fails.append(f"干净 0 命中应保持 ok=True: {r.error or r.text}")
    return fails


def test_rc_nonzero_still_fails() -> list[str]:
    """rc!=0 失败路径回归不变。"""
    fails: list[str] = []
    spy = ReplaySpy((2, "", "boom"))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            r = BinwalkRescanTool(ctx).execute(file_ref="fw.bin")
    finally:
        restore()
    if r.ok or "码 2" not in (r.error or ""):
        fails.append(f"rc!=0 失败路径回归: {r.error}")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("missing_file_guides_without_container", test_missing_file_guides_without_container),
        ("stderr_failure_blocked_even_on_rc0", test_stderr_failure_blocked_even_on_rc0),
        ("normal_scan_regression", test_normal_scan_regression),
        ("clean_zero_hits_still_ok", test_clean_zero_hits_still_ok),
        ("rc_nonzero_still_fails", test_rc_nonzero_still_fails),
    ]:
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

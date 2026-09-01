"""安全加固回归测试:zip/tar-slip 提取、analysis 路径越界读、gitleaks shell 注入。

覆盖 2026-08-27 三项安全修复,零 API 零 Docker。
"""
from __future__ import annotations

import io
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # 项目根(important/)

from firmware_audit.step0.step0_preprocess import _decompress_archive
from firmware_audit.step5_agent.providers.tools.base import (
    ToolContext,
    resolve_analysis_file,
    resolve_within,
)
from firmware_audit.step5_agent.providers.tools.gitleaks_scan import build_gitleaks_cmd

# ---- Bug B: zip/tar-slip 越界写 ----

def _make_zip_slip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("root/ok.txt", "good")
        z.writestr("../../evil.txt", "pwned")        # 越界常规项
        z.writestr("/abs_evil.txt", "pwned")         # 绝对路径
        # 构造一条绝对路径形式:python zipfile 不允许真正绝对成员名,用 ../ 已够


def _make_tar_slip(path: Path) -> None:
    with tarfile.open(path, "w") as t:
        ti = tarfile.TarInfo("root/ok.txt")
        ti.size = len("good")
        t.addfile(ti, io.BytesIO(b"good"))
        bad = tarfile.TarInfo("../../evil.txt")      # 越界
        bad.size = len(b"pwned")
        t.addfile(bad, io.BytesIO(b"pwned"))


def test_zip_slip_blocked() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        src, dest = td / "t.zip", td / "out"
        _make_zip_slip(src)
        _decompress_archive(src, dest)  # 应跳过越界项,不抛
        if not (dest / "root" / "ok.txt").is_file():
            fails.append("正常 zip 项应被安全提取")
        if (td / "evil.txt").exists():
            fails.append("zip-slip 越界文件被写入(../evil.txt)")
        if (td / "abs_evil.txt").exists():
            fails.append("zip-slip 绝对路径项被写入")
    return fails


def test_tar_slip_blocked() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        src, dest = td / "t.tar", td / "out"
        _make_tar_slip(src)
        _decompress_archive(src, dest)
        if not (dest / "root" / "ok.txt").is_file():
            fails.append("正常 tar 项应被安全提取")
        if (td / "evil.txt").exists():
            fails.append("tar-slip 越界文件被写入(../../evil.txt)")
    return fails


def test_preprocess_fallback_on_bad_archive() -> list[str]:
    """损坏/危险归档不崩,回退交 binwalk(preprocess 兜底路径)。"""
    fails: list[str] = []
    from firmware_audit.step0.step0_preprocess import preprocess
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        src = td / "t.zip"
        _make_zip_slip(src)  # 合法 zip(含越界项)→ 仍成功解出好项,不会回退
        inputs, skip = preprocess(src, td / "extracted")
        if not skip:
            fails.append(f"含越界项但合法的 zip 应正常解出(skip_binwalk=True): {skip}")
        if not (td / "extracted" / "root" / "ok.txt").is_file():
            fails.append("preprocess 应解出正常项")
    return fails


# ---- C4: resolve_within 收敛原语 ----

def test_resolve_within() -> list[str]:
    """resolve_within 边界契约(C4 收敛的路径穿越判定原语)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        root = Path(_td)
        (root / "sub").mkdir()
        # 正常子路径 → 绝对路径
        if resolve_within(root, "sub") != (root / "sub").resolve():
            fails.append("正常子路径应解析")
        # 反斜杠宽容
        if resolve_within(root, "sub\\deep") != (root / "sub" / "deep").resolve():
            fails.append("反斜杠应宽容换算")
        # 根自身(./空串)与子路径 → 放行;越界/空 None → None
        if resolve_within(root, ".") != root.resolve():
            fails.append("'.' 应解析为根(containment 允许等于根)")
        for bad in ("", "/", "..", "../x", "sub/../../x", "C:\\evil"):
            if resolve_within(root, bad) is not None:
                fails.append(f"越界/空引用应按 None 拒绝: {bad!r}")
        if resolve_within(root, None) is not None:
            fails.append("None 引用应按 None 拒绝")
    return fails


# ---- Bug A: analysis 工具路径越界读 ----

def test_resolve_analysis_blocks_escape() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as _td:
        td = Path(_td)
        proc = td / "process"
        ana = proc / "analysis" / "unitree" / "bin"
        ana.mkdir(parents=True)
        (ana / "idlc.imports.json").write_text("[]", encoding="utf-8")
        # 越界目标文件(process/analysis 之外可读的文件)
        (proc.parent / "host_secret.json").write_text("secret", encoding="utf-8")
        ctx = ToolContext(process_dir=proc)

        ok = resolve_analysis_file(ctx, "unitree/bin/idlc", ".imports.json")
        if ok is None:
            fails.append("正常相对路径应解析到 analysis 工件")

        # 相对越界 ../ 指向 analysis 上级
        esc = resolve_analysis_file(ctx, "../host_secret", ".json")
        if esc is not None:
            fails.append(f"../ 越界应按 None 拒绝: {esc}")

        # 绝对路径(宿主任意文件)
        abs_file = proc.parent / "host_secret.json"
        esc2 = resolve_analysis_file(ctx, str(abs_file).replace("\\", "/"), "")
        if esc2 is not None:
            fails.append(f"绝对路径应按 None 拒绝: {esc2}")
        # 绝对路径(Unix 形态根)
        if resolve_analysis_file(ctx, "/etc/passwd", ".c") is not None:
            fails.append("根绝对路径应按 None 拒绝")
    return fails


# ---- Bug C: gitleaks shell 注入 ----

def test_gitleaks_cmd_quotes_source() -> list[str]:
    fails: list[str] = []
    benign = build_gitleaks_cmd("/work/extracted/unitree/bin/idlc")
    if "--source /work/extracted/unitree/bin/idlc " not in benign:
        fails.append(f"良性 source 应保留未转义(路径如常): {benign}")
    # 含 shell 元字符的 source 必须被单引号包裹
    evil = ';$(id) &`cat /etc/passwd`'
    cmd = build_gitleaks_cmd(evil)
    if f"'--source {evil}" not in cmd and f"'{evil}'" not in cmd:
        fails.append(f"含元字符的 source 必须被 shlex.quote 包裹: {cmd}")
    # 元字符不得裸露在引号外(可执行)
    if cmd.count("$(id)") != 1 or cmd.index("$(id)") < cmd.index("--source"):
        fails.append("转义后元字符应整体保留在 source 的引号内")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("zip_slip_blocked", test_zip_slip_blocked),
        ("tar_slip_blocked", test_tar_slip_blocked),
        ("preprocess_fallback_on_bad_archive", test_preprocess_fallback_on_bad_archive),
        ("resolve_analysis_blocks_escape", test_resolve_analysis_blocks_escape),
        ("gitleaks_cmd_quotes_source", test_gitleaks_cmd_quotes_source),
        ("resolve_within", test_resolve_within),
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
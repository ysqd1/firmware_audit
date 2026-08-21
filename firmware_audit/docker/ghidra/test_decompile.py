"""Ghidra 反编译测试脚本。

用法:
    python test_decompile.py <elf_file>

验证:
    1. Ghidra 镜像可运行 analyzeHeadless
    2. ExtractInfo.py 脚本正确产出 4 个文件
    3. 产出文件内容非空且格式正确
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

GHIDRA_IMAGE = "ghidra"
_CONT_INPUT = "/work/input"
_CONT_OUTPUT = "/work/output"
_CONT_PROJECT = "/work/project"


def main():
    if len(sys.argv) < 2:
        print("用法: python test_decompile.py <elf_file>")
        sys.exit(1)

    elf_file = Path(sys.argv[1]).resolve()
    if not elf_file.is_file():
        print(f"错误: 文件不存在: {elf_file}")
        sys.exit(1)

    print(f"[测试] ELF 文件: {elf_file}")
    print(f"[测试] 大小: {elf_file.stat().st_size} bytes")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        project_dir = tmpdir / "project"
        project_dir.mkdir()
        output_dir = tmpdir / "output"
        output_dir.mkdir()

        args = [
            _CONT_PROJECT, "audit",
            "-import", f"{_CONT_INPUT}/{elf_file.name}",
            "-postScript", "ExtractInfo.py", _CONT_OUTPUT,
            "-deleteProject",
            "-overwrite",
            "-scriptPath", "/opt/ghidra/Ghidra/Features/Decompiler/ghidra_scripts",
        ]

        import subprocess
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{elf_file.parent}:{_CONT_INPUT}",
            "-v", f"{output_dir}:{_CONT_OUTPUT}",
            "-v", f"{project_dir}:{_CONT_PROJECT}",
            GHIDRA_IMAGE,
        ] + args

        print(f"[测试] 运行: docker run --rm -v ... ghidra analyzeHeadless ...")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        print(f"[测试] 退出码: {proc.returncode}")
        if proc.returncode != 0:
            print(f"[测试] 失败!")
            print(f"[测试] stdout (最后500字符):\n{proc.stdout[-500:]}")
            print(f"[测试] stderr (最后500字符):\n{proc.stderr[-500:]}")
            sys.exit(1)

        # 验证产出
        print(f"\n[验证] 检查产出文件...")
        expected = ["decompiled.c", "functions.json", "imports.json", "symbols.json"]
        all_ok = True

        for name in expected:
            fpath = output_dir / name
            if not fpath.exists():
                print(f"  [缺失] {name}")
                all_ok = False
                continue

            size = fpath.stat().st_size
            if size == 0:
                print(f"  [空文件] {name} (0 bytes)")
                all_ok = False
                continue

            print(f"  [OK] {name} ({size} bytes)")

            # 检查 JSON 格式
            if name.endswith(".json"):
                try:
                    data = json.loads(fpath.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        print(f"       -> {len(data)} 条记录")
                    elif isinstance(data, dict):
                        print(f"       -> {len(data)} 个键")
                except json.JSONDecodeError as e:
                    print(f"  [JSON错误] {name}: {e}")
                    all_ok = False

            # 检查 decompiled.c 前几行
            if name == "decompiled.c":
                lines = fpath.read_text(encoding="utf-8").splitlines()
                print(f"       -> {len(lines)} 行")
                if lines:
                    print(f"       -> 首行: {lines[0][:80]}")

        # 拷贝产出到当前目录供检查
        dest = Path("test_output")
        dest.mkdir(exist_ok=True)
        for name in expected:
            src = output_dir / name
            if src.exists():
                import shutil
                shutil.copy2(src, dest / name)

        print(f"\n[结果] 产出已拷贝到: {dest.resolve()}")
        if all_ok:
            print("[结果] 全部通过! Ghidra 反编译 + ExtractInfo.py 工作正常。")
        else:
            print("[结果] 部分失败,请检查上方日志。")
            sys.exit(1)


if __name__ == "__main__":
    main()

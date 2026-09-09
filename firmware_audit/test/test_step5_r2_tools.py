"""票01 r2 工具族 execute 层单测(离线,mock 沙箱)。

只测外部行为(spec Testing Decisions Seam 1):给定工具入参与工作区状态,
断言 ToolResult 的 ok/text/data 与"接口边界本身"(run_in_sandbox 的命令行/
超时/entrypoint)。覆盖:
  - r2_list_functions:aflj 命令 + timeout=600;超时/未命中文案引导降级
    r2_disassemble_function 便宜路径;非 ELF/路径越界引导性 ok=False 零容器
  - r2_disassemble_function:af+pdf 命令;未命中附函数名提示(第二次 f 命令);
    危险字符目标在工具层拒绝(命令拼接面)
  - 非 ELF 守卫同款复用于 r2_disassemble_function

mock 补丁点:r2 族共享名 run_in_sandbox 在 r2_base 命名空间(经 run_r2 调用)。
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import r2_base
from firmware_audit.step5_agent.providers.tools.base import ToolContext
from firmware_audit.step5_agent.providers.tools.r2_disassemble_function import (
    R2DisassembleFunctionTool,
)
from firmware_audit.step5_agent.providers.tools.r2_list_functions import (
    R2ListFunctionsTool,
)

_ELF_MAGIC = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 8


def _make_ctx(root: Path) -> ToolContext:
    """最小工作区:extracted/bin/app 是真 ELF(magic 对),bin/note.txt 非 ELF。"""
    (root / "extracted" / "bin").mkdir(parents=True, exist_ok=True)
    (root / "extracted" / "bin" / "app").write_bytes(_ELF_MAGIC)
    (root / "extracted" / "bin" / "note.txt").write_text("hello", encoding="utf-8")
    return ToolContext(process_dir=root)


class _SandboxSpy:
    """run_in_sandbox 替身:按序回放 (rc, out, err),记录每次调用的 args/timeout。"""

    def __init__(self, *replays):
        self.replays = list(replays)
        self.calls: list[dict] = []

    def __call__(self, args, entrypoint, ctx, timeout=120, extra_mounts=None):
        self.calls.append({"args": list(args), "entrypoint": entrypoint,
                           "timeout": timeout})
        return self.replays.pop(0) if self.replays else (0, "", "")

    @property
    def last(self) -> dict:
        if not self.calls:
            raise AssertionError("不应有容器调用")
        return self.calls[-1]


def _install(spy: _SandboxSpy):
    """补丁 r2_base.run_in_sandbox,返回恢复函数(try/finally 配对)。"""
    orig = r2_base.run_in_sandbox
    r2_base.run_in_sandbox = spy
    return lambda: setattr(r2_base, "run_in_sandbox", orig)


def test_list_functions_ok_and_timeout() -> list[str]:
    fails: list[str] = []
    aflj = json.dumps([
        {"name": "main", "offset": "0x00400890", "size": 64},
        {"name": "fcn.00400900", "offset": "0x00400900", "size": 128},
    ])
    spy = _SandboxSpy((1, "WARN anal\n" + aflj, ""))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            r = R2ListFunctionsTool(ctx).execute(file_ref="bin/app")
    finally:
        restore()
    if not r.ok:
        fails.append(f"aflj 应以 stdout 解析为准(rc=1 不可靠): {r.error}")
        return fails
    if len(r.data) != 2 or r.data[0]["name"] != "main":
        fails.append(f"data 解析异常: {r.data}")
    if "bin/app" not in r.text or "2 个函数" not in r.text:
        fails.append(f"text 应汇总函数数: {r.text[:120]}")
    # 接口边界:entrypoint=r2、-A + aflj、timeout=600(ADR-0010 定值)
    if spy.last["entrypoint"] != "r2":
        fails.append(f"entrypoint 应为 r2: {spy.last['entrypoint']}")
    if spy.last["timeout"] != 600:
        fails.append(f"aflj timeout 应为 600(ADR-0010): {spy.last['timeout']}")
    args = spy.last["args"]
    if args[0] != "-q" or "-A" not in args or "aflj" not in args:
        fails.append(f"命令应含 -q/-A/aflj: {args}")
    if not args[-1].endswith("/work/extracted/bin/app"):
        fails.append(f"目标容器路径应在末尾: {args}")
    return fails


def test_list_functions_failure_guides_downgrade() -> list[str]:
    """超时/无输出 → ok=False,文案引导 r2_disassemble_function 便宜路径。"""
    fails: list[str] = []
    for rc, out, err in ((124, "", "docker run timed out after 600s"), (0, "", "")):
        spy = _SandboxSpy((rc, out, err))
        restore = _install(spy)
        try:
            with tempfile.TemporaryDirectory() as td:
                ctx = _make_ctx(Path(td))
                r = R2ListFunctionsTool(ctx).execute(file_ref="bin/app")
        finally:
            restore()
        if r.ok:
            fails.append(f"rc={rc} 无解析结果应 ok=False")
        elif "r2_disassemble_function" not in (r.error or ""):
            fails.append(f"失败文案应引导降级单函数路径: {r.error}")
    return fails


def test_list_functions_non_elf_and_escape() -> list[str]:
    """非 ELF/路径越界/文件缺失 → 引导性 ok=False,零容器调用。"""
    fails: list[str] = []
    spy = _SandboxSpy()
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            t = R2ListFunctionsTool(ctx)
            r = t.execute(file_ref="bin/note.txt")
            if r.ok or "不是 ELF" not in (r.error or ""):
                fails.append(f"非 ELF 应引导性拒绝: {r.error}")
            r2 = t.execute(file_ref="../../etc/passwd")
            if r2.ok or "非法路径" not in (r2.error or ""):
                fails.append(f"越界应拒绝: {r2.error}")
            r3 = t.execute(file_ref="bin/missing")
            if r3.ok or "不存在" not in (r3.error or ""):
                fails.append(f"缺失文件应引导: {r3.error}")
    finally:
        restore()
    if spy.calls:
        fails.append(f"守卫拒绝路径不应触发容器: {spy.calls}")
    return fails


def test_disassemble_ok_and_miss_hint() -> list[str]:
    fails: list[str] = []
    # 命中:pdf 产出反汇编
    spy = _SandboxSpy((0, "/  (fcn) main 64\n0x00400890  push rbp\n", ""))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            r = R2DisassembleFunctionTool(ctx).execute(file_ref="bin/app",
                                                       func_or_addr="sym.main")
            # 未命中:第一次 pdf 空 → 第二次 f 列 flags 附提示
            spy2 = _SandboxSpy((0, "", ""), (0,
                "0x00400890 512 sym.main\n0x00401000 16 sym.imp.system\n"
                "0x00402000 32 sym.dohicky\n", ""))
            r2_base.run_in_sandbox = spy2  # 换替身不动恢复函数(同一 orig)
            r2 = R2DisassembleFunctionTool(ctx).execute(file_ref="bin/app",
                                                        func_or_addr="0xdeadbeef")
    finally:
        restore()
    if not r.ok:
        fails.append(f"pdf 命中应 ok: {r.error}")
    elif "push rbp" not in r.text:
        fails.append("text 应含反汇编体")
    else:
        cmd = " ".join(spy.last["args"])
        if "af @ sym.main" not in cmd or "pdf @ sym.main" not in cmd:
            fails.append(f"命令应为 af+pdf 便宜路径: {cmd}")

    if r2.ok:
        fails.append("未命中应 ok=False")
    elif "sym.imp.system" not in (r2.error or "") or "sym.main" not in (r2.error or ""):
        fails.append(f"未命中应附函数名提示: {r2.error}")
    if len(spy2.calls) != 2:
        fails.append(f"未命中应触发一次 f 提示调用: {spy2.calls}")
    else:
        hint_cmd = " ".join(spy2.calls[1]["args"])
        if hint_cmd.count("-c") != 1 or " f" not in hint_cmd:
            fails.append(f"提示调用应为 f(flags)命令: {hint_cmd}")
        if spy2.calls[1]["timeout"] > r2_base.R2_DEFAULT_TIMEOUT:
            fails.append("提示调用不应超过廉价超时")
    return fails


def test_disassemble_rejects_unsafe_target() -> list[str]:
    """危险字符目标(命令拼接面)工具层拒绝,零容器调用。"""
    fails: list[str] = []
    spy = _SandboxSpy()
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            t = R2DisassembleFunctionTool(ctx)
            for evil in ("sym.a; pdf @ sym.b", "sym.a;qq", "a b", "$(id)", "sym.\nx"):
                r = t.execute(file_ref="bin/app", func_or_addr=evil)
                if r.ok:
                    fails.append(f"危险目标应拒绝: {evil!r}")
    finally:
        restore()
    if spy.calls:
        fails.append(f"拒绝路径不应触发容器: {spy.calls}")
    return fails


def test_disassemble_non_elf_guard() -> list[str]:
    fails: list[str] = []
    spy = _SandboxSpy()
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td))
            r = R2DisassembleFunctionTool(ctx).execute(file_ref="bin/note.txt",
                                                       func_or_addr="sym.main")
    finally:
        restore()
    if r.ok or "不是 ELF" not in (r.error or ""):
        fails.append(f"非 ELF 应引导性拒绝: {r.error}")
    if spy.calls:
        fails.append("非 ELF 不应触发容器")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("list_functions_ok_and_timeout", test_list_functions_ok_and_timeout),
        ("list_functions_failure_guides_downgrade", test_list_functions_failure_guides_downgrade),
        ("list_functions_non_elf_and_escape", test_list_functions_non_elf_and_escape),
        ("disassemble_ok_and_miss_hint", test_disassemble_ok_and_miss_hint),
        ("disassemble_rejects_unsafe_target", test_disassemble_rejects_unsafe_target),
        ("disassemble_non_elf_guard", test_disassemble_non_elf_guard),
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

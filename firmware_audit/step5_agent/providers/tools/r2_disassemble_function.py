"""r2_disassemble_function:按函数名/地址读单函数反汇编(r2 pdf,现算)。

单函数 af 便宜路径(ADR-0010):不为读一个函数付全量分析(aflj/aaa)或
Ghidra。未命中时附该文件前 N 个函数名提示(照 find_decompiled_function 对
.c 的先例),LLM 不烧迭代轮次即可自我纠正;提示名来自符号表 flags(f 命令,
不触发分析)。
"""
from __future__ import annotations

from .base import AgentTool, ToolResult
from .r2_base import (
    container_elf_path,
    elf_guard,
    run_r2,
    sanitize_func_or_addr,
)

_HINT_LIMIT = 20  # 未命中提示附的函数名上限(与 find_decompiled_function 的 30 对齐取更省值)


class R2DisassembleFunctionTool(AgentTool):
    name = "r2_disassemble_function"
    description = ("按函数名或地址读单个函数的反汇编(r2 pdf 现算,秒级)。"
                   "func_or_addr 接受符号名(sym.main / sym.imp.system / fcn.<hex>)"
                   "或地址(0x…)。想看反编译 C 用 find_decompiled_function(读缓存)。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的 ELF 路径"},
        "func_or_addr": {"type": "str", "required": True,
                         "desc": "符号名或地址,如 sym.imp.system / 0x00400890"},
    }

    def _run(self, file_ref: str, func_or_addr: str) -> ToolResult:
        guard = elf_guard(self.ctx, file_ref)
        if guard:
            return ToolResult(ok=False, text="", error=guard)
        target = func_or_addr.strip()
        if not sanitize_func_or_addr(target):
            return ToolResult(
                ok=False, text="",
                error=(f"非法目标 {func_or_addr!r}(只接受符号名 sym.* / fcn.* / 地址 0x*,"
                       "不含空格与特殊字符)"),
            )
        cpath = container_elf_path(self.ctx, file_ref)
        # af @ 目标 先做单函数分析(无全量分析时的便宜路径),pdf 随后反汇编
        rc, out, err = run_r2(
            self.ctx, cpath, ["-c", f"af @ {target}; pdf @ {target}"],
        )
        body = (out or "").strip()
        if body and "Cannot" not in body[:200] and not body.startswith("ERROR"):
            return ToolResult(
                ok=True,
                text=f"{file_ref} :: {target} 反汇编({len(body.splitlines())} 行):\n{body}",
                data={"file": file_ref, "target": target},
            )
        # 未命中:附该文件的符号名提示(f 列 flags,不触发分析,秒级)
        names = _flag_names(self.ctx, cpath)
        hint = f"; 该文件的函数/符号(前{_HINT_LIMIT}): {', '.join(names)}" if names else ""
        return ToolResult(
            ok=False, text="",
            error=(f"'{target}' 反汇编无产出(rc={rc}): {(err or body)[:120]}{hint};"
                   "名字来自函数清单(r2_list_functions)或 .functions.json,勿凭空拼凑"),
        )


def _flag_names(ctx, cpath: str, limit: int = _HINT_LIMIT) -> list[str]:
    """r2 f(flags)输出 → 函数/符号名列表(sym.* / fcn.*),供未命中提示。"""
    _rc, out, _err = run_r2(ctx, cpath, ["-c", "f"])
    names: list[str] = []
    for line in (out or "").splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0].startswith("0x") and parts[-1].startswith(("sym.", "fcn.", "method.")):
            name = parts[-1]
            if name not in names:
                names.append(name)
                if len(names) >= limit:
                    break
    return names

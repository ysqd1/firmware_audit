"""find_decompiled_function:读已产出的反编译 C,按函数名切片段。

只读缓存、只检索:在既有 .c 边车里**定位**函数,本身不触发任何反编译。
反编译的唯一入口是 ghidra_decompile(升级层,幂等缓存);缺 .c 时的报错
文案引导升级链(ADR-0010 票04):先 r2 层查证,信息不够才反编译。
名字里的 find 强调其定位:在既有 .c 里**检索**函数,而非执行反编译。

命名体系约束(2026-08-19 错误研究 E1 落地):
  只认 Ghidra 反编译产物里的函数名——真实符号名(如 main/CallSystem)
  或 FUN_<8位十六进制地址>。r2_xref_query 返回的 r2 命名(fcn.<hex>/
  mangled C++ 方法名)不能直接传入,需先经 functions.json 按 callees 反查。
"""
from __future__ import annotations

import re

from .base import AgentTool, ToolResult, resolve_analysis_file

_FUNC_HEADER = re.compile(r"^// ===== Function: (.+?) @ ([0-9a-fA-F]+) =====")


def extract_function(c_path, func_name: str) -> str | None:
    """切出单个函数:从 `// ===== Function: name @ addr =====` 到下一个函数头。

    同名函数逐个追加(Ghidra 通常唯一,防御性处理)。
    """
    lines = c_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    out: list[str] = []
    in_target = False
    for line in lines:
        m = _FUNC_HEADER.match(line.strip())
        if m:
            if in_target:
                break
            in_target = m.group(1) == func_name
            if in_target:
                out.append(line)
        elif in_target:
            out.append(line)
    return "".join(out) if out else None


class FindDecompiledFunctionTool(AgentTool):
    name = "find_decompiled_function"
    description = ("检索某 ELF 已反编译的函数 C 代码(读反编译边车切片,毫秒级,不重跑 Ghidra)。"
                   "func_name 只认 Ghidra 命名:真实符号名或 FUN_<8位hex>;r2_xref_query 返回的 "
                   "fcn.<hex>/mangled 方法名不能直接用,先读 functions.json 按 callees 反查真实名。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的 ELF 路径"},
        "func_name": {"type": "str", "required": True,
                      "desc": "Ghidra 函数名(真实符号或 FUN_<8位hex>;未知名先读 .functions.json 反查)"},
    }

    def _run(self, file_ref: str, func_name: str) -> ToolResult:
        path = resolve_analysis_file(self.ctx, file_ref, ".c")
        if path is None:
            return ToolResult(
                ok=False, text="",
                error=(f"未找到反编译产物 analysis/{file_ref}.c(没人反编译过或超时零产出)。"
                       "升级链: 先用 r2 层查证(r2_list_functions/r2_disassemble_function/"
                       "r2_xref_query);r2 信息不够时用 ghidra_decompile 反编译该文件后重查"),
            )
        body = extract_function(path, func_name)
        if body is None:
            # 给 LLM 一个可操作的错误:附函数名供其改查清单
            names = _list_func_names(path, limit=30)
            hint = f"; 该文件共有这些函数(前30): {', '.join(names)}" if names else ""
            return ToolResult(
                ok=False, text="",
                error=(f"函数 '{func_name}' 不在 {path.name}{hint};"
                       "若是 fcn./mangled 名请经 functions.json 按 callees 反查真实名"
                       "(老工件有 functions.json;新反编译产物用 r2_list_functions 现算清单)"),
            )
        return ToolResult(ok=True, text=body, data={"func_name": func_name, "file": file_ref})


def _list_func_names(c_path, limit: int) -> list[str]:
    names: list[str] = []
    for line in c_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _FUNC_HEADER.match(line.strip())
        if m:
            names.append(m.group(1))
            if len(names) >= limit:
                break
    return names

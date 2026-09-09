"""r2_list_functions:对 ELF 现算函数清单(r2 aflj,JSON 输出)。

r2 两级分析漏斗的廉价层入口(ADR-0010):查函数清单不必先付分钟级 Ghidra。
aflj 前需全量分析(-A),大库分钟级,成本预算进超时 R2_ANALYZE_TIMEOUT=600;
超时/未命中的错误文案引导降级到单函数 af 便宜路径(r2_disassemble_function)。
"""
from __future__ import annotations

from .base import AgentTool, ToolResult
from .r2_base import (
    R2_ANALYZE_TIMEOUT,
    container_elf_path,
    elf_guard,
    parse_r2_json,
    run_r2,
)


class R2ListFunctionsTool(AgentTool):
    name = "r2_list_functions"
    description = ("列 ELF 的函数清单(r2 aflj 现算,含函数名/地址/大小,JSON)。"
                   "需全量分析,大文件可达分钟级;超时或失败时改用 "
                   "r2_disassemble_function 按符号名/地址直接反汇编单函数(便宜路径)。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的 ELF 路径"},
    }

    def _run(self, file_ref: str) -> ToolResult:
        guard = elf_guard(self.ctx, file_ref)
        if guard:
            return ToolResult(ok=False, text="", error=guard)
        cpath = container_elf_path(self.ctx, file_ref)
        rc, out, err = run_r2(
            self.ctx, cpath, ["-A", "-c", "aflj"], timeout=R2_ANALYZE_TIMEOUT,
        )
        # r2 退出码不可靠(r2_xref_query 同款纪律):以 stdout JSON 解析为准
        data = parse_r2_json(out)
        if data is None:
            return ToolResult(
                ok=False, text="",
                error=(f"r2 函数清单失败(rc={rc}): {(err or out)[:200]}。"
                       "全量分析超时或输出异常时,改用 r2_disassemble_function "
                       "按符号名(sym.*)或地址(0x*)反汇编单函数(af 便宜路径,秒级)。"),
            )
        if not data:
            return ToolResult(
                ok=True, text=f"{file_ref} 无函数条目(stripped/静态链接或加壳特征)",
                data=[],
            )
        lines = [
            f"{d.get('offset', '?')}  {d.get('name', '?')}  size={d.get('size', '?')}"
            for d in data if isinstance(d, dict)
        ]
        return ToolResult(
            ok=True,
            text=f"{file_ref} 共 {len(data)} 个函数:\n" + "\n".join(lines),
            data=data,
        )

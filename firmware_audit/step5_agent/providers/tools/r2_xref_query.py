"""r2_xref_query:沙箱容器内 radare2 查交叉引用(axtj JSON 输出)。

原名 xref_query(票01 更名,行为不变):与 r2_list_functions /
r2_disassemble_function 同族命名,前缀 r2_* 表示"现算"(ADR-0010)。

补 Ghidra 导出盲区:imports.json 的 call_sites 为空时,用 r2 确认调用链。
-A 全分析在中等 ELF 上秒级~十秒级;大库可能到分钟级,timeout 兜底。
"""
from __future__ import annotations

from .base import AgentTool, ToolResult
from .cli_base import container_path
from .r2_base import parse_r2_json, run_r2


class R2XrefQueryTool(AgentTool):
    name = "r2_xref_query"
    description = ("查某符号(如 sym.imp.system)在 ELF 里被谁调用(axtj 交叉引用,JSON)。"
                   "imports 查到危险函数但 call_sites 为空时用它定位调用者。"
                   "注意: 只支持函数/导入符号,数据符号(全局变量/OBJ)不支持;"
                   "返回的函数名是 r2 命名(fcn.<hex>/mangled 方法名),"
                   "不能直接传给 find_decompiled_function,需经 functions.json 按 callees 反查。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的 ELF 路径"},
        "symbol": {"type": "str", "required": True,
                   "desc": "符号名(如 sym.imp.system;裸名自动补 sym.imp. 前缀)"},
    }

    def _run(self, file_ref: str, symbol: str) -> ToolResult:
        cpath = container_path(self.ctx, file_ref)
        if cpath is None:
            return ToolResult(ok=False, text="", error=f"非法路径: {file_ref}")
        sym = symbol.strip()
        # axtj 查 data/code 引用;符号名宽容补前缀
        if not (sym.startswith("sym.") or sym.startswith("fcn.") or sym.startswith("sub.")):
            sym = f"sym.imp.{sym}"
        rc, out, err = run_r2(
            self.ctx, cpath,
            # -e bin.relocs.apply=true: 2026-08-22 实发 r2 对未应用重定位的
            # ELF 报 "WARN: Relocs has not been applied" 后 axtj 无输出;
            # r2 官方提示即加此参数(或 bin.cache),应用重定位后 xref 才可靠
            ["-A", "-e", "bin.relocs.apply=true", "-c", f"axtj {sym}"],
            timeout=180,
        )
        # r2 退出码不可靠(命令成功也常返回 1,部分场景甚至 124),
        # 判定以 stdout JSON 解析结果为准
        data = parse_r2_json(out)
        if data is None:
            # r2 对 data 符号(OBJ,如全局变量 video_device_path)的 axt 查询
            # 一律报 "ERROR: Invalid argument"(实测 2026-08-22,axt/axtj 同)
            # —— 这不是路径/参数错误,是 r2 只支持函数/导入符号的 xref。
            # 给 LLM 可操作的指引,避免它反复重试同样的 data 符号查询。
            if "Invalid argument" in (err or "") or "Invalid argument" in out:
                return ToolResult(
                    ok=False, text="",
                    error=(f"符号 {symbol} 可能是数据符号(全局变量/OBJ),"
                           "axtj 仅支持函数或导入符号(如 sym.imp.system)的交叉引用;"
                           "查全局变量的引用请改用 strings_query(带 refs)或读 "
                           "<file>.strings.json/.functions.json。"),
                )
            return ToolResult(ok=False, text="", error=f"r2 无输出或无法解析(rc={rc}): {(err or out)[:200]}")
        if not data:
            return ToolResult(ok=True, text=f"{symbol} 无交叉引用(未被调用或符号不存在)", data=[])
        lines = [
            f"{d.get('from', '?')}  in {d.get('fcn_name') or d.get('function', '?')}  ({d.get('type', '?')})"
            for d in data
        ]
        return ToolResult(
            ok=True,
            text=f"{symbol} 交叉引用 {len(data)} 条:\n" + "\n".join(lines),
            data=data,
        )

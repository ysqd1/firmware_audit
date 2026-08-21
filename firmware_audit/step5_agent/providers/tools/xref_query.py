"""xref_query:沙箱容器内 radare2 查交叉引用(axtj JSON 输出)。

补 Ghidra 导出盲区:imports.json 的 call_sites 为空时,用 r2 确认调用链。
-A 全分析在中等 ELF 上秒级~十秒级;大库可能到分钟级,timeout 兜底。
"""
from __future__ import annotations

import json

from .base import AgentTool, ToolResult
from .cli_base import container_path, run_in_sandbox


class XrefQueryTool(AgentTool):
    name = "xref_query"
    description = ("查某符号(如 sym.imp.system)在 ELF 里被谁调用(axtj 交叉引用,JSON)。"
                   "imports 查到危险函数但 call_sites 为空时用它定位调用者。"
                   "注意:返回的函数名是 r2 命名(fcn.<hex>/mangled 方法名),"
                   "不能直接传给 find_decompiled_function,需经 functions.json 按 callees 反查。")
    params_doc = 'Action Input: {"file_ref": "unitree/bin/idlc", "symbol": "sym.imp.system"}'

    def _run(self, file_ref: str, symbol: str) -> ToolResult:
        cpath = container_path(self.ctx, file_ref)
        if cpath is None:
            return ToolResult(ok=False, text="", error=f"非法路径: {file_ref}")
        sym = symbol.strip()
        # axtj 查 data/code 引用;符号名宽容补前缀
        if not (sym.startswith("sym.") or sym.startswith("fcn.") or sym.startswith("sub.")):
            sym = f"sym.imp.{sym}"
        rc, out, err = run_in_sandbox(
            ["-q", "-A", "-c", f"axtj {sym}", cpath],
            "r2", self.ctx, timeout=180,
        )
        # r2 退出码不可靠(命令成功也常返回 1,部分场景甚至 124),
        # 判定以 stdout JSON 解析结果为准
        data = _parse_r2_json(out)
        if data is None:
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


def _parse_r2_json(out: str) -> list | None:
    """r2 stdout 末尾才是命令结果;逐行回退找 JSON 数组。"""
    for line in reversed(out.strip().splitlines()):
        line = line.strip()
        if line.startswith("["):
            try:
                data = json.loads(line)
                return data if isinstance(data, list) else None
            except json.JSONDecodeError:
                continue
    return None

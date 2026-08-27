"""read_file:读 process/ 下工件文件(路径白名单防越界)。

Agent 间"工件是唯一契约"的回查机制:下游 Agent 用它按需拉取
attack_surface.json / findings.json / 反编译产物细节,不把整个工件塞进对话。
"""
from __future__ import annotations

from pathlib import Path

from .base import AgentTool, ToolResult

# 单次读取行数上限:防 Agent 一次把大工件全量读进上下文
DEFAULT_LINES = 200


class ReadFileTool(AgentTool):
    name = "read_file"
    description = "读取 process/ 目录下的工件文件(分页,默认前 200 行):前序 Agent 的 JSON 工件、报告、反编译 .c 等。"
    params_doc = ('Action Input: {"path": "fileinfo.json", "offset": 0, "limit": 50} '
                  "—— path 相对 process/(示例为固定存在的文件,请按需替换为目标工件路径);offset/limit 可选")

    def _run(self, path: str, offset: int = 0, limit: int = DEFAULT_LINES) -> ToolResult:
        root = self.ctx.process_dir.resolve()
        p = (Path(path) if Path(path).is_absolute() else root / path).resolve()
        if p != root and root not in p.parents:
            return ToolResult(ok=False, text="", error=f"路径越界: {path}(只允许 process/ 之下)")
        if not p.exists():
            return ToolResult(ok=False, text="", error=f"文件不存在: {path}")
        if p.is_dir():
            items = sorted(x.name for x in p.iterdir())
            return ToolResult(ok=True, text=f"{path}/ 是目录: {', '.join(items[:50])}", data=items)

        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(lines)
        chunk = lines[offset : offset + limit]
        if not chunk and total:
            return ToolResult(
                ok=False, text="",
                error=f"offset={offset} 超出文件总行数 {total}",
            )
        header = f"[{path} 第 {offset + 1}-{min(offset + limit, total)} 行,共 {total} 行]\n"
        return ToolResult(ok=True, text=header + "\n".join(chunk), data={"total_lines": total})

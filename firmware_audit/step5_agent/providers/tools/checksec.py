"""checksec:沙箱容器内跑 slimm609/checksec,输出二进制保护属性 JSON。"""
from __future__ import annotations

import json

from .base import AgentTool, ToolResult
from .cli_base import container_path, run_in_sandbox

# 保护属性缺陷的判定规则(用于 text 摘要的人读排序,不动原始 JSON)
_FIELD_ORDER = ["relro", "canary", "nx", "pie", "fortify", "symbols"]


class ChecksecTool(AgentTool):
    name = "checksec"
    description = "查 ELF 的安全保护属性(RELRO/Canary/NX/PIE/Fortify)。可利用性评估:NX 关闭 + 无 PIE → 上调。"
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的 ELF 路径"},
    }

    def _run(self, file_ref: str) -> ToolResult:
        cpath = container_path(self.ctx, file_ref)
        if cpath is None:
            return ToolResult(ok=False, text="", error=f"非法路径: {file_ref}")
        rc, out, err = run_in_sandbox(
            [f"--file={cpath}", "--format=json"], "checksec", self.ctx, timeout=60,
        )
        if rc != 0:
            return ToolResult(ok=False, text="", error=f"checksec 退出码 {rc}: {err.strip()[:300]}")
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return ToolResult(ok=False, text="", error=f"checksec 输出非 JSON: {out[:200]}")
        # --format=json 输出 {"/容器路径": {...}} 或单元素数组,统一取属性 dict
        if isinstance(data, dict):
            entry = next(iter(data.values()), {})
        elif isinstance(data, list) and data:
            entry = data[0]
        else:
            entry = {}
        summary = "  ".join(f"{k}={entry.get(k, '?')}" for k in _FIELD_ORDER if k in entry)
        return ToolResult(ok=True, text=f"{file_ref}: {summary}", data=entry)

"""strings_query:读 Step4 strings.json,按正则检索可疑字符串。"""
from __future__ import annotations

import json
import re

from .base import AgentTool, ToolResult, resolve_analysis_file

# 内置检索模式;Agent 也可传自定义 regex(pattern 以 "re:" 前缀)
STRING_PATTERNS: dict[str, str] = {
    "url": r"https?://[^\s\"'<>]+",
    "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    # 硬编码口令形态:password=xxx / pwd: xxx / token=xxx(等号或冒号后跟非空白)
    "password": r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey)\b\s*[=:]\s*\S{3,}",
    "key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    # /etc/shadow 条目形态:用户:$算法$
    "shadow": r"(?m)^[a-z_][a-z0-9_-]{0,31}:\$[0-9]\$",
    # 调试后门形态:以冒号分隔的空口令字段
    "empty_password": r"(?i)\b(ak=\|sk=|token=|secret=)\s*$",
}


class StringsQueryTool(AgentTool):
    name = "strings_query"
    description = "按模式检索 ELF 字符串表(Step4 提取,含地址与引用函数):url / ip / password / key / shadow / empty_password,或自定义正则。"
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的 ELF 路径"},
        "pattern": {"type": "str", "required": True,
                    "desc": "内置模式: url/ip/password/key/shadow/empty_password;或 're:<正则>'"},
        "max_results": {"type": "int", "default": 30, "desc": "命中上限"},
    }

    def _run(self, file_ref: str, pattern: str, max_results: int = 30) -> ToolResult:
        path = resolve_analysis_file(self.ctx, file_ref, ".strings.json")
        if path is None:
            return ToolResult(
                ok=False, text="",
                error=f"未找到 analysis/{file_ref}.strings.json(仅 ELF 有字符串表)",
            )
        rx = self._compile(pattern)
        if rx is None:
            return ToolResult(
                ok=False, text="",
                error=f"未知模式 '{pattern}';内置: {', '.join(STRING_PATTERNS)} 或 're:<正则>'",
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        strings = data.get("strings", []) if isinstance(data, dict) else data

        hits = []
        for s in strings:
            value = s.get("value", "")
            m = rx.search(value)
            if not m:
                continue
            refs = s.get("refs") or []
            ref_funcs = sorted({r.get("function", "") for r in refs if r.get("function")})
            hits.append({
                "address": s.get("address", ""),
                "match": m.group(0),
                "value": value,
                "ref_functions": ref_funcs,
            })
            if len(hits) >= max_results:
                break

        if not hits:
            return ToolResult(ok=True, text=f"{file_ref} 按 '{pattern}' 无命中", data=[])
        lines = [
            f"{h['address']}  {h['match']}"
            + (f"  (引用: {', '.join(h['ref_functions'])})" if h["ref_functions"] else "")
            for h in hits
        ]
        total = len(strings)
        return ToolResult(
            ok=True,
            text=f"命中 {len(hits)}/{total} 条(模式 {pattern}):\n" + "\n".join(lines),
            data=hits,
        )

    @staticmethod
    def _compile(pattern: str):
        if pattern.startswith("re:"):
            try:
                return re.compile(pattern[3:])
            except re.error:
                return None
        p = STRING_PATTERNS.get(pattern)
        return re.compile(p) if p else None

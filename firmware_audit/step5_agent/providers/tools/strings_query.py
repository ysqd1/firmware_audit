"""strings_query:按模式检索二进制字符串表(混合型,ADR-0010 票02)。

边车优先:analysis/<rel>.strings.json 存在则读边车(毫秒级,不调容器)。
缺边车就地对原始二进制跑 r2 izz 兜底(经沙箱,extracted 只读挂载、断网),
**不限 ELF**——izz 对任意 extracted 文件有效,不透明 blob 的字符串审计由此
打通。pattern 过滤(内置模式集 + re: 自定义)在边车路与兜底路同样生效;
内置模式集迁接原 Step4 "ELF 硬编码预扫"的 _TEXT_PATTERNS 家族(private_key/
shadow_hash/wifi_psk/password_kw),批量预扫能力变为按需查询。
"""
from __future__ import annotations

import json
import re

from .base import AgentTool, ToolResult, resolve_analysis_file
from .cli_base import container_path
from .r2_base import parse_r2_json, run_r2

# 内置检索模式;Agent 也可传自定义 regex(pattern 以 "re:" 前缀)。
# wifi_psk/shadow_hash/private_key/password_kw 自 Step4 _TEXT_PATTERNS 迁接
# (票02,bytes → str 形态);url/ip/password/key/shadow/empty_password 为
# 工具既有模式,原样保留(旧调用兼容)。
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
    # ---- Step4 _TEXT_PATTERNS 迁接(查询时过滤取代批量预扫) ----
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY",
    "shadow_hash": r"\$[156]\$[^\s:$]{8,}",
    "wifi_psk": r"(?i)(?:psk|passphrase|wpa-psk|wpa_passphrase|pre-shared[-_]?key)"
                r"\s*[:=]\s*[\"']?[^\s\"'<>]+",
    "password_kw": r"(?i)(?:password|passwd|secret|api[_-]?key|apikey|token|credential)"
                   r"[_A-Z0-9]*\s*[:=]\s*[\"']?[^\s\"'<>]+",
}


class StringsQueryTool(AgentTool):
    name = "strings_query"
    description = ("按模式检索二进制/文件字符串(优先读 analysis 边车,毫秒级;缺边车自动"
                   "对原始文件跑 r2 izz 兜底,非 ELF 也可):url/ip/password/password_kw/"
                   "key/private_key/shadow/shadow_hash/wifi_psk/empty_password,或自定义正则。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的文件路径(不限 ELF)"},
        "pattern": {"type": "str", "required": True,
                    "desc": "内置模式: url/ip/password/password_kw/key/private_key/shadow/"
                            "shadow_hash/wifi_psk/empty_password;或 're:<正则>'"},
        "max_results": {"type": "int", "default": 30, "desc": "命中上限"},
    }

    def _run(self, file_ref: str, pattern: str, max_results: int = 30) -> ToolResult:
        rx = self._compile(pattern)
        if rx is None:
            return ToolResult(
                ok=False, text="",
                error=f"未知模式 '{pattern}';内置: {', '.join(STRING_PATTERNS)} 或 're:<正则>'",
            )
        strings, source = self._load_strings(file_ref)
        if strings is None:
            return ToolResult(
                ok=False, text="",
                error=(f"{file_ref} 既无 analysis/<rel>.strings.json 边车,r2 izz 也未取得"
                       "字符串(文件不存在或 r2 异常)。用 list_files 确认路径;文本类文件可"
                       "直接 read_file 读原文;不透明 blob 先 binwalk_rescan 看签名。"),
            )

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
            return ToolResult(ok=True, text=f"{file_ref} 按 '{pattern}' 无命中({source})", data=[])
        lines = [
            f"{h['address']}  {h['match']}"
            + (f"  (引用: {', '.join(h['ref_functions'])})" if h["ref_functions"] else "")
            for h in hits
        ]
        total = len(strings)
        return ToolResult(
            ok=True,
            text=f"命中 {len(hits)}/{total} 条(模式 {pattern},来源 {source}):\n" + "\n".join(lines),
            data=hits,
        )

    def _load_strings(self, file_ref: str) -> tuple[list | None, str]:
        """边车优先 → (字符串列表, "边车");缺边车 r2 izz 兜底 → (列表, "r2 izz");
        都不可得 → (None, "")。"""
        path = resolve_analysis_file(self.ctx, file_ref, ".strings.json")
        if path is not None:
            data = json.loads(path.read_text(encoding="utf-8"))
            strings = data.get("strings", []) if isinstance(data, dict) else data
            return strings, "边车"
        # r2 兜底:izz 对任意 extracted 文件有效(不限 ELF,ADR-0010);
        # 路径越界由 container_path 拒绝(None → 上层引导文案)
        cpath = container_path(self.ctx, file_ref)
        if cpath is None:
            return None, ""
        _rc, out, _err = run_r2(self.ctx, cpath, ["-c", "izzj"])
        data = parse_r2_json(out)
        if data is None:
            return None, ""
        strings = [
            {"address": str(d.get("vaddr") or d.get("paddr") or ""),
             "value": d.get("string", ""), "refs": []}
            for d in data if isinstance(d, dict)
        ]
        return strings, "r2 izz"

    @staticmethod
    def _compile(pattern: str):
        if pattern.startswith("re:"):
            try:
                return re.compile(pattern[3:])
            except re.error:
                return None
        p = STRING_PATTERNS.get(pattern)
        return re.compile(p) if p else None

"""semgrep_scan:沙箱容器内跑 semgrep(本地规则),扫提取的脚本/源码。

对 extracted/ 下脚本类文件(python/js/php/lua/bash)做语义级漏洞匹配,
补齐 Step4 只做字符串扫描(_TEXT_PATTERNS)缺失的"真漏洞"判断。
本地规则离线可用,不依赖 p/ 网络规则(sandbox 无外网,实测 p/ 不可靠)。

规则文件:providers/tools/rules/semgrep_security.yaml,随本工具挂载进容器。
"""
from __future__ import annotations

import json
from pathlib import Path

from .base import AgentTool, ToolResult
from .cli_base import EXTRACTED_MOUNT, container_path, run_in_sandbox, sdk_exclude_flags

# 本文件所在目录下的 rules/ 规则文件(宿主机绝对路径,挂载进容器)
_RULES_HOST = Path(__file__).parent / "rules" / "semgrep_security.yaml"
_RULES_MOUNT = "/work/rules"
_SEMGREP_EXIT_MATCH = 1  # semgrep 退出码:0=无发现,1=有命中,>1=错误


class SemgrepScanTool(AgentTool):
    name = "semgrep_scan"
    description = ("对 extracted/ 下脚本/源码跑语义级漏洞匹配(semgrep 本地规则):"
                   "命令注入/SQL注入/反序列化。比字符串扫描(passwd/url)更接近真漏洞。")
    params_doc = ('Action Input: {"path": "unitree/opt/lib/vlc/lua"}  —— 相对 extracted '
                  '根;缺省可传 "." 扫全部脚本(较慢),支持单文件/目录')

    def _run(self, path: str = ".") -> ToolResult:
        root = _RULES_HOST
        if not root.is_file():
            return ToolResult(ok=False, text="", error=f"本地 semgrep 规则缺失: {root}")

        # 相对 extracted 根 → 容器内绝对路径(semgrep 不从容器工作目录解析相对路径)
        if path in ("", ".", "./"):
            cpath = EXTRACTED_MOUNT
        else:
            cpath = container_path(self.ctx, path)
            if cpath is None:
                return ToolResult(ok=False, text="", error=f"非法路径: {path}")

        rc, out, err = run_in_sandbox(
            ["--config", f"{_RULES_MOUNT}/semgrep_security.yaml", "--json",
             "--quiet", "--no-git-ignore", *sdk_exclude_flags(), cpath],
            "semgrep", self.ctx, timeout=300,
            extra_mounts=[(_RULES_HOST.parent, _RULES_MOUNT)],
        )
        # semgrep 退出码 1 = 有命中(正常),0 = 无命中;其他为错误
        if rc not in (0, _SEMGREP_EXIT_MATCH):
            return ToolResult(ok=False, text="",
                              error=f"semgrep 失败(码 {rc}): {(err or out).strip()[:300]}")
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return ToolResult(ok=False, text="", error=f"semgrep 输出非 JSON: {out[:200]}")

        results = data.get("results", []) if isinstance(data, dict) else []
        if not results:
            return ToolResult(ok=True, text=f"{path}: 未命中疑似脚本漏洞", data=[])

        # 按 check_id 去重,LLM 只需概要 → 详查用 xref/find_decompiled_function
        seen: set[tuple] = set()
        lines = [f"{path} 命中 {len(results)} 条 semgrep 规则:"]
        for r in results:
            extra = r.get("extra", {})
            cid = r.get("check_id", "?")
            fpath = r.get("path", "")
            line = r.get("start", {}).get("line", 0)
            msg = extra.get("message", "").strip()
            sev = extra.get("severity", "WARNING")
            key = (cid, fpath, line)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"[{sev}] {fpath}:{line} {cid}")
            if msg:
                lines.append(f"    {msg}")
        return ToolResult(ok=True,
                          text="\n".join(lines[:60]),  # 防超长,后续可 read_file 分页
                          data=[{"check_id": r.get("check_id"),
                                 "path": r.get("path"), "line": r.get("start", {}).get("line"),
                                 "severity": r.get("extra", {}).get("severity"),
                                 "message": r.get("extra", {}).get("message", "")}
                                for r in results[:200]])
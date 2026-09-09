"""semgrep_scan:沙箱容器内跑 semgrep(本地规则),扫提取的脚本/源码。

对 extracted/ 下脚本类文件(python/js/php/lua/bash)做语义级漏洞匹配,
补齐 Step4 只做字符串扫描(_TEXT_PATTERNS)缺失的"真漏洞"判断。
path="."(根/缺省)为**双扫**:extracted(全规则)+ analysis(仅 *.c,
Ghidra 反编译代码的 C 危险调用形态,2026-09-04;实测 633MB/253s,88 个
解析错误被 semgrep 自行跳过不进结果)。显式子目录路径仍只扫 extracted。
本地规则离线可用,不依赖 p/ 网络规则(sandbox 无外网,实测 p/ 不可靠)。

规则文件:providers/tools/rules/semgrep_security.yaml,随本工具挂载进容器。
"""
from __future__ import annotations

import json
from pathlib import Path

from .base import AgentTool, ToolResult
from .cli_base import (ANALYSIS_MOUNT, EXTRACTED_MOUNT, analysis_root,
                       container_path, extracted_tool_path, run_in_sandbox,
                       sdk_exclude_flags)

# 本文件所在目录下的 rules/ 规则文件(宿主机绝对路径,挂载进容器)
_RULES_HOST = Path(__file__).parent / "rules" / "semgrep_security.yaml"
_RULES_MOUNT = "/work/rules"
_SEMGREP_EXIT_MATCH = 1  # semgrep 退出码:0=无发现,1=有命中,>1=错误
_EXTRACT_TIMEOUT = 900        # extracted 脚本树实测 ~250s,但 300s 曾被 Defender 波动打爆(rc=124),给 3 倍余量
_ANALYSIS_C_TIMEOUT = 900     # 反编译 C 树实测 ~253s(633MB),留 3 倍余量
_RESULT_CAP = 200             # data 结构化结果上限(旧版同值)


class SemgrepScanTool(AgentTool):
    name = "semgrep_scan"
    description = ("语义级漏洞匹配(semgrep 本地规则):'.' 双扫 extracted 脚本"
                   "(命令注入/SQL注入/反序列化)+ analysis 反编译 C(危险调用"
                   "形态);显式子目录路径只扫 extracted。比字符串扫描更接近真漏洞。")
    params = {
        "path": {"type": "str", "default": ".",
                 "desc": "相对 extracted 根的路径(单文件/目录);缺省 '.' 双扫 "
                         "extracted 全部脚本 + analysis 全部反编译 C(较慢,约数分钟)"},
    }

    def _run(self, path: str = ".") -> ToolResult:
        if not _RULES_HOST.is_file():
            return ToolResult(ok=False, text="",
                              error=f"本地 semgrep 规则缺失: {_RULES_HOST}")

        if path in ("", ".", "./"):
            return self._scan_roots(path)

        # 显式子目录:相对 extracted 根 → 容器内绝对路径
        # (semgrep 不从容器工作目录解析相对路径)
        cpath = container_path(self.ctx, path)
        if cpath is None:
            return ToolResult(ok=False, text="", error=f"非法路径: {path}")
        results, err = self._scan_one(
            [*self._base_args(), *sdk_exclude_flags(), cpath],
            _EXTRACT_TIMEOUT,
            [(_RULES_HOST.parent, _RULES_MOUNT)])
        if err is not None:
            return ToolResult(ok=False, text="", error=err)
        return self._format(results, path)

    # ---- 根/缺省:双扫(extracted 全规则 + analysis 仅 *.c) ----

    def _scan_roots(self, path: str) -> ToolResult:
        results: list[dict] = []
        errors: list[str] = []
        legs = [
            ([*self._base_args(), *sdk_exclude_flags(), EXTRACTED_MOUNT],
             _EXTRACT_TIMEOUT,
             [(_RULES_HOST.parent, _RULES_MOUNT)],
             None),
            ([*self._base_args(), "--include", "*.c", ANALYSIS_MOUNT],
             _ANALYSIS_C_TIMEOUT,
             [(_RULES_HOST.parent, _RULES_MOUNT),
              (analysis_root(self.ctx).resolve(), ANALYSIS_MOUNT, "ro")],
             "analysis"),
        ]
        for args, timeout, mounts, prefix in legs:
            rs, err = self._scan_one(args, timeout, mounts)
            if err is not None:
                errors.append(err)
                continue
            results.extend(self._convert(r, path, prefix) for r in rs)
        if len(errors) == len(legs):
            # 两路全挂才报错:单路失败不崩,带上成功路的结果与失败注记
            return ToolResult(ok=False, text="",
                              error=";".join(errors)[:400])
        text = self._format_text(results, path, errors, c_hint=True)
        return ToolResult(ok=True, text=text, data=results[:_RESULT_CAP])

    # ---- 单路扫描:返回 (results, 错误串|None) ----

    def _base_args(self) -> list[str]:
        """双扫共用的 semgrep 基础参数(本地规则 + JSON 到 stdout)。"""
        return ["--config", f"{_RULES_MOUNT}/semgrep_security.yaml", "--json",
                "--quiet", "--no-git-ignore"]

    def _scan_one(self, args: list[str], timeout: int,
                  extra_mounts: list[tuple]) -> tuple[list[dict], str | None]:
        rc, out, err = run_in_sandbox(args, "semgrep", self.ctx,
                                      timeout=timeout, extra_mounts=extra_mounts)
        # semgrep 退出码 1 = 有命中(正常),0 = 无命中;其他为错误
        if rc not in (0, _SEMGREP_EXIT_MATCH):
            return [], f"semgrep 失败(码 {rc}): {(err or out).strip()[:200]}"
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return [], f"semgrep 输出非 JSON: {out[:200]}"
        return (data.get("results", []) if isinstance(data, dict) else []), None

    def _convert(self, r: dict, path: str, prefix: str | None) -> dict:
        """单条结果 → 工具路径形态(ADR-0008:LLM 会照抄进 findings.file)。"""
        if prefix is None:
            fpath = extracted_tool_path(path, r.get("path", ""))
        else:
            fpath = extracted_tool_path(path, r.get("path", ""),
                                        mount=ANALYSIS_MOUNT, prefix=prefix)
        return {"check_id": r.get("check_id"),
                "path": fpath,
                "line": r.get("start", {}).get("line"),
                "severity": r.get("extra", {}).get("severity") or "WARNING",
                "message": r.get("extra", {}).get("message", "")}

    def _format_text(self, results: list[dict], path: str,
                     errors: list[str], c_hint: bool = False) -> str:
        # 按 (check_id, 路径, 行号) 去重,LLM 只需概要 → 详查用 xref/decompile
        seen: set[tuple] = set()
        lines = [f"{path} 命中 {len(results)} 条 semgrep 规则:"]
        for m in results:
            key = (m["check_id"], m["path"], m["line"])
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"[{m['severity']}] {m['path']}:{m['line']} {m['check_id']}")
            if m["message"]:
                lines.append(f"    {m['message']}")
        if errors:
            lines.append(f"(注: {';'.join(errors)[:200]} — 该路结果缺失)")
        truncated = len(lines) >= 60
        if truncated:
            lines.append("(达上限截断,可用更小 path 收窄)")
        if c_hint:
            lines.append("(反编译 C 命中是疑点信号,"
                         "用 find_decompiled_function/r2_xref_query 复查)")
        return "\n".join(lines[:60])

    def _format(self, results: list[dict], path: str) -> ToolResult:
        """显式子目录路的格式化(行为与旧版一致:无命中短句,不再拼注记)。"""
        if not results:
            return ToolResult(ok=True, text=f"{path}: 未命中疑似脚本漏洞", data=[])
        return ToolResult(ok=True, text=self._format_text(results, path, []),
                          data=[self._convert(r, path, None) for r in results[:200]])

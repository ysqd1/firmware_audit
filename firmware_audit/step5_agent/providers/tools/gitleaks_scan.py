"""gitleaks_scan:沙箱容器内跑 gitleaks,扫描 extracted/ 下的硬编码密钥/凭据。

对应 DeepAudit 的 GitleaksTool。检测 API Key/私钥/数据库凭据/OAuth token/
JWT secret 等多种密钥类型。用 --no-git(固件不是 git 仓库),只扫文件内容。
退出码 0=无泄漏,1=有泄漏,其余=错误(gitleaks 0 也可用 --exit-code 0 但此处按码区分)。
"""
from __future__ import annotations

import json
import shlex

from .base import AgentTool, ToolResult
from .cli_base import (EXTRACTED_MOUNT, container_path, extracted_tool_path,
                       run_in_sandbox)


def build_gitleaks_cmd(source: str) -> str:
    """构造单容器内 gitleaks detect + cat 报告的 shell 命令。

    两次独立 docker run 容器 /tmp 不共享,故报告读出必须与检测同容器。
    source 为容器内路径,用 shlex.quote 转义,防固件文件名/Agent 参数中
    的 shell 元字符注入(2026-08-27 安全加固)。注意: 不用 .format/f-string,
    shell 的 ${rc} 会被 str.format 当占位符抛 KeyError('rc')。
    """
    src = shlex.quote(source)
    return ("gitleaks detect --no-git --source " + src +
            " --report-format json --report-path /tmp/gitleaks-report.json"
            " --exit-code 0; rc=$?; echo __RC__${rc}; cat /tmp/gitleaks-report.json")


class GitleaksScanTool(AgentTool):
    name = "gitleaks_scan"
    description = ("扫描 extracted/ 下的硬编码密钥/凭据(gitleaks):API Key/私钥/"
                   "数据库凭据/OAuth token/JWT secret。与 strings_query 互补,走语义"
                   "规则而非正则,误报更低。")
    params = {
        "path": {"type": "str", "default": ".",
                 "desc": "相对 extracted 根的目录;缺省 '.' 扫全树(较慢)"},
    }

    def _run(self, path: str = ".") -> ToolResult:
        # 相对 extracted 根 → 容器内绝对路径(gitleaks --source 需真实容器路径)
        if path in ("", ".", "./"):
            cpath = EXTRACTED_MOUNT
        else:
            cpath = container_path(self.ctx, path)
            if cpath is None:
                return ToolResult(ok=False, text="", error=f"非法路径: {path}")

        # 单容器内完成 detect + cat 报告:两次独立 docker run 容器 /tmp 不共享,
        # 报告文件若落在第一次容器则第二次读不到。
        # source 经 build_gitleaks_cmd 内 shlex.quote 转义,防 shell 注入。
        cmd = build_gitleaks_cmd(cpath)
        rc, out, err = run_in_sandbox(["-c", cmd], "sh", self.ctx, timeout=300)
        if rc != 0:
            return ToolResult(ok=False, text="",
                              error=f"gitleaks 执行失败(码 {rc}): {(err or out).strip()[:300]}")
        # stdout 形如 "__RC__<gitleaks退出码>\n<JSON报告>";退出码在标记行同行,
        # 报告从下一行起。--exit-code 0 下命中不算错,非零即真实错误(路径缺失等)。
        marker = "__RC__"
        if marker in out:
            _, _, after = out.partition(marker)
            after_lines = after.splitlines()
            g_rc = after_lines[0].strip() if after_lines else "0"
            findings_out = "\n".join(after_lines[1:]).strip()
        else:
            g_rc, findings_out = "0", out.strip()
        if g_rc != "0":
            return ToolResult(ok=False, text="",
                              error=f"gitleaks 失败(退出码 {g_rc}): {err.strip()[:300]}")
        if not findings_out or findings_out in ("null", "[]"):
            return ToolResult(ok=True, text=f"{path}: 未发现硬编码密钥", data=[])
        try:
            findings = json.loads(findings_out)
        except json.JSONDecodeError:
            return ToolResult(ok=False, text="", error=f"gitleaks 报告非 JSON: {findings_out[:200]}")
        if not isinstance(findings, list):
            return ToolResult(ok=False, text="", error=f"gitleaks 报告结构异常: {type(findings)}")

        # 路径换算成工具路径(ADR-0008):报告 File 是容器挂载根相对口径,
        # LLM 会照抄进 findings.file,必须在输出层统一 extracted/ 前缀
        lines = [f"{path} 命中 {len(findings)} 处密钥泄露:"]
        for f in findings[:60]:
            rule = f.get("RuleID", "?")
            fp = extracted_tool_path(path, f.get("File", "?"))
            line = f.get("StartLine", 0)
            secret = f.get("Secret", "")
            masked = (secret[:4] + "*" * 8) if len(secret) > 4 else "****"
            lines.append(f"[{rule}] {fp}:{line}  {masked}")
        return ToolResult(ok=True,
                          text="\n".join(lines),
                          data=[{"rule": f.get("RuleID"),
                                 "file": extracted_tool_path(path, f.get("File", "?")),
                                 "line": f.get("StartLine"), "secret": f.get("Secret")}
                                for f in findings[:200]])

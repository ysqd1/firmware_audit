"""Agent 工具注册表。

每工具一个子类文件;make_tools() 按上下文实例化,ReAct 循环按 name 分发。
工具分三类:
  CLI 类(checksec/cve_bin_tool_scan/r2_* 族/semgrep_scan/gitleaks_scan/binwalk_rescan)
  API 类(cve_lookup/web_search)
  读盘类(rest)
make_tools(exclude=...) 支持按 name 排除可选工具(如 cve_bin_tool_scan 对嵌入式
交叉库误报偏多,可运行时关闭),骨架不变。
"""
from __future__ import annotations

from .base import AgentTool, ToolContext, ToolResult
from .binwalk_rescan import BinwalkRescanTool
from .checksec import ChecksecTool
from .cve_bin_tool_scan import CveBinToolScanTool
from .cve_lookup import CveLookupTool
from .find_decompiled_function import FindDecompiledFunctionTool
from .ghidra_decompile import GhidraDecompileTool
from .gitleaks_scan import GitleaksScanTool
from .imports_query import ImportsQueryTool
from .list_files import ListFilesTool
from .r2_disassemble_function import R2DisassembleFunctionTool
from .r2_list_functions import R2ListFunctionsTool
from .r2_xref_query import R2XrefQueryTool
from .read_file import ReadFileTool
from .sandbox_verify import SandboxVerifyTool
from .search_code import SearchCodeTool
from .semgrep_scan import SemgrepScanTool
from .strings_query import StringsQueryTool
from .web_search import WebSearchTool

# 默认开启的完整工具集(新增工具在此登记)
_DEFAULT_TOOLS: tuple[type[AgentTool], ...] = (
    FindDecompiledFunctionTool,
    ImportsQueryTool,
    StringsQueryTool,
    ReadFileTool,
    ListFilesTool,
    SearchCodeTool,
    R2ListFunctionsTool,
    R2DisassembleFunctionTool,
    R2XrefQueryTool,
    GhidraDecompileTool,
    ChecksecTool,
    CveBinToolScanTool,
    CveLookupTool,
    SemgrepScanTool,
    GitleaksScanTool,
    SandboxVerifyTool,
    BinwalkRescanTool,
    WebSearchTool,
)


def make_tools(ctx: ToolContext, exclude: set[str] | None = None) -> dict[str, AgentTool]:
    """实例化工具注册表。exclude:按 name 排除的可选工具集合(如 {"cve_bin_tool_scan"})。

    未显式传 exclude 时读环境变量 STEP5_EXCLUDE_TOOLS(逗号分隔)作为默认排除集,
    便于运行时关闭误报偏多的工具而不改代码(骨架不变)。

    exclude 里的名字若不在 _DEFAULT_TOOLS 中会静默忽略(注册表幂等)。
    """
    if exclude is None:  # 支持环境变量运行时排除(显式传 exclude 优先,否则用 env)
        import os
        raw = os.environ.get("STEP5_EXCLUDE_TOOLS", "")
        exclude = {n.strip() for n in raw.split(",") if n.strip()}
    tools = {t.name: t(ctx) for t in _DEFAULT_TOOLS if t.name not in exclude}
    if exclude:
        skipped = [n for n in exclude if n in {t.name for t in _DEFAULT_TOOLS}]
        if skipped:
            print(f"[tools] 可选工具已排除: {', '.join(sorted(skipped))}")
    return tools


__all__ = ["AgentTool", "ToolContext", "ToolResult", "make_tools",
           "FindDecompiledFunctionTool", "ImportsQueryTool", "StringsQueryTool",
           "ReadFileTool", "ListFilesTool", "SearchCodeTool", "ChecksecTool",
           "R2ListFunctionsTool", "R2DisassembleFunctionTool", "R2XrefQueryTool",
           "GhidraDecompileTool",
           "CveBinToolScanTool", "CveLookupTool",
           "SemgrepScanTool", "GitleaksScanTool", "SandboxVerifyTool",
           "BinwalkRescanTool", "WebSearchTool"]

"""Agent 工具注册与 Blind Discovery 授权契约。

每工具一个子类文件;make_tools() 按上下文实例化,ReAct 循环按 name 分发。
工具分三类:
  CLI 类(checksec/cve_bin_tool_scan/r2_* 族/semgrep_scan/gitleaks_scan/binwalk_rescan)
  API 类(cve_lookup/web_search)
  读盘类(rest)
每条注册记录同时声明角色权限与中断重放策略，未来 Host 只查本契约，不根据
工具名或提示词猜测。make_tools(exclude=...) 保留完整 legacy 工具实例化能力；
Blind Discovery 调用方必须先经 tool_names_for_role/authorize_tool 授权。
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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
from .qemu_precheck import QemuPrecheckTool
from .qemu_session import QemuExecuteTool
from .r2_disassemble_function import R2DisassembleFunctionTool
from .r2_list_functions import R2ListFunctionsTool
from .r2_xref_query import R2XrefQueryTool
from .read_file import ReadFileTool
from .sandbox_verify import SandboxVerifyTool
from .search_code import SearchCodeTool
from .semgrep_scan import SemgrepScanTool
from .strings_query import StringsQueryTool
from .web_search import WebSearchTool


BLIND_DISCOVERY_ROLES = ("recon", "analysis", "verification")
_DEEP_ROLES = frozenset(("analysis", "verification"))
_ALL_ROLES = frozenset(BLIND_DISCOVERY_ROLES)
_NO_ROLES: frozenset[str] = frozenset()


class ReplayPolicy(str, Enum):
    """Host 遇到只有 ``tool_started`` 的调用时可采取的恢复策略。"""

    READ_ONLY_IDEMPOTENT = "read_only_idempotent"
    CACHE_VALIDATED = "cache_validated"
    NEVER = "never"


@dataclass(frozen=True)
class ToolContract:
    """单个工具的工厂、Blind Discovery 权限与中断重放元数据。"""

    tool_type: type[AgentTool]
    roles: frozenset[str]
    replay_policy: ReplayPolicy

    @property
    def name(self) -> str:
        return self.tool_type.name


class ToolAuthorizationError(ValueError):
    """工具不存在或未授权给请求角色。"""


# 单一审计表：顺序沿用原注册表，角色集合严格来自 ADR-0012。CVE/公开查询
# 工具保留实现供未来独立模式设计，但 Blind Discovery 三角色均不可见。
_TOOL_CONTRACTS: tuple[ToolContract, ...] = (
    # find_decompiled_function 读已有反编译边车、不发起 Ghidra(ADR-0012
    # 2026-09-16 D1):授权 analysis/verification 深挖角色,recon 仍不可见。
    ToolContract(FindDecompiledFunctionTool, _DEEP_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(ImportsQueryTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(StringsQueryTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(ReadFileTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(ListFilesTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(SearchCodeTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(R2ListFunctionsTool, _DEEP_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(R2DisassembleFunctionTool, _DEEP_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(R2XrefQueryTool, _DEEP_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(GhidraDecompileTool, _DEEP_ROLES, ReplayPolicy.CACHE_VALIDATED),
    ToolContract(ChecksecTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(CveBinToolScanTool, _NO_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(CveLookupTool, _NO_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(SemgrepScanTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(GitleaksScanTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(SandboxVerifyTool, _DEEP_ROLES, ReplayPolicy.NEVER),
    # qemu_precheck 只读静态预检(票 05,ADR-0013):不执行目标不建会话,
    # 幂等可重放;授权深挖角色,recon 不可见。sandbox_verify 所在基础镜像
    # 零 qemu(票 03 结构性隔离),脚本路径无法触达 QEMU 执行。
    ToolContract(QemuPrecheckTool, _DEEP_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    # qemu_execute 单发执行会话(票 16,ADR-0013):每次调用即一个会话,消耗
    # 名额且不可重放(NEVER——重放等于隐藏的额外执行);授权深挖角色且
    # analysis/verification 名额独立记账,recon 不可见。
    ToolContract(QemuExecuteTool, _DEEP_ROLES, ReplayPolicy.NEVER),
    ToolContract(BinwalkRescanTool, _ALL_ROLES, ReplayPolicy.READ_ONLY_IDEMPOTENT),
    ToolContract(WebSearchTool, _NO_ROLES, ReplayPolicy.NEVER),
)

_CONTRACT_BY_NAME = {contract.name: contract for contract in _TOOL_CONTRACTS}


def tool_contracts() -> dict[str, ToolContract]:
    """返回按工具名索引的注册契约副本，供 Host 审计和恢复决策。"""
    return dict(_CONTRACT_BY_NAME)


def tool_names_for_role(role: str) -> tuple[str, ...]:
    """返回角色在 Blind Discovery 中可见的工具名，保持注册顺序。"""
    if role not in BLIND_DISCOVERY_ROLES:
        allowed = ", ".join(BLIND_DISCOVERY_ROLES)
        raise ToolAuthorizationError(f"未知 Agent 角色 {role!r}；允许值: {allowed}")
    return tuple(contract.name for contract in _TOOL_CONTRACTS if role in contract.roles)


def authorize_tool(role: str, tool_name: str) -> ToolContract:
    """校验角色的单次工具 Action，并返回其重放契约。"""
    if role not in BLIND_DISCOVERY_ROLES:
        tool_names_for_role(role)  # 统一未知角色错误文案
    contract = _CONTRACT_BY_NAME.get(tool_name)
    available = ", ".join(tool_names_for_role(role))
    if contract is None:
        raise ToolAuthorizationError(
            f"工具 {tool_name!r} 未注册，角色 {role} 无法调用；"
            f"可用工具: {available}"
        )
    if role not in contract.roles:
        raise ToolAuthorizationError(
            f"Blind Discovery 角色 {role} 无权调用工具 {tool_name}；"
            f"可用工具: {available}。请改用已授权工具或提交当前调查建议"
        )
    return contract


def make_tools(
    ctx: ToolContext,
    exclude: set[str] | None = None,
    *,
    role: str | None = None,
) -> dict[str, AgentTool]:
    """实例化工具注册表；role 非空时只构造该角色获授权的工具。

    exclude 按 name 排除可选工具集合(如 {"cve_bin_tool_scan"})。

    未显式传 exclude 时读环境变量 STEP5_EXCLUDE_TOOLS(逗号分隔)作为默认排除集,
    便于运行时关闭误报偏多的工具而不改代码(骨架不变)。

    exclude 里的名字若不在 _TOOL_CONTRACTS 中会静默忽略(注册表幂等)。
    """
    allowed = set(tool_names_for_role(role)) if role is not None else None
    if exclude is None:  # 支持环境变量运行时排除(显式传 exclude 优先,否则用 env)
        import os
        raw = os.environ.get("STEP5_EXCLUDE_TOOLS", "")
        exclude = {n.strip() for n in raw.split(",") if n.strip()}
    tools = {
        contract.name: (
            contract.tool_type(ctx, role=role) if role is not None
            else contract.tool_type(ctx)
        )
        for contract in _TOOL_CONTRACTS
        if contract.name not in exclude
        and (allowed is None or contract.name in allowed)
    }
    if exclude:
        skipped = [n for n in exclude if n in _CONTRACT_BY_NAME]
        if skipped:
            print(f"[tools] 可选工具已排除: {', '.join(sorted(skipped))}")
    return tools


__all__ = ["AgentTool", "ToolContext", "ToolResult", "make_tools",
           "ReplayPolicy", "ToolContract", "ToolAuthorizationError",
           "tool_contracts", "tool_names_for_role", "authorize_tool",
           "FindDecompiledFunctionTool", "ImportsQueryTool", "StringsQueryTool",
           "ReadFileTool", "ListFilesTool", "SearchCodeTool", "ChecksecTool",
           "R2ListFunctionsTool", "R2DisassembleFunctionTool", "R2XrefQueryTool",
           "GhidraDecompileTool",
           "CveBinToolScanTool", "CveLookupTool",
           "SemgrepScanTool", "GitleaksScanTool", "SandboxVerifyTool",
           "QemuPrecheckTool", "QemuExecuteTool",
           "BinwalkRescanTool", "WebSearchTool"]

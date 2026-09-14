"""Host 侧工具参数规范化与执行的共享内部契约。

Analysis tracer 与 Recon runner 对"合法参数如何固化、adapter 失约如何转为
失败 ToolResult"的需求完全一致,单一出处避免两处分叉。
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from ..providers.tools.base import ToolResult
from .json_values import clone_json_value

# 声明为路径的参数统一反斜杠换算(Windows 习惯写入的参数不产生幽灵路径)。
_PATH_ARGUMENTS = frozenset(("path", "file_ref", "directory", "target_dir"))


def normalize_tool_arguments(
    params: dict[str, dict],
    checked: dict[str, Any],
) -> dict[str, Any]:
    """固化默认值及声明枚举,并按工具实际规则规范化路径参数。"""
    normalized: dict[str, Any] = {}
    for name, declaration in params.items():
        if name in checked:
            value = checked[name]
        elif "default" in declaration:
            value = deepcopy(declaration["default"])
        else:
            continue
        if isinstance(value, str):
            value = value.strip()
            enum = declaration.get("enum") or ()
            canonical = next(
                (item for item in enum if str(item).lower() == value.lower()),
                None,
            )
            if canonical is not None:
                value = canonical
            if name in _PATH_ARGUMENTS:
                value = value.replace("\\", "/")
        normalized[name] = value
    return clone_json_value(normalized, "normalized tool arguments")


def execute_tool(tool: object, arguments: dict[str, Any], *, method: str = "execute") -> ToolResult:
    """工具 adapter 失约也转为失败 ToolResult,保留本次逻辑调用身份。"""
    try:
        result = getattr(tool, method)(**arguments)
    except Exception as exc:
        return ToolResult(
            ok=False,
            text="",
            error=f"工具 adapter 抛出 {type(exc).__name__}: {exc}",
        )
    if isinstance(result, ToolResult):
        return result
    return ToolResult(
        ok=False,
        text="",
        error=f"工具 adapter 必须返回 ToolResult，实际为 {type(result).__name__}",
    )

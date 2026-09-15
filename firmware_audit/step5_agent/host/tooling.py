"""Host 侧工具参数规范化与执行的共享内部契约。

Analysis tracer、Recon runner 与 Verification runner 对"合法参数如何固化、
adapter 失约如何转为失败 ToolResult"的需求完全一致,单一出处避免两处分叉。
恢复期的持久化工具调用校验(计数/身份/状态/replay policy)为 Analysis 与
Verification 共用,由 ``validate_saved_tool_call`` 承载。
"""
from __future__ import annotations

from copy import deepcopy
import json
from typing import Any

from ..providers.tools import ReplayPolicy, authorize_tool
from ..providers.tools.base import ToolResult, validate_params
from .json_values import JsonValueError, clone_json_value
from .session import ProposalRejectedError
from .store import StoreError

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


def json_clone_or_reject(value: Any, label: str) -> Any:
    """校验并复制纯 JSON 值,把共享边界错误转换为 Proposal 拒绝。"""
    try:
        return clone_json_value(value, label)
    except JsonValueError as exc:
        raise ProposalRejectedError(str(exc)) from exc


def regeneration_feedback(detail: str) -> str:
    """无效回复的整份重生成提示:回喂拒绝理由,不接受局部补丁(ADR-0012 L43)。"""
    return json.dumps({
        "error": "invalid_agent_proposal",
        "detail": detail,
        "instruction": (
            "上一份回复被 Host 整份拒绝且未产生任何效果;请修正问题,"
            "从头生成一份完整 JSON,不要发送局部补丁。"
        ),
    }, ensure_ascii=False)


def recover_cached_tool(tool: object, arguments: dict[str, Any]) -> ToolResult | None:
    """Cache-aware adapters must explicitly support both probe and safe retry."""
    try:
        if not callable(getattr(tool, "execute_after_interruption", None)):
            raise TypeError("缓存工具缺少 execute_after_interruption")
        result = tool.recover_cached_result(**arguments)
        if result is not None and not isinstance(result, ToolResult):
            raise TypeError("缓存校验必须返回 ToolResult 或 None")
        return result
    except Exception as exc:
        return ToolResult(ok=False, text="", error=(
            f"缓存恢复失败: {type(exc).__name__}: {exc}；未自动重放，请选择替代取证动作"
        ))


def validate_saved_tool_call(
    evidence_store,
    candidate_id: str,
    *,
    call,
    pending,
    logical_tool_calls: int,
    tool_attempts: int,
    evidence,
    role: str,
) -> None:
    """恢复期统一校验持久化工具调用的计数、身份、状态与 replay policy。

    从不信任投影派生重放许可或成本:活动调用取 pending 的工具与参数,完成
    调用取最后一条 Evidence,逐字段与 tool_started 契约比对。Analysis 与
    Verification 的恢复路径共用,行为口径单一出处。
    """
    active = pending is not None and pending["proposal"]["kind"] == "tool_action"
    if (type(logical_tool_calls) is not int or type(tool_attempts) is not int
            or tool_attempts < 0
            or logical_tool_calls != len(evidence) + int(active)):
        raise StoreError("工具调用计数损坏")
    if call is None:
        if logical_tool_calls or tool_attempts:
            raise StoreError("缺少逻辑调用记录")
        return
    if not isinstance(call, dict):
        raise StoreError("逻辑调用记录结构损坏")
    if active:
        sequence = pending["sequence"]
        proposal = pending["proposal"]
        tool_name, arguments = proposal["tool"], proposal["arguments"]
    else:
        if not evidence:
            raise StoreError("工具调用缺少 Evidence")
        reference = evidence[-1]
        sequence, tool_name, arguments = reference.sequence, reference.tool, reference.arguments
    contract = authorize_tool(role, tool_name)
    checked, error = validate_params(contract.tool_type.params, arguments)
    if error:
        raise StoreError("持久化工具参数失约")
    arguments = normalize_tool_arguments(contract.tool_type.params, checked)
    attempt, status, finished = call["attempt"], call["status"], call["finished"]
    if (call["call_id"] != f"call-{sequence:06d}"
            or call["evidence_id"] != f"ev-{sequence:06d}"
            or call["tool"] != tool_name or call["arguments"] != arguments
            or call["replay_policy"] != contract.replay_policy.value
            or type(attempt) is not int or not 0 <= attempt <= tool_attempts
            or type(finished) is not bool
            or status not in ("prepared", "started", "finished", "interrupted")
            or (attempt == 0) != (status == "prepared")
            or (status == "finished" and not finished)
            or (finished and status not in ("finished", "interrupted"))
            or (status == "interrupted" and contract.replay_policy is not ReplayPolicy.NEVER)
            or (active and pending["executing"] != (attempt > 0))
            or (not active and not finished)):
        raise StoreError("工具调用身份、状态或 replay policy 损坏")
    if finished:
        slot = evidence_store.restore_slot(candidate_id, sequence)
        if evidence_store.recover(slot) is None:
            raise StoreError("tool_finished 缺少持久化 Observation")

"""逐步 Agent Session：一次模型请求只返回一个经校验的 Proposal。

本模块是模型文本与未来 Host 控制循环之间的 seam。它负责纯 JSON 解析、
角色动作限制、精确错误反馈，以及复用 ContextManager/Transcript 发起单次请求；
它没有工具注册表、循环或阶段状态，因此不能执行动作或推进调查生命周期。

协议刻意只固定本票已经确认的形状。``state_delta`` 的领域字段会由后续 Host
Policy 工单定义；这里仅保证它是 JSON object，并保证 Related Candidate 只能
位于其中。终止动作的内容同样全部放在 state delta，``next`` 只表达唯一动作。
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import time
from typing import Any

from ..engine.context import ContextManager
from ..engine.transcript import Transcript

MAX_DECISION_SUMMARY_CHARS = 500

ROLE_NEXT_KINDS: dict[str, tuple[str, ...]] = {
    "recon": ("tool_action", "complete_survey"),
    "analysis": ("tool_action", "submit_case", "close_investigation"),
    "verification": ("tool_action", "complete_verification"),
}

_TOP_FIELDS = ("decision_summary", "state_delta", "next")
_ACTION_FIELDS = ("kind", "tool", "arguments")
_FINAL_FIELDS = ("kind",)


@dataclass(frozen=True)
class ValidationIssue:
    """单个协议问题；字段始终齐全，便于直接反馈给模型。"""

    path: str
    expected: str
    actual: str
    allowed_values: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "field_path": self.path,
            "expected": self.expected,
            "actual": self.actual,
            "allowed_values": list(self.allowed_values),
        }


@dataclass(frozen=True)
class ProposalError:
    """整份回复无效；调用者不得应用其中任何局部字段。"""

    issues: tuple[ValidationIssue, ...]
    raw_reply: str

    def feedback_message(self) -> str:
        """生成同一 Session 下一次整份重生成所需的结构化提示。"""
        return json.dumps({
            "error": "invalid_agent_proposal",
            "issues": [issue.as_dict() for issue in self.issues],
            "instruction": "从头生成一份完整 JSON；不要发送局部补丁。",
        }, ensure_ascii=False)


@dataclass(frozen=True)
class ActionProposal:
    """请求 Host 执行一个工具；本对象自身没有执行能力。"""

    decision_summary: str
    state_delta: dict[str, Any]
    tool: str
    arguments: dict[str, Any]
    kind: str = "tool_action"


@dataclass(frozen=True)
class FinalProposal:
    """角色工作完成建议；是否推进生命周期仍由 Host 决定。"""

    decision_summary: str
    state_delta: dict[str, Any]
    kind: str


ProposalResult = ActionProposal | FinalProposal | ProposalError


class _DecodedObject(dict):
    """保留 JSON 重复键信息；普通 dict 会在校验前静默覆盖。"""

    def __init__(self, pairs: list[tuple[str, Any]]):
        super().__init__()
        duplicates: list[str] = []
        for key, value in pairs:
            if key in self:
                duplicates.append(key)
            self[key] = value
        self.duplicates = tuple(duplicates)


def _role(role: str) -> str:
    if role not in ROLE_NEXT_KINDS:
        allowed = ", ".join(ROLE_NEXT_KINDS)
        raise ValueError(f"未知 Agent 角色 {role!r}；允许值: {allowed}")
    return role


def protocol_instruction(role: str) -> str:
    """返回该角色的供应商无关纯 JSON 回复契约。"""
    role = _role(role)
    allowed = ROLE_NEXT_KINDS[role]
    kinds = " / ".join(allowed)
    terminal_examples = [kind for kind in allowed if kind != "tool_action"]
    terminal = terminal_examples[0]
    return f"""每次只输出一份纯 JSON，不要 Markdown、代码围栏或额外文字。
顶层必须且只能有 decision_summary、state_delta、next：
{{
  "decision_summary": "不超过 {MAX_DECISION_SUMMARY_CHARS} 字的简短判断",
  "state_delta": {{"related_candidates": []}},
  "next": {{"kind": "tool_action", "tool": "工具名", "arguments": {{}}}}
}}
decision_summary 必须是非空字符串；state_delta 必须是 object。Related Candidate
proposal 如有，只能放在 state_delta.related_candidates 数组中。next.kind 对
{role} 只允许 {kinds}。tool_action 的 next 必须且只能包含 kind/tool/arguments；
终止建议写作 {{"kind": "{terminal}"}}，其内容放入 state_delta。每次只能提出
一个 next；Host 校验后才会应用状态、执行工具或决定是否推进生命周期。"""


def _actual(value: object, *, missing: bool = False) -> str:
    if missing:
        return "missing"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


def _enum_actual(value: object, *, missing: bool = False) -> str:
    """枚举错误既保留实际 JSON 值，又能区分缺失字段。"""
    if missing:
        return "missing"
    return json.dumps(value, ensure_ascii=False, default=str)


def _unknown_issues(value: dict, allowed: tuple[str, ...], path: str) -> list[ValidationIssue]:
    return [
        ValidationIssue(
            path=f"{path}.{key}" if path != "$" else f"$.{key}",
            expected="known field",
            actual="unknown field",
            allowed_values=allowed,
        )
        for key in value
        if key not in allowed
    ]


def _required_issue(value: dict, field: str, path: str, expected: str) -> ValidationIssue | None:
    if field in value:
        return None
    prefix = "$" if path == "$" else path
    return ValidationIssue(
        path=f"{prefix}.{field}",
        expected=expected,
        actual="missing",
    )


def _reject_json_constant(value: str) -> None:
    """Python 默认接受 NaN/Infinity；纯 JSON 协议明确拒绝这些扩展值。"""
    raise ValueError(f"invalid JSON constant {value}")


def _decode(raw_reply: str) -> tuple[dict[str, Any] | None, list[ValidationIssue]]:
    try:
        value = json.loads(
            raw_reply,
            object_pairs_hook=_DecodedObject,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        return None, [ValidationIssue(
            path="$",
            expected="JSON object",
            actual=f"invalid JSON: {exc}",
        )]
    if not isinstance(value, dict):
        return None, [ValidationIssue(
            path="$",
            expected="JSON object",
            actual=_actual(value),
        )]
    return value, _duplicate_issues(value, "$")


def _duplicate_issues(value: object, path: str) -> list[ValidationIssue]:
    """递归定位重复字段，保证唯一 ``next`` 等字段不会被后值覆盖。"""
    issues: list[ValidationIssue] = []
    if isinstance(value, _DecodedObject):
        issues.extend(
            ValidationIssue(
                path=f"{path}.{key}",
                expected="unique field",
                actual="duplicate field",
            )
            for key in value.duplicates
        )
        for key, child in value.items():
            issues.extend(_duplicate_issues(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(_duplicate_issues(child, f"{path}[{index}]"))
    return issues


def _top_issues(value: dict[str, Any]) -> list[ValidationIssue]:
    """校验固定顶层字段与 decision summary。"""
    issues = _unknown_issues(value, _TOP_FIELDS, "$")
    for field, expected in (
        ("decision_summary", f"non-empty string of at most {MAX_DECISION_SUMMARY_CHARS} characters"),
        ("state_delta", "JSON object"),
        ("next", "JSON object"),
    ):
        issue = _required_issue(value, field, "$", expected)
        if issue:
            issues.append(issue)

    summary = value.get("decision_summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_DECISION_SUMMARY_CHARS:
        if "decision_summary" in value:
            issues.append(ValidationIssue(
                path="$.decision_summary",
                expected=f"non-empty string of at most {MAX_DECISION_SUMMARY_CHARS} characters",
                actual=_actual(summary),
            ))
    return issues


def _state_delta_issues(value: dict[str, Any]) -> list[ValidationIssue]:
    """校验 state delta 容器及本票已确定的 Related Candidate 位置。"""
    issues: list[ValidationIssue] = []
    state_delta = value.get("state_delta")
    if not isinstance(state_delta, dict):
        if "state_delta" in value:
            issues.append(ValidationIssue(
                path="$.state_delta",
                expected="JSON object",
                actual=_actual(state_delta),
            ))
    elif "related_candidates" in state_delta:
        related = state_delta["related_candidates"]
        if not isinstance(related, list) or any(not isinstance(item, dict) for item in related):
            issues.append(ValidationIssue(
                path="$.state_delta.related_candidates",
                expected="array of JSON objects",
                actual=_actual(related),
            ))
    return issues


def _next_issues(next_value: object, role: str) -> list[ValidationIssue]:
    """校验唯一 next 的角色枚举及按 kind 区分的严格字段。"""
    issues: list[ValidationIssue] = []
    if next_value is _MISSING:
        return issues  # 缺失错误由固定顶层字段校验统一生成
    if not isinstance(next_value, dict):
        return [ValidationIssue(
            path="$.next",
            expected="JSON object",
            actual=_actual(next_value),
        )]

    kind = next_value.get("kind")
    allowed_kinds = ROLE_NEXT_KINDS[role]
    if not isinstance(kind, str) or kind not in allowed_kinds:
        issues.append(ValidationIssue(
            path="$.next.kind",
            expected="role-allowed next kind",
            actual=_enum_actual(kind, missing="kind" not in next_value),
            allowed_values=allowed_kinds,
        ))
        issues.extend(_unknown_issues(next_value, _FINAL_FIELDS, "$.next"))
        return issues

    next_fields = _ACTION_FIELDS if kind == "tool_action" else _FINAL_FIELDS
    issues.extend(_unknown_issues(next_value, next_fields, "$.next"))
    if kind == "tool_action":
        for field, expected in (("tool", "non-empty string"), ("arguments", "JSON object")):
            issue = _required_issue(next_value, field, "$.next", expected)
            if issue:
                issues.append(issue)
        tool = next_value.get("tool")
        arguments = next_value.get("arguments")
        if "tool" in next_value and (not isinstance(tool, str) or not tool.strip()):
            issues.append(ValidationIssue(
                path="$.next.tool", expected="non-empty string", actual=_actual(tool)))
        if "arguments" in next_value and not isinstance(arguments, dict):
            issues.append(ValidationIssue(
                path="$.next.arguments", expected="JSON object", actual=_actual(arguments)))
    return issues


_MISSING = object()


def parse_proposal(raw_reply: str, role: str) -> ProposalResult:
    """整份校验模型回复，成功才构造 ActionProposal/FinalProposal。"""
    role = _role(role)
    value, issues = _decode(raw_reply)
    if value is None:
        return ProposalError(tuple(issues), raw_reply)

    issues.extend(_top_issues(value))
    issues.extend(_state_delta_issues(value))
    next_value = value.get("next", _MISSING)
    issues.extend(_next_issues(next_value, role))

    if issues:
        return ProposalError(tuple(issues), raw_reply)
    summary = value["decision_summary"]
    state_delta = value["state_delta"]
    assert isinstance(next_value, dict)  # _next_issues 已完整校验
    kind = next_value["kind"]
    if kind == "tool_action":
        return ActionProposal(
            decision_summary=summary,
            state_delta=state_delta,
            tool=next_value["tool"],
            arguments=next_value["arguments"],
        )
    return FinalProposal(
        decision_summary=summary,
        state_delta=state_delta,
        kind=kind,
    )


class AgentSession:
    """可逐步驱动的语义会话；``step`` 永远只发起一次模型请求。"""

    def __init__(self, role: str, llm, context: ContextManager,
                 transcript: Path | Transcript | None = None):
        self.role = _role(role)
        self.llm = llm
        self.context = context
        self.transcript = transcript if isinstance(transcript, Transcript) else Transcript(transcript)
        self.request_count = 0

    def _messages(self) -> list[dict]:
        """把角色协议并入请求副本，不改写调用方持有的 ContextManager。"""
        messages = self.context.build_messages()
        instruction = protocol_instruction(self.role)
        system = dict(messages[0])
        if instruction not in system["content"]:
            system["content"] = f"{system['content']}\n\n{instruction}"
        return [system, *messages[1:]]

    def reset_for_resume(self) -> None:
        """Retain fixed system instructions only; Host supplies rebuilt state next."""
        previous = self.context
        self.context = ContextManager(
            previous.system["content"], "",
            max_est_tokens=previous.max_est_tokens,
            trigger_ratio=previous.trigger_ratio,
        )

    def step(self, input_message: str | None = None) -> ProposalResult:
        """可选回填上一 Observation View/协议错误，再请求一个 Proposal 后暂停。"""
        if input_message is not None:
            self.context.append("user", input_message)
            self.transcript.log(self.request_count + 1, "user", input_message)
        messages = self._messages()
        self.request_count += 1
        started = time.time()
        reply, usage_value = self.llm.chat(messages)
        usage = dict(usage_value or {})
        reasoning = usage.pop("reasoning_content", "")
        content = f"{reasoning}\n{reply}".strip() if reasoning else reply
        self.transcript.log(
            self.request_count,
            "assistant",
            content,
            usage=usage,
            elapsed=time.time() - started,
            in_chars=sum(len(message.get("content", "")) for message in messages),
        )
        self.context.append("assistant", reply)
        return parse_proposal(reply, self.role)

"""Host Agent Session 协议测试（ScriptedLLM，零工具、零网络）。"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from firmware_audit.step5_agent.engine.context import ContextManager
from firmware_audit.step5_agent.engine.transcript import assistant_replay_body
from firmware_audit.step5_agent.host.session import (
    ActionProposal,
    AgentSession,
    FinalProposal,
    ProposalError,
    parse_proposal,
    protocol_instruction,
)
from firmware_audit.test.scripted_llm import ScriptedLLM


def _reply(next_: dict, state_delta: dict | None = None) -> str:
    return json.dumps({
        "decision_summary": "读取入口配置以确认外部暴露关系",
        "state_delta": state_delta or {},
        "next": next_,
    }, ensure_ascii=False)


def test_parse_tool_action_into_action_proposal() -> None:
    parsed = parse_proposal(
        _reply({
            "kind": "tool_action",
            "tool": "read_file",
            "arguments": {"path": "extracted/etc/config"},
        }, {"working_hypothesis": "配置可能暴露管理接口"}),
        role="analysis",
    )

    assert isinstance(parsed, ActionProposal)
    assert parsed.decision_summary == "读取入口配置以确认外部暴露关系"
    assert parsed.state_delta == {"working_hypothesis": "配置可能暴露管理接口"}
    assert parsed.tool == "read_file"
    assert parsed.arguments == {"path": "extracted/etc/config"}


def test_protocol_instruction_describes_strict_role_contract() -> None:
    prompt = protocol_instruction("recon")

    assert "纯 JSON" in prompt
    assert "decision_summary" in prompt
    assert "state_delta" in prompt
    assert "related_candidates" in prompt
    assert "tool_action" in prompt
    assert "complete_survey" in prompt
    assert "submit_case" not in prompt


@pytest.mark.parametrize(
    ("role", "kind"),
    [
        ("recon", "complete_survey"),
        ("analysis", "submit_case"),
        ("analysis", "close_investigation"),
        ("verification", "complete_verification"),
    ],
)
def test_parse_role_specific_terminal_into_final_proposal(role: str, kind: str) -> None:
    parsed = parse_proposal(_reply({"kind": kind}), role=role)

    assert isinstance(parsed, FinalProposal)
    assert parsed.kind == kind


def test_related_candidates_are_state_delta_only() -> None:
    related = [{"target": "extracted/bin/httpd", "signal": "second entry point"}]
    valid = parse_proposal(
        _reply(
            {"kind": "tool_action", "tool": "read_file", "arguments": {}},
            {"related_candidates": related},
        ),
        role="analysis",
    )
    misplaced = parse_proposal(json.dumps({
        "decision_summary": "发现独立入口",
        "state_delta": {},
        "related_candidates": related,
        "next": {"kind": "close_investigation"},
    }), role="analysis")

    assert isinstance(valid, ActionProposal)
    assert valid.state_delta["related_candidates"] == related
    assert isinstance(misplaced, ProposalError)
    assert any(issue.path == "$.related_candidates" for issue in misplaced.issues)


@pytest.mark.parametrize(
    ("role", "kind", "allowed"),
    [
        ("recon", "submit_case", {"tool_action", "complete_survey"}),
        ("analysis", "complete_survey", {"tool_action", "submit_case", "close_investigation"}),
        ("verification", "close_investigation", {"tool_action", "complete_verification"}),
        ("analysis", "invented", {"tool_action", "submit_case", "close_investigation"}),
    ],
)
def test_role_restriction_returns_allowed_kinds(role: str, kind: str, allowed: set[str]) -> None:
    parsed = parse_proposal(_reply({"kind": kind}), role=role)

    assert isinstance(parsed, ProposalError)
    issue = next(issue for issue in parsed.issues if issue.path == "$.next.kind")
    assert issue.expected == "role-allowed next kind"
    assert set(issue.allowed_values) == allowed
    assert issue.actual == json.dumps(kind)


@pytest.mark.parametrize("raw", ["not json", '{"decision_summary":"cut'])
def test_non_json_and_truncated_json_return_structured_root_error(raw: str) -> None:
    parsed = parse_proposal(raw, role="analysis")

    assert isinstance(parsed, ProposalError)
    assert parsed.issues[0].path == "$"
    assert parsed.issues[0].expected == "JSON object"
    assert parsed.issues[0].allowed_values == ()
    assert "field_path" in parsed.feedback_message()
    assert "expected" in parsed.feedback_message()
    assert "allowed_values" in parsed.feedback_message()


def test_duplicate_json_fields_are_rejected_instead_of_silently_overwritten() -> None:
    raw = (
        '{"decision_summary":"first","decision_summary":"second",'
        '"state_delta":{},"next":{"kind":"submit_case"}}'
    )

    parsed = parse_proposal(raw, role="analysis")

    assert isinstance(parsed, ProposalError)
    assert parsed.issues[0].path == "$.decision_summary"
    assert parsed.issues[0].expected == "unique field"


@pytest.mark.parametrize(
    ("payload", "path", "expected"),
    [
        ({"decision_summary": 7, "state_delta": {}, "next": {"kind": "submit_case"}},
         "$.decision_summary", "non-empty string of at most 500 characters"),
        ({"decision_summary": "ok", "state_delta": [], "next": {"kind": "submit_case"}},
         "$.state_delta", "JSON object"),
        ({"decision_summary": "ok", "state_delta": {"related_candidates": {}},
          "next": {"kind": "submit_case"}},
         "$.state_delta.related_candidates", "array of JSON objects"),
        ({"decision_summary": "ok", "state_delta": {}, "next": []},
         "$.next", "JSON object"),
        ({"decision_summary": "ok", "state_delta": {},
          "next": {"kind": "tool_action", "tool": 4, "arguments": {}}},
         "$.next.tool", "non-empty string"),
        ({"decision_summary": "ok", "state_delta": {},
          "next": {"kind": "tool_action", "tool": "read_file", "arguments": []}},
         "$.next.arguments", "JSON object"),
    ],
)
def test_wrong_types_return_precise_field_errors(payload: dict, path: str, expected: str) -> None:
    parsed = parse_proposal(json.dumps(payload), role="analysis")

    assert isinstance(parsed, ProposalError)
    assert any(issue.path == path and issue.expected == expected for issue in parsed.issues)


@pytest.mark.parametrize(
    ("payload", "path"),
    [
        ({"decision_summary": "ok", "state_delta": {}, "next": {"kind": "submit_case"},
          "surprise": True}, "$.surprise"),
        ({"decision_summary": "ok", "state_delta": {},
          "next": {"kind": "tool_action", "tool": "read_file", "arguments": {},
                   "surprise": True}}, "$.next.surprise"),
        ({"decision_summary": "ok", "state_delta": {},
          "next": {"kind": "submit_case", "arguments": {}}}, "$.next.arguments"),
    ],
)
def test_unknown_fields_are_rejected(payload: dict, path: str) -> None:
    parsed = parse_proposal(json.dumps(payload), role="analysis")

    assert isinstance(parsed, ProposalError)
    issue = next(issue for issue in parsed.issues if issue.path == path)
    assert issue.expected == "known field"
    assert issue.allowed_values


def test_session_makes_one_request_reuses_context_and_transcript(tmp_path: Path) -> None:
    llm = ScriptedLLM([
        _reply({"kind": "tool_action", "tool": "read_file", "arguments": {"path": "x"}}),
        _reply({"kind": "close_investigation"}),
    ])
    context = ContextManager("fixed system", "current investigation")
    transcript = tmp_path / "transcript.jsonl"
    session = AgentSession(role="analysis", llm=llm, context=context, transcript=transcript)

    first = session.step()

    assert isinstance(first, ActionProposal)
    assert len(llm.calls) == 1
    assert llm.calls[0][0]["content"].startswith("fixed system")
    assert "纯 JSON" in llm.calls[0][0]["content"]
    assert "submit_case" in llm.calls[0][0]["content"]
    assert context.system["content"] == "fixed system"
    assert context.recent == [{"role": "assistant", "content": llm.replies[0]}]
    entries = [json.loads(line) for line in transcript.read_text(encoding="utf-8").splitlines()]
    assert [(entry["step"], entry["phase"]) for entry in entries] == [(1, "assistant")]

    second = session.step("Observation View: file contents")

    assert second.kind == "close_investigation"
    assert len(llm.calls) == 2
    assert llm.calls[1][-2:] == [
        {"role": "assistant", "content": llm.replies[0]},
        {"role": "user", "content": "Observation View: file contents"},
    ]
    entries = [json.loads(line) for line in transcript.read_text(encoding="utf-8").splitlines()]
    assert [(entry["step"], entry["phase"]) for entry in entries] == [
        (1, "assistant"),
        (2, "user"),
        (2, "assistant"),
    ]


def test_invalid_session_reply_has_no_tool_or_loop_side_effect(tmp_path: Path) -> None:
    llm = ScriptedLLM(["not json", _reply({"kind": "close_investigation"})])
    context = ContextManager("fixed system", "current investigation")
    session = AgentSession(
        role="analysis",
        llm=llm,
        context=context,
        transcript=tmp_path / "transcript.jsonl",
    )

    result = session.step()

    assert isinstance(result, ProposalError)
    assert len(llm.calls) == 1
    assert session.request_count == 1
    assert not hasattr(session, "tools")
    assert not hasattr(session, "run")


# ---- 票 26:parser 正文与 reasoning 分离留存、原始回复可重放 ----

def _assistant_entries(transcript_path: Path) -> list[dict]:
    entries = [
        json.loads(line)
        for line in transcript_path.read_text(encoding="utf-8").splitlines()
    ]
    return [entry for entry in entries if entry["phase"] == "assistant"]


def test_step_logs_parser_body_and_reasoning_separately(tmp_path: Path) -> None:
    """content 即 parse_proposal 的逐字输入;reasoning 分字段独立留存,
    且不回灌控制上下文(票 26)。"""
    reply = _reply({"kind": "tool_action", "tool": "read_file", "arguments": {}})
    reasoning = "先读入口配置,再判断暴露面。"
    llm = ScriptedLLM([(reply, {
        "prompt_tokens": 12, "completion_tokens": 34,
        "reasoning_content": reasoning,
    })])
    context = ContextManager("fixed system", "current investigation")
    transcript = tmp_path / "transcript.jsonl"
    session = AgentSession(role="analysis", llm=llm, context=context,
                           transcript=transcript)

    result = session.step()

    assert isinstance(result, ActionProposal)
    entries = _assistant_entries(transcript)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["content"] == reply  # 逐字 parser 输入,无拼接
    assert entry["reasoning"] == reasoning  # 独立字段,可审计
    assert entry["usage"] == {"prompt_tokens": 12, "completion_tokens": 34}
    # 控制上下文只回灌正文,reasoning 不进对话记忆。
    assert context.recent == [{"role": "assistant", "content": reply}]


def test_assistant_replay_body_roundtrips_parser_input(tmp_path: Path) -> None:
    """新格式事件:reader 取回的正文可原样重放 parser,结论与原次一致。"""
    reply = _reply({"kind": "submit_case"})
    llm = ScriptedLLM([(reply, {"reasoning_content": "案卷已成熟"})])
    transcript = tmp_path / "transcript.jsonl"
    session = AgentSession(role="analysis", llm=llm,
                           context=ContextManager("s", ""),
                           transcript=transcript)
    original = session.step()

    entry = _assistant_entries(transcript)[0]
    replay = assistant_replay_body(entry)

    assert replay.replayable is True
    assert replay.body == reply
    assert replay.reasoning == "案卷已成熟"
    assert replay.note is None
    assert parse_proposal(replay.body, "analysis").kind == original.kind  # type: ignore[union-attr]


def test_assistant_replay_body_marks_legacy_merged_content_not_replayable() -> None:
    """旧格式(reasoning 并入 content,无边界)明确标记不可精确重放,
    不推测切分、不补造正文(票 26)。"""
    merged = "先想想。\n{\"decision_summary\": \"合并存储\"}"

    replay = assistant_replay_body({
        "step": 1, "phase": "assistant", "content": merged,
        "usage": {"prompt_tokens": 1, "completion_tokens": 2},
    })

    assert replay.replayable is False
    assert replay.body is None
    assert replay.reasoning is None
    assert replay.note is not None and "旧格式" in replay.note


def test_assistant_replay_body_rejects_non_assistant_events() -> None:
    """user/tool 等事件没有 parser 输入,reader 如实标注而不是误判格式。"""
    replay = assistant_replay_body({
        "step": 1, "phase": "user", "content": "Candidate 上下文",
    })

    assert replay.replayable is False
    assert replay.body is None
    assert "非 assistant 事件" in replay.note


def test_assistant_replay_body_tolerates_null_reasoning(tmp_path: Path) -> None:
    reply = _reply({"kind": "close_investigation"})
    llm = ScriptedLLM([(reply, {"reasoning_content": None})])
    transcript = tmp_path / "transcript.jsonl"
    AgentSession(role="analysis", llm=llm, context=ContextManager("s", ""),
                 transcript=transcript).step()

    replay = assistant_replay_body(_assistant_entries(transcript)[0])

    assert replay.replayable is True
    assert replay.body == reply
    assert replay.reasoning is None

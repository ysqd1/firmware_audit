"""Host Recon runner tests: overview, input gate, survey gate, Candidate Store."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from firmware_audit import file_rules
from firmware_audit.step5_agent.engine.context import ContextManager
from firmware_audit.step5_agent.host import (
    ActionProposal,
    AgentSession,
    FinalProposal,
    HostReconRunner,
    ReconRunResult,
)
from firmware_audit.step5_agent.host.recon import (
    RECON_SESSION_SYSTEM,
    build_site_overview,
    input_failure_reason,
)
from firmware_audit.step5_agent.providers.tools import (
    ToolContext,
    make_tools,
    tool_names_for_role,
)
from firmware_audit.step5_agent.providers.tools.base import ToolResult
from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.test.test_step5_host_analysis import FakeTool


@pytest.fixture(autouse=True)
def _deterministic_excludes(monkeypatch):
    """概览/输入分类的 SDK 排除口径用固定名单,不随 profile 全局状态漂移。"""
    monkeypatch.setattr(file_rules, "SEARCH_EXCLUDE_DIRS", ["usr/lib"])


def _make_tree(process_dir: Path, files: dict[str, int]) -> None:
    for rel, size in files.items():
        path = process_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)


def test_site_overview_summarizes_auditable_tree(tmp_path: Path) -> None:
    process_dir = tmp_path / "process"
    _make_tree(process_dir, {
        "extracted/bin/robotd": 500,
        "extracted/etc/device.conf": 40,
        "extracted/usr/lib/libc.so.6": 900,
        "extracted/README": 5,
    })
    _make_tree(process_dir, {
        "analysis/etc/device.conf.c": 11,
        "analysis/bin/robotd.strings.json": 2,
    })

    overview = build_site_overview(process_dir)

    assert overview["extracted_present"] is True
    assert overview["total_file_count"] == 4
    assert overview["auditable_file_count"] == 3
    dirs = {entry["name"]: entry for entry in overview["top_level_dirs"]}
    assert dirs["bin/"] == {"name": "bin/", "files": 1, "bytes": 500}
    assert dirs["etc/"] == {"name": "etc/", "files": 1, "bytes": 40}
    assert dirs["(root)"] == {"name": "(root)", "files": 1, "bytes": 5}
    assert "usr/" not in dirs
    assert overview["largest_files"][0] == {"path": "extracted/bin/robotd", "bytes": 500}
    assert all(item["path"].startswith("extracted/") for item in overview["largest_files"])
    assert overview["extension_distribution"][".conf"] == 1
    assert overview["analysis_sidecars"] == {"c": 1, "strings_json": 1, "imports_json": 0}
    assert input_failure_reason(overview) is None


@pytest.mark.parametrize(
    ("files", "dirs", "expected"),
    [
        ({}, [], "extraction_missing"),
        ({}, ["extracted"], "empty_tree"),
        ({"extracted/usr/lib/libz.so": 10}, [], "no_valid_targets"),
    ],
)
def test_invalid_inputs_classify_as_input_failure(
    tmp_path: Path, files: dict[str, int], dirs: list[str], expected: str,
) -> None:
    process_dir = tmp_path / "process"
    process_dir.mkdir(parents=True)
    for directory in dirs:
        (process_dir / directory).mkdir(parents=True)
    if files:
        _make_tree(process_dir, files)
    overview = build_site_overview(process_dir)
    assert overview["extracted_present"] is bool(files or dirs)
    assert input_failure_reason(overview) == expected


def test_evidence_recorder_seeds_sequence_from_existing_files(tmp_path: Path) -> None:
    from firmware_audit.step5_agent.host.evidence import EvidenceRecorder

    existing = tmp_path / "investigations" / "recon" / "evidence"
    existing.mkdir(parents=True)
    (existing / "ev-000002.json").write_text("{}", encoding="utf-8")
    (existing / "ev-000003.json").write_text("{}", encoding="utf-8")
    (existing / "notes.txt").write_text("not evidence", encoding="utf-8")

    recorder = EvidenceRecorder(tmp_path)
    recorder.seed_sequence_from_files()

    slot = recorder.reserve("cand-0001")
    assert slot.evidence_id == "ev-000004"


# ---- Host Recon Action Loop ----


class FakeReconSession:
    role = "recon"

    def __init__(self, proposals: list[object]):
        self.proposals = iter(proposals)
        self.inputs: list[str | None] = []

    def step(self, input_message: str | None = None):
        self.inputs.append(input_message)
        return next(self.proposals)


class EndlessActionSession:
    """永远提出 tool_action,用于耗尽轮次上限。"""

    role = "recon"

    def __init__(self):
        self.inputs: list[str | None] = []

    def step(self, input_message: str | None = None):
        self.inputs.append(input_message)
        return ActionProposal(
            decision_summary="继续侦查",
            state_delta={},
            tool="read_file",
            arguments={"path": "extracted/etc/device.conf"},
        )


def _recon_action(
    state_delta: dict | None = None,
    tool: str = "read_file",
    arguments: dict | None = None,
) -> ActionProposal:
    return ActionProposal(
        decision_summary="浅层侦查动作",
        state_delta=state_delta or {},
        tool=tool,
        arguments=arguments or {"path": "extracted/etc/device.conf"},
    )


def _survey(state_delta: dict) -> FinalProposal:
    return FinalProposal(
        decision_summary="提交完整 survey",
        state_delta=state_delta,
        kind="complete_survey",
    )


def _survey_delta(**overrides) -> dict:
    delta = {
        "attack_surface": [
            {"target": "extracted/etc/device.conf", "reason": "设备管理配置"},
            {"target": "extracted/bin/robotd", "reason": "网络守护进程"},
        ],
        "candidates": [
            {
                "kind": "signal",
                "target": "extracted/etc/device.conf",
                "signal": "配置含口令样式条目",
                "evidence_id": "ev-000001",
                "next_action": "核实口令用途与影响面",
            },
            {
                "kind": "coverage",
                "target": "extracted/bin/robotd",
                "signal": "网络守护进程二进制,本轮仅枚举未深查",
                "evidence_id": "ev-000001",
                "next_action": "字符串与导入核查后按需反编译审计",
            },
        ],
        "checked_scope": ["extracted/etc/"],
        "coverage_gaps": [
            {"area": "extracted/bin/", "reason": "网络守护进程未做字符串与导入核查"},
        ],
    }
    delta.update(overrides)
    return delta


def _workspace(tmp_path: Path, files: dict[str, int] | None = None) -> Path:
    process_dir = tmp_path / "process"
    _make_tree(process_dir, files or {"extracted/etc/device.conf": 24, "extracted/bin/robotd": 64})
    return process_dir


def _run(
    tmp_path: Path,
    session,
    tools: dict | None = None,
    **runner_kwargs,
) -> ReconRunResult:
    if tools is None:
        tools = {"read_file": FakeTool(ToolResult(ok=True, text="token=literal", raw="token=literal"))}
    runner = HostReconRunner(tmp_path, tools, **runner_kwargs)
    return runner.run(session, _workspace(tmp_path))


def test_recon_records_evidence_and_persists_candidate_store(tmp_path: Path) -> None:
    session = FakeReconSession([
        _recon_action({"notes": "读取管理配置"}),
        _survey(_survey_delta()),
    ])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    assert result.rounds_used == 2
    assert result.reason is None
    assert [reference.evidence_id for reference in result.evidence] == ["ev-000001"]
    evidence_path = tmp_path / "investigations" / "recon" / "evidence" / "ev-000001.json"
    saved_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert saved_evidence["candidate_id"] == "recon"
    assert saved_evidence["investigation_id"] == "recon-survey"
    assert saved_evidence["tool"] == "read_file"
    assert saved_evidence["arguments"]["path"] == "extracted/etc/device.conf"
    assert "Observation View [ev-000001]" in session.inputs[1]
    assert "token=literal" in session.inputs[1]
    assert result.session_state == {"notes": "读取管理配置"}

    assert result.store_path == tmp_path / "candidates.json"
    store = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    assert store["schema_version"] == 1
    assert store["survey"]["checked_scope"] == ["extracted/etc/"]
    assert store["survey"]["coverage_gaps"][0]["area"] == "extracted/bin/"
    assert store["session_state"] == {"notes": "读取管理配置"}
    assert store["candidates"] == [
        {
            "proposal_id": "proposal-0001",
            "kind": "signal",
            "target": "extracted/etc/device.conf",
            "signal": "配置含口令样式条目",
            "evidence_id": "ev-000001",
            "next_action": "核实口令用途与影响面",
            "possible_source": None,
            "possible_sink": None,
            "extras": {},
        },
        {
            "proposal_id": "proposal-0002",
            "kind": "coverage",
            "target": "extracted/bin/robotd",
            "signal": "网络守护进程二进制,本轮仅枚举未深查",
            "evidence_id": "ev-000001",
            "next_action": "字符串与导入核查后按需反编译审计",
            "possible_source": None,
            "possible_sink": None,
            "extras": {},
        },
    ]
    assert result.candidates[0].proposal_id == "proposal-0001"
    assert result.survey is not None and result.survey["attack_surface"][0]["target"] == "extracted/etc/device.conf"


def test_deep_tool_request_is_rejected_and_agent_recovers(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="token=literal", raw="token=literal"))
    session = FakeReconSession([
        _recon_action(tool="ghidra_decompile", arguments={"file_ref": "extracted/bin/robotd"}),
        _recon_action(tool="r2_list_functions", arguments={"file_ref": "extracted/bin/robotd"}),
        _recon_action(),
        _survey(_survey_delta()),
    ])

    result = _run(tmp_path, session, tools={"read_file": tool})

    assert result.status == "completed"
    rejection = session.inputs[1]
    assert "无权调用" in rejection
    assert "ghidra_decompile" in rejection
    assert "list_files" in rejection  # 反馈列出可用浅层工具
    r2_rejection = session.inputs[2]
    assert "r2_list_functions" in r2_rejection
    assert [reference.tool for reference in result.evidence] == ["read_file"]
    assert len(tool.calls) == 1


def test_round_limit_default_env_override_and_exhaustion(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("STEP5_RECON_MAX_ITERS", raising=False)
    assert HostReconRunner(tmp_path, {}).max_rounds == 30
    monkeypatch.setenv("STEP5_RECON_MAX_ITERS", "2")
    assert HostReconRunner(tmp_path, {}).max_rounds == 2
    monkeypatch.setenv("STEP5_RECON_MAX_ITERS", "abc")
    assert HostReconRunner(tmp_path, {}).max_rounds == 30
    monkeypatch.setenv("STEP5_RECON_MAX_ITERS", "0")
    assert HostReconRunner(tmp_path, {}).max_rounds == 1

    result = _run(tmp_path, EndlessActionSession(), max_rounds=2)

    assert result.status == "incomplete"
    assert result.reason == "rounds_exhausted"
    assert result.rounds_used == 2
    assert result.survey is None and result.candidates == ()
    assert not (tmp_path / "candidates.json").exists()


@pytest.mark.parametrize("section", ["attack_surface", "candidates", "checked_scope", "coverage_gaps"])
def test_survey_rejected_while_any_section_missing(tmp_path: Path, section: str) -> None:
    delta = {key: value for key, value in _survey_delta().items() if key != section}
    session = FakeReconSession([_recon_action(), _survey(delta), _survey(_survey_delta())])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    assert f"$.state_delta.{section}" in session.inputs[2]
    assert "survey_rejected" in session.inputs[2]
    # 重提被接受后,store 才落盘且只落一次
    store = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    assert len(store["candidates"]) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c.pop("target"),
        lambda c: c.update(signal="  "),
        lambda c: c.pop("next_action"),
        lambda c: c.update(kind="hypothesis"),
        lambda c: c.pop("evidence_id"),
        lambda c: c.update(evidence_id="ev-999999"),
    ],
)
def test_survey_rejected_when_candidate_not_actionable(tmp_path: Path, mutation) -> None:
    delta = _survey_delta()
    mutation(delta["candidates"][0])
    session = FakeReconSession([_recon_action(), _survey(delta), _survey(_survey_delta())])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    feedback = session.inputs[2]
    assert "$.state_delta.candidates[0]" in feedback
    assert "survey_rejected" in feedback


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.update(attack_surface=[{"reason": "缺 target"}]),
        lambda s: s.update(attack_surface=["裸字符串"]),
        lambda s: s.update(checked_scope=[42]),
        lambda s: s.update(coverage_gaps=[{"reason": "缺 area"}]),
        lambda s: s.update(candidates=[]),
    ],
)
def test_survey_rejected_on_malformed_sections(tmp_path: Path, mutation) -> None:
    delta = _survey_delta()
    mutation(delta)
    session = FakeReconSession([_recon_action(), _survey(delta)])

    result = _run(tmp_path, session, max_rounds=2)

    assert result.status == "incomplete"
    assert result.reason == "rounds_exhausted"
    assert not (tmp_path / "candidates.json").exists()


def test_candidates_allow_empty_source_sink_and_preserve_extras(tmp_path: Path) -> None:
    delta = _survey_delta(
        candidates=[
            {
                "kind": "signal",
                "target": "extracted/etc/device.conf",
                "signal": "配置含口令样式条目",
                "evidence_id": "ev-000001",
                "next_action": "核实口令用途",
                "rationale": "token= 字样出现在管理配置",
            },
            {
                "kind": "coverage",
                "target": "extracted/bin/robotd",
                "signal": "网络守护进程,外部输入解析入口",
                "evidence_id": "ev-000001",
                "next_action": "字符串与导入核查后反编译审计",
                "possible_source": "",
                "possible_sink": "system 调用",
            },
        ],
    )
    session = FakeReconSession([_recon_action(), _survey(delta)])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    signal, coverage = result.candidates
    assert signal.possible_source is None and signal.possible_sink is None
    assert signal.extras == {"rationale": "token= 字样出现在管理配置"}
    assert coverage.kind == "coverage"
    assert coverage.possible_source == ""
    assert coverage.possible_sink == "system 调用"
    store = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    assert [item["proposal_id"] for item in store["candidates"]] == [
        "proposal-0001", "proposal-0002",
    ]


def test_invalid_input_ends_as_input_failure_without_model(tmp_path: Path) -> None:
    process_dir = tmp_path / "process"
    process_dir.mkdir()
    session = FakeReconSession([])  # 任何 step 调用都会 StopIteration

    result = HostReconRunner(tmp_path, {}).run(session, process_dir)

    assert result.status == "input_failure"
    assert result.reason in ("extraction_missing", "empty_tree", "no_valid_targets")
    assert result.reason == "extraction_missing"
    assert session.inputs == []
    assert not (tmp_path / "candidates.json").exists()


def test_runner_rejects_non_recon_session(tmp_path: Path) -> None:
    class AnalysisSession:
        role = "analysis"

    with pytest.raises(ValueError, match="role='recon'"):
        HostReconRunner(tmp_path, {}).run(AnalysisSession(), _workspace(tmp_path))


def test_second_run_evidence_ids_continue_after_existing_files(tmp_path: Path) -> None:
    prior = tmp_path / "investigations" / "recon" / "evidence"
    prior.mkdir(parents=True)
    (prior / "ev-000001.json").write_text("{}", encoding="utf-8")
    delta = _survey_delta()
    for candidate in delta["candidates"]:
        candidate["evidence_id"] = "ev-000002"
    session = FakeReconSession([_recon_action(), _survey(delta)])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    assert result.evidence[0].evidence_id == "ev-000002"
    assert (tmp_path / "investigations/recon/evidence/ev-000002.json").exists()


def test_param_contract_violation_is_fed_back_without_side_effect(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="must not run", raw="must not run"))
    session = FakeReconSession([
        _recon_action(arguments={"path": 7}),
        _recon_action(),
        _survey(_survey_delta()),
    ])

    result = _run(tmp_path, session, tools={"read_file": tool})

    assert result.status == "completed"
    assert tool.calls == [{"limit": 200, "offset": 0, "path": "extracted/etc/device.conf"}]
    assert "参数未通过接口契约" in session.inputs[1]


# ---- 端到端:临时解包树 + 真实工具 + 真实 AgentSession + ScriptedLLM ----


def test_end_to_end_scripted_llm_produces_readable_survey_and_store(tmp_path: Path) -> None:
    process_dir = tmp_path / "process"
    _make_tree(process_dir, {
        "extracted/etc/device.conf": 30,
        "extracted/bin/robotd": 64,
    })
    (process_dir / "extracted" / "etc" / "device.conf").write_text(
        "admin_token=literal-secret\n", encoding="utf-8",
    )
    run_dir = tmp_path / "run"
    tools = make_tools(ToolContext(process_dir=process_dir), role="recon")
    assert set(tools) == set(tool_names_for_role("recon"))
    assert "ghidra_decompile" not in tools and "r2_xref_query" not in tools

    llm = ScriptedLLM([
        json.dumps({
            "decision_summary": "先枚举顶层结构",
            "state_delta": {"notes": "枚举顶层"},
            "next": {"kind": "tool_action", "tool": "list_files",
                     "arguments": {"directory": "."}},
        }, ensure_ascii=False),
        json.dumps({
            "decision_summary": "读取管理配置核实口令样式",
            "state_delta": {"focus": "extracted/etc/device.conf"},
            "next": {"kind": "tool_action", "tool": "read_file",
                     "arguments": {"path": "extracted/etc/device.conf"}},
        }, ensure_ascii=False),
        json.dumps({
            "decision_summary": "攻击面与候选已齐备,提交 survey",
            "state_delta": {
                "attack_surface": [
                    {"target": "extracted/etc/device.conf", "reason": "设备管理配置"},
                    {"target": "extracted/bin/robotd", "reason": "网络守护进程二进制"},
                ],
                "candidates": [
                    {
                        "kind": "signal",
                        "target": "extracted/etc/device.conf",
                        "signal": "管理配置含 admin_token= 硬编码样式条目",
                        "evidence_id": "ev-000002",
                        "next_action": "核实 token 的实际用途与影响面",
                    },
                    {
                        "kind": "coverage",
                        "target": "extracted/bin/robotd",
                        "signal": "网络守护进程,外部输入解析入口,本轮未深查",
                        "evidence_id": "ev-000001",
                        "next_action": "strings/imports 核查后按需反编译审计",
                    },
                ],
                "checked_scope": ["extracted/(顶层枚举)", "extracted/etc/device.conf"],
                "coverage_gaps": [
                    {"area": "extracted/bin/robotd", "reason": "守护进程未做字符串与导入核查"},
                ],
            },
            "next": {"kind": "complete_survey"},
        }, ensure_ascii=False),
    ])
    session = AgentSession(
        "recon", llm,
        ContextManager(RECON_SESSION_SYSTEM, ""),
        transcript=run_dir / "recon" / "transcript.jsonl",
    )

    runner = HostReconRunner(run_dir, tools)
    result = runner.run(session, process_dir)

    assert result.status == "completed"
    assert result.rounds_used == 3
    assert result.store_path == run_dir / "candidates.json"
    assert [reference.tool for reference in result.evidence] == [
        "list_files", "read_file",
    ]
    store = json.loads(result.store_path.read_text(encoding="utf-8"))
    assert [item["kind"] for item in store["candidates"]] == ["signal", "coverage"]
    assert store["candidates"][0]["evidence_id"] == "ev-000002"
    assert store["survey"]["coverage_gaps"][0]["area"] == "extracted/bin/robotd"
    for item in store["candidates"]:
        evidence_path = run_dir / "investigations" / "recon" / "evidence" / f"{item['evidence_id']}.json"
        assert evidence_path.exists()
    assert (run_dir / "recon" / "transcript.jsonl").exists()
    # 真实 Session 收到的首轮消息含 Host 注入的现场概览
    assert "site_overview" in session.context.recent[0]["content"]
    assert "bin/" in session.context.recent[0]["content"]


def test_survey_rejected_with_empty_checked_scope(tmp_path: Path) -> None:
    delta = _survey_delta(checked_scope=[])
    session = FakeReconSession([_recon_action(), _survey(delta), _survey(_survey_delta())])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    feedback = session.inputs[2]
    assert "$.state_delta.checked_scope" in feedback
    assert "empty array" in feedback


def test_coverage_gaps_require_a_coverage_candidate(tmp_path: Path) -> None:
    signal_only = _survey_delta(candidates=[_survey_delta()["candidates"][0]])
    session = FakeReconSession([_recon_action(), _survey(signal_only), _survey(_survey_delta())])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    feedback = session.inputs[2]
    assert "$.state_delta.candidates" in feedback
    assert "coverage" in feedback
    # 缺 coverage 候选的 survey 不落盘;补齐重提后两种 kind 均入库
    assert [candidate.kind for candidate in result.candidates] == ["signal", "coverage"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c.update(claim_profile="authentication"),  # 不在枚举内
        lambda c: c.update(anchor=["handle_msg"]),
        lambda c: c.update(mechanism=42),
        lambda c: c.update(component_or_entry={"a": 1}),
        lambda c: c.update(check_goal=True),
    ],
)
def test_survey_rejected_on_bad_fingerprint_input_fields(
    tmp_path: Path, mutation,
) -> None:
    """claim_profile 枚举与 fingerprint 输入字段类型在 survey 门被拒,供下游去重可靠归一。"""
    delta = _survey_delta()
    mutation(delta["candidates"][0])
    session = FakeReconSession([_recon_action(), _survey(delta), _survey(_survey_delta())])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    feedback = session.inputs[2]
    assert "survey_rejected" in feedback
    assert "$.state_delta.candidates[0]" in feedback


# ---- 票 25:错放进嵌套 fingerprint 对象的领域字段在 survey 门整份拒绝 ----


@pytest.mark.parametrize(
    "mutation,expected_path",
    [
        (
            lambda c: c.update(extras={"fingerprint": {
                "claim_profile": "credentials", "anchor": "device.conf:1",
            }}),
            "$.state_delta.candidates[0].extras.fingerprint.claim_profile",
        ),
        (
            lambda c: c.update(fingerprint={"mechanism": "command injection"}),
            "$.state_delta.candidates[0].fingerprint.mechanism",
        ),
    ],
)
def test_survey_rejected_on_fingerprint_nested_fields(
    tmp_path: Path, mutation, expected_path: str,
) -> None:
    """领域字段错放进嵌套 fingerprint 对象整份拒绝并指路平铺,不静默降级为 generic。"""
    delta = _survey_delta()
    mutation(delta["candidates"][0])
    session = FakeReconSession([_recon_action(), _survey(delta), _survey(_survey_delta())])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    feedback = session.inputs[2]
    assert "survey_rejected" in feedback
    assert expected_path in feedback
    assert "平铺" in feedback
    # 只有修正后的重提入库;入库记录不再携带嵌套对象
    store = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    assert all(
        "fingerprint" not in item.get("extras", {}) for item in store["candidates"])


def test_recon_prompt_example_candidate_passes_gate_with_flat_fields(
    tmp_path: Path,
) -> None:
    """提示里的完整 candidate 示例(平铺字段)必须真能通过 survey 门并带值入库。"""
    blocks = re.findall(r"```json\n(.*?)\n```", RECON_SESSION_SYSTEM, re.S)
    assert blocks, "提示缺少完整 candidate 示例"
    candidate = json.loads(blocks[0])
    assert candidate["kind"] == "signal"
    assert "fingerprint" not in candidate  # fingerprint 是 Host 派生值,不是输入
    candidate["evidence_id"] = "ev-000001"
    delta = _survey_delta(candidates=[
        candidate, _survey_delta()["candidates"][1],
    ])
    session = FakeReconSession([_recon_action(), _survey(delta)])

    result = _run(tmp_path, session)

    assert result.status == "completed"
    stored = json.loads(
        (tmp_path / "candidates.json").read_text(encoding="utf-8"))["candidates"][0]
    # v1 原始 proposal 工件把 fingerprint 输入字段收进 extras 透传(既有兼容链),
    # 值必须原样保留,后续 CandidateStore.build 归一时顶层读回。
    assert stored["extras"]["claim_profile"] == candidate["claim_profile"]
    assert stored["extras"]["anchor"] == candidate["anchor"]
    assert stored["extras"]["mechanism"] == candidate["mechanism"]
    assert "fingerprint" not in stored["extras"]  # 平铺输入不得包成嵌套对象

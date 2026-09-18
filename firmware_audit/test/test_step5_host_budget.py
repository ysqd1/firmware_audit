"""Ticket 10:协议失败、预算与停止规则的 Action Loop 与纯逻辑测试。

覆盖:四层配置解析与生效快照、预算台账(llm/token/生效轮/工具/活动时长)、
守卫三限、局部轮次上限、运行总预算耗尽的"保存现场不落终态"、not_started
落账原语、服务中断零终态零记账,以及三角色的三次协议失败收束。
全部走公开 seam:真 Host 循环 + Fake Session/Fake tools + 注入时钟。
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pytest

from firmware_audit.step5_agent.host import (
    DEFAULT_ANALYSIS_MAX_ROUNDS,
    DEFAULT_BUDGET_CONFIG,
    DEFAULT_VERIFICATION_MAX_ROUNDS,
    ENV_KEYS,
    BudgetExhaustedError,
    BudgetLedger,
    ConfigError,
    HostAnalysisTracer,
    HostReconRunner,
    HostVerificationRunner,
    RunBudget,
    load_config_snapshot,
    persist_config_snapshot,
    resolve_effective_config,
)
from firmware_audit.step5_agent.host.budget import (
    BUDGET_SCHEMA_VERSION,
    CONFIG_SCHEMA_VERSION,
)
from firmware_audit.step5_agent.host.store import StoreError
from firmware_audit.step5_agent.engine.context import ContextManager
from firmware_audit.step5_agent.host.analysis import ANALYSIS_SESSION_SYSTEM
from firmware_audit.step5_agent.host.session import AgentSession
from firmware_audit.step5_agent.providers.llm_client import LLMError
from firmware_audit.step5_agent.providers.tools.base import ToolResult
from firmware_audit.test.test_step5_host_analysis import (
    FakeSession,
    FakeTool,
    _action,
    _close,
    GENERIC_REQUIRED,
)
from firmware_audit.test.test_step5_host_recon import (
    FakeReconSession,
    _recon_action,
    _survey,
    _survey_delta,
    _workspace,
)
from firmware_audit.test.test_step5_host_verification import (
    FakeSession as FakeVerificationSession,
)
from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.test.test_step5_host_verification import (
    _prepared_tracer,
    _result,
    _v_action,
    _v_complete,
)


class FakeClock:
    """单调可拨时钟:活动时长断言不依赖真实 sleep。"""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class UsageSession(FakeSession):
    """带用量的 Session:token 记账可见(重生成请求同样计入)。"""

    def __init__(self, proposals: list[object], prompt: int = 10, completion: int = 5):
        super().__init__(proposals)
        self.last_usage = {"prompt_tokens": prompt, "completion_tokens": completion}


class StepAdvancingSession(FakeSession):
    """每步推进 1 秒的可拨时钟 Session:活动时段按步长可见。"""

    def __init__(self, proposals: list[object], clock: FakeClock):
        super().__init__(proposals)
        self.clock = clock

    def step(self, input_message: str | None = None):
        self.clock.advance(1.0)
        return super().step(input_message)


def _budget(tmp_path: Path, clock: FakeClock | None = None, **overrides) -> RunBudget:
    resolved = dict(DEFAULT_BUDGET_CONFIG)
    resolved.update(overrides)
    return RunBudget.load(
        tmp_path, clock=clock if clock is not None else FakeClock(), config=resolved,
        persist=False,
    )


def _ledger_document(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "budget.json").read_text(encoding="utf-8"))


# ---- S1 纯逻辑:配置解析四层优先级与快照 ----


def test_config_priority_is_explicit_env_profile_default() -> None:
    document = resolve_effective_config(
        explicit={"max_llm_calls": 7},
        env={ENV_KEYS["max_tool_attempts"]: "9", ENV_KEYS["max_llm_calls"]: "8"},
        profile={"max_llm_calls": 6, "max_tool_attempts": 5, "max_candidates": 3},
    )
    resolved, sources = document["resolved"], document["sources"]
    assert resolved["max_llm_calls"] == 7 and sources["max_llm_calls"] == "explicit"
    assert resolved["max_tool_attempts"] == 9 and sources["max_tool_attempts"] == "environment"
    assert resolved["max_candidates"] == 3 and sources["max_candidates"] == "profile"
    assert resolved["analysis_max_rounds"] == DEFAULT_ANALYSIS_MAX_ROUNDS
    assert sources["analysis_max_rounds"] == "default"
    assert resolved["max_active_seconds"] == 7200.0


def test_invalid_env_falls_through_but_bad_explicit_is_fatal() -> None:
    document = resolve_effective_config(
        env={ENV_KEYS["recon_max_rounds"]: "not-a-number"})
    assert document["resolved"]["recon_max_rounds"] == 30
    assert document["sources"]["recon_max_rounds"] == "default"

    with pytest.raises(ConfigError, match="显式参数"):
        resolve_effective_config(explicit={"max_llm_calls": 0})
    with pytest.raises(ConfigError, match="profile"):
        resolve_effective_config(profile={"max_candidates": "many"})


def test_out_of_bounds_env_falls_through_to_next_layer() -> None:
    """环境层的越界数值(负上限/零)同样视为缺省,不与显式层校验分叉。"""
    document = resolve_effective_config(env={
        ENV_KEYS["max_llm_calls"]: "-3",
        ENV_KEYS["max_active_seconds"]: "0",
    })
    assert document["resolved"]["max_llm_calls"] == 400
    assert document["resolved"]["max_active_seconds"] == 7200.0
    assert document["sources"]["max_llm_calls"] == "default"


def test_injected_run_budget_config_is_validated() -> None:
    with pytest.raises(ConfigError, match="RunBudget 配置"):
        RunBudget.load(Path(tempfile.mkdtemp()), config={"max_llm_calls": -1})


def test_effective_config_snapshot_is_persisted_and_reloadable(tmp_path: Path) -> None:
    document = resolve_effective_config(
        env={ENV_KEYS["verification_max_rounds"]: "12"})
    path = persist_config_snapshot(tmp_path, document)

    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["schema_version"] == CONFIG_SCHEMA_VERSION
    assert saved["resolved"]["verification_max_rounds"] == 12
    assert saved["sources"]["verification_max_rounds"] == "environment"
    assert load_config_snapshot(tmp_path) == saved

    path.write_text('{"schema_version": 99}', encoding="utf-8")
    with pytest.raises(StoreError, match="配置快照"):
        load_config_snapshot(tmp_path)


def test_env_keys_stay_coherent_with_role_resolvers(monkeypatch) -> None:
    """键名单一纪律:配置链与各角色 resolver 读同名环境变量,不漂移。"""
    from firmware_audit.step5_agent.host.candidates import resolve_processing_slots
    from firmware_audit.step5_agent.host import (
        resolve_analysis_max_rounds,
        resolve_verification_max_rounds,
    )
    from firmware_audit.step5_agent.host.recon import resolve_recon_max_rounds

    monkeypatch.setenv(ENV_KEYS["recon_max_rounds"], "4")
    monkeypatch.setenv(ENV_KEYS["analysis_max_rounds"], "5")
    monkeypatch.setenv(ENV_KEYS["verification_max_rounds"], "6")
    monkeypatch.setenv(ENV_KEYS["max_candidates"], "2")
    document = resolve_effective_config(env={
        ENV_KEYS["recon_max_rounds"]: "4",
        ENV_KEYS["analysis_max_rounds"]: "5",
        ENV_KEYS["verification_max_rounds"]: "6",
        ENV_KEYS["max_candidates"]: "2",
    })
    assert resolve_recon_max_rounds() == document["resolved"]["recon_max_rounds"] == 4
    assert resolve_analysis_max_rounds() == document["resolved"]["analysis_max_rounds"] == 5
    assert resolve_verification_max_rounds() == (
        document["resolved"]["verification_max_rounds"]) == 6
    # 初始案例上限沿用票 07 的名额旋钮,同一变量不造第二个名字。
    assert resolve_processing_slots() == document["resolved"]["max_candidates"] == 2
    assert DEFAULT_VERIFICATION_MAX_ROUNDS == 15


# ---- S1 纯逻辑:台账记账、恢复与守卫 ----


def test_ledger_counts_real_usage_and_survives_reload(tmp_path: Path) -> None:
    clock = FakeClock()
    ledger = BudgetLedger(tmp_path / "budget.json", clock=clock)
    ledger.start_active()
    clock.advance(2.5)
    ledger.record_llm_call({"prompt_tokens": 100, "completion_tokens": 40})
    ledger.record_llm_call()  # 无用量的 Fake Session 同样计一次真实请求
    ledger.record_validated_round()
    ledger.record_logical_tool_call()
    ledger.record_tool_execution()
    ledger.record_tool_execution()  # 同 call_id 重放:attempt 计,逻辑调用不增
    ledger.stop_active()
    clock.advance(60.0)  # 停机间隔:不再计入
    document = _ledger_document(tmp_path)
    assert document["schema_version"] == BUDGET_SCHEMA_VERSION
    assert document["llm_calls"] == 2
    assert document["prompt_tokens"] == 100
    assert document["completion_tokens"] == 40
    assert document["validated_rounds"] == 1
    assert document["logical_tool_calls"] == 1
    assert document["tool_attempts"] == 2
    assert document["active_seconds"] == pytest.approx(2.5)

    reloaded = BudgetLedger(tmp_path / "budget.json", clock=clock)
    assert reloaded.snapshot() == ledger.snapshot()


def test_ledger_drops_dangling_active_segment_on_reload(tmp_path: Path) -> None:
    clock = FakeClock()
    ledger = BudgetLedger(tmp_path / "budget.json", clock=clock)
    ledger.start_active()
    clock.advance(3.0)
    ledger.record_llm_call()  # 保存点:活动量 3s 已入账
    clock.advance(4.0)  # 崩溃前的尾部活动 + 停机,恢复时一并弃置

    resumed = BudgetLedger(tmp_path / "budget.json", clock=clock)
    assert resumed.active_seconds == pytest.approx(3.0)
    clock.advance(5.0)
    assert resumed.active_seconds == pytest.approx(3.0)  # 段已闭合


def test_ledger_rejects_corrupt_document(tmp_path: Path) -> None:
    path = tmp_path / "budget.json"
    path.write_text('{"schema_version": 1, "llm_calls": "many"}', encoding="utf-8")
    with pytest.raises(StoreError, match="预算台账"):
        BudgetLedger(path)


def test_run_budget_guards_each_limit(tmp_path: Path) -> None:
    clock = FakeClock()
    budget = _budget(tmp_path, clock=clock, max_llm_calls=1, max_tool_attempts=1,
                     max_active_seconds=10.0)
    budget.require_llm()
    budget.require_tool()
    budget.record_llm_call()
    with pytest.raises(BudgetExhaustedError, match="llm_calls"):
        budget.require_llm()
    budget.record_tool_execution()
    with pytest.raises(BudgetExhaustedError, match="tool_attempts"):
        budget.require_tool()

    time_budget = _budget(tmp_path, clock=clock, max_active_seconds=10.0)
    time_budget.start_active()
    clock.advance(10.0)
    with pytest.raises(BudgetExhaustedError, match="active_seconds"):
        time_budget.require_llm()


def test_default_run_budget_persists_env_layer_snapshot(tmp_path: Path) -> None:
    RunBudget.load(tmp_path)
    saved = load_config_snapshot(tmp_path)
    assert saved["resolved"] == DEFAULT_BUDGET_CONFIG
    assert set(saved["sources"].values()) == {"default"}


# ---- S3/S4:局部轮次上限 ----


def test_analysis_local_round_cap_closes_unresolved_budget_exhausted(
        tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool}, max_rounds=1)
    candidate = host.add_candidate({"target": "extracted/bin/router"})

    investigation = host.run_analysis(
        candidate.candidate_id, FakeSession([_action({}), _action({})]))

    assert (investigation.lifecycle_status, investigation.disposition,
            investigation.stop_reason) == (
        "finished", "unresolved", "budget_exhausted")
    assert len(investigation.evidence) == 1
    events = [
        json.loads(line)["kind"]
        for line in (tmp_path / "investigations" / candidate.candidate_id
                     / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events[-1] == "round_budget_exhausted"


def test_analysis_round_cap_survives_resume(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool}, max_rounds=2,
                              budget=_budget(tmp_path))
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    # StopIteration 作为受控中断:1 轮已应用并持久化。
    with pytest.raises(StopIteration):
        host.run_analysis(candidate.candidate_id, FakeSession([_action({})]))

    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool}, max_rounds=2,
                                 budget=_budget(tmp_path))
    investigation = resumed.run_analysis(
        candidate.candidate_id, FakeSession([_action({}), _close()]))
    # 恢复后只剩 1 轮:第 2 个动作触发轮次耗尽,close 不再可达。
    assert (investigation.disposition, investigation.stop_reason) == (
        "unresolved", "budget_exhausted")


def test_verification_retries_consume_local_round_budget(tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(
        tmp_path, {"read_file": tool}, tracer, max_rounds=1,
        budget=_budget(tmp_path),
    )
    invalid = type("Invalid", (), {})  # revalidate 拒绝的未知类型
    session = FakeVerificationSession([invalid, _v_complete()])

    outcome = runner.run_case(candidate_id, session)

    # 无效尝试烧掉唯一一轮:硬轮次上限先于三连失败与重生成收束。
    assert outcome.verdict == "inconclusive"
    assert outcome.stop_reason == "budget_exhausted"
    assert len(session.inputs) == 1


# ---- S3/S4/S5:三次协议失败的角色收束 ----


def test_verification_three_strikes_finalize_inconclusive_without_finding(
        tmp_path: Path) -> None:
    tracer, ids = _prepared_tracer(tmp_path, count=2)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer,
                                    budget=_budget(tmp_path))
    bad = _v_action({"claim_results": {
        "root_cause": _result("supported", "ev-000001")}})  # 引用冻结案卷 Evidence

    outcome = runner.run_case(ids[0], FakeVerificationSession([bad, bad, bad]))

    assert (outcome.verdict, outcome.stop_reason) == ("inconclusive", "protocol_error")
    assert outcome.finding_id is None
    assert not (tmp_path / "findings.json").exists()
    investigation = tracer.investigation_for(ids[0])
    assert (investigation.disposition, investigation.stop_reason) == (
        "inconclusive", "protocol_error")
    saved = json.loads(outcome.results_path.read_text(encoding="utf-8"))
    assert saved["stop_reason"] == "protocol_error"

    # 不阻断后续队列:下一案卷正常复核并确认。
    followup = runner.run_case(ids[1], FakeVerificationSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000003", claim=name) for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ]))
    assert followup.verdict == "confirmed"


def test_verification_protocol_error_never_confirms_even_with_full_results(
        tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer,
                                    budget=_budget(tmp_path))
    # 首轮已提交全部必填结果,随后三连无效:复核未合法收尾,不聚合出 confirmed。
    invalid = type("Invalid", (), {})
    outcome = runner.run_case(candidate_id, FakeVerificationSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002", claim=name) for name in GENERIC_REQUIRED}}),
        invalid, invalid, invalid,
    ]))

    assert (outcome.verdict, outcome.stop_reason) == ("inconclusive", "protocol_error")
    assert outcome.finding_id is None
    assert not (tmp_path / "findings.json").exists()


# ---- D2(ADR-0012 2026-09-16):轮次耗尽按已持久化 Claim Result 聚合 ----
# 预算耗尽不要求额外收到 complete_verification;结论与停止原因分别表达
# 证据判断与执行过程。


def test_round_exhaustion_confirms_full_support_without_complete(tmp_path: Path) -> None:
    """已提交完整独立支持、未发 complete_verification → confirmed + budget_exhausted。"""
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(
        tmp_path, {"read_file": tool}, tracer, max_rounds=1, budget=_budget(tmp_path))
    # 唯一一轮:动作携带全部必填 Claim 的独立 supported 结果(引用本次 ev-000002)。
    session = FakeVerificationSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002", claim=name)
            for name in GENERIC_REQUIRED}}),
    ])

    outcome = runner.run_case(candidate_id, session)

    assert (outcome.verdict, outcome.stop_reason) == ("confirmed", "budget_exhausted")
    assert outcome.finding_id == "f-0001"
    findings = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert [f["candidate_id"] for f in findings["findings"]] == [candidate_id]
    investigation = tracer.investigation_for(candidate_id)
    assert (investigation.disposition, investigation.stop_reason) == (
        "confirmed", "budget_exhausted")


def test_round_exhaustion_with_missing_claims_is_inconclusive(tmp_path: Path) -> None:
    """缺项(仅部分必填有结果)→ inconclusive,不生成 Finding。"""
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(
        tmp_path, {"read_file": tool}, tracer, max_rounds=1, budget=_budget(tmp_path))
    session = FakeVerificationSession([
        _v_action({"claim_results": {
            "target_exists": _result("supported", "ev-000002", claim="target_exists")}}),
    ])

    outcome = runner.run_case(candidate_id, session)

    assert (outcome.verdict, outcome.stop_reason) == ("inconclusive", "budget_exhausted")
    assert set(outcome.unsupported) == set(GENERIC_REQUIRED) - {"target_exists"}
    assert outcome.finding_id is None
    assert not (tmp_path / "findings.json").exists()


def test_round_exhaustion_with_decisive_refutation_is_rejected(tmp_path: Path) -> None:
    """决定性 Claim 被独立反证 → rejected,即使其余必填全部 supported。"""
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(
        tmp_path, {"read_file": tool}, tracer, max_rounds=1, budget=_budget(tmp_path))
    results = {name: _result("supported", "ev-000002", claim=name)
               for name in GENERIC_REQUIRED}
    results["root_cause"] = _result("refuted", "ev-000002", claim="root_cause")
    session = FakeVerificationSession([_v_action({"claim_results": results})])

    outcome = runner.run_case(candidate_id, session)

    assert (outcome.verdict, outcome.stop_reason) == ("rejected", "budget_exhausted")
    assert "root_cause" in outcome.decisive_refuted
    assert outcome.finding_id is None
    assert not (tmp_path / "findings.json").exists()


def test_recon_three_strikes_end_as_input_failure_protocol_error(
        tmp_path: Path) -> None:
    process_dir = _workspace(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="observed", raw="observed"))
    runner = HostReconRunner(tmp_path, {"read_file": tool},
                             budget=_budget(tmp_path))
    bad = type("Invalid", (), {})

    result = runner.run(FakeReconSession([bad, bad, bad]), process_dir)

    assert (result.status, result.reason) == ("input_failure", "protocol_error")
    assert result.rounds_used == 3
    assert result.evidence == ()
    assert not (tmp_path / "candidates.json").exists()


def test_recon_guard_rejections_count_as_strikes(tmp_path: Path) -> None:
    process_dir = _workspace(tmp_path)
    runner = HostReconRunner(
        tmp_path, {"read_file": FakeTool(ToolResult(ok=True, text="x", raw="x"))},
        budget=_budget(tmp_path))
    proposal = _recon_action(tool="r2_disassemble_function", arguments={
        "file_ref": "extracted/bin/robotd", "function": "main"})

    session = FakeReconSession([proposal, proposal, proposal])
    result = runner.run(session, process_dir)

    assert (result.status, result.reason) == ("input_failure", "protocol_error")
    assert result.rounds_used == 3
    assert "无权调用" in (session.inputs[1] or "")


# ---- S3:运行总预算耗尽——保存现场、不落终态、not_started ----


def test_run_total_llm_budget_exhaustion_saves_state_without_terminal(
        tmp_path: Path) -> None:
    clock = FakeClock()
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool},
                              budget=_budget(tmp_path, clock=clock, max_llm_calls=1))
    candidate = host.add_candidate({"target": "extracted/bin/router"})

    with pytest.raises(BudgetExhaustedError, match="llm_calls"):
        host.run_analysis(candidate.candidate_id, UsageSession([
            _action({}), _action({}), _close()]))

    investigation = host.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "investigating"  # 未消耗终态
    assert investigation.disposition is None
    assert investigation.stop_reason is None
    assert len(investigation.evidence) == 1
    document = _ledger_document(tmp_path)
    assert document["llm_calls"] == 1
    assert document["prompt_tokens"] == 10
    assert document["completion_tokens"] == 5

    # 提高上限后从保存的现场继续:同一调查补一轮收尾。
    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool},
                                 budget=_budget(tmp_path, clock=clock,
                                                max_llm_calls=10))
    finished = resumed.run_analysis(candidate.candidate_id, FakeSession([_close()]))
    assert finished.lifecycle_status == "finished"
    assert finished.disposition == "closed"


def test_run_total_tool_budget_exhaustion_mid_action_saves_pending(
        tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool},
                              budget=_budget(tmp_path, max_tool_attempts=1))
    candidate = host.add_candidate({"target": "extracted/bin/router"})

    with pytest.raises(BudgetExhaustedError, match="tool_attempts"):
        host.run_analysis(candidate.candidate_id, FakeSession([
            _action({}), _action({}), _close()]))

    investigation = host.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "investigating"
    assert investigation.logical_tool_calls == 2  # 第二动作已获身份,执行被拒
    assert investigation.tool_attempts == 1

    resumed = HostAnalysisTracer(tmp_path, {"read_file": tool},
                                 budget=_budget(tmp_path, max_tool_attempts=10))
    finished = resumed.run_analysis(candidate.candidate_id, FakeSession([_close()]))
    assert finished.disposition == "closed"
    assert resumed.investigation_for(candidate.candidate_id).tool_attempts == 2


def test_verification_run_total_budget_exhaustion_keeps_case_verifying(
        tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(
        tmp_path, {"read_file": tool}, tracer,
        # 案卷准备已消耗 2 次分析请求;上限 3 = 再允许 1 轮复核取证。
        budget=_budget(tmp_path, max_llm_calls=3))

    with pytest.raises(BudgetExhaustedError, match="llm_calls"):
        runner.run_case(candidate_id, FakeVerificationSession([
            _v_action({"claim_results": {
                name: _result("supported", "ev-000002", claim=name) for name in GENERIC_REQUIRED}}),
            _v_complete(),
        ]))

    assert tracer.investigation_for(candidate_id).lifecycle_status == "verifying"
    assert not (tmp_path / "verifications" / candidate_id / "results.json").exists()

    resumed = HostVerificationRunner(
        tmp_path, {"read_file": tool}, tracer, budget=_budget(tmp_path))
    outcome = resumed.run_case(candidate_id, FakeVerificationSession([
        _v_complete(),
    ]))
    assert (outcome.verdict, outcome.stop_reason) == ("confirmed", "completed")


def test_verification_service_interruption_keeps_case_recoverable(
        tmp_path: Path) -> None:
    tracer, (candidate_id,) = _prepared_tracer(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="device.conf", raw="device.conf"))
    runner = HostVerificationRunner(tmp_path, {"read_file": tool}, tracer,
                                    budget=_budget(tmp_path))

    class FailingSession(FakeVerificationSession):
        def step(self, input_message=None):
            self.inputs.append(input_message)
            raise LLMError("服务暂时不可用")

    with pytest.raises(LLMError, match="服务暂时不可用"):
        runner.run_case(candidate_id, FailingSession([]))

    investigation = tracer.investigation_for(candidate_id)
    assert investigation.lifecycle_status == "verifying"  # 中断不消耗终态
    assert investigation.disposition is None
    assert not (tmp_path / "verifications" / candidate_id / "results.json").exists()

    resumed = HostVerificationRunner(
        tmp_path, {"read_file": tool}, tracer, budget=_budget(tmp_path))
    outcome = resumed.run_case(candidate_id, FakeVerificationSession([
        _v_action({"claim_results": {
            name: _result("supported", "ev-000002", claim=name) for name in GENERIC_REQUIRED}}),
        _v_complete(),
    ]))
    assert (outcome.verdict, outcome.stop_reason) == ("confirmed", "completed")


def test_mark_not_started_and_queued_ids_close_unprocessed_candidates(
        tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool}, budget=_budget(tmp_path))
    first = host.add_candidate({"target": "extracted/a"})
    second = host.add_candidate({"target": "extracted/b"})
    third = host.add_candidate({"target": "extracted/c"})
    host.run_analysis(first.candidate_id, FakeSession([_action({}), _close()]))
    assert host.queued_ids() == (second.candidate_id, third.candidate_id)

    marked = host.mark_not_started(second.candidate_id)
    assert (marked.lifecycle_status, marked.disposition, marked.stop_reason) == (
        "finished", "not_started", "budget_exhausted")
    assert host.queued_ids() == (third.candidate_id,)

    # 已开始的调查不得用 not_started 收束。
    with pytest.raises(StopIteration):
        host.run_analysis(third.candidate_id, FakeSession([_action({})]))
    with pytest.raises(ValueError, match="只有未开始"):
        host.mark_not_started(third.candidate_id)
    events = [
        json.loads(line)["kind"]
        for line in (tmp_path / "investigations" / second.candidate_id
                     / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events[-1] == "marked_not_started"


# ---- S3:服务中断——零终态、零记账、strike 不沾染 ----


def test_service_interruption_preserves_state_and_skips_ledger(
        tmp_path: Path) -> None:
    clock = FakeClock()
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool},
                              budget=_budget(tmp_path, clock=clock))
    candidate = host.add_candidate({"target": "extracted/bin/router"})

    class FailingSession(FakeSession):
        def step(self, input_message=None):
            self.inputs.append(input_message)
            raise LLMError("服务暂时不可用")

    with pytest.raises(LLMError, match="服务暂时不可用"):
        host.run_analysis(candidate.candidate_id, FailingSession([]))

    investigation = host.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "queued"  # 中断不消耗终态
    assert investigation.disposition is None
    document = _ledger_document(tmp_path)
    assert document["llm_calls"] == 0  # 失败请求无回复,不计
    assert document["active_seconds"] == 0.0  # 空转时段即封段

    # 恢复:新 Session 从保存的 lifecycle 继续,strike 从零起算。
    finished = host.run_analysis(candidate.candidate_id, UsageSession([
        _action({}), _close()]))
    assert finished.disposition == "closed"
    document = _ledger_document(tmp_path)
    assert document["llm_calls"] == 2
    assert document["validated_rounds"] == 2
    assert document["prompt_tokens"] == 20


def test_protocol_regenerations_count_llm_but_not_tools_or_rounds(
        tmp_path: Path) -> None:
    from firmware_audit.step5_agent.host import ProposalError, ValidationIssue

    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool},
                              budget=_budget(tmp_path))
    candidate = host.add_candidate({"target": "extracted/bin/router"})
    invalid = ProposalError((ValidationIssue(
        path="$.next.kind", expected="role-allowed next kind", actual='"x"',
    ),), raw_reply="{}")

    investigation = host.run_analysis(candidate.candidate_id, UsageSession([
        invalid, invalid,
        _action({}), _close(),
    ]))

    assert investigation.disposition == "closed"
    assert investigation.no_progress_count == 0  # 重生成不进 no-progress
    document = _ledger_document(tmp_path)
    assert document["llm_calls"] == 4  # 2 次重生成 + 动作 + 收尾都是真实请求
    assert document["validated_rounds"] == 2  # 只有被应用的回复算生效轮
    assert document["tool_attempts"] == 1
    assert document["logical_tool_calls"] == 1
    assert document["prompt_tokens"] == 40


def test_active_time_excludes_gap_between_runs(tmp_path: Path) -> None:
    clock = FakeClock()
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool},
                              budget=_budget(tmp_path, clock=clock))
    first = host.add_candidate({"target": "extracted/a"})
    second = host.add_candidate({"target": "extracted/b"})
    host.run_analysis(first.candidate_id, StepAdvancingSession(
        [_action({}), _close()], clock))
    clock.advance(500.0)  # 停机等待恢复:间隔不计入 active time
    host.run_analysis(second.candidate_id, StepAdvancingSession(
        [_action({}), _close(("ev-000002",))], clock))

    document = _ledger_document(tmp_path)
    assert document["active_seconds"] == pytest.approx(4.0)  # 每次运行 2 步 × 1s


def test_analysis_protocol_error_does_not_block_following_candidate(
        tmp_path: Path) -> None:
    from firmware_audit.step5_agent.host import ProposalError, ValidationIssue

    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool}, budget=_budget(tmp_path))
    first = host.add_candidate({"target": "extracted/a"})
    second = host.add_candidate({"target": "extracted/b"})
    invalid = ProposalError((ValidationIssue(
        path="$.next.kind", expected="role-allowed next kind", actual='"x"',
    ),), raw_reply="{}")

    failed = host.run_analysis(first.candidate_id, FakeSession([invalid] * 3))
    assert (failed.disposition, failed.stop_reason) == ("unresolved", "protocol_error")

    # 不阻断后续队列:下一 Candidate 正常调查并收束。
    followup = host.run_analysis(second.candidate_id, FakeSession([
        _action({}), _close()]))
    assert (followup.disposition, followup.stop_reason) == ("closed", "agent_closed")
    assert followup.evidence[0].evidence_id == "ev-000001"


def test_runners_default_to_shared_run_budget(tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="x", raw="x"))
    host = HostAnalysisTracer(tmp_path, {"read_file": tool})
    # 默认接线:构造即解析环境层配置并落生效快照;台账随首次真实消耗落盘。
    assert load_config_snapshot(tmp_path)["resolved"] == DEFAULT_BUDGET_CONFIG
    candidate = host.add_candidate({"target": "extracted/a"})
    with pytest.raises(StopIteration):
        host.run_analysis(candidate.candidate_id, FakeSession([_action({})]))
    document = _ledger_document(tmp_path)
    assert document["llm_calls"] == 1
    assert document["validated_rounds"] == 1


def test_budget_is_shared_across_recon_and_analysis(tmp_path: Path) -> None:
    process_dir = _workspace(tmp_path)
    tool = FakeTool(ToolResult(ok=True, text="observed", raw="observed"))
    # 上限 3:recon 消耗 2(1 动作 + 1 survey),analysis 第 2 轮请求被拒。
    recon = HostReconRunner(tmp_path, {"read_file": tool},
                            budget=_budget(tmp_path, max_llm_calls=3))
    result = recon.run(FakeReconSession([
        _recon_action(),
        _survey(_survey_delta()),
    ]), process_dir)
    assert result.status == "completed"
    assert _ledger_document(tmp_path)["llm_calls"] == 2

    host = HostAnalysisTracer(tmp_path, {"read_file": tool},
                              budget=_budget(tmp_path, max_llm_calls=3))
    host.add_candidate({"target": "extracted/etc/device.conf"})
    with pytest.raises(BudgetExhaustedError, match="llm_calls"):
        host.run_analysis("cand-0001", FakeSession([
            _action({}), _action({}), _close()]))


def test_run_total_active_time_exhaustion_mid_run_saves_state(tmp_path: Path) -> None:
    """Spec 弱覆盖补齐:运行中拨满活动时长 → 保存现场不落终态,可恢复。"""
    clock = FakeClock()
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    host = HostAnalysisTracer(
        tmp_path, {"read_file": tool},
        budget=_budget(tmp_path, clock=clock, max_active_seconds=1.5))
    candidate = host.add_candidate({"target": "extracted/bin/router"})

    with pytest.raises(BudgetExhaustedError, match="active_seconds"):
        host.run_analysis(candidate.candidate_id, StepAdvancingSession(
            [_action({}), _action({}), _close()], clock))

    investigation = host.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "investigating"
    assert investigation.stop_reason is None
    document = _ledger_document(tmp_path)
    assert document["active_seconds"] == pytest.approx(2.0)
    assert document["validated_rounds"] == 1

    resumed = HostAnalysisTracer(
        tmp_path, {"read_file": tool},
        budget=_budget(tmp_path, clock=clock, max_active_seconds=100.0))
    finished = resumed.run_analysis(candidate.candidate_id, FakeSession([_close()]))
    assert finished.disposition == "closed"


# ---- D3(ADR-0012 2026-09-16):Host 显式触发的上下文压缩 ----
# 真 AgentSession + ScriptedLLM:超阈值触发、预算/Transcript 留痕、后续动作
# 继续、预算不足不多发请求、压缩失败还原且不影响权威状态。


def _session_reply(state_delta: dict, kind: str) -> str:
    """构造 AgentSession 协议的原始 JSON 回复(与 ScriptedLLM 配套)。"""
    nxt = ({"kind": "tool_action", "tool": "read_file",
            "arguments": {"path": "extracted/etc/device.conf"}}
           if kind == "tool_action" else {"kind": kind})
    return json.dumps({"decision_summary": "推进调查", "state_delta": state_delta,
                       "next": nxt}, ensure_ascii=False)


def _compaction_script() -> list[str]:
    """两步取证(全 Claim supported 引用 ev-000001)→ 压缩 → 提交案卷。"""
    return [
        _session_reply({"hypothesis": {"statement": "配置暴露固定令牌"}},
                       "tool_action"),
        _session_reply({"claims": {
            name: {"status": "supported", "evidence_ids": ["ev-000001"]}
            for name in GENERIC_REQUIRED}}, "tool_action"),
        "压缩摘要:已确认事实:配置暴露固定令牌;未决:影响面。",
        _session_reply({"admission_reason": "ready"}, "submit_case"),
    ]


def test_host_compacts_over_threshold_context_with_real_session(
        tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="token=literal", raw="token=literal"))
    budget = _budget(tmp_path)
    tracer = HostAnalysisTracer(tmp_path, {"read_file": tool}, budget=budget)
    candidate = tracer.add_candidate({"target": "extracted/etc/device.conf"})
    transcript = tmp_path / "transcripts" / "transcript.jsonl"
    # 低阈值:两轮动作后上下文超阈,Host 在第三次 step 前显式压缩。
    context = ContextManager(
        ANALYSIS_SESSION_SYSTEM, "", max_est_tokens=200, trigger_ratio=0.5)
    session = AgentSession(
        "analysis", ScriptedLLM(_compaction_script()), context,
        transcript=transcript)

    investigation = tracer.run_analysis(candidate.candidate_id, session)

    # 压缩只改模型上下文;调查正常推进到案卷提交
    assert investigation.lifecycle_status == "ready_for_verification"
    assert context.compactions == 1
    assert context.recent and context.recent[0]["role"] == "assistant"
    # 权威状态与 Evidence 不受压缩影响
    assert len(investigation.evidence) == 2
    assert set(investigation.state["claims"]) == set(GENERIC_REQUIRED)

    # Transcript 留痕:host_compaction 事件带 usage
    events = [json.loads(line) for line
              in transcript.read_text(encoding="utf-8").splitlines()]
    compaction = [e for e in events if e["phase"] == "host_compaction"]
    assert len(compaction) == 1
    assert "压缩" in compaction[0]["content"]

    # 预算:llm_calls = 3 个语义步 + 1 次压缩;压缩不计 validated_rounds
    document = _ledger_document(tmp_path)
    assert document["llm_calls"] == 4
    assert document["validated_rounds"] == 3


def test_compaction_blocked_by_budget_saves_scene_without_extra_request(
        tmp_path: Path) -> None:
    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    budget = _budget(tmp_path, max_llm_calls=2)
    tracer = HostAnalysisTracer(tmp_path, {"read_file": tool}, budget=budget)
    candidate = tracer.add_candidate({"target": "extracted/etc/device.conf"})
    transcript = tmp_path / "transcripts" / "transcript.jsonl"
    context = ContextManager(
        ANALYSIS_SESSION_SYSTEM, "", max_est_tokens=200, trigger_ratio=0.5)
    session = AgentSession(
        "analysis", ScriptedLLM(_compaction_script()), context,
        transcript=transcript)

    with pytest.raises(BudgetExhaustedError, match="llm_calls"):
        tracer.run_analysis(candidate.candidate_id, session)

    # 预算不足不多发请求:两个语义步之后压缩请求被拒,无第三次模型调用
    document = _ledger_document(tmp_path)
    assert document["llm_calls"] == 2
    investigation = tracer.investigation_for(candidate.candidate_id)
    assert investigation.lifecycle_status == "investigating"
    events = [json.loads(line) for line
              in transcript.read_text(encoding="utf-8").splitlines()]
    assert not [e for e in events if e["phase"] == "host_compaction"]


def test_compaction_failure_restores_context_and_run_continues(
        tmp_path: Path) -> None:
    class CompactionBoomLLM(ScriptedLLM):
        """压缩请求(带 max_tokens=4096)失败,语义步正常。"""

        def chat(self, messages, **kw):
            if kw.get("max_tokens") == 4096:
                self.calls.append(list(messages))
                raise RuntimeError("压缩请求失败")
            return super().chat(messages, **kw)

    tool = FakeTool(ToolResult(ok=True, text="same", raw="same"))
    budget = _budget(tmp_path)
    tracer = HostAnalysisTracer(tmp_path, {"read_file": tool}, budget=budget)
    candidate = tracer.add_candidate({"target": "extracted/etc/device.conf"})
    context = ContextManager(
        ANALYSIS_SESSION_SYSTEM, "", max_est_tokens=200, trigger_ratio=0.5)
    session = AgentSession(
        "analysis",
        CompactionBoomLLM(_compaction_script()[:2] + [
            _session_reply({"admission_reason": "ready"}, "submit_case")]),
        context, transcript=None)

    investigation = tracer.run_analysis(candidate.candidate_id, session)

    # 压缩失败还原保留区(前两轮完整保留,第三轮照常追加),调查照常收尾
    assert investigation.lifecycle_status == "ready_for_verification"
    assert context.compactions == 0
    assert len(context.recent) == 6  # 两轮动作 + 第三轮观察/回复,零丢失
    document = _ledger_document(tmp_path)
    assert document["llm_calls"] == 3  # 失败的压缩请求不记账

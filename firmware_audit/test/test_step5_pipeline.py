"""Step5 公开入口端到端与上下文单测(ScriptedLLM,零 API 零 Docker)。

票 14 公开切换后,本文件是 spec Seam 4:沿 public Step5 runner(生产
session factory + 真 AgentSession + 真 read_file 工具)+ 临时工作区 +
ScriptedLLM,跑通 recon → Candidate Store → Investigation → Verification →
确定性报告 → manifest → sealed run,并断言世代工件、默认 resume、强制新
世代、预算耗尽 not_started、sealed immutability 与旧三工件零读取。

另保留 engine/context 四分区与压缩契约、启动门、resolve_workspace、无 key
报错等入口级测试。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.engine.context import ContextManager, est_tokens
from firmware_audit.step5_agent.host.generation import load_run_state
from firmware_audit.step5_agent.run_step5 import step5_run
from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.test.test_step5_host_analysis import GENERIC_REQUIRED
from firmware_audit.test.test_step5_host_verification import _FACET_BY_CLAIM


def _make_workspace(td: Path) -> Path:
    """伪造最小工作区:target 形态(含 process/)+ extracted 启动门 + 旧三工件。"""
    target = td / "target"
    ext = target / "process" / "extracted" / "etc"
    ext.mkdir(parents=True)
    (ext / "device.conf").write_text("admin_token=literal-value\nmode=managed\n",
                                     encoding="utf-8")
    bin_dir = target / "process" / "extracted" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "robotd").write_bytes(b"\x7fELFrobotd")
    # 旧语义工件:新流程不得读取或迁移(AC:不读写旧三种结果工件)
    legacy = target / "process" / "agent" / "1_analysis"
    legacy.mkdir(parents=True)
    for name in ("survey.json", "findings.json", "verified_findings.json"):
        (legacy / name).write_text("{}", encoding="utf-8")
    return target


# ---- 纯 JSON 协议剧本(与 host 测试 helper 同构的原始 JSON 形态)----

def _json(top_summary: str, state_delta: dict, next_kind: str,
          tool: str = "read_file",
          arguments: dict | None = None) -> str:
    if next_kind == "tool_action":
        nxt = {"kind": "tool_action", "tool": tool,
               "arguments": arguments or {"path": "extracted/etc/device.conf"}}
    else:
        nxt = {"kind": next_kind}
    return json.dumps({
        "decision_summary": top_summary,
        "state_delta": state_delta,
        "next": nxt,
    }, ensure_ascii=False)


def _recon_action() -> str:
    return _json("读取管理配置取证", {}, "tool_action", "read_file")


def _survey_delta() -> dict:
    return {
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


def _scoring() -> str:
    return json.dumps({"factors": {
        "external_reachability": {"score": 2, "evidence_id": "ev-000001",
                                  "note": "管理接口可达"},
    }}, ensure_ascii=False)


def _analysis_claims(evidence_id: str) -> dict:
    return {"claims": {
        name: {"status": "supported", "evidence_ids": [evidence_id]}
        for name in GENERIC_REQUIRED
    }}


def _claim_results(evidence_id: str) -> dict:
    results = {}
    for name in GENERIC_REQUIRED:
        record = {
            "judgment": "supported",
            "observed": "独立读取配置确认字段真实存在",
            "method": "read_file 独立复核",
            "evidence_ids": [evidence_id],
        }
        if name in _FACET_BY_CLAIM:
            facet, value = _FACET_BY_CLAIM[name]
            record[facet] = value
        results[name] = record
    return {"claim_results": results}


def full_chain_script() -> list[str]:
    """一次完整 Host 运行的全部模型回复(2 Candidate → 2 Finding)。

    Evidence 编号确定性:recon ev-000001;analysis c1 ev-000002/3、
    c2 ev-000004/5;verification c1 ev-000006/7、c2 ev-000008/9。
    """
    script = [
        _recon_action(),                                            # recon 取证
        _json("铺面完成", _survey_delta(), "complete_survey"),      # recon survey
        _scoring(), _scoring(),                                     # 评分 ×2
    ]
    for claims_evidence in ("ev-000002", "ev-000004"):              # analysis ×2
        script += [
            _json("读取目标取证", {"hypothesis": {"statement": "配置暴露固定令牌"}},
                  "tool_action"),
            _json("逐项推进 Claim", _analysis_claims(claims_evidence), "tool_action"),
            _json("案卷成熟", {"admission_reason": "ready"}, "submit_case"),
        ]
    for results_evidence in ("ev-000006", "ev-000008"):             # verification ×2
        script += [
            _json("独立重新取证", {}, "tool_action"),
            _json("提交逐项 Claim Result", _claim_results(results_evidence),
                  "tool_action"),
            _json("复核完成", {}, "complete_verification"),
        ]
    script.append("本轮两个案卷均有独立证据支撑;覆盖缺口建议跟进 robotd。")
    return script


def test_host_public_entry_end_to_end(capsys) -> list[str]:
    """公开入口一次完整运行:Host 模式、世代工件、sealed、报告与旧工件零读取。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        target = _make_workspace(Path(td))
        legacy = target / "process" / "agent" / "1_analysis"
        llm = ScriptedLLM(full_chain_script())
        summary = step5_run(target, llm=llm)

        if summary["mode"] != "host":
            fails.append(f"公开入口应处于 Host 模式: {summary['mode']}")
        if "cve_cache_warning" in summary:
            fails.append("Blind Discovery 启动不做 CVE 预检,摘要不得携带该字段")
        if summary["generation"] != "gen-0001" or summary["status"] != "completed":
            fails.append(f"应新建 gen-0001 并封存: {summary['generation']}/{summary['status']}")
        if summary["candidates"] != 2 or summary["findings"] != 2:
            fails.append(f"2 Candidate → 2 Finding: {summary}")

        gen_dir = Path(summary["gen_dir"])
        if gen_dir != target / "process" / "generations" / "gen-0001":
            fails.append(f"世代根应在工作区 generations/ 下: {gen_dir}")
        state = load_run_state(gen_dir)
        if state["status"] != "completed":
            fails.append(f"run_state 应 completed: {state}")
        manifest = json.loads((gen_dir / "manifest.json").read_text(encoding="utf-8"))
        if "seal" not in manifest:
            fails.append("manifest 应含封存 digest")
        report = gen_dir / "report.md"
        if not report.is_file():
            fails.append("确定性事实报告 report.md 缺失")
        else:
            text = report.read_text(encoding="utf-8")
            for needle in ("## 2. Confirmed Findings", "## 1. 运行摘要与有效配置",
                           "Evidence Index"):
                if needle not in text:
                    fails.append(f"事实报告缺章节锚点 {needle!r}")

        findings = json.loads((gen_dir / "findings.json").read_text(encoding="utf-8"))
        if [f["candidate_id"] for f in findings["findings"]] != ["cand-0001", "cand-0002"]:
            fails.append(f"confirmed Finding 应逐 Candidate 落账: {findings['findings']}")

        # 独立 Verification(D4):逐 Claim 检查清单持久化,证据入口仅定位
        for cand in ("cand-0001", "cand-0002"):
            checklist = json.loads(
                (gen_dir / "verifications" / cand / "checklist.json").read_text(
                    encoding="utf-8"))
            if [item["claim"] for item in checklist["items"]] != list(GENERIC_REQUIRED):
                fails.append(f"{cand} 检查清单应逐必填 Claim 展开")
            if not checklist["evidence_entries"]:
                fails.append(f"{cand} 检查清单应带证据入口")
            if "定位" not in checklist["evidence_entries_note"]:
                fails.append("证据入口应明示仅定位用途")
            results = json.loads(
                (gen_dir / "verifications" / cand / "results.json").read_text(
                    encoding="utf-8"))
            if results["verdict"] != "confirmed" or results["finding_id"] is None:
                fails.append(f"{cand} 复核应 confirmed 并携带 Finding: {results['verdict']}")

        # 生产 session factory 的 transcript 落在各自权威目录
        for transcript in (
            gen_dir / "investigations" / "recon" / "transcript.jsonl",
            gen_dir / "investigations" / "cand-0001" / "transcript.jsonl",
            gen_dir / "verifications" / "cand-0001" / "transcript.jsonl",
        ):
            if not transcript.is_file():
                fails.append(f"transcript 缺失: {transcript}")

        # 预算台账:recon 2 + 评分 2 + analysis 3×2 + verification 3×2 + 注记 1
        ledger = json.loads((gen_dir / "budget.json").read_text(encoding="utf-8"))
        if ledger["llm_calls"] != 17:
            fails.append(f"llm_calls 应为 17: {ledger['llm_calls']}")

        # 旧三工件原样保留,未被读取或迁移
        for name in ("survey.json", "findings.json", "verified_findings.json"):
            if (legacy / name).read_text(encoding="utf-8") != "{}":
                fails.append(f"旧工件 {name} 不应被改写")

        captured = capsys.readouterr()
        if "预检" in captured.err or "cve_cache" in captured.err:
            fails.append(f"Host 启动不得输出 CVE 缓存预检: {captured.err[:200]}")
    return fails


def test_public_entry_resumes_after_service_interruption() -> list[str]:
    """默认 resume:服务中断保留现场,续跑同世代完成并保持预算单调。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        target = _make_workspace(Path(td))
        script = full_chain_script()
        with_disaster = ScriptedLLM(script[:8])  # 第 9 次调用(analysis c2 第2步)耗尽
        try:
            step5_run(target, llm=with_disaster)
            fails.append("ScriptedLLM 耗尽应作为服务中断上抛")
        except RuntimeError as exc:
            if "耗尽" not in str(exc):
                fails.append(f"中断形态应是回复耗尽: {exc}")
        gen_dir = target / "process" / "generations" / "gen-0001"
        state = load_run_state(gen_dir)
        if state["status"] != "running" or not (state["stop_reason"] or "").startswith(
                "interrupted:"):
            fails.append(f"中断应保持 running 并记录 interrupted: {state}")
        first_ledger = json.loads((gen_dir / "budget.json").read_text(encoding="utf-8"))

        # 续跑:新 LLM 实例补齐剩余剧本(analysis c2 收尾 + 复核×2 + 注记)
        remainder = [
            _json("逐项推进 Claim", _analysis_claims("ev-000004"), "tool_action"),
            _json("案卷成熟", {"admission_reason": "ready"}, "submit_case"),
        ]
        for results_evidence in ("ev-000006", "ev-000008"):
            remainder += [
                _json("独立重新取证", {}, "tool_action"),
                _json("提交逐项 Claim Result", _claim_results(results_evidence),
                      "tool_action"),
                _json("复核完成", {}, "complete_verification"),
            ]
        remainder.append("续跑完成,两案卷均有独立证据。")
        summary = step5_run(target, llm=ScriptedLLM(remainder))
        if summary["generation"] != "gen-0001" or summary["created"]:
            fails.append(f"默认应恢复同世代: {summary['generation']}/{summary['created']}")
        if summary["status"] != "completed" or summary["findings"] != 2:
            fails.append(f"恢复后应完成并聚齐 Finding: {summary['status']}/{summary['findings']}")
        second_ledger = json.loads((gen_dir / "budget.json").read_text(encoding="utf-8"))
        if second_ledger["llm_calls"] != first_ledger["llm_calls"] + 9:
            fails.append(f"预算应单调累计 8+9=17: {first_ledger['llm_calls']}"
                         f" → {second_ledger['llm_calls']}")
    return fails


def test_public_entry_force_and_sealed_immutability() -> list[str]:
    """--force 创建新世代;封存世代只读(再跑/强跑都不改写机器工件)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        target = _make_workspace(Path(td))
        first = step5_run(target, llm=ScriptedLLM(full_chain_script()))
        gen1 = Path(first["gen_dir"])
        sealed = {
            path.name: path.read_bytes() for path in (
                gen1 / "manifest.json", gen1 / "findings.json",
                gen1 / "report.md", gen1 / "run_state.json",
            )
        }

        # 默认再跑:completed 只读 → 直接开新世代,不改写封存工件
        second = step5_run(target, llm=ScriptedLLM(full_chain_script()))
        if second["generation"] != "gen-0002":
            fails.append(f"封存后默认再跑应开新世代: {second['generation']}")
        if second["status"] != "completed":
            fails.append(f"新世代应完成: {second['status']}")

        # force 同样只是新世代(兼容入口,不再原地覆盖)
        third = step5_run(target, llm=ScriptedLLM(full_chain_script()), force=True)
        if third["generation"] != "gen-0003" or not third["created"]:
            fails.append(f"force 应创建 gen-0003: {third['generation']}/{third['created']}")

        for name, payload in sealed.items():
            if (gen1 / name).read_bytes() != payload:
                fails.append(f"封存机器工件不可变被破坏: {name}")
    return fails


def test_public_entry_budget_exhaustion_marks_not_started(monkeypatch) -> list[str]:
    """运行预算耗尽:进行中调查保留现场,未开始 Candidate 收账 not_started。"""
    fails: list[str] = []
    monkeypatch.setenv("STEP5_MAX_LLM_CALLS", "7")  # recon2+评分2+c1全程3 = 7
    try:
        with tempfile.TemporaryDirectory() as td:
            target = _make_workspace(Path(td))
            summary = step5_run(target, llm=ScriptedLLM(full_chain_script()))
            if summary["status"] != "running" or summary["stop_reason"] != "budget_exhausted":
                fails.append(f"应按预算耗尽收束: {summary['status']}/{summary['stop_reason']}")
            gen_dir = Path(summary["gen_dir"])
            state = load_run_state(gen_dir)
            if state["stop_reason"] != "budget_exhausted":
                fails.append(f"run_state 应记 budget_exhausted: {state}")
            store = json.loads((gen_dir / "candidates.json").read_text(encoding="utf-8"))
            by_id = {c["candidate_id"]: c for c in store["candidates"]}
            if not by_id["cand-0002"]["queue"]["selected"]:
                fails.append("cand-0002 应为已入选未处理,而非落选")
            second = json.loads((gen_dir / "investigations" / "cand-0002"
                                 / "state.json").read_text(encoding="utf-8"))
            if second["state"]["investigation"]["disposition"] != "not_started":
                fails.append(f"未开始 Candidate 应收账 not_started: "
                             f"{second['state']['investigation']}")
            first = json.loads((gen_dir / "investigations" / "cand-0001"
                                / "state.json").read_text(encoding="utf-8"))
            if first["state"]["investigation"]["lifecycle_status"] != "ready_for_verification":
                fails.append("进行中责任不得被预算耗尽静默丢弃")
    finally:
        monkeypatch.delenv("STEP5_MAX_LLM_CALLS", raising=False)
    return fails


def test_public_entry_resumes_finalizing_generation_straight_to_seal(
        monkeypatch) -> list[str]:
    """spec Seam 4:封存失败保持 finalizing,公开入口续跑只补封存、同世代完成。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.host import driver as driver_module

    with tempfile.TemporaryDirectory() as td:
        target = _make_workspace(Path(td))
        real_seal = driver_module.seal_run
        calls = {"n": 0}

        def flaky_seal(gen_dir, analyst_notes=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("manifest 写盘中断")
            return real_seal(gen_dir, analyst_notes=analyst_notes)

        monkeypatch.setattr(driver_module, "seal_run", flaky_seal)
        try:
            step5_run(target, llm=ScriptedLLM(full_chain_script()))
            fails.append("首次封存失败应上抛(现场保持 finalizing)")
        except RuntimeError as exc:
            if "manifest" not in str(exc):
                fails.append(f"中断形态应是封存失败: {exc}")
        gen_dir = target / "process" / "generations" / "gen-0001"
        state = load_run_state(gen_dir)
        if state["status"] != "finalizing" or not (state["stop_reason"] or ""
                                                   ).startswith("seal_failed"):
            fails.append(f"封存失败应保持 finalizing: {state}")

        monkeypatch.setattr(driver_module, "seal_run", real_seal)
        # 恢复只续封存:唯一模型请求是可选 Analyst Notes,不重跑任何 Session。
        summary = step5_run(target, llm=ScriptedLLM(["恢复后的可选注记。"]))
        if summary["generation"] != "gen-0001" or summary["created"]:
            fails.append(f"finalizing 应恢复同世代: {summary['generation']}")
        if summary["status"] != "completed" or summary["findings"] != 2:
            fails.append(f"恢复后应封存完成: {summary['status']}/{summary['findings']}")
        ledger = json.loads((gen_dir / "budget.json").read_text(encoding="utf-8"))
        if ledger["llm_calls"] != 17 + 1:  # 17(处理全程) + 1(恢复期注记)
            fails.append(f"finalizing 恢复不得重跑处理: llm_calls={ledger['llm_calls']}")
        if load_run_state(gen_dir)["status"] != "completed":
            fails.append("恢复后 run_state 应 completed")
    return fails


def test_no_legacy_flags_or_preflight_in_entry() -> list[str]:
    """公开入口源码契约:无旧行为 flag/预检/双模式残留(票 14 AC)。"""
    fails: list[str] = []
    source = (Path(__file__).resolve().parents[1] / "step5_agent"
              / "run_step5.py").read_text(encoding="utf-8")
    for banned in ("STEP5_VERIFY_K", "STEP5_RESUME_DEGRADED",
                   "STEP5_ORCHESTRATOR_MAX_ITERS", "cve_cache_preflight",
                   "Orchestrator"):
        if banned in source:
            fails.append(f"公开入口不得残留 legacy 语义: {banned}")
    if "host" not in source:
        fails.append("公开入口应经 Host 控制层接线")
    return fails


# ---- engine/context(保留:四分区构建/阈值压缩/失败还原) ----

def test_build_messages_partitions() -> list[str]:
    fails: list[str] = []
    cm = ContextManager("SYS", "INIT")
    cm.append("assistant", "a1")
    cm.append("user", "o1")
    msgs = cm.build_messages()
    if [m["content"] for m in msgs] != ["SYS", "INIT", "a1", "o1"]:
        fails.append("无压缩时应是 system+init+recent")
    cm.summaries.append("SUM1")
    msgs2 = cm.build_messages()
    if len(msgs2) != 5 or "SUM1" not in msgs2[2]["content"] or msgs2[2]["role"] != "user":
        fails.append("概括区应插在 init 与 recent 之间")
    if cm.needs_compaction():  # 默认阈值高,小上下文不应触发
        fails.append("小上下文误触发压缩")
    return fails


def test_compaction_boundary_and_failure() -> list[str]:
    fails: list[str] = []
    # 低阈值强制触发:6 条 recent(a/o×3),压缩最老一半并对齐 assistant 边界
    llm = ScriptedLLM(["压缩摘要:已确认事实若干"])
    cm = ContextManager("SYS", "INIT", max_est_tokens=10, trigger_ratio=0.5)
    for i in range(3):
        cm.append("assistant", f"a{i}")
        cm.append("user", f"o{i}")
    done = cm.maybe_compact(llm)
    if not done or cm.compactions != 1:
        fails.append("超阈值应触发压缩")
    if len(cm.recent) != 2 or cm.recent[0]["content"] != "a2":
        fails.append(f"压缩后应保留最近一轮对: {[m['content'] for m in cm.recent]}")
    if "压缩摘要" not in cm.summaries[0]:
        fails.append("摘要未写入概括区")
    if not llm.calls or "a0" not in llm.calls[0][1]["content"]:
        fails.append("压缩调用应携带被压缩的原文")

    # 压缩失败(LLM 抛错):还原保留区,不丢历史
    class BoomLLM(ScriptedLLM):
        def chat(self, messages, **kw):
            self.calls.append(list(messages))
            raise RuntimeError("压缩网络炸了")

    cm2 = ContextManager("SYS", "INIT", max_est_tokens=10, trigger_ratio=0.5)
    for i in range(3):
        cm2.append("assistant", f"a{i}")
        cm2.append("user", f"o{i}")
    n_before = len(cm2.recent)
    if cm2.maybe_compact(BoomLLM([])):
        fails.append("LLM 失败时 compact 应返回 False")
    if len(cm2.recent) != n_before or cm2.summaries != []:
        fails.append("压缩失败必须还原保留区")
    return fails


def test_compact_at_600k_threshold() -> list[str]:
    """600k 阈值规模化稳定性:~700k est tokens 上下文触发压缩,边界对齐/构建正常。"""
    fails: list[str] = []
    llm = ScriptedLLM(["600k 摘要:已确认事实/已排除项/未决问题/证据指针", "备用"])
    cm = ContextManager("SYS", "INIT")  # 默认 1M 窗口 × 0.6 = 600k 阈值
    # 350 轮 × (assistant+user),每条 ~2000 字符 → est ≈ 700k > 600k
    for i in range(350):
        cm.append("assistant", f"a{i} " + "x" * 2000)
        cm.append("user", f"o{i} " + "y" * 2000)
    if not cm.needs_compaction():
        fails.append(f"~700k est tokens 应超过 600k 阈值, est={est_tokens(cm.build_messages())}")
    before = len(cm.recent)
    if not cm.maybe_compact(llm):
        fails.append("超阈值时 maybe_compact 应执行压缩")
    if cm.compactions != 1 or not cm.summaries:
        fails.append("压缩产物应写入概括区")
    if not (0 < len(cm.recent) < before):
        fails.append(f"压缩后保留区应收缩: {before} → {len(cm.recent)}")
    if cm.recent and cm.recent[0]["role"] != "assistant":
        fails.append("压缩后保留区开头应对齐 assistant 边界")
    msgs = cm.build_messages()
    if len(msgs) != 3 + len(cm.recent):  # system+init+summary+recent
        fails.append(f"构建消息数不符: {len(msgs)}")
    return fails


# ---- 入口契约(保留) ----

def _scrub_env() -> dict[str, str | None]:
    """弹出并返回 LLM/STEP5_* 环境键,隔离真实 .env(load_env_file 以
    setdefault 注入,旧值会顺序敏感污染后续默认值断言)。"""
    families = (lambda k: k.startswith("STEP5_")
                or k in ("FIRMWARE_AUDIT_LLM_API_KEY", "DEEPSEEK_API_KEY",
                         "LLM_API_KEY", "FIRMWARE_AUDIT_LLM_BASE_URL",
                         "FIRMWARE_AUDIT_LLM_MODEL", "LLM_BASE_URL",
                         "LLM_MODEL", "FIRMWARE_AUDIT_CVE_CACHE_DIR"))
    return {k: os.environ.pop(k, None)
            for k in list(os.environ) if families(k)}


def _restore_env(saved: dict[str, str | None]) -> None:
    """回放快照:测试中途经 load_env_file 新注入的家族键也一并清掉。"""
    families = (lambda k: k.startswith("STEP5_")
                or k in ("FIRMWARE_AUDIT_LLM_API_KEY", "DEEPSEEK_API_KEY",
                         "LLM_API_KEY", "FIRMWARE_AUDIT_LLM_BASE_URL",
                         "FIRMWARE_AUDIT_LLM_MODEL", "LLM_BASE_URL",
                         "LLM_MODEL", "FIRMWARE_AUDIT_CVE_CACHE_DIR"))
    for k in list(os.environ):
        if k not in saved and families(k):
            os.environ.pop(k, None)
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


def test_startup_gate_requires_extracted() -> list[str]:
    """启动门新语义(ADR-0011):仅 extracted/ 的工作区放行;无解包产物拒绝
    且文案指向 Step1;老工作区(analysis/ 边车当缓存)照样放行。"""
    from firmware_audit.step5_agent.providers.llm_client import LLMError

    fails: list[str] = []
    saved = _scrub_env()  # _no_key_error → load_env_file 会加载真实 .env
    try:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # 仅 extracted/(无任何 analysis/ 工件)→ 过门,死在无 key(而非 FileNotFoundError)
            only_ext = root / "fresh"
            (only_ext / "extracted").mkdir(parents=True)

            class _NoKeyLLM:
                available = False
            try:
                step5_run(only_ext, llm=_NoKeyLLM())
                fails.append("无 key 应抛 LLMError(启动门已过)")
            except LLMError:
                pass
            except FileNotFoundError as e:
                fails.append(f"仅 extracted/ 的工作区应过启动门: {e}")

            # 无 extracted/ → 拒绝,文案指向 Step1
            empty = root / "bare"
            empty.mkdir()
            try:
                step5_run(empty, llm=_NoKeyLLM())
                fails.append("无 extracted/ 应被启动门拒绝")
            except LLMError:
                fails.append("无 extracted/ 应在无 key 检查之前被门拒绝")
            except FileNotFoundError as e:
                if "extracted/" not in str(e) or "Step1" not in str(e):
                    fails.append(f"拒绝文案应指向 extracted/ 与 Step1: {e}")
    finally:
        _restore_env(saved)
    return fails


def test_resolve_workspace_absolute() -> list[str]:
    """resolve_workspace 必须返回绝对路径(2026-08-19 checksec/xref 实发 bug)。"""
    from firmware_audit.step5_agent.run_step5 import resolve_workspace

    fails: list[str] = []
    old_cwd = os.getcwd()
    try:
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            (Path(td) / "t1" / "process").mkdir(parents=True)
            # 分支一:入参含 process/ 子目录(普通 target 形态)
            ws = resolve_workspace(Path("t1"))
            if not ws.is_absolute():
                fails.append(f"target 分支应返回绝对路径: {ws}")
            elif ws != (Path(td) / "t1" / "process").resolve():
                fails.append(f"应定位到 t1/process: {ws}")
            # 分支二:入参本身即工作区(分区子工作区/直传 process 形态)
            ws2 = resolve_workspace(Path("t1") / "process")
            if not ws2.is_absolute():
                fails.append(f"工作区直传分支也应绝对: {ws2}")
            os.chdir(old_cwd)  # Windows:先离开 td,TemporaryDirectory 才能清理
    finally:
        os.chdir(old_cwd)
    return fails


def test_no_key_error_locates_env_file() -> list[str]:
    """无 key 报错(2026-08-19):.env 规范位置在 firmware_audit/ 下并自动加载;
    报错需写清找到的文件与缺 key 诊断,或给出创建模板。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.providers import llm_client
    from firmware_audit.step5_agent.providers.llm_client import LLMClient, LLMError
    from firmware_audit.step5_agent.run_step5 import _no_key_error

    keys = ("FIRMWARE_AUDIT_LLM_API_KEY", "DEEPSEEK_API_KEY", "LLM_API_KEY",
            "FIRMWARE_AUDIT_LLM_BASE_URL", "FIRMWARE_AUDIT_LLM_MODEL",
            "LLM_BASE_URL", "LLM_MODEL")
    # LLMClient 构造会 load_env_file 把本地 .env 的 STEP5_* 注入 os.environ,
    # 顺序敏感地污染后续默认值断言——一并快照还原(host 测试 delenv 先例)。
    saved = _scrub_env()
    old_anchors = llm_client._ENV_ANCHORS
    try:
        # 正向:.env 自动加载生效(有 key 行 → LLMClient 可用,且环境变量优先不覆盖)
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".env").write_text(
                "# 注释行\nFIRMWARE_AUDIT_LLM_API_KEY=sk-from-file\n"
                "FIRMWARE_AUDIT_LLM_MODEL=model-from-file\n", encoding="utf-8")
            llm_client._ENV_ANCHORS = [Path(td)]
            c = LLMClient()
            if not c.available or c.api_key != "sk-from-file":
                fails.append(f".env 自动加载失败: {c.api_key[:8] if c.api_key else '空'}")
            os.environ["FIRMWARE_AUDIT_LLM_API_KEY"] = "sk-from-env"
            c2 = LLMClient()
            if c2.api_key != "sk-from-env":
                fails.append("已设环境变量应优先于 .env,不被覆盖")

        # 分支一:.env 存在但无有效 key 行 → 报错指出该文件缺 key
        for k in keys:  # 清掉正向分支注入的残留,保证"仍无 key"前置成立
            os.environ.pop(k, None)
        with tempfile.TemporaryDirectory() as td:
            envf = Path(td) / ".env"
            envf.write_text("# 只有注释,没有 key\n", encoding="utf-8")
            llm_client._ENV_ANCHORS = [Path(td)]
            (Path(td) / "extracted").mkdir()  # 过 step5_run 的解包启动门(ADR-0011)
            try:
                step5_run(Path(td))
                fails.append("无 key 时应抛 LLMError")
            except LLMError as e:
                msg = str(e)
                if str(envf) not in msg:
                    fails.append(f"报错应含 .env 绝对路径: {msg[:120]}")
                if "API key" not in msg:
                    fails.append("报错应诊断缺 key 行")

        # 分支二:.env 完全不存在 → 给出 firmware_audit/ 下的创建模板
        with tempfile.TemporaryDirectory() as td:
            llm_client._ENV_ANCHORS = [Path(td)]  # 空目录,锚点重定向后不搜默认链
            err = str(_no_key_error())
            if "未找到 .env" not in err or "创建 .env" not in err:
                fails.append(f"未找到分支应给创建建议: {err[:150]}")
            if "FIRMWARE_AUDIT_LLM_API_KEY=sk-" not in err:
                fails.append("创建模板应含 key 行示例")
    finally:
        llm_client._ENV_ANCHORS = old_anchors
        _restore_env(saved)  # 含测试中途经 load_env_file 新注入的家族键
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("build_messages_partitions", test_build_messages_partitions),
        ("compaction_boundary_and_failure", test_compaction_boundary_and_failure),
        ("compact_at_600k_threshold", test_compact_at_600k_threshold),
        ("startup_gate_requires_extracted", test_startup_gate_requires_extracted),
        ("resolve_workspace_absolute", test_resolve_workspace_absolute),
        ("no_legacy_flags_or_preflight_in_entry",
         test_no_legacy_flags_or_preflight_in_entry),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}"
          "(端到端用例仅 pytest 模式)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())

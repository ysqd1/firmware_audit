"""票 19 AC5/AC9:确定性 LLM 替身驱动 Analysis → 独立 Verification 重放与
确定性报告链(qemu_execute 真实后端;ScriptedLLM 零 API)。

- 真实后端(门控):analysis 两次单发执行已交付 opkg 通路并冻结案卷;
  verification 按案卷 Evidence Reference 的声明输入在独立会话重放,取得
  独立 Evidence;Host 聚合 confirmed Finding;确定性报告 Evidence Index
  呈现 qemu_execute,Finding 只引用 verification 自己的证据。
- 离线(Docker 替身):qemu 正常退出 Evidence 不自动产生 confirmed
  Finding——verification unresolved 时案卷 inconclusive、报告无 confirmed。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.run_step5 import step5_run
from firmware_audit.test.scripted_llm import ScriptedLLM
from firmware_audit.test.test_step5_host_analysis import GENERIC_REQUIRED
from firmware_audit.test.test_step5_host_verification import _FACET_BY_CLAIM
from firmware_audit.test.test_step5_qemu_session import (
    TGT8_SQUASH,
    _copy_rel,
    fake_docker,
)

QEMU_LIST = {
    "file_ref": "extracted/fw/bin/opkg", "firmware_root": "extracted/fw",
    "args": "list-installed", "use_strace": False, "timeout_seconds": 90,
    "adapt_binds": "rw:/var/lock=base/varlock",
}
QEMU_INFO = {**QEMU_LIST, "args": "info busybox"}


def _make_workspace(td: Path) -> Path:
    """target/8 opkg 最小子树 + recon 取证入口(extracted/etc/opkg.conf)。"""
    target = td / "target"
    root = target / "process" / "extracted" / "fw"
    for rel in ("bin/opkg", "lib/libc.so", "lib/ld-musl-mips-sf.so.1",
                "lib/libgcc_s.so.1", "lib/libubox.so",
                "etc/opkg.conf", "usr/lib/opkg/status"):
        assert _copy_rel(TGT8_SQUASH, root, rel), f"固件子树缺失: {rel}"
    return target


def _json(top_summary: str, state_delta: dict, next_kind: str,
          tool: str | None = None, arguments: dict | None = None) -> str:
    if next_kind == "tool_action":
        nxt = {"kind": "tool_action", "tool": tool, "arguments": arguments}
    else:
        nxt = {"kind": next_kind}
    return json.dumps({"decision_summary": top_summary,
                       "state_delta": state_delta, "next": nxt},
                      ensure_ascii=False)


def _survey_delta() -> dict:
    return {
        "attack_surface": [
            {"target": "extracted/bin/opkg", "reason": "包管理程序"},
        ],
        "candidates": [
            {
                "kind": "signal",
                "target": "extracted/bin/opkg",
                "signal": "包管理入口,动态行为需真实执行观察",
                "evidence_id": "ev-000001",
                "next_action": "用 qemu_execute 观察真实业务通路",
            },
        ],
        "checked_scope": ["extracted/etc/"],
        "coverage_gaps": [],
    }


def _analysis_claims() -> dict:
    return {"claims": {
        name: {"status": "supported",
               "evidence_ids": ["ev-000002", "ev-000003"],
               "note": "qemu_execute 真实执行观察"}
        for name in GENERIC_REQUIRED
    }}


def _claim_results() -> dict:
    results = {}
    for name in GENERIC_REQUIRED:
        record = {
            "judgment": "supported",
            "observed": "独立会话按台账重放取得一致观察",
            "method": "qemu_execute 独立重放",
            "evidence_ids": ["ev-000004", "ev-000005"],
        }
        if name in _FACET_BY_CLAIM:
            facet, value = _FACET_BY_CLAIM[name]
            record[facet] = value
        results[name] = record
    return {"claim_results": results}


def _scoring() -> str:
    """评分请求是独立 LLM 契约:回复为裸 factors JSON(非提案)。"""
    return json.dumps({"factors": {
        "external_reachability": {"score": 2, "evidence_id": "ev-000001",
                                  "note": "包管理入口"}},
    }, ensure_ascii=False)


@pytest.mark.skipif(not TGT8_SQUASH.is_dir(), reason="target/8 解包树缺失")
def test_verification_independent_replay_and_report_chain(
        tmp_path: Path, monkeypatch) -> None:
    """真实后端:重放链与报告呈现(AC5); Finding 只背 verification 证据。"""
    from firmware_audit.docker.docker_utils import docker_available
    from firmware_audit.step5_agent.providers.tools.qemu_base import (
        QEMU_EXEC_V2_IMAGE,
    )
    if not docker_available(QEMU_EXEC_V2_IMAGE):
        pytest.skip(f"Docker 或镜像 {QEMU_EXEC_V2_IMAGE} 不可用")
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSION_EXECUTIONS", raising=False)
    target = _make_workspace(tmp_path)

    script = [
        _json("读取包配置取证", {}, "tool_action", "read_file",
              {"path": "extracted/etc/opkg.conf"}),
        _json("铺面完成", _survey_delta(), "complete_survey"),
        _scoring(),
        # analysis(cand-0001):两次单发 qemu_execute + 提交案卷
        _json("执行业务通路取证", {
            "hypothesis": {"statement": "opkg 通路存在可观察的业务行为"}},
            "tool_action", "qemu_execute", dict(QEMU_LIST)),
        _json("对照执行取证", _analysis_claims(),
              "tool_action", "qemu_execute", dict(QEMU_INFO)),
        _json("案卷成熟", {"admission_reason": "ready"}, "submit_case"),
        # verification(cand-0001):独立会话按声明输入重放 + 收尾
        _json("独立重放业务通路", {}, "tool_action", "qemu_execute",
              dict(QEMU_LIST)),
        _json("独立重放对照", {}, "tool_action", "qemu_execute",
              dict(QEMU_INFO)),
        _json("复核完成", _claim_results(), "complete_verification"),
        "案卷由独立重放证据支撑;建议跟进包管理面。",
    ]
    summary = step5_run(target, llm=ScriptedLLM(script))
    assert summary["status"] == "completed", summary
    assert summary["findings"] == 1, summary
    gen_dir = Path(summary["gen_dir"])

    # 配置快照:QEMU 预算块生效值与来源如实(无 profile 层时来源 default)
    config = json.loads((gen_dir / "config.json").read_text(encoding="utf-8"))
    assert config["resolved"]["qemu_max_sessions"] == 3
    assert config["sources"]["qemu_max_sessions"] == "default"
    assert config["resolved"]["qemu_max_session_executions"] == 4
    assert config["sources"]["qemu_max_session_executions"] == "default"

    # 会话台账:analysis 与 verification 各自独立会话执行了相同声明输入
    ledger = json.loads((gen_dir / "qemu_sessions" / "ledger.json")
                        .read_text(encoding="utf-8"))
    by_role = {}
    for session in ledger["sessions"]:
        by_role.setdefault(session["role"], []).append(session)
    assert sorted(by_role) == ["analysis", "verification"]
    for role, sessions in by_role.items():
        assert len(sessions) == 2, (role, len(sessions))
    for a, v in zip(sorted(by_role["analysis"],
                           key=lambda s: s["session_id"]),
                    sorted(by_role["verification"],
                           key=lambda s: s["session_id"])):
        da = a["executions"][0]["declared"]
        dv = v["executions"][0]["declared"]
        assert da["argv"] == dv["argv"]
        assert (da["target"]["sha256"] == dv["target"]["sha256"])
        assert a["session_id"] != v["session_id"]

    # Evidence:verification 独立取得(同声明输入、不同运行产物 digest);
    # 案卷冻结的 Evidence Reference 携带声明输入(重建重放的台账入口)
    ref_a = json.loads((gen_dir / "investigations" / "cand-0001" / "evidence"
                        / "ev-000002.json").read_text(encoding="utf-8"))
    ref_v = json.loads((gen_dir / "verifications" / "cand-0001" / "evidence"
                        / "ev-000004.json").read_text(encoding="utf-8"))
    assert ref_a["tool"] == ref_v["tool"] == "qemu_execute"
    assert ref_a["digest"] != ref_v["digest"], "重放必须独立运行,非复用产物"
    # 案卷冻结的 Evidence Reference 携带声明输入(重建重放的台账入口),
    # 与 verification 实际执行的声明逐字一致——按台账重建闭环
    case_payload = json.loads((gen_dir / "verifications" / "cand-0001"
                               / "case.json").read_text(encoding="utf-8"))
    qemu_refs = [r for r in case_payload.get("evidence_references", [])
                 if r.get("tool") == "qemu_execute"]
    assert qemu_refs and all(r.get("arguments") for r in qemu_refs)
    assert {r["arguments"]["args"] for r in qemu_refs} == {
        "list-installed", "info busybox"}
    executed_v = json.loads((gen_dir / "verifications" / "cand-0001" / "evidence"
                             / "ev-000004.json").read_text(encoding="utf-8"))
    assert executed_v["arguments"] == next(
        r["arguments"] for r in qemu_refs
        if r["arguments"]["args"] == "list-installed")

    # Finding 只引用 verification 自己的证据(不直接复用 analysis 运行产物)
    findings = json.loads((gen_dir / "findings.json").read_text(encoding="utf-8"))
    finding = findings["findings"][0]
    finding_evidence = sorted(
        ref["evidence_id"] for ref in finding["evidence_references"])
    assert finding_evidence == ["ev-000004", "ev-000005"], finding_evidence

    # 确定性报告:QEMU Evidence 呈现在 Evidence Index;Finding 证据同上
    report = (gen_dir / "report.md").read_text(encoding="utf-8")
    assert "## 2. Confirmed Findings(1)" in report
    qemu_index_lines = [line for line in report.splitlines()
                        if "tool=qemu_execute" in line]
    assert len(qemu_index_lines) == 4, qemu_index_lines
    for evidence_id in ("ev-000004", "ev-000005"):
        assert evidence_id in report


def test_qemu_success_does_not_auto_confirm_finding(
        tmp_path: Path, monkeypatch, fake_docker) -> None:
    """离线(AC9):qemu 正常退出只是 Observation——verification unresolved
    时案卷 inconclusive、无 confirmed Finding、报告如实呈现,不因成功自动
    确认。"""
    from firmware_audit.test.test_step5_qemu_session import _arm_workspace
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSIONS", raising=False)
    monkeypatch.delenv("STEP5_QEMU_MAX_SESSION_EXECUTIONS", raising=False)
    target = tmp_path / "target"
    (target / "process").mkdir(parents=True)
    _arm_workspace(target / "process")
    (target / "process" / "extracted" / "etc").mkdir(parents=True,
                                                     exist_ok=True)
    (target / "process" / "extracted" / "etc" / "opkg.conf").write_text(
        "dest root /\n", encoding="utf-8")
    list_args = {
        "file_ref": "extracted/fw/usr/sbin/nvram",
        "firmware_root": "extracted/fw",
        "args": "get wl0_ssid", "use_strace": False,
    }
    unresolved_results = {"claim_results": {
        name: {"judgment": "unresolved",
               "observed": "复核会话未取得决定性观察",
               "method": "qemu_execute 独立执行",
               "limitations": "工具配额内未能覆盖决定性材料"}
        for name in GENERIC_REQUIRED
    }}
    script = [
        _json("读取配置取证", {}, "tool_action", "read_file",
              {"path": "extracted/etc/opkg.conf"}),
        _json("铺面完成", _survey_delta(), "complete_survey"),
        _scoring(),
        _json("执行取证", {
            "hypothesis": {"statement": "动态行为待观察"}},
            "tool_action", "qemu_execute", dict(list_args)),
        _json("逐项推进 Claim", {
            "claims": {name: {"status": "supported",
                              "evidence_ids": ["ev-000002"],
                              "note": "qemu 真实执行观察"}
                       for name in GENERIC_REQUIRED}},
            "tool_action", "read_file",
            {"path": "extracted/etc/opkg.conf"}),
        _json("案卷成熟", {"admission_reason": "ready"}, "submit_case"),
        # verification:不再执行,直接判 unresolved(证据不足不是反证)
        _json("复核完成", unresolved_results, "complete_verification"),
        "复核证据不足,结论保持不可判定。",
    ]
    summary = step5_run(target, llm=ScriptedLLM(script))
    assert summary["status"] == "completed", summary
    assert summary["findings"] == 0, summary
    gen_dir = Path(summary["gen_dir"])
    results = json.loads((gen_dir / "verifications" / "cand-0001"
                          / "results.json").read_text(encoding="utf-8"))
    assert results["verdict"] == "inconclusive"
    report = (gen_dir / "report.md").read_text(encoding="utf-8")
    assert "## 2. Confirmed Findings(0)" in report
    assert "tool=qemu_execute" in report  # Evidence 仍在案卷中可追溯

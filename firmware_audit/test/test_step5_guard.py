"""Step5 recon v3(survey.json)防幻觉守护单测(ScriptedLLM,零 API 零 Docker)。

覆盖 2026-08-29 recon-analysis 边界 spec 的守护项:
  - survey v3 禁止字段(顶层 findings / 任意层级判级键)→ 解析层拒绝并降级观察点 + summary 注明
  - v2 风格攻击面结构按违规拒绝(v2 兼容层 2026-08-29 已移除,不做宽容重建)
  - survey save/load 往返(schema_version=3)
  - _resolve_survey_path 只认 survey.json,不回退旧 attack_surface.json
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.data.artifacts import (
    SURVEY_VERSION,
    _resolve_survey_path,
    load_survey,
    parse_survey_artifact,
    save_survey,
)
from firmware_audit.step5_agent.data.prompts import RECON_SYSTEM


def test_survey_forbidden_findings_degrade() -> list[str]:
    """顶层 findings 数组出现(recon 禁止)→ 整段拒绝,survey 不含 findings;
    v2 兼容层已移除(2026-08-29),findings 不再"宽容转观察点"。"""
    fails: list[str] = []
    raw = ('Final Answer: {"summary": "侦察完成", '
           '"findings": [{"title": "危险导入 system", "severity": "high", '
           '"file": "unitree/bin/idlc"}], '
           '"components": [{"name": "idlc", "version": "", "cve": [], "source": "cve_bin_tool_scan"}]}')
    obj = parse_survey_artifact(raw)
    if obj is None:
        fails.append("含 findings 的输入应可被解析(v3 容器,findings 被拒绝而非崩溃)")
        return fails
    if "findings" in obj:
        fails.append("v3 survey 不得再含 findings 顶层键")
    if obj.get("schema_version") != SURVEY_VERSION:
        fails.append(f"schema_version 应为 {SURVEY_VERSION}, got {obj.get('schema_version')}")
    if "severity" in json.dumps(obj, ensure_ascii=False):
        fails.append("v3 survey 任意层级不得残留 severity 判级键")
    obs = obj.get("high_risk_areas") or []
    if any("危险导入 system" in o.get("detail", "") for o in obs):
        fails.append(f"findings 条目不应被转为观察点(v2 兼容已移除): {obs}")
    if "findings" not in (obj.get("summary") or "") or "已被拒绝" not in (obj.get("summary") or ""):
        fails.append(f"summary 应注明 findings 被拒绝: {obj.get('summary')}")
    if obj.get("components") != [{"name": "idlc", "version": "", "cve": [], "source": "cve_bin_tool_scan"}]:
        fails.append("健康 components 应原样保留(不因 findings 拒绝而丢失)")
    return fails


def test_survey_forbidden_judgment_keys_degrade() -> list[str]:
    """任意层级判级/证据链键(severity/evidence 等)出现 → 该条降级为观察点并从原处剔除。"""
    fails: list[str] = []
    raw = ('Final Answer: {"summary": "s", '
           '"components": ['
           '{"name": "healthy", "version": "1.0", "cve": [], "source": "cve_bin_tool_scan"},'
           '{"name": "bad", "version": "2.0", "severity": "high", "evidence": "guess", "cve": []}'
           '], '
           '"high_risk_areas": [{"file": "a", "metric": "m", "detail": "d"}], '
           '"entry_points": [{"file": "x", "reason": "r"}]}')
    obj = parse_survey_artifact(raw)
    if obj is None:
        fails.append("解析失败")
        return fails
    if any("severity" in json.dumps(c, ensure_ascii=False) for c in obj.get("components") or []):
        fails.append("含判级键的 components 项必须被剔除: " + json.dumps(obj.get("components")))
    if obj.get("components") != [{"name": "healthy", "version": "1.0", "cve": [], "source": "cve_bin_tool_scan"}]:
        fails.append(f"健康 components 项应保留、违规项剔除: {obj.get('components')}")
    obs = obj.get("high_risk_areas") or []
    if not any(o.get("detail") == "bad" for o in obs):
        fails.append(f"违规 components 项应降级为 high_risk_areas 观察点: {obs}")
    if "降级" not in (obj.get("summary") or ""):
        fails.append(f"summary 应注明违规键降级: {obj.get('summary')}")
    if not any(e.get("file") == "x" for e in obj.get("entry_points") or []):
        fails.append("健康 entry_points 应保留")
    return fails


def test_survey_v2_style_input_rejected() -> list[str]:
    """v2 风格攻击面结构(顶层 findings + instance_seq/source_agent)按违规拒绝:
    findings 整段不入 survey、判级键不残留;健康 components 保留。v2 兼容层
    已于 2026-08-29 移除,不再"宽松重建为观察点"。"""
    fails: list[str] = []
    v2 = {
        "schema": 2, "agent": "recon", "summary": "旧攻击面",
        "findings": [{"title": "老发现", "severity": "high", "file": "unitree/bin/idlc",
                      "instance_seq": 0, "source_agent": "recon"}],
        "components": [{"name": "curl", "version": "7.88", "cve": ["CVE-2023-38545"],
                        "source": "cve_bin_tool_scan"}],
    }
    obj = parse_survey_artifact("Final Answer: " + json.dumps(v2, ensure_ascii=False))
    if obj is None:
        fails.append("v2 风格结构应可解析(v3 容器,禁止字段被拒绝而非崩溃)")
    else:
        if "findings" in obj:
            fails.append("v2 findings 顶层键应被拒绝移除")
        if obj.get("schema_version") != SURVEY_VERSION:
            fails.append(f"重建后应为 {SURVEY_VERSION}")
        if "severity" in json.dumps(obj, ensure_ascii=False):
            fails.append("v2 重建后不得残留 severity 判级键")
        obs = obj.get("high_risk_areas") or []
        if any("老发现" in o.get("detail", "") for o in obs):
            fails.append(f"v2 findings 不应被转观察点(v2 兼容已移除): {obs}")
        if "findings" not in (obj.get("summary") or ""):
            fails.append(f"summary 应注明 findings 被拒绝: {obj.get('summary')}")
        if obj.get("components") != [{"name": "curl", "version": "7.88",
                                      "cve": ["CVE-2023-38545"], "source": "cve_bin_tool_scan"}]:
            fails.append("v2 健康 components 应保留")
    return fails


def test_survey_save_load_roundtrip() -> list[str]:
    """save_survey → load_survey 往返:schema_version=3,字段完整、可再解析。"""
    fails: list[str] = []
    obj = parse_survey_artifact('Final Answer: {"summary": "R", '
                                '"arch_snapshot": {"top_level_dirs": ["u"], "os_or_runtime": "linux"}, '
                                '"components": [{"name": "a", "version": "1", "cve": [], "source": "cve_bin_tool_scan"}], '
                                '"entry_points": [{"file": "e", "reason": "r"}], '
                                '"high_risk_areas": [{"file": "f", "metric": "m", "detail": "d"}], '
                                '"recommended_actions": [{"priority": "high", "action": "act"}]}')
    if obj is None:
        fails.append("v3 全字段解析失败")
        return fails
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "survey.json"
        out = save_survey(p, "recon", obj, "raw")
        if out.suffix != ".json":
            fails.append("正常解析应存 .json")
        back = load_survey(p)
        if back is None:
            fails.append("load_survey 应能读回")
            return fails
        if back.get("schema_version") != SURVEY_VERSION:
            fails.append(f"回读 schema_version 应为 {SURVEY_VERSION}: {back.get('schema_version')}")
        if back.get("components") != [{"name": "a", "version": "1", "cve": [], "source": "cve_bin_tool_scan"}]:
            fails.append(f"回读 components 不符: {back.get('components')}")
        if back.get("arch_snapshot") != {"top_level_dirs": ["u"], "os_or_runtime": "linux"}:
            fails.append(f"回读 arch_snapshot 不符: {back.get('arch_snapshot')}")
        if back.get("recommended_actions") != [{"priority": "high", "action": "act"}]:
            fails.append("回读 recommended_actions 不符")
        # 降级分支:非法文本 → .md
        p2 = Path(td) / "b.json"
        out2 = save_survey(p2, "recon", None, "纯文本")
        if out2.suffix != ".md" or load_survey(p2) is not None:
            fails.append("依赖降级 .md 时 load_survey 应返回 None")
    return fails


def test_survey_resolve_path_fallback() -> list[str]:
    """_resolve_survey_path 只认 survey.json;v2 兼容层已移除(2026-08-29),
    缺失 survey.json 时不回退 attack_surface.json(返回 None)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        if _resolve_survey_path(d) is not None:
            fails.append("空目录应返回 None")
        (d / "attack_surface.json").write_text("{}", encoding="utf-8")
        r = _resolve_survey_path(d)
        if r is not None:
            fails.append(f"仅存在旧 attack_surface.json 时应返回 None(不回退): {r}")
        (d / "survey.json").write_text("{}", encoding="utf-8")
        r2 = _resolve_survey_path(d)
        if r2 is None or r2.name != "survey.json":
            fails.append(f"存在 survey.json 时应返回该文件: {r2}")
    return fails


def test_recon_system_prompt_v3() -> list[str]:
    """recon v3 提示词:输出聚焦 v3 结构、判级移交 analysis、防幻觉红线(role_evidence)。"""
    fails: list[str] = []
    for needle in ("arch_snapshot", "components_grouped", "role_evidence", "entry_points",
                   "high_risk_areas", "recommended_actions", "判级与证据链移交 analysis",
                   "high_risk_areas 只标工具 Observation 原文",
                   "版本/CVE 不凭记忆", "禁止仅凭文件名猜角色"):
        if needle not in RECON_SYSTEM:
            fails.append(f"RECON_SYSTEM 应含 v3 说明 '{needle}'")
    # v3 无 findings:recon 提示词不应指导产出 findings 数组
    if "Final Answer 的 JSON 结构(components" in RECON_SYSTEM:
        fails.append("RECON_SYSTEM 终模板不得是旧的 components 追加式")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("survey_forbidden_findings_degrade", test_survey_forbidden_findings_degrade),
        ("survey_forbidden_judgment_keys_degrade", test_survey_forbidden_judgment_keys_degrade),
        ("survey_v2_style_input_rejected", test_survey_v2_style_input_rejected),
        ("survey_save_load_roundtrip", test_survey_save_load_roundtrip),
        ("survey_resolve_path_fallback", test_survey_resolve_path_fallback),
        ("recon_system_prompt_v3", test_recon_system_prompt_v3),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())
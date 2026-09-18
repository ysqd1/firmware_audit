"""Confirmed Finding 的确定性 severity 矩阵(ADR-0012 L59,票 12)。

Severity 完全由冻结的结构化复核结果重算:Verifier 在 Claim Result 上给出
结构化影响与前置条件(``actual_impact.impact_scope`` /
``preconditions.trigger_condition`` / ``mitigations.mitigation_effect``,
ADR-0012 L47),Host 按固定矩阵生成初始严重度。已证实缓解使触发条件左移
一档;完全阻断实际影响则反驳决定性 Claim(由聚合层落为 rejected,不生成
Finding);关键信息缺失时按最重档代入但禁止 critical——最高等级必须建立在
完整事实之上。人工调整不在此处:只能经票 13 的 review overlay 追加表达。

本模块零 IO;Claim Result facet 的协议校验规则也以数据形态在这里声明,
由 verification 的提交/恢复路径共用执行。
"""
from __future__ import annotations

from typing import Any, Mapping

# Severity 词汇单一出处;票 13 的 review overlay 从这里引用。
SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")

# 影响范围四档:仅加固建议 / 局部对象或单一功能 / 完整组件或关键服务 /
# 系统级或信任边界。
IMPACT_SCOPES = ("hardening", "local", "component", "system")
# 触发条件三档:特殊 / 有限 / 宽松。
TRIGGER_CONDITIONS = ("special", "limited", "loose")
# 已证实缓解的实际效果:部分缓解(左移一档)/ 完全阻断(反驳决定性 Claim)。
MITIGATION_EFFECTS = ("partial", "blocking")

# 行=影响范围(仅加固 → 系统/信任边界),列=触发条件(特殊 → 宽松)。
SEVERITY_MATRIX: dict[str, tuple[str, ...]] = {
    "hardening": ("info", "info", "low"),
    "local": ("low", "low", "medium"),
    "component": ("medium", "medium", "high"),
    "system": ("high", "high", "critical"),
}

# Claim Result 允许携带的结构化 facet:claim → {facet 字段: 合法值}。
# 只允许出现在对应 claim 上,且要求 judgment=supported(提交路径强制);
# preconditions 为 not_applicable 时无需 facet——"无前置条件"按宽松触发计。
CLAIM_RESULT_FACETS: dict[str, dict[str, tuple[str, ...]]] = {
    "actual_impact": {"impact_scope": IMPACT_SCOPES},
    "preconditions": {"trigger_condition": TRIGGER_CONDITIONS},
    "mitigations": {"mitigation_effect": MITIGATION_EFFECTS},
}

# 已证实部分缓解的触发条件左移;特殊条件是地板,不再左移。
_TRIGGER_LEFT_SHIFT = {"loose": "limited", "limited": "special", "special": "special"}


def _facet(record: Any, judgment: str, field: str, allowed: tuple[str, ...]):
    """读取合法 facet;judgment 不符或值非法按信息缺失处理。"""
    if not isinstance(record, Mapping) or record.get("judgment") != judgment:
        return None
    value = record.get(field)
    return value if value in allowed else None


def severity_assessment(claim_results: Any) -> dict[str, Any]:
    """从 confirmed Claim Results 重算初始 severity;纯函数、零 IO。

    返回的 ``decisive_refutation`` 表达"完全阻断缓解反驳决定性 Claim";
    severity 字段此时只供参考,聚合层应按 rejected 收束,不生成 Finding。
    """
    results = claim_results if isinstance(claim_results, Mapping) else {}

    mitigations = results.get("mitigations")
    mitigation_effect = _facet(
        mitigations, "supported", "mitigation_effect", MITIGATION_EFFECTS)

    impact_scope = _facet(
        results.get("actual_impact"), "supported", "impact_scope", IMPACT_SCOPES)

    preconditions = results.get("preconditions")
    if isinstance(preconditions, Mapping) and preconditions.get(
            "judgment") == "not_applicable":
        # 无前置条件 = 最宽松触发,且这是完整信息而非缺失。
        trigger_condition = "loose"
    else:
        trigger_condition = _facet(
            preconditions, "supported", "trigger_condition", TRIGGER_CONDITIONS)

    incomplete = impact_scope is None or trigger_condition is None
    # 关键信息缺失按最重档代入:未知信息不能降低严重度;但 critical 封顶,
    # 最高等级必须建立在完整事实之上(ADR-0012 故事 128)。
    effective_impact = impact_scope if impact_scope is not None else "system"
    effective_trigger = trigger_condition if trigger_condition is not None else "loose"
    if mitigation_effect == "partial":
        effective_trigger = _TRIGGER_LEFT_SHIFT[effective_trigger]
    severity = SEVERITY_MATRIX[effective_impact][
        TRIGGER_CONDITIONS.index(effective_trigger)]
    if incomplete and severity == "critical":
        severity = "high"
    return {
        "severity": severity,
        "impact_scope": impact_scope,
        "trigger_condition": trigger_condition,
        "mitigation_effect": mitigation_effect,
        "incomplete": incomplete,
        "decisive_refutation": (
            "actual_impact" if mitigation_effect == "blocking" else None),
    }

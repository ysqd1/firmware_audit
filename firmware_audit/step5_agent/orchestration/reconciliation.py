"""reconciliation:report.md 事后对账纯函数群(ADR-0007,零 IO / 零 LLM)。

T2 自 orchestrator 迁出(spec: step5 编排层包化):报告解析、条目匹配、
三枚举比对、状态聚合全在此;编排主体只留"读盘 → 调用 → 落盘 + stderr 告警"
薄壳(Orchestrator._reconcile_report)。差异清单字段结构与迁出前一字不变,
落盘与时间戳由调用方负责。
"""
from __future__ import annotations

import re

# ---- ADR-0007(2026-09-03):report.md 事后对账(纯函数,零 LLM / 零 IO) ----

# 报告呈现失真治理(方向 c:素材收敛 + 事后对账双保险)。失真的根因在转写环节
# (LLM 把长 Observation 转写 markdown 出错),素材已逐字段喂全,提示词红线约束
# 不了"跨条目串条"(失真 3),故对账必须靠机器:解析 report.md 正文(分区标题 +
# 标签行)与 verified_findings 逐条比对,产出差异清单由 Orchestrator 落盘
# report_reconciliation.json + stderr 警告;仅告警不自动重生成、不阻塞。
#
# 对账只核**确定性事实**(2026-09-03,用户决策:证据不检查):file(位置)、
# severity(危害度)、confidence(置信度)、verified(复核结论)——文件路径与
# 枚举值是可自动相等判定的硬事实,零偏差;rationale/详情内容属语义判断,
# 规则化必有偏差(12 字符连续重合曾把合理压缩转述误报为 warning,target/1
# wangyi 实锤),故不检查,理由溯源回归人工。
#
# 轻提示词约定(编排提示词 _ORCH_TMPL 的报告规范,见 orchestrator 模块):
# 每条已复核 finding 需带标签行
#   - **位置：** <file>（可带 :: func / @ addr）
#   - **severity：** <critical|high|medium|low|info>
#   - **置信度：** high|medium|low → **复核结论：** ✓（已证实）| ✗（误报）| ⚠（未经复核）
#   未复核条目置信度标注"（初值）"。结构非契约(LLM 自由写 markdown),解析失败
#   的条目在清单里显式标 unparsed(不静默)。

# 标题行为条目还是分区:带编号(###/#### N. xxx)或 ≥4 个 # → 条目;否则(≤3 个 #
# 且无编号,如 ### HIGH/## 未复核疑点)→ 分区(找 severity 枚举)。避免 LLM 用
# 3# 写条目时被当分区吞掉(静默丢条,review 2026-09-03)
_RECON_HDR_RE = re.compile(r"^(#{2,5})\s+(?:(\d+)\s*[.、)]?\s*)?(.+?)\s*$")
# verified 提取哨兵:区分"解析出 None(⚠ 未复核)"与"根本没提取到(显式 unparsed)"
_RECON_UNSET = object()
# 标签行:'- **位置：** value' 或 '**置信度（初值）：** value' 等
_RECON_LABEL_RE = re.compile(
    r"^\s*(?:[-*+]\s*)?\*{1,2}\s*([^*:：]+?)\s*[:：](?:\*{1,2}\s*)?(.*)$")
_RECON_SEV_RE = re.compile(r"(critical|high|medium|low|info)", re.IGNORECASE)
_RECON_CONF_RE = re.compile(r"\b(high|medium|low)\b")


def _recon_norm(s: str) -> str:
    """归一化:小写 + 去全部非字母数字(空白/标点/反引号),中文保留。
    用于标题/file 匹配与枚举值比对(容忍空格/标点/路径分隔符差异)。"""
    return "".join(c for c in str(s or "").lower() if c.isalnum())


def _recon_section_severity(section: str) -> str | None:
    """分区标题(### HIGH / ### INFO（已复核）)→ severity;无枚举返回 None。"""
    m = _RECON_SEV_RE.search(section)
    return m.group(1).lower() if m else None


def _recon_parse_enum(text: str) -> str | None:
    """从文本提取 3 值枚举(high/medium/low,confidence 用;severity 走 _RECON_SEV_RE)。"""
    m = _RECON_CONF_RE.search(text)
    return m.group(1).lower() if m else None


def _recon_parse_verdict(text: str):
    """复核结论文本 → True(已证实)/ False(误报)/ None(⚠ 未经复核)。"""
    t = str(text or "")
    if "⚠" in t or "未经复核" in t or "未进入" in t:
        return None
    return not ("✗" in t or "误报" in t or "不成立" in t)


def _recon_parse_report(report_md: str) -> list[dict]:
    """report.md 正文 → 条目列表[{index,title,section,file,severity,confidence,
    verified}]。标题行带编号或 ≥4# → 条目;其余(≤3# 无编号)→ 分区
    (severity 推断用)。labels 标签行拾取字段。"""
    items: list[dict] = []
    cur: dict | None = None
    section = ""
    for raw in report_md.splitlines():
        line = raw.strip()
        hdr = _RECON_HDR_RE.match(line)
        if hdr:
            numbered = hdr.group(2)
            if numbered or len(hdr.group(1)) >= 4:
                if cur is not None:
                    items.append(cur)
                cur = {
                    "index": int(numbered) if numbered else None,
                    "title": hdr.group(3).strip(),
                    "section": section,
                    "file": "", "severity": None, "confidence": None,
                    "verified": _RECON_UNSET,
                }
            else:
                section = hdr.group(3)
            continue
        if cur is None:
            continue
        lb = _RECON_LABEL_RE.match(line)
        if not lb:
            continue
        label = lb.group(1).strip().replace("（初值）", "").replace("(初值)", "")
        value = lb.group(2).strip()
        if label == "位置":
            cur["file"] = value.replace("`", "").replace("\\", "/")
            # 剥离 :: func 与 @ addr(比对用 file;func/addr 不进清单首行)
            cur["file"] = re.split(r"\s*::\s*|\s*@\s*", cur["file"])[0].strip()
        elif label in ("置信度",):
            cur["confidence"] = _recon_parse_enum(value) or cur["confidence"]
            if cur["verified"] is _RECON_UNSET:   # 复核结论常与置信度同行
                cur["verified"] = _recon_parse_verdict(value)
        elif label == "复核结论":
            cur["verified"] = _recon_parse_verdict(value)
        elif label in ("severity", "严重度", "严重级别"):
            sev_m = _RECON_SEV_RE.search(value)   # 5 值:critical|high|medium|low|info
            cur["severity"] = sev_m.group(1).lower() if sev_m else cur["severity"]
    if cur is not None:
        items.append(cur)
    # 分区推断 severity(条目自带标签优先)
    for it in items:
        if it["severity"] is None:
            it["severity"] = _recon_section_severity(it.get("section", ""))
    return items


def reconcile_report(report_md: str, verified_findings: list[dict]) -> dict:
    """report.md 与 verified_findings 对账(ADR-0007) → 差异清单 dict。

    逐条(按标题归一化匹配工件 finding)比对**确定性事实**(2026-09-03 用户决策,
    证据/理由内容不检查——语义判断规则化必有偏差,回归人工):
    - file(位置):报告位置行 vs 工件 file,一致 → ok;报告缺位置行 → ok=None
    - severity/confidence/verified 三枚举值比对:提取到 → ok=True/False(error 级);
      提取不到 → ok=None(显式 unparsed,不静默)
    - 报告有条目但工件对不上 → unmatched
    清单含 summary 汇总与 each item{index,title,file,matched,checks,status}。
    纯函数零 IO/零 LLM:时间戳与落盘由调用方(Orchestrator._reconcile_report)
    负责,测试可直接断言返回值。
    """
    findings_by_norm: dict[str, dict] = {}
    for f in verified_findings or []:
        if isinstance(f, dict):
            findings_by_norm.setdefault(_recon_norm(f.get("title", "")), f)

    items: list[dict] = []
    for it in _recon_parse_report(report_md):
        norm_title = _recon_norm(it["title"])
        finding = findings_by_norm.get(norm_title)
        checks: dict = {}
        if finding is None:
            items.append({
                "index": it["index"], "title": it["title"], "file": it["file"],
                "matched": False, "checks": {}, "status": "unmatched",
            })
            continue

        # ---- file 存在性/一致性(位置行 vs 工件 file) ----
        if not it["file"]:
            checks["file"] = {"ok": None, "artifact": finding.get("file"), "report": None}
        else:
            checks["file"] = {
                "ok": _recon_norm(finding.get("file")) == _recon_norm(it["file"]),
                "artifact": finding.get("file"), "report": it["file"],
            }

        # ---- 三枚举比对(取值方:工件 = 唯一真值) ----
        # 提取失败判定:severity/confidence 用 None;verified 用哨兵(⚠ 解析出的
        # None 是"未复核"的有效值,须与"没提取到"区分)
        for key, art_val, rep_val, unset in (
                ("severity", finding.get("severity"), it["severity"], None),
                ("confidence", finding.get("confidence"), it["confidence"], None),
                ("verified", finding.get("verified"), it["verified"], _RECON_UNSET)):
            if rep_val is unset:
                checks[key] = {"ok": None, "artifact": art_val, "report": None}
            else:
                checks[key] = {
                    "ok": _recon_norm(str(art_val)) == _recon_norm(str(rep_val)),
                    "artifact": art_val, "report": rep_val,
                }

        # ---- 状态聚合:unparsed(提取失败)> mismatch > ok ----
        # (rationale/evidence 内容不检查:2026-09-03 用户决策,理由溯源回归人工)
        field_oks = [checks[k]["ok"] for k in ("file", "severity", "confidence",
                                               "verified") if k in checks]
        if any(o is None for o in field_oks):
            status = "unparsed"                      # 提取不到字段,显式报出(不静默)
        elif any(o is False for o in field_oks):
            status = "mismatch"                      # 有字段不符(误差级告警)
        else:
            status = "ok"
        items.append({
            "index": it["index"], "title": it["title"], "file": it["file"],
            "matched": True, "checks": checks, "status": status,
        })

    summary = {
        "report_items": len(items),
        "matched": sum(1 for i in items if i["matched"]),
        "ok": sum(1 for i in items if i["status"] == "ok"),
        "mismatch": sum(1 for i in items if i["status"] == "mismatch"),
        "unparsed": sum(1 for i in items if i["status"] == "unparsed"),
        "unmatched": sum(1 for i in items if i["status"] == "unmatched"),
    }
    return {"summary": summary, "items": items}


__all__ = ["reconcile_report"]

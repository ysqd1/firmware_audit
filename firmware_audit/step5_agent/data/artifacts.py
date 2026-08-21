"""Agent 间工件契约:Finding 数据类 + 宽容解析 + 落盘。

工件链:agent/attack_surface.json → findings.json → verified_findings.json
统一容器 {agent, summary, findings: [...]};LLM 输出天然不稳,解析层
只降级不崩溃(缺字段给默认值,多余字段保留在 extras)。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\}|\[.*\])\s*```", re.S)

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    title: str
    severity: str = "info"          # critical/high/medium/low/info
    file: str = ""
    func: str = ""
    addr: str = ""
    evidence: str = ""              # 代码片段/字符串值等
    cve: str = ""
    confidence: str = ""            # high/medium/low
    verified: bool | None = None    # None=未复核;verification 填
    rationale: str = ""             # 复核结论(verification 填)
    extras: dict = field(default_factory=dict)  # LLM 多给的字段原样保留

    def to_dict(self) -> dict:
        d = asdict(self)
        if not self.extras:
            d.pop("extras")
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        if not isinstance(d, dict):
            return cls(title=str(d))
        known = cls.__dataclass_fields__
        kwargs = {k: v for k, v in d.items() if k in known}
        extras = {k: v for k, v in d.items() if k not in known}
        f = cls(**kwargs)
        f.title = str(f.title or "未命名发现")
        if f.severity not in SEVERITIES:
            f.severity = "info"
        f.extras = extras
        return f


def strip_fence(text: str) -> str:
    """剥 ```json 围栏;无围栏时原样返回。"""
    m = FENCE_RE.search(text)
    return m.group(1) if m else text


def parse_artifact(final_answer: str) -> dict | None:
    """Final Answer 文本 → 工件容器 dict。宽容:
    - 剥围栏;前后非 JSON 文本容忍(找第一个 { 到最后一个 })
    - findings 缺失时给空列表;顶层直接是 list 时包成容器
    解析彻底失败返回 None(调用方降级存 .md)。
    """
    s = strip_fence(final_answer.strip())
    if not s:
        return None
    start, end = s.find("{"), s.rfind("}")
    l_start, l_end = s.find("["), s.rfind("]")
    # 顶层可能是 {..} 或 [..],取范围更大的候选
    candidates = []
    if start != -1 and end > start:
        candidates.append(s[start : end + 1])
    if l_start != -1 and l_end > l_start:
        candidates.append(s[l_start : l_end + 1])
    for cand in sorted(candidates, key=len, reverse=True):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, list):
            return {"summary": "", "findings": obj}
        if isinstance(obj, dict):
            if "findings" not in obj:
                obj["findings"] = []
            obj["findings"] = [Finding.from_dict(f) for f in obj.get("findings") or []]
            return obj
    return None


SCHEMA_VERSION = 1


def save_artifact(path: Path, agent: str, parsed: dict | None, raw: str) -> Path:
    """工件落盘:能解析存 JSON,否则原文本存 .md(降级但信息不丢)。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    if parsed is not None:
        out = {
            "schema": SCHEMA_VERSION,
            "agent": agent,
            "summary": parsed.get("summary", ""),
            "findings": [f.to_dict() if isinstance(f, Finding) else f for f in parsed["findings"]],
        }
        for k, v in parsed.items():  # LLM 多给的顶层字段保留(components 等)
            if k not in out:
                out[k] = v
        path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        return path
    md = path.with_suffix(".md")
    md.write_text(f"# {agent} 原始输出(JSON 解析失败降级)\n\n{raw}\n", encoding="utf-8")
    return md


def load_artifact(path: Path) -> dict | None:
    """读回工件(断点续跑喂下游)。宽容:失败返回 None。"""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    obj.setdefault("summary", "")
    obj.setdefault("findings", [])
    return obj


def artifact_summary(path: Path, max_chars: int = 1500) -> str:
    """下游 Agent 初始注入用的摘要:summary + findings 标题行(截断)。
    细节让下游用 read_file 按需拉,不把整个工件塞进对话。
    .md 降级工件(解析失败)读原文前段,提示下游自行 read_file。"""
    obj = load_artifact(path)
    if obj is None:
        try:
            text = path.with_suffix(".md").read_text(encoding="utf-8")
        except OSError:
            return f"(工件 {path.name} 读取失败)"
        hint = f"(JSON 解析失败的降级工件,全文用 read_file 读 {path.with_suffix('.md').name})\n"
        return hint + text[:max_chars]
    lines = [obj.get("summary", "").strip()]
    for f in obj.get("findings", []):
        sev = f.get("severity", "info")
        title = f.get("title", "?")
        loc = f.get("file", "") + ("/" + f.get("func", "") if f.get("func") else "")
        cve = f" [{f['cve']}]" if f.get("cve") else ""
        lines.append(f"- [{sev}] {title} @ {loc}{cve}")
    text = "\n".join(l for l in lines if l)
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n...(截断,全文用 read_file 读 {path.name})"
    return text

"""Agent 间工件契约:Finding 数据类 + 宽容解析 + 落盘。

工件链(2026-08-29):agent/survey.json → findings.json → verified_findings.json
- findings 类工件(analysis/verification):统一容器 {agent, summary, findings: [...]}
- 侦察(recon v3)工件为 survey.json:见 parse_survey_artifact(无 findings/判级字段;
  旧 attack_surface.json 命名于 2026-08-29 移除 v2 兼容层,不再回退读取)。
LLM 输出天然不稳,解析层只降级不崩溃(缺字段给默认值,多余字段保留在 extras)。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*\}|\[.*\])\s*```", re.S)

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")

# 排序权重表(单一出处,T6 收编):列表序即从高到低,序号即排序键。
# 消费方:复核引擎取前 K 排序(verify_phase.rank_findings)、summarize 清单
# 呈现(actions.SummarizeTool)。表外键(空/未知枚举)由消费方给大数兜底。
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCES)}


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
    source_agent: str = ""          # 溯源:产出该 finding 的 Agent(schema v2)
    instance_seq: int | None = None  # 溯源:产出实例序号(schema v2;0_recon → 0)
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


SCHEMA_VERSION = 2  # v2(2026-08-28):finding 增 source_agent/instance_seq 溯源字段


def save_artifact(path: Path, agent: str, parsed: dict | None, raw: str) -> Path:
    """工件落盘:能解析存 JSON,否则原文本存 .md(降级但信息不丢)。

    落盘时给每条 finding 补 source_agent=agent(schema v2 溯源);
    instance_seq 由 orchestrator 聚合时再补(run_agent 不知道 seq)。
    """
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
        # 溯源补齐:该工件产出的 finding 标记 source_agent(不覆盖已有值)
        for f in out["findings"]:
            if isinstance(f, dict) and not f.get("source_agent"):
                f["source_agent"] = agent
        path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        return path
    md = path.with_suffix(".md")
    md.write_text(f"# {agent} 原始输出(JSON 解析失败降级)\n\n{raw}\n", encoding="utf-8")
    return md


def save_aggregate(path: Path, agent: str, summary: str, findings: list) -> Path:
    """聚合工件落盘(T6 收编):编排层聚合产物走 schema v2 容器,无 .md 降级。

    与 save_artifact 的分工:后者承接 LLM Final Answer(解析失败降级 .md);
    本函数承接编排侧已聚合好的 findings(verification 每疑点一实例的阶段
    产物,merge_verdicts 输出),字段原样写入不解析不降级——溯源字段由
    调用方经 stamp_provenance/merge_verdicts 补齐。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema": SCHEMA_VERSION, "agent": agent, "summary": summary,
        "findings": findings,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def stamp_provenance(findings: list, agent: str, seq: int,
                     only_missing: bool = False) -> None:
    """schema v2 溯源字段回写(就地):每条 dict finding 标 source_agent/instance_seq。

    runner 落盘时不知道 seq(save_artifact 只补 source_agent),seq 由编排层
    调度返回后回填。两种策略(与收编前各消费点语义逐字一致):
    - only_missing=False(verification 复核语义,默认):无条件覆盖——复核
      结论产自哪个实例必须如实标注,实例返回工件自带值不保留;
    - only_missing=True(编排调度回填语义,actions):instance_seq 仅缺省时补
      (断点续跑工件保留原始实例号),source_agent 不动(落盘时已补)。
    """
    for f in findings:
        if not isinstance(f, dict):
            continue
        if only_missing:
            if f.get("instance_seq") is None:
                f["instance_seq"] = seq
        else:
            f["source_agent"] = agent
            f["instance_seq"] = seq


def rewrite_artifact(path: Path, obj: dict) -> bool:
    """工件回写磁盘(T6 收编):溯源/归一化回填后整包重写。

    OSError 吞掉返回 False——回填失败不阻塞调度(聚合层 ingest 仍会补),
    与收编前 actions 的 try/except-pass 语义一致。
    """
    try:
        path.write_text(json.dumps(obj, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        return True
    except OSError:
        return False


def load_artifact(path: Path) -> dict | None:
    """读回工件(断点续跑喂下游)。宽容:失败返回 None。
    v1 工件(无 source_agent/instance_seq)读到时补默认值,消费方无感。"""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    obj.setdefault("summary", "")
    obj.setdefault("findings", [])
    if obj.get("schema", 1) < 2:
        obj["schema"] = obj.get("schema", 1)   # 保留原版本号,聚合层补溯源
        for f in obj["findings"]:
            if isinstance(f, dict):
                f.setdefault("source_agent", obj.get("agent", ""))
                f.setdefault("instance_seq", None)
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


# ---------------------------------------------------------------------------
# recon v3 工件:survey.json(2026-08-29,对齐 DeepAudit recon 语义)
# ---------------------------------------------------------------------------
# 禁止字段:findings 数组 + 任意层级的判级/证据链键(severity/confidence/
# verified/evidence/rationale)。recon 只铺面不判级,判级与证据链移交 analysis。
SURVEY_VERSION = 3
SURVEY_FORBIDDEN_KEYS = ("severity", "confidence", "verified", "evidence", "rationale")
# role 推断必需证据(见 prompt:禁止裸 role)
_SURVEY_OBS_METRIC_FORBIDDEN = "违规判级/证据链键降级(recon 禁止)"


def _tostr(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(v)


def extract_json_object(text: str) -> dict | None:
    """从文本中宽容取出一个 dict JSON(首个 { 到最后一个 })。

    宽容 JSON 提取的单一出处(T6 收编):survey 解析与编排层 report.json
    副产品共用;调用方先剥围栏(strip_fence)。非 dict/解析失败返回 None。

    过度转义修复保守档(票02,2026-09-11):原文解析失败且错误类型恰为
    Invalid \\escape 时,剥掉非法转义的反斜杠重试一次。接受条件三合一,缺一
    维持 None 降级:①原文确属该错误类型(Invalid \\uXXXX 等不触发);
    ②归一化后能完整解析;③解析结果通过工件形状校验(_artifact_shaped,
    survey v3 键或 findings 容器)。target/5 实测:recon Final Answer 字符串值
    里 \\$SERVER 的 \\$ 是唯一非法转义(\\\" 均合法),整份 14787 字符合格侦察
    因它降级 → 编排层白烧约 50 万 token 补跑。
    """
    if not text:
        return None
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    cand = text[start : end + 1]
    try:
        obj = json.loads(cand)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError as e:
        # startswith 而非全等:不同 CPython 构建/版本的解码器 msg 可能带后缀
        # (如 repr 形态);"Invalid \uXXXX escape" 等其他错误不会误匹配
        if not e.msg.startswith("Invalid \\escape"):
            return None
    repaired = _strip_invalid_escapes(cand)
    try:
        obj = json.loads(repaired)
    except json.JSONDecodeError:
        return None
    if isinstance(obj, dict) and _artifact_shaped(obj):
        return obj
    return None


# 合法 JSON 字符串转义字符("\/ b f n r t u;\\ 与 \u 靠第二个字符落在此集合放行)
_JSON_VALID_ESCAPES = frozenset('"\\/bfnrtu')

# 工件形状校验键(票02 修复档接受条件 3):survey v3 结构键或 findings 容器键,
# 至少其一存在才接受修复结果——防止"归一化碰巧能解析"的错误数据混进工件链。
# 只收结构键(schema_version 是值不受验的标签,不入选);键集与 _normalize_survey
# 的 survey v3 输出键平行,survey 结构演进时需同步(现状规模可接受,不抽单一出处)。
_ARTIFACT_SHAPE_KEYS = ("arch_snapshot", "components", "entry_points",
                        "high_risk_areas", "recommended_actions")


def _strip_invalid_escapes(text: str) -> str:
    """剥掉非法转义的反斜杠(纯函数,票02):\\X 且 X ∉ 合法转义集 → X。

    线性扫描合法转义对(含 \\\\ 与 \\u)原样保留,避免把"合法反斜杠对 +
    非法转义"(如 \\\\$)二次破坏;只处理字符串内部形态,结构字符不碰。
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            if text[i + 1] in _JSON_VALID_ESCAPES:
                out.append(text[i:i + 2])
            else:
                out.append(text[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _artifact_shaped(obj) -> bool:
    """工件形状校验(票02):dict 含 findings 列表或任一 survey v3 结构键。"""
    if not isinstance(obj, dict) or not obj:
        return False
    if isinstance(obj.get("findings"), list):
        return True
    return any(k in obj for k in _ARTIFACT_SHAPE_KEYS)


_REMOVE = object()


def _sanitize_survey(value, degraded: list):
    """递归清洗:含禁止键(findings 数组或判级键)的 dict 整条降级入 degraded。

    返回清洗后的值;被降级处返回 _REMOVE(调用方移除并补空占位)。
    只降级不崩溃:数组内坏项剔除,层的其他健康项保留。
    """
    if isinstance(value, dict):
        keys = set(value)
        if keys & set(SURVEY_FORBIDDEN_KEYS) or "findings" in keys:
            degraded.append(_obs_from_forbidden(value, _SURVEY_OBS_METRIC_FORBIDDEN))
            return _REMOVE
        cleaned = {}
        for k, v in value.items():
            r = _sanitize_survey(v, degraded)
            if r is not _REMOVE:
                cleaned[k] = r
        return cleaned
    if isinstance(value, list):
        out = []
        for item in value:
            r = _sanitize_survey(item, degraded)
            if r is not _REMOVE:
                out.append(r)
        return out
    return value


def _obs_from_forbidden(value, metric: str) -> dict:
    """违规 dict/条目 → high_risk_areas 观察点(只保留可观测字段,套用给定 metric)。"""
    if isinstance(value, dict):
        f = value.get("file")
        if not isinstance(f, str):
            f = ""
        title = _tostr(value.get("title") or value.get("name")
                       or value.get("action") or value)
        return {"file": f, "metric": metric, "detail": title}
    return {"file": "", "metric": metric, "detail": _tostr(value)}


def _normalize_survey(obj: dict) -> dict:
    """把 LLM 原始 dict 归一为 v3 survey 结构(含防幻觉降级)。
    v2 兼容层 2026-08-29 已移除:findings/判级键一律按违规处理,不再"宽容转换"。"""
    notes: list[str] = []
    high = list(obj.get("high_risk_areas") or [])

    # 1) recon 禁止字段:顶层 findings 数组或判级/证据链键出现即拒绝并注明
    #    (findings 无健康可观测对象,不产观察点;判级键在子树层面按步骤 3 降级)
    top_forbidden = [k for k in obj if k == "findings" or k in SURVEY_FORBIDDEN_KEYS]
    if top_forbidden:
        notes.append(f"顶层禁止键 {','.join(top_forbidden)} 已被拒绝(recon 不判级、不产 findings)")

    # 2) 其余子树清洗:任意层级 forbidden 键 → 剔除并降级为观察点
    degraded: list[dict] = []
    cleaned: dict = {}
    for k, v in obj.items():
        if k == "findings" or k in SURVEY_FORBIDDEN_KEYS:
            continue  # findings/判级键已在步骤1拒绝
        r = _sanitize_survey(v, degraded)
        if r is _REMOVE:
            # 整个子树全被降级丢失 → 按类型补空占位,保 schema 不断裂
            r = {} if k == "arch_snapshot" else [] if isinstance(v, list) else {}
        cleaned[k] = r
    if degraded:
        high.extend(degraded)
        notes.append(f"剔除 {len(degraded)} 处违规判级/证据链字段,已降级为 high_risk_areas 观察点")

    summary = _tostr(cleaned.get("summary") or "")
    if notes:
        summary = (summary + "\n\n[recon schema 守护] " + "；".join(notes)).strip()

    return {
        "schema_version": SURVEY_VERSION,
        "arch_snapshot": cleaned.get("arch_snapshot", {}),
        "components": cleaned.get("components") or [],
        "entry_points": cleaned.get("entry_points") or [],
        "high_risk_areas": high,
        "recommended_actions": cleaned.get("recommended_actions") or [],
        "summary": summary,
    }


def parse_survey_artifact(final_answer: str) -> dict | None:
    """recon Final Answer → v3 survey 工件 dict(schema_version=3)。

    防幻觉守护:findings 数组(任意层级)与 severity/confidence/verified/evidence/
    rationale(任意层级)出现即拒绝并降级为 high_risk_areas 观察点 + summary 注明
    (v2 兼容层已移除,旧 attack_surface 结构不再宽容转换)。解析彻底失败返回 None(调用方降级存 .md)。
    """
    obj = extract_json_object(strip_fence(final_answer.strip()))
    if obj is None:
        return None
    return _normalize_survey(obj)


def save_survey(path: Path, agent: str, parsed: dict | None, raw: str) -> Path:
    """recon v3 工件落盘:能解析按 survey 结构存 JSON,否则原文本存 .md 降级。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    if parsed is not None:
        out = dict(parsed)
        out["schema_version"] = SURVEY_VERSION
        out.setdefault("agent", agent)
        for k, v in parsed.items():  # LLM 额外的健康顶层字段原样保留
            out.setdefault(k, v)
        path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        return path
    md = path.with_suffix(".md")
    md.write_text(f"# {agent} 原始输出(JSON 解析失败降级)\n\n{raw}\n", encoding="utf-8")
    return md


def load_survey(path: Path) -> dict | None:
    """读回 survey 工件(宽容:失败/结构异常返回 None)。数组字段给默认空值。"""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    obj.setdefault("schema_version", SURVEY_VERSION)
    for k in ("components", "entry_points", "high_risk_areas", "recommended_actions"):
        if not isinstance(obj.get(k), list):
            obj[k] = []
    if not isinstance(obj.get("arch_snapshot"), dict):
        obj["arch_snapshot"] = {}
    obj.setdefault("summary", "")
    return obj


def _resolve_survey_path(name_dir: Path) -> Path | None:
    """定位实例目录下 recon 的 survey.json(v3 唯一命名,不回退旧 attack_surface.json)。

    供 brief/聚合复用:读 sidecar 时统一经此定位。
    """
    p = name_dir / "survey.json"
    return p if p.is_file() else None

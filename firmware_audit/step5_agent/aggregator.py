"""FindingAggregator —— 子 Agent findings 的聚合/去重/重合计分。

从 Orchestrator 拆出的纯逻辑(2026-08-30,架构体检):
findings 聚合(_ingest)与重合计分(_overlap_ratio)不依赖调度/LLM/文件,
只维护一个聚合列表 all_findings,故独立成深模块,可脱离 Orchestrator 单测。

职责边界:
- 本模块只管"把新 findings 并入聚合列表、命中重复键时合并而非丢弃"。
- 调度史(_dispatches)/同类型取最新(_agent_results)/预算差分(_pending_focuses)
  仍是 Orchestrator 的职责,不搬下来。
"""
from __future__ import annotations

from dataclasses import dataclass, field

# 同一条 finding 的字段:新实例有值且已有为空 → 补;verification 的复核权威字段直接覆盖
# (ADR-0003:verification 可修改 confidence——存疑项降级保留,故 confidence 也在覆盖集)
_OVERRIDE_KEYS = ("verified", "rationale", "confidence")


@dataclass
class FindingAggregator:
    """聚合子 Agent 产出的 findings,维护一个去重合并后的列表。

    Orchestrator 持有本实例并委托 _ingest 的活;all_findings 即聚合结果。
    """

    all_findings: list = field(default_factory=list)

    # ---- 纯工具 ----

    @staticmethod
    def dedup_key(f: dict) -> tuple:
        """去重键:file+func+addr+标题规范化(比 v2 的 (title,file) 更细)。"""
        title_norm = " ".join(str(f.get("title", "")).split()).lower()
        return (str(f.get("file", "")).strip(), str(f.get("func", "")).strip(),
                str(f.get("addr", "")).strip(), title_norm)

    @staticmethod
    def norm_text(s) -> str:
        """差分比对归一化:统一路径分隔符 + 压空白 + 小写(simple contains 用)。"""
        return " ".join(str(s or "").replace("\\", "/").split()).lower()

    # ---- 聚合 ----

    def ingest(self, sub) -> None:
        """把子 Agent findings 并入聚合;命中重复键时**合并**而非丢弃(深化版本
        保留:已有 evidence 保留,新实例补 confidence/evidence 空位;
        verification 是复核权威,其 verified/rationale 直接覆盖)。
        recon(recon v3 survey)跳过:recon 只铺面不判级、无 findings;
        即便磁盘遗留旧 findings 残留也显式忽略不聚合(recon 判级移交 analysis)。"""
        if sub.agent_name == "recon":
            return
        for f in sub.findings:
            if not isinstance(f, dict):
                continue
            key = self.dedup_key(f)
            for i, existing in enumerate(self.all_findings):
                if self.dedup_key(existing) != key:
                    continue
                merged = dict(existing)
                for k, v in f.items():
                    if v in (None, "", [], {}):
                        continue
                    if not merged.get(k):
                        merged[k] = v      # 新实例有值且已有为空 → 补
                # 复核权威字段:verification 实例直接覆盖(后段修正前段)
                if sub.agent_name == "verification":
                    for k in _OVERRIDE_KEYS:
                        if k in f:
                            merged[k] = f[k]
                if merged.get("instance_seq") is None:
                    merged["instance_seq"] = sub.seq
                merged.setdefault("source_agent", sub.agent_name)
                self.all_findings[i] = merged
                break
            else:
                g = dict(f)
                if g.get("instance_seq") is None:
                    g["instance_seq"] = sub.seq
                g.setdefault("source_agent", sub.agent_name)
                self.all_findings.append(g)

    def overlap_ratio(self, new_findings: list) -> float:
        """重合计分(Task6.5):新实例 findings 与既有 all_findings(本实例
        ingest 前)按(title 归一化 + file 归一化)二元组匹配的重复比例;
        空输入或无既有聚合时返回 0.0。"""
        if not new_findings:
            return 0.0
        existing = set()
        for f in self.all_findings:
            if not isinstance(f, dict):
                continue
            existing.add((self.norm_text(f.get("title", "")),
                          self.norm_text(f.get("file", ""))))
        if not existing:
            return 0.0
        hit = sum(
            1 for f in new_findings
            if isinstance(f, dict) and (self.norm_text(f.get("title", "")),
                                        self.norm_text(f.get("file", ""))) in existing)
        return hit / len(new_findings)


__all__ = ["FindingAggregator"]

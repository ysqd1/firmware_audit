"""handoff——交接块构建与交接快照落盘(ADR-0009 T4)。

纯数据进、文本/副作用出,不接 host:动作层把已过滤的数据(实际执行的调度、
累计 findings)显式递进来,本模块不感知编排主体。三个出口:

- build_handoff:        组装注入子 Agent 简报尾部的交接文本块
- build_rerun_brief:    交接块之外追加已覆盖清单 + 差分 task 提示(补跑简报)
- save_handoff_snapshot:交接结构化落盘 handoff_<seq>_<type>.json(可审计)

_now 时间戳 helper 按 spec"小格式化 helper 留在各自消费者旁"在此原地保留
一份(dispatch_log 同款先例)。
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .state import STATUS_LABEL, SubAgentResult


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def build_handoff(agent: str, task: str, context: str,
                  executed: list[SubAgentResult],
                  all_findings: list[dict]) -> str:
    """交接块(注入子 Agent 简报尾部):任务状态/前次结果/累计发现/上下文。"""
    lines = ["", "--- 交接信息(编排器自动注入) ---"]
    if executed:
        lines.append("前序任务状态:")
        for d in executed:
            art = d.artifact_path.name if d.artifact_path else "无"
            t = (d.request.get("task") or "")[:40]
            lines.append(f"  - 实例[{d.seq}] {d.agent_name}「{t}」:"
                         f"{STATUS_LABEL.get(d.status, d.status)},工件 {art},"
                         f"findings {len(d.findings or [])} 条")
    prev = [d for d in executed if d.agent_name == agent]
    if prev:
        last = prev[-1]
        art = last.artifact_path.name if last.artifact_path else "无"
        lines.append(f"本次为 {agent} 的第 {len(prev) + 1} 次调用:上一次输出 {art}"
                     f"({len(last.findings or [])} findings);请在既有结果基础上"
                     "补充推进,不要重复已完成的工作")
    if all_findings:
        lines.append(f"全链路累计 findings: {len(all_findings)} 条"
                     "(细节可用 read_file 读取上列工件)")
    if context:
        lines.append(f"本次任务补充上下文: {context}")
    lines.append("工件按 agent/<seq>_<type>/ 目录组织,可直接 read_file 读取")
    return "\n".join(lines)


def build_rerun_brief(agent: str, handoff: str, all_findings: list[dict],
                      call_count: int, max_findings: int = 30) -> str:
    """补跑简报增补(Task6.7):既有交接块 + 已覆盖清单(all_findings 的
    title/file,前 30 条)+ 差分 task 提示;经 extra_brief 注入子 Agent
    简报尾部(run_agent 透传),配合 ANALYSIS_SYSTEM 补跑红线食用。"""
    round_no = call_count + 1
    lines = [handoff, "",
             f"--- 已覆盖清单(前 {max_findings} 条,编排器注入) ---"]
    if all_findings:
        for f in all_findings[:max_findings]:
            lines.append(f"- {f.get('title', '?')} @ {f.get('file', '')}")
        if len(all_findings) > max_findings:
            lines.append(f"...(共 {len(all_findings)} 条,余下省略)")
    else:
        lines.append("(暂无已覆盖 findings)")
    lines.append(f"本实例为第 {round_no} 轮补跑,聚焦未覆盖疑点,"
                 "禁止重复提交已存在标题")
    return "\n".join(lines)


def save_handoff_snapshot(orch_dir: Path, seq: int, agent: str, task: str,
                          context: str, handoff_text: str,
                          executed: list[SubAgentResult],
                          cumulative_findings: int) -> None:
    """交接快照:结构化落盘 handoff_<seq>_<type>.json,文本块是其投影。
    交接从此可审计、可程序化消费(与 transcript 互补)。"""
    snapshot = {
        "seq": seq,
        "to_agent": agent,
        "task": task,
        "context": context,
        "prior_dispatches": [
            {"seq": d.seq, "agent": d.agent_name, "status": d.status,
             "task": d.request.get("task", ""),
             "artifact": str(d.artifact_path) if d.artifact_path else None,
             "findings": len(d.findings or [])}
            for d in executed],
        "prior_same_agent": {
            "calls": len([d for d in executed if d.agent_name == agent]),
            "last_summary": next(
                (d.summary for d in reversed(executed) if d.agent_name == agent), ""),
        },
        "cumulative_findings": cumulative_findings,
        "ts": _now(),
    }
    try:
        orch_dir.mkdir(parents=True, exist_ok=True)
        (orch_dir / f"handoff_{seq}_{agent}.json").write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2),
            encoding="utf-8")
    except OSError:
        pass  # 快照失败不阻塞调度(handoff 文本块仍会注入)


__all__ = ["build_handoff", "build_rerun_brief", "save_handoff_snapshot"]

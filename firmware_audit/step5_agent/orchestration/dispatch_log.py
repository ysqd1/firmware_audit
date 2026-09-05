"""DispatchLog——调度留痕小类(ADR-0009 T3:调度日志收类)。

全量调度尝试(含被拒/重复)的记录管理、status_history 变迁与
dispatch_log.json 落盘(含 mkdir)的全部知识收在本类;编排主体
(orchestrator 模块)只经四个动词消费,不再拼日志记录 dict:

- start:       真实调度发起,登记 running 记录,返回记录引用供终态回填
- finish:      回填终态(running→success/degraded/failed/skipped 变迁留痕)
- interrupted: 异常向上传播时 running 记录回填 interrupted(不留悬挂 running)
- attempt:     不经 running 阶段的一次性留痕(跳过/降级/拒绝/重复)

记录字段结构与落盘内容与收类前完全不变:seq/agent/task/status/request/
started_at/finished_at/duration_ms/artifact_path/summary/error/
status_history(+budget_state/duplicate_of 条件键)。每次记录变更即整表
落盘(发起即留痕:编排进程异常退出也不丢已发生的调度史)。

包内依赖:只 import state(共享词汇 DispatchStatus;T4 收编本模块原临时
重复的 running/interrupted 落盘字面量,值不变)。不 import 编排主体(spec
包内依赖方向:orchestrator → 各模块,禁止反向)。_now 时间戳 helper 按
spec"小格式化 helper 留在各自消费者旁"在此原地保留一份。
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

from .state import DispatchStatus


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class DispatchLog:
    """调度留痕:全量调度尝试(含被拒/重复)的记录管理与 dispatch_log.json 落盘。

    接口只有四个动词(start/finish/interrupted/attempt);日志 list、
    status_history 变迁、落盘知识全部内聚,编排主体不感知记录形态。
    """

    def __init__(self, orch_dir: Path):
        self._dir = orch_dir
        self._records: list[dict] = []

    # ---- 落盘(类内唯一写盘点;每次记录变更即整表落盘) ----

    def _flush(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        (self._dir / "dispatch_log.json").write_text(
            json.dumps(self._records, ensure_ascii=False, indent=2),
            encoding="utf-8")

    # ---- 四动词接口 ----

    def start(self, seq: int, agent: str, task: str, request: dict) -> dict:
        """登记调度开始(running),返回记录引用供终态回填。"""
        rec = {"seq": seq, "agent": agent, "task": task, "status": DispatchStatus.RUNNING,
               "request": request, "started_at": _now(), "finished_at": None,
               "duration_ms": None, "artifact_path": None, "summary": "",
               "error": "", "status_history": [{"status": DispatchStatus.RUNNING, "ts": _now()}]}
        self._records.append(rec)
        self._flush()
        return rec

    def finish(self, rec: dict, status: str, *, duration_ms: int | None = None,
               artifact: str | None = None, summary: str = "",
               error: str = "", budget_state: dict | None = None) -> None:
        """回填调度终态:状态变迁 running→success/degraded/failed 落痕。

        budget_state(Task6.8)为该实例的结构化预算状态快照(聚合后取,
        含 overlap_ratio/pending 差分),原样写入该条 dispatch_log 记录。"""
        rec["status"] = status
        rec["finished_at"] = _now()
        rec["duration_ms"] = duration_ms
        rec["artifact_path"] = artifact
        rec["summary"] = summary
        rec["error"] = error
        if budget_state is not None:
            rec["budget_state"] = budget_state
        rec["status_history"].append({"status": status, "ts": _now()})
        self._flush()

    def interrupted(self, rec: dict) -> None:
        """执行中断兜底:run_agent 抛异常向上传播时,running 记录回填为
        interrupted(LLMError 终止整个 Step5 的场景),不留悬挂的运行中状态。"""
        if rec.get("status") == DispatchStatus.RUNNING:
            rec["status"] = DispatchStatus.INTERRUPTED
            rec["finished_at"] = _now()
            rec["error"] = rec.get("error") or "子 Agent 执行中断(异常向上传播)"
            rec["status_history"].append(
                {"status": DispatchStatus.INTERRUPTED, "ts": _now()})
            self._flush()

    def attempt(self, agent: str, task: str, request: dict, status: str,
                t0: float, *, seq: int | None = None,
                artifact: str | None = None, summary: str = "",
                error: str = "", duplicate_of: int | None = None,
                budget_state: dict | None = None) -> None:
        """单次留痕:跳过/降级/拒绝/重复等不经过 running 阶段的调度尝试。

        budget_state 仅在实例已登记(skipped/degraded 复跑等)时有值。"""
        rec = {"seq": seq, "agent": agent, "task": task, "status": status,
               "request": request, "started_at": _now(), "finished_at": _now(),
               "duration_ms": int((time.time() - t0) * 1000),
               "artifact_path": artifact, "summary": summary, "error": error,
               "status_history": [{"status": status, "ts": _now()}]}
        if duplicate_of is not None:
            rec["duplicate_of"] = duplicate_of
        if budget_state is not None:
            rec["budget_state"] = budget_state
        self._records.append(rec)
        self._flush()

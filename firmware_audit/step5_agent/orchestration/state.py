"""state——编排共享词汇(ADR-0009 T4):调度状态枚举、状态中文标签、单次执行结果封装。

包内叶子:actions/handoff/dispatch_log/orchestrator 都消费本模块,而它不
import 包内任何兄弟模块——编排层的环由这里切断(orchestrator 装配动作类、
被动作回调,import 方向因此只能单向 orchestrator → actions → handoff → state)。

只放共享词汇:小格式化 helper(_now 等)留在各自消费者旁(spec 决策),
state 不做杂物抽屉。STATUS_LABEL 转正为公开名(原 orchestrator._STATUS_LABEL,
是测试唯一还在 import 的私有符号)。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# ---- 状态枚举(取代散落字符串;值即落盘值,与 dispatch_log/result.json 一致) ----

class DispatchStatus:
    """调度/实例状态全集(值域闭合,守卫测试断言)。"""
    RUNNING = "running"
    SUCCESS = "success"
    SKIPPED = "skipped"        # .json 工件已存在,跳过
    DEGRADED = "degraded"      # 仅 .md 降级工件存在(解析失败),复跑默认重跑
    FAILED = "failed"
    INTERRUPTED = "interrupted"  # 异常向上传播,running 记录回填
    REJECTED = "rejected"      # 顺序门/上限/未知 agent 等前置拒绝
    DUPLICATE = "duplicate"    # 类型+任务唯一性拒绝

    ALL = (RUNNING, SUCCESS, SKIPPED, DEGRADED, FAILED, INTERRUPTED, REJECTED, DUPLICATE)
    DONE_OK = (SUCCESS, SKIPPED)          # 视为完成的成功态
    EXECUTED = (SUCCESS, SKIPPED, DEGRADED, FAILED)  # 实际执行的调度(占 seq)


STATUS_LABEL = {DispatchStatus.SUCCESS: "成功",
                DispatchStatus.SKIPPED: "跳过(工件已存在)",
                DispatchStatus.DEGRADED: "降级(仅 .md 工件,复跑)",
                DispatchStatus.FAILED: "失败",
                DispatchStatus.RUNNING: "运行中",
                DispatchStatus.INTERRUPTED: "中断",
                DispatchStatus.DUPLICATE: "重复(已拒绝)",
                DispatchStatus.REJECTED: "拒绝"}


@dataclass
class SubAgentResult:
    """单个子 Agent 执行的结果封装:状态/输出/错误/请求/统计,供协调器判断与传递。"""

    seq: int
    agent_name: str
    status: str = DispatchStatus.RUNNING   # DispatchStatus 值域
    artifact_path: Path | None = None
    summary: str = ""
    findings: list = field(default_factory=list)
    error: str = ""
    request: dict = field(default_factory=dict)      # dispatch_agent 请求参数
    usage: dict = field(default_factory=dict)
    duration_ms: int = 0
    steps: int = 0
    tool_calls: list = field(default_factory=list)
    # Task6 动态分配:预算耗尽标记(steps==max_iters 或 react 强制收尾未完成)
    budget_exhausted: bool = False
    # Task6 重合检测:该实例 findings 与既有聚合(title/file 归一化)的重复比例
    overlap_ratio: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status in DispatchStatus.DONE_OK and not self.error

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "agent": self.agent_name,
            "task": self.request.get("task", ""),
            "status": self.status,
            "artifact_path": str(self.artifact_path) if self.artifact_path else None,
            "summary": self.summary,
            "findings": self.findings,
            "error": self.error,
            "request": self.request,
            "usage": self.usage,
            "duration_ms": self.duration_ms,
            "steps": self.steps,
            "budget_exhausted": self.budget_exhausted,
            "overlap_ratio": self.overlap_ratio,
        }


__all__ = ["DispatchStatus", "STATUS_LABEL", "SubAgentResult"]

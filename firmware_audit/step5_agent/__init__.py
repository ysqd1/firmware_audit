"""Step5 Agent 层:Host 控制的逐 Candidate 调查生命周期(ADR-0012,票 14 切换)。

架构见 docs/adr/0012 与 step5_agent/host/;旧 LLM orchestration 已随公开
切换删除,不保留双模式或旧行为开关。

对外入口:
    from firmware_audit.step5_agent import step5_run   # 或 run_step5.step5_run
"""
from .run_step5 import step5_run

__all__ = ["step5_run"]


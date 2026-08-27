"""Step5 Agent 层:三 Agent(recon/analysis/verification)串行 ReAct。

架构见 important/agents.md 与 important/requirements.md。

对外入口:
    from firmware_audit.step5_agent import step5_run   # 或 run_step5.step5_run
"""
from .run_step5 import step5_run

__all__ = ["step5_run"]


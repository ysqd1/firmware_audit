"""ADR-0012 Host 控制层。

当前 expand 阶段只暴露逐步 Agent Session 协议；调查生命周期、工具执行与
持久化会由后续工单继续内聚在本包，公开 Step5 入口暂不切换。
"""

from .session import (
    ActionProposal,
    AgentSession,
    FinalProposal,
    ProposalError,
    ValidationIssue,
    parse_proposal,
    protocol_instruction,
)

__all__ = [
    "ActionProposal",
    "AgentSession",
    "FinalProposal",
    "ProposalError",
    "ValidationIssue",
    "parse_proposal",
    "protocol_instruction",
]

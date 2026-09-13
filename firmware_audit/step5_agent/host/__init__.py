"""ADR-0012 Host 控制层。

当前 expand 阶段暴露逐步 Agent Session 协议与单 Candidate Analysis tracer；
完整持久化、队列和复核会由后续工单继续内聚在本包，公开 Step5 入口暂不切换。
"""

from .analysis import (
    Candidate,
    HostAnalysisTracer,
    Investigation,
    ProposalRejectedError,
)
from .evidence import EvidenceReference
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
    "Candidate",
    "EvidenceReference",
    "FinalProposal",
    "HostAnalysisTracer",
    "Investigation",
    "ProposalError",
    "ProposalRejectedError",
    "ValidationIssue",
    "parse_proposal",
    "protocol_instruction",
]

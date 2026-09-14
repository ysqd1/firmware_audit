"""ADR-0012 Host 控制层。

当前 expand 阶段暴露逐步 Agent Session 协议、单 Candidate Analysis tracer
与 Recon→Candidate Store 入口;去重队列、Claim/复核与公开入口切换由后续
工单继续内聚在本包。
"""

from .analysis import (
    Candidate,
    HostAnalysisTracer,
    Investigation,
    ProposalRejectedError,
)
from .evidence import EvidenceReference
from .recon import (
    CandidateProposal,
    HostReconRunner,
    ReconRunResult,
    build_site_overview,
    input_failure_reason,
)
from .session import (
    ActionProposal,
    AgentSession,
    FinalProposal,
    ProposalError,
    ValidationIssue,
    parse_proposal,
    protocol_instruction,
    revalidate_proposal,
)

__all__ = [
    "ActionProposal",
    "AgentSession",
    "Candidate",
    "CandidateProposal",
    "EvidenceReference",
    "FinalProposal",
    "HostAnalysisTracer",
    "HostReconRunner",
    "Investigation",
    "ProposalError",
    "ProposalRejectedError",
    "ReconRunResult",
    "ValidationIssue",
    "build_site_overview",
    "input_failure_reason",
    "parse_proposal",
    "protocol_instruction",
    "revalidate_proposal",
]

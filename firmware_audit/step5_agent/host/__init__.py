"""ADR-0012 Host 控制层。

当前 expand 阶段暴露逐步 Agent Session 协议、单 Candidate Analysis tracer、
Recon→Candidate Store 入口与 Candidate 去重/评分/双队列;Claim/复核与公开
入口切换由后续工单继续内聚在本包。
"""

from .analysis import (
    Candidate,
    HostAnalysisTracer,
    Investigation,
    ProposalRejectedError,
)
from .candidates import (
    CANDIDATE_STORE_SCHEMA_VERSION,
    CLAIM_PROFILES,
    CandidateIntakeError,
    CandidateStore,
    ComparisonOutcome,
    IntakeCandidate,
    PriorityScorer,
    Selection,
    SemanticComparator,
    coverage_fingerprint,
    normalize_intake,
    normalize_target_path,
    select_for_processing,
    signal_fingerprint,
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
    "CANDIDATE_STORE_SCHEMA_VERSION",
    "CLAIM_PROFILES",
    "Candidate",
    "CandidateIntakeError",
    "CandidateProposal",
    "CandidateStore",
    "ComparisonOutcome",
    "EvidenceReference",
    "FinalProposal",
    "HostAnalysisTracer",
    "HostReconRunner",
    "IntakeCandidate",
    "Investigation",
    "PriorityScorer",
    "ProposalError",
    "ProposalRejectedError",
    "ReconRunResult",
    "Selection",
    "SemanticComparator",
    "ValidationIssue",
    "build_site_overview",
    "coverage_fingerprint",
    "input_failure_reason",
    "normalize_intake",
    "normalize_target_path",
    "parse_proposal",
    "protocol_instruction",
    "revalidate_proposal",
    "select_for_processing",
    "signal_fingerprint",
]

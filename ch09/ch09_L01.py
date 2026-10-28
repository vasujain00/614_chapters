from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class DecisionEnvelope:
    # Identity (4)
    trace_id:              str
    agent_id:              str
    step_number:           int
    session_id:            str
    # Decision (4)
    chosen_route:          str
    rejected_alternatives: Dict[str, float]   # route -> score
    reasoning_summary:     str                # <= 200 chars, no raw content
    confidence:            float              # calibrated P(chosen is correct)
    # Versions (3)
    prompt_version_hash:   str
    content_hash:          str
    model_version:         str
    # Cost (5)
    latency_ms:            int
    tokens_in:             int
    tokens_out:            int
    estimated_cost_usd:    float
    status:                str                # ok | flagged | blocked
    # Source (3)
    retrieval_sources:     List[str]          = field(default_factory=list)  # id@version
    cache_ages_s:          Dict[str, int]     = field(default_factory=dict)
    freshness_flags:       List[str]          = field(default_factory=list)

# Full implementation: github.com/mastering-agentic-security/ch9

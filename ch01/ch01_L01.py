from dataclasses import dataclass, field
from typing import List
import datetime

@dataclass
class AgentDecisionEnvelope:
    trace_id: str          # cross-system correlation
    agent_id: str
    step: int
    chosen_route: str
    rejected_routes: List[dict]  # with reasoning scores
    prompt_version: str
    content_hash: str       # NEVER raw PII
    latency_ms: int
    tokens_consumed: int
    trust_ring: int          # 0-3 at time of decision
    injection_score: float   # from input boundary
    status: str              # ok | flagged | blocked
    timestamp: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))

    # Full implementation: github.com/mastering-agentic-security/ch1

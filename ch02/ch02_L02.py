from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable
from collections import defaultdict, deque
from enum import IntEnum
import time

class Ring(IntEnum):
    RING_0_HUMAN_ONLY = 0
    RING_1_TRUSTED    = 1
    RING_2_STANDARD   = 2
    RING_3_SANDBOXED  = 3

@dataclass
class ToolPolicy:
    tool_name: str
    allowed_rings: List[Ring]
    param_constraints: Dict[str, Optional[List[Any]]] = field(default_factory=dict)
    rate_limit_per_minute: int = 60

class AgentGateway:
    """LLMs never invoke tools directly. Every call passes here first.
    The five checks run in the order of Table 2.1 and the first failure wins."""

    def __init__(self, policies: Dict[str, ToolPolicy],
                 verify_identity: Callable[[str, bytes], Optional[Ring]],
                 trust_oracle: Callable[[str], float],
                 audit: Callable[[str, str, str], None]):
        self.policies = policies
        self.verify_identity = verify_identity   # SVID / OAuth 2.1 verifier -> ring or None
        self.trust_oracle = trust_oracle         # trust scoring engine
        self.audit = audit
        self._calls: Dict[tuple, deque] = defaultdict(deque)  # (agent, tool) -> timestamps

    def check(self, agent_id: str, credential: bytes,
              tool_name: str, params: Dict[str, Any]) -> bool:
        # 1. Identity: who is calling, cryptographically. The caller's ring is
        #    DERIVED from the verified identity, never supplied by the caller.
        agent_ring = self.verify_identity(agent_id, credential)
        if agent_ring is None:
            return self._deny(agent_id, tool_name, "identity")

        # 2. Authorization: does this ring permit this tool at all?
        policy = self.policies.get(tool_name)
        if not policy:
            return self._deny(agent_id, tool_name, "unknown_tool")
        if agent_ring not in policy.allowed_rings:
            return self._deny(agent_id, tool_name, "auth")

        # 3. Parameters: values inside the per-ring allowlist
        for param, vals in policy.param_constraints.items():
            if vals and params.get(param) not in vals:
                return self._deny(agent_id, tool_name, f"param:{param}")

        # 4. Trust score: has the agent been demoted since its ring was issued?
        if self.trust_oracle(agent_id) < 0.40:
            return self._deny(agent_id, tool_name, "trust")

        # 5. Rate limit: token bucket per agent per tool
        if not self._rate_ok(agent_id, tool_name, policy.rate_limit_per_minute):
            return self._deny(agent_id, tool_name, "rate_limit")

        self.audit(agent_id, tool_name, "allow")
        return True  # all five checks passed

    def _rate_ok(self, agent_id: str, tool_name: str, per_minute: int) -> bool:
        now = time.monotonic()
        q = self._calls[(agent_id, tool_name)]
        while q and now - q[0] > 60.0:
            q.popleft()
        if len(q) >= per_minute:
            return False
        q.append(now)
        return True

    def _deny(self, agent_id: str, tool_name: str, reason: str) -> bool:
        self.audit(agent_id, tool_name, f"deny:{reason}")
        return False

# Policy preventing the ad tech incident:
# budget_policy = ToolPolicy("budget_api", [Ring.RING_2_STANDARD],
#     param_constraints={"mode": ["read"]})  # "write" is blocked
# Full implementation: github.com/mastering-agentic-security/ch2

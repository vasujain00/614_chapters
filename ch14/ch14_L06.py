from dataclasses import dataclass, replace
from typing import List, Optional, Callable, Dict
from enum import IntEnum


class BlastRadiusLevel(IntEnum):     # ordered so "tighter" is a smaller value
    LOCAL = 0
    SESSION = 1
    CROSS_SESSION = 2
    EXTERNAL = 3


@dataclass
class AgentConstraints:
    agent_id: str
    max_blast_radius: BlastRadiusLevel = BlastRadiusLevel.SESSION
    max_tools_per_session: int = 20
    memory_write_requires_approval: bool = False
    external_call_requires_approval: bool = True
    ring_level: int = 2              # Chapter 2 rings: 0 human-only ... 3 sandbox


class AdaptiveConstraintManager:
    """Tightens every dimension of AgentConstraints in proportion to a measured
    capability_delta (see the proxy definition in the prose: composite of
    benchmark delta, tool-count delta, and autonomy-level step, normalised to
    the previous model; 1.0 = composite doubled)."""

    TIGHTEN_ABOVE = 0.3

    def __init__(self, security_budget: "SecurityBudget"):
        self.budget = security_budget
        self.constraints: Dict[str, AgentConstraints] = {}
        self.model_version: Optional[str] = None
        self.on_tighten_callbacks: List[Callable[[str, AgentConstraints, AgentConstraints], None]] = []

    def register_agent(self, constraints: AgentConstraints):
        self.constraints[constraints.agent_id] = constraints

    def on_model_upgrade(self, new_version: str, capability_delta: float) -> dict:
        old_version, self.model_version = self.model_version, new_version
        if capability_delta <= self.TIGHTEN_ABOVE:
            return {"action": "no_change", "old_model": old_version,
                    "new_model": new_version, "capability_delta": capability_delta}
        changed = self._tighten_all_constraints(capability_delta)
        for check_id, base in (("injection_detector", 0.5), ("blast_radius_checker", 0.6)):
            if check_id in self.budget.checks:          # only known checks; else no-op is a bug
                self.budget.update_threat_weight(check_id, min(1.0, base + capability_delta * 0.4))
        return {"action": "constraints_tightened" if changed else "no_change",
                "old_model": old_version, "new_model": new_version,
                "capability_delta": capability_delta, "agents_updated": changed}

    def _tighten_all_constraints(self, delta: float) -> int:
        changed = 0
        for agent_id, c in list(self.constraints.items()):
            before = replace(c)
            # Tool budget: shrink by 20% of delta, rounded UP so a delta of 0.6
            # on 20 tools removes 3 (15%) not 2 (10%); floor at 5.
            reduction = -(-int(c.max_tools_per_session * delta * 0.2 * 100) // 100)
            c.max_tools_per_session = max(5, c.max_tools_per_session - max(1, reduction))
            # Blast radius: step one level tighter per 0.5 of delta.
            steps = int(delta // 0.5)
            c.max_blast_radius = BlastRadiusLevel(max(0, c.max_blast_radius - steps))
            # Ring: a materially more capable model drops one ring of privilege
            # (towards the sandbox) until it re-earns it via Chapter 8's ladder.
            if delta > 0.5 and c.ring_level < 3:
                c.ring_level += 1
            if delta > 0.5:
                c.memory_write_requires_approval = True
            if delta > 0.3:
                c.external_call_requires_approval = True
            if c != before:
                changed += 1
                for cb in self.on_tighten_callbacks:
                    cb(agent_id, before, c)
        return changed

    def on_threat_intelligence_update(self, threat_id: str, severity: float):
        """severity: 0.0-1.0. Raises KeyError for an unregistered check so a
        misnamed feed entry is noticed rather than silently ignored."""
        self.budget.update_threat_weight(threat_id, severity)

# Expected (delta 0.6 on an agent with 20 tools, CROSS_SESSION, ring 1):
#   max_tools_per_session 20 -> 17 (15%), max_blast_radius -> SESSION, ring_level -> 2,
#   memory_write_requires_approval -> True. on_model_upgrade(..., 0.1) -> "no_change".

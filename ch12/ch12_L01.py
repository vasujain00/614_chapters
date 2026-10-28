# Full implementation: github.com/mastering-agentic-security/ch12
import asyncio, time
from dataclasses import dataclass, field
from typing import Set, Dict, Optional

@dataclass
class AgentNode:
    agent_id: str
    downstream: Set[str]    = field(default_factory=set)
    memory_stores: Set[str] = field(default_factory=set)
    fallback_id: Optional[str] = None
    budget_pool: Optional[str] = None

def transitive_downstream(root: str, registry: Dict[str, AgentNode]) -> Set[str]:
    """Blast radius is the whole reachable graph, not the first hop."""
    seen, stack = set(), [root]
    while stack:
        a = stack.pop()
        for d in registry[a].downstream:
            if d not in seen:
                seen.add(d); stack.append(d)
    return seen

async def _step(name: str, coro, audit: list, timeout_s: float):
    t0 = time.monotonic()
    try:
        await asyncio.wait_for(coro, timeout=timeout_s)
        audit.append({"step": name, "ok": True, "ms": int((time.monotonic()-t0)*1000)})
    except Exception as exc:                                   # noqa: BLE001
        audit.append({"step": name, "ok": False, "err": repr(exc),
                      "ms": int((time.monotonic()-t0)*1000)})

async def containment_cascade(node: AgentNode, registry: Dict[str, AgentNode],
                              budget_s: float = 60.0) -> list:
    """Seven steps, 60-second budget, in the order of Chapter 7's table. Step 1 first;
    step 2 before step 3; budget frozen (6) before token revocation (5) is
    relied on; everything else concurrent. One hung call must never stall the
    rest, so each step has its own timeout and the gather never raises.
    Every step emits an audit record so Chapter 9's envelope store can
    reconstruct the cascade afterwards."""
    audit: list = []
    victims = transitive_downstream(node.agent_id, registry)

    # Step 1 -- isolation gates everything else
    await _step("1_isolate", isolate_agent(node.agent_id), audit, 5)

    # Step 2 -- memory must be frozen BEFORE dependents are told (Chapter 7 ordering constraint)
    await _step("2_quarantine_memory", quarantine_memory(node.memory_stores), audit, 15)

    # Steps 3, 4, 6 -- independent, concurrent, individually time-boxed
    await asyncio.gather(
        _step("3_defensive_posture", defensive_posture(victims),           audit, 10),
        _step("4_notify_upstream",   notify_upstream(node.agent_id),       audit, 10),
        _step("6_freeze_budget",     freeze_budget(node.budget_pool),      audit, 10),
        return_exceptions=True,
    )
    # Steps 5, 7 -- token revocation is relied on only after the budget is frozen
    await asyncio.gather(
        _step("5_revoke_tokens",     revoke_tokens(node.agent_id),         audit, 10),
        _step("7_network_contain",   sever_mcp_channels(node.agent_id),    audit, 10),
        return_exceptions=True,
    )

    # Not part of the seven-step cascade: recovery begins by activating the fallback
    if node.fallback_id:
        await _step("post_activate_fallback", activate_fallback(node.fallback_id), audit, 10)

    total_ms = sum(a["ms"] for a in audit)
    audit.append({"step": "cascade_complete", "ok": all(a["ok"] for a in audit),
                  "ms": total_ms, "within_budget": total_ms <= budget_s * 1000})
    await envelope_store.append_many(node.agent_id, audit)    # Chapter 9 store
    return audit

from hashlib import sha256

def decide_bid(request, agent, boundary, audit):
    scored = agent.score_routes(request)              # [(route, score), ...]
    chosen, *rejected = sorted(scored, key=lambda r: -r[1])
    env = AgentDecisionEnvelope(
        trace_id=request.trace_id, agent_id=agent.id, step=agent.step,
        chosen_route=chosen[0],
        rejected_routes=[{"route": r, "score": s} for r, s in rejected],
        prompt_version=agent.prompt_version,
        content_hash=sha256(request.raw).hexdigest(),
        latency_ms=agent.last_latency_ms, tokens_consumed=agent.last_tokens,
        trust_ring=agent.ring, injection_score=boundary.score(request),
        status="flagged" if boundary.score(request) > 0.7 else "ok",
    )
    audit.emit(env)                                   # before the action, never after
    return chosen[0]

# Emitted envelope for the Day 2, 11:15 bid request:
# {"trace_id": "b7e2...", "agent_id": "bidder-prod-3", "step": 41882,
#  "chosen_route": "set_multiplier(100.0)",
#  "rejected_routes": [{"route": "set_multiplier(1.2)", "score": 0.31},
#                      {"route": "hold", "score": 0.08}],
#  "trust_ring": 2, "injection_score": 0.91, "status": "flagged", ...}

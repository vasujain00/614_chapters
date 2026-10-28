from langgraph.types import interrupt

def blocking_gate(state: AgentState) -> AgentState:
    decision = interrupt({"review": build_review_context(state["action"], gateway, envelopes, baseline)})
    if decision["approved"] and decision["action_hash"] == gateway.hash_params(state["action"]):
        return {**state, "authorized": True}
    return {**state, "authorized": False, "reason": decision.get("reason", "denied")}

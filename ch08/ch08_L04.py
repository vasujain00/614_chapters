def build_review_context(action, gateway, envelopes, baseline) -> dict:
    """Everything a reviewer sees comes from systems the agent cannot write."""
    env = envelopes.get(action.trace_id)                 # as emitted, not as summarised
    return {
        "action_hash":  gateway.hash_params(action),      # approval binds to this
        "tool_call":    gateway.describe(action),          # name + exact parameters
        "diff":         gateway.preview_diff(action),      # before/after for any write
        "alternatives": env.rejected_routes,               # with the agent's scores
        "confidence":   env.confidence,
        "calibration":  baseline.calibration_for(action.agent_id, env.confidence),
        "anomaly":      baseline.anomaly_score(env),       # independent of the agent
        "history":      envelopes.similar(action, n=3),
        "agent_claim":  action.summary,                    # shown last, labelled as a claim
    }

def execute_if_approved(action, approval, gateway):
    if approval.action_hash != gateway.hash_params(action):
        raise PermissionError("approved parameters differ from execution parameters")
    approval.verify_signature()                            # approver authenticated, decision signed
    return gateway.call(action)

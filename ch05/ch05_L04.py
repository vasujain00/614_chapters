# Full implementation: github.com/mastering-agentic-security/ch5
memory_config = {
  "write_validation": {
    "instruction_detection": True,      # block instruction-bearing content
    "rate_limit_per_agent": 50,         # writes per hour per agent
    "cross_boundary_requires_authz": True  # short-term -> long-term needs gate
  },
  "provenance": {
    "required_fields": ["source","trust_level","written_at","agent_id"],
    "audit_log": "immutable",           # write-once, no agent can modify
    "ring_mapping": {"ring0": "full", "ring3": "isolated_partition"}
  },
  "read_filtering": {
    "check_trust_level_at_read": True,  # re-verify before context assembly
    "dogwood_temporal_gate": True       # apply Dogwood formerly/count_within
  },
  "temporal": {
    "ttl_by_trust": {"ring0": "30d","ring1": "7d","ring2": "24h","ring3": "1h"},
    "freshness_check_required": ["financial", "regulatory", "access_control"]
  }
}

# Mastering Agentic AI Security -- Code Listings

Companion code for *Mastering Agentic AI Security* (Packt, 2026). One directory per chapter; one file per listing, numbered in the order the listings appear in the chapter (`chNN_LKK`). Non-Python listings keep their own extension so the policy language, shell command or configuration is clear at a glance.

| Extension  | What it is |
|------------|------------|
| `.py`      | Python 3.11+ |
| `.dogwood` | Amazon Bedrock AgentCore temporal-policy rules (Chapter 4 defines the grammar in `ch04/ch04_L01.dogwood`) |
| `.cedar`   | Cedar authorization policy |
| `.colang`  | NVIDIA NeMo Guardrails Colang 2.0 flow |
| `.yaml`    | OpenTelemetry Collector / threshold configuration |
| `.sql`     | PostgreSQL |
| `.sh`      | Shell commands (garak, spire-server) |
| `.json`    | Example record |

## Running the code

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest tests/            # behavioural checks on the self-contained listings
```

Three kinds of listing appear in the book, and the distinction matters before you run anything:

1. **Self-contained.** Runs as-is with the standard library (plus `numpy` where noted). These are covered by `tests/test_listings.py`: the delegation token chain, the signed envelope, the memory firewall gate, the hash-pinning registry, the canonical-form normaliser, the PSI computation, the compliance hash chain, the trust ladder, the containment graph, and the two-agent regression harness.
2. **Framework-bound.** Correct against a pinned library version but needs that library and, usually, credentials or a running service: PyRIT (`ch10_L01`), Garak (`ch10_L02`), LangGraph (`ch06_L06`, `ch08_L01`, `ch08_L05`), Bedrock `ApplyGuardrail` (`ch06_L04`), Guardrails AI (`ch06_L05`), OpenTelemetry (`ch09_L03`, `ch09_L05`), sentence-transformers (`ch11_L04`).
3. **Illustrative skeletons.** Show the shape of a control and call into components the chapter describes in prose (`call_model`, `tool_registry`, `dogwood.evaluate_request`, the cascade primitives in `ch12_L01`). They parse and import cleanly; the undefined names are the integration points you supply. Each is marked `# Full implementation: github.com/mastering-agentic-security/chN` in the book.

Every Python file in this bundle parses, imports under a stub harness, and has no unused imports or undefined names other than the deliberate integration points listed above.

## Index

### Chapter 1 -- Why Agents Are Different
| File | Contents |
|------|----------|
| `ch01_L01.py` | `AgentDecisionEnvelope` -- the audit-layer envelope dataclass |
| `ch01_L02.py` | `decide_bid()` -- emitting a populated envelope at a decision point, with the Day 2 incident envelope |
| `ch01_L03.py` | `TrustAssumption` and the priority sort for the two-hour threat-model exercise |

### Chapter 2 -- Trust Boundaries and Least Privilege
| File | Contents |
|------|----------|
| `ch02_L01.cedar` | Cedar policy: bidding agents may read the budget API and never write it |
| `ch02_L02.py` | `AgentGateway` -- the five-check gateway sequence of Table 2.1 |
| `ch02_L03.py` | `AlgorithmicCircuitBreaker` -- ALLOW / PAUSE / HALT on token ratio, denials and anomaly score |
| `ch02_L04.py` | Checklist 2.1: budget security validation procedure |

### Chapter 3 -- Prompt Injection
| File | Contents |
|------|----------|
| `ch03_L01.py` | Dual-LLM pattern: `ToolGateway`, `controller_sanitize()`, `DualLLMController` |
| `ch03_L02.py` | `spotlight()` -- datamarking and delimiting untrusted content |
| `ch03_L03.py` | `canary_check()` -- runnable canary comparison |

### Chapter 4 -- Tool Use and Action Safety
| File | Contents |
|------|----------|
| `ch04_L01.dogwood` | Dogwood rule grammar (informal) |
| `ch04_L02.dogwood` | Budget cap: `sum_within` |
| `ch04_L03.dogwood` | Rate limit and burst detection: `count_within` |
| `ch04_L04.dogwood` | Cross-customer access and `bind` |
| `ch04_L05.dogwood` | Response-time exfiltration check: `formerly` |
| `ch04_L06.py` | `validate_tool_call()` -- pre-execution validation |
| `ch04_L07.py` | `verify_tool_response()` -- post-execution verification |
| `ch04_L08.py` | `SagaOrchestrator` with `StepType`, retry and pivot handling |
| `ch04_L09.py` | Integrated `ToolGateway` -- all four verification stages |
| `ch04_L10.py` | `ToolRegistry.verify_hash()` -- description hash pinning |

### Chapter 5 -- Memory and Context Security
| File | Contents |
|------|----------|
| `ch05_L01.py` | `MemoryFirewall` with the deterministic `_is_instruction_bearing()` gate, `MemoryEntry`, `EXPIRY_BY_TRUST` |
| `ch05_L02.py` | `filter_reads()` -- read-time filter and dormant-entry (sleeper) monitor |
| `ch05_L03.dogwood` | Memory write-requires-approval and read-requires-trusted-source policies |
| `ch05_L04.py` | `memory_config` -- four-layer defence configuration |
| `ch05_L05.sql` | Memory quarantine as a single tagged update |

### Chapter 6 -- Guardrail Architecture
| File | Contents |
|------|----------|
| `ch06_L01.py` | `DualLLMController` -- symbolic references and typed fields only |
| `ch06_L02.py` | `SemanticFirewall` with context-dependent thresholds |
| `ch06_L03.colang` | NeMo Colang 2.0 retrieval rail |
| `ch06_L04.py` | Bedrock `ApplyGuardrail` on a retrieval or output node |
| `ch06_L05.py` | Guardrails AI `Guard` with PII and provenance validators |
| `ch06_L06.py` | LangGraph guardrail topology (`ring_gate`, `hitl_checkpoint`) |

### Chapter 7 -- Agent-to-Agent Security
| File | Contents |
|------|----------|
| `ch07_L01.py` | `DelegationToken` -- HMAC-signed, attenuating, chain-verified |
| `ch07_L02.py` | `AgentCircuitBreaker` with the ordered containment cascade |
| `ch07_L03.sh` | Minimal SPIRE workload registration |
| `ch07_L04.py` | Signed envelope `seal()` / `verify()` with nonce and timestamp window |

### Chapter 8 -- Human-in-the-Loop Security Architecture
| File | Contents |
|------|----------|
| `ch08_L01.py` | `blocking_gate()` -- Pattern 1 as a LangGraph interrupt |
| `ch08_L02.py` | `async_approval_gate()` -- Pattern 2 with real escalation |
| `ch08_L03.py` | Trust ladder: `TrustState`, `PROMO_CRITERIA`, `promote()`, `demote()` |
| `ch08_L04.py` | `build_review_context()` and hash-bound `execute_if_approved()` |
| `ch08_L05.py` | Durable HITL: `approval_node`, `build_graph(AsyncPostgresSaver)`, `sla_sweeper` |
| `ch08_L06.py` | `SagaCompensator` -- continues past a failed compensator and pages on-call |

### Chapter 9 -- Observability for Non-Deterministic Systems
| File | Contents |
|------|----------|
| `ch09_L01.py` | `DecisionEnvelope` -- 19 fields matching Table 9.2 |
| `ch09_L02.py` | `compute_psi()` / `alert_on_drift()` |
| `ch09_L03.py` | OpenTelemetry GenAI span attributes for a routing decision |
| `ch09_L04.yaml` | Collector `tail_sampling` policy that keeps every anomalous trace |
| `ch09_L05.py` | `mcp_call()` -- traceparent propagation in MCP `_meta` |

### Chapter 10 -- Red Teaming and Continuous Testing
| File | Contents |
|------|----------|
| `ch10_L01.py` | PyRIT `CrescendoAttack` against a deployed agent (attack-executor API, pyrit >= 0.9) |
| `ch10_L02.sh` | Garak nightly scan and CI gate |
| `ch10_L03.py` | `RegressionCase` and the ratchet (`RatchetViolation`) |
| `ch10_L04.py` | Two-agent system harness reproducing the opening incident as a test |
| `ch10_L05.py` | `compute_evasion_trend()` |

### Chapter 11 -- Output Validation and Evasion-Resistant Detection
| File | Contents |
|------|----------|
| `ch11_L01.py` | `canonical_form()` -- NFKC, zero-width stripping, UTS #39 confusables |
| `ch11_L02.yaml` | Dynamic similarity thresholds by role and purpose |
| `ch11_L03.py` | `inject_and_verify()` -- canaries alongside, never instead of, the user query |
| `ch11_L04.py` | Claim extraction and source grounding (bi-encoder + cross-encoder) |
| `ch11_L05.py` | `rewrite_links()` -- output channel sanitisation |
| `ch11_L06.py` | `run_output_pipeline()` with HOLD / DEGRADE / PASS failure modes |

### Chapter 12 -- Incident Response for Compromised Agents
| File | Contents |
|------|----------|
| `ch12_L01.py` | `containment_cascade()` -- seven steps, ordering constraints, 60-second budget, audit records |
| `ch12_L02.json` | Minimal envelope record for forensics |
| `ch12_L03.sql` | Recursive provenance-chain reconstruction |
| `ch12_L04.py` | Recovery state machine with REMEDIATED -> RING3 entry |

### Chapter 13 -- Governance, Compliance, and the Road Ahead
| File | Contents |
|------|----------|
| `ch13_L01.dogwood` | `ApproveSale` must precede `SellShares` |
| `ch13_L02.py` | `ComplianceEnvelope` -- hash over every field, hash chain, `verify()` |

### Chapter 14 -- Next-Generation Threats and Defenses
| File | Contents |
|------|----------|
| `ch14_L01.py` | `WatcherAgent` -- deterministic anomaly scoring that does not absorb gradual poisoning |
| `ch14_L02.py` | `verify_precondition`, path containment, strict `AgentActionOutput` |
| `ch14_L03.py` | `SleeperProber` |
| `ch14_L04.py` | `latency_budget` -- a real deadline via a worker pool |
| `ch14_L05.py` | `SecurityBudget` -- exact knapsack with mandatory controls pinned |
| `ch14_L06.py` | `AdaptiveConstraintManager` |

## Conventions

- Security checks raise exceptions (`DelegationError`, `PermissionError`, `MemoryWriteBlocked`, `HoldForReview`); none use `assert`, which `python -O` strips.
- Timestamps are timezone-aware (`datetime.now(timezone.utc)`); `utcnow()` is not used.
- Hashes are over a canonical JSON serialisation of every field, never a subset. Signatures in the listings are HMAC-SHA256 for brevity; production code should use Ed25519 or a KMS-held key, as the chapters note.
- Model names in the listings (`gpt-4o`, `all-MiniLM-L6-v2`) are the versions under test when the book was written; substitute current ones.

## Licence

[AUTHOR: confirm with Packt; MIT is Packt's default for companion repositories.] See the book for the discussion that accompanies each listing; the code is not a substitute for it.

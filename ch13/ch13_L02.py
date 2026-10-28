# Full implementation: github.com/mastering-agentic-security/ch13
from dataclasses import dataclass, field, asdict
from typing import List, Optional
import hashlib, json
from datetime import datetime, timezone

@dataclass
class ComplianceEnvelope:
    trace_id: str               # W3C traceparent-compatible
    agent_id: str               # verified identity (Ch. 7 SPIFFE/Entra)
    model_version: str          # model + prompt version hash
    chosen_route: str           # what the agent decided to do
    rejected_routes: List[dict] # alternatives + probability scores
    data_sensitivity: str       # classification, not raw content
    source_doc_hashes: List[str]  # SHA-256, not raw documents
    dogwood_policy_id: str      # which temporal policy governed this
    dogwood_verdict: str        # ALLOW / DENY + temporal condition met
    human_oversight_flag: bool  # was human review required/obtained
    ring_at_decision: int       # trust ring 0-3 (Ch. 2 privilege model)
    # Fields auditors actually ask for:
    lawful_basis: str           # GDPR Art. 6 basis, e.g. "contract", "legitimate_interest"
    retention_class: str        # maps to the retention schedule, e.g. "7y_financial"
    fria_id: Optional[str] = None  # AI Act Art. 27 fundamental-rights impact assessment
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())
    prev_envelope_hash: str = ""  # hash chain: tamper-evident, append-only
    envelope_hash: str = ""       # set by seal(); sign externally (KMS/HSM)

    def _canonical(self) -> bytes:
        """Every field except the hash itself, in a deterministic encoding.
        Hashing only trace_id + route + timestamp would let rejected_routes,
        the Dogwood verdict, the oversight flag or the ring be rewritten
        after the fact without invalidating the proof."""
        body = asdict(self)
        body.pop("envelope_hash")
        return json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")

    def seal(self, prev: Optional["ComplianceEnvelope"] = None) -> "ComplianceEnvelope":
        self.prev_envelope_hash = prev.envelope_hash if prev else "GENESIS"
        self.envelope_hash = hashlib.sha256(self._canonical()).hexdigest()
        return self

    def verify(self, prev: Optional["ComplianceEnvelope"] = None) -> bool:
        if hashlib.sha256(self._canonical()).hexdigest() != self.envelope_hash:
            return False                                  # record was altered
        expected_prev = prev.envelope_hash if prev else "GENESIS"
        return self.prev_envelope_hash == expected_prev   # chain intact

# Periodically anchor the latest envelope_hash in a signed, externally held
# location (a KMS-signed digest, a WORM bucket, or a transparency log). The
# chain proves nothing was changed in the middle; the anchor proves the end
# was not rewritten wholesale.

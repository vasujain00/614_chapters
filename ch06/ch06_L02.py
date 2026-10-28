import numpy as np

def cosine_similarity(a, b):
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9))

class SemanticFirewall:
    """Flags content whose embedding sits close to the instruction centroid.

    instr_sim is a SIMILARITY: higher means more instruction-like. Content is
    flagged when instr_sim EXCEEDS the threshold, so a high-risk context must
    use a LOWER threshold (more sensitive), not a higher one."""

    DEFAULT_THRESHOLDS = {
        "high_risk": 0.60,   # payments, PII, destructive tools: flag early
        "medium_risk": 0.72,
        "low_risk":  0.85,   # read-only summarisation: tolerate more
    }
    ALIGNMENT_FLOOR = 0.25   # retrieved chunk must relate to the live query

    def __init__(self, encoder, instruction_examples: list[str],
                 thresholds: dict | None = None):
        self.encoder = encoder
        # Centroid of known injection / instruction phrasings, built offline
        # from your own red-team corpus and refreshed on a schedule.
        vecs = np.stack([encoder.encode(t) for t in instruction_examples])
        self.instruction_centroid = vecs.mean(axis=0)
        self.thresholds = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}
        self.query_embedding = None

    def set_query(self, query_text: str):
        """Call once per request so retrieved chunks can be checked for relevance."""
        self.query_embedding = self.encoder.encode(query_text)

    def classify(self, content: str, operation_context: str = "medium_risk"):
        if operation_context not in self.thresholds:
            # Unknown context: fail closed to the strictest setting.
            operation_context = "high_risk"
        threshold = self.thresholds[operation_context]
        embedding = self.encoder.encode(content)
        instr_sim = cosine_similarity(embedding, self.instruction_centroid)

        # Cross-layer consistency: a chunk that does not relate to the query
        # was not retrieved for the user; it was retrieved for the attacker.
        if self.query_embedding is not None:
            query_align = cosine_similarity(embedding, self.query_embedding)
            if query_align < self.ALIGNMENT_FLOOR:
                return {"flag": True, "reason": "context_mismatch",
                        "score": instr_sim, "query_align": query_align}

        return {"flag": instr_sim > threshold, "reason": "instruction_like"
                if instr_sim > threshold else None,
                "score": instr_sim, "threshold": threshold}

# Full implementation: github.com/mastering-agentic-security/ch6

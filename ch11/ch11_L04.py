# Full implementation: github.com/mastering-agentic-security/ch11
from dataclasses import dataclass
from typing import Optional
import re
from types import SimpleNamespace
from sentence_transformers import SentenceTransformer, CrossEncoder, util

@dataclass
class ClaimGrounding:
    claim_text: str
    grounded: bool
    source_doc_id: Optional[str]
    support_score: float

_CLAIM = re.compile(r"\d|\b(is|are|was|were|has|have|increased|decreased|costs?|rate|percent|%)\b", re.I)

def extract_claims(output: str) -> list[str]:
    """Deterministic first pass: a claim is a sentence that asserts a checkable fact
    (a number, a quantity, a state-of-the-world verb). An LLM pass can add recall
    later; it must never be the only extractor, because it is itself injectable."""
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", output) if s.strip()]
    return [s for s in sentences if _CLAIM.search(s)]

_bi = SentenceTransformer("all-MiniLM-L6-v2")                    # candidate retrieval
_cross = CrossEncoder("cross-encoder/nli-deberta-v3-base")     # entailment re-rank

def find_supporting_passage(claim: str, source_docs: list):
    """Bi-encoder narrows to the top-5 passages; the cross-encoder scores
    entailment. Returns the best passage with .score and .doc_id."""
    passages = [(doc.id, p) for doc in source_docs for p in doc.passages]
    if not passages:
        return SimpleNamespace(doc_id=None, score=0.0)
    sims = util.cos_sim(_bi.encode(claim), _bi.encode([p for _, p in passages]))[0]
    top = sorted(range(len(passages)), key=lambda i: -float(sims[i]))[:5]
    scores = _cross.predict([(passages[i][1], claim) for i in top])  # [contradiction, entailment, neutral]
    best = max(range(len(top)), key=lambda j: scores[j][1])
    return SimpleNamespace(doc_id=passages[top[best]][0], score=float(scores[best][1]))

def ground_output(output: str, source_docs: list) -> dict:
    claims = extract_claims(output)          # LLM-based extraction
    groundings = []
    for claim in claims:
        match = find_supporting_passage(claim, source_docs)
        groundings.append(ClaimGrounding(
            claim_text=claim, grounded=match.score > 0.75,
            source_doc_id=match.doc_id, support_score=match.score
        ))
    grounded = [g for g in groundings if g.grounded]
    score = len(grounded) / max(len(groundings), 1)
    return {'grounding_score': score, 'claims': groundings}

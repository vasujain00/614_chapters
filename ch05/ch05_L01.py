# Full implementation: github.com/mastering-agentic-security/ch5
import re, uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# Deterministic: a fixed signature set, no model in the loop. Tune the set
# from your own incident data; never let an LLM decide what passes the gate.
INSTRUCTION_PATTERNS = re.compile(r"""
    \b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\b |
    \byou\s+are\s+now\b |
    \b(system|developer)\s+prompt\b |
    \bwhen(ever)?\s+(you|the\s+agent)\s+(see|read|encounter)s?\b |
    \balways\s+(respond|reply|answer|send|forward)\b |
    \b(exec|execute|run)\s+(this|the\s+following)\b |
    <\|im_start\|> | \[INST\] | <<SYS>>
""", re.I | re.X)
IMPERATIVE_RATIO_MAX = 0.35   # share of sentences that are bare imperatives

class MemoryWriteBlocked(Exception):
    """Raised for every rejected write; the caller never sees a silent drop."""

# Ring ceiling on how long an entry is believed on the strength of the write alone.
# The effective TTL is min(this, the information type's shelf life); see 5.5.
EXPIRY_BY_TRUST = {0: timedelta(days=30), 1: timedelta(days=7),
                   2: timedelta(hours=24), 3: timedelta(hours=1)}

@dataclass
class MemoryEntry:
    content: str
    source: str
    trust_level: int          # ring of the writer, 0-3
    agent_id: str
    written_at: datetime
    expires_at: datetime
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

class MemoryFirewall:
    def _is_instruction_bearing(self, content: str) -> bool:
        """Deterministic gate. Two checks, both cheap:
        1. Known instruction signatures (regex above).
        2. Imperative density: memory should record facts, not commands.
           A write where >35% of sentences open with an imperative verb is
           rejected regardless of signature matches."""
        if INSTRUCTION_PATTERNS.search(content):
            return True
        sentences = [s for s in re.split(r"[.!?]\s+", content) if s.strip()]
        if not sentences:
            return False
        imperative = sum(1 for s in sentences
                         if re.match(r"^(do|send|write|delete|forward|call|"
                                     r"ignore|respond|reply|execute|run)\b",
                                     s.strip(), re.I))
        return imperative / len(sentences) > IMPERATIVE_RATIO_MAX

    def write(self, content, source, trust_level, agent_id):
        if self._is_instruction_bearing(content):
            self.audit.log("BLOCKED_WRITE", agent_id, source)
            raise MemoryWriteBlocked("Instruction-bearing content rejected")
        if self._rate_exceeded(agent_id, source):
            self.audit.log("RATE_BLOCK", agent_id, source)
            raise MemoryWriteBlocked("Rate limit: writes from source exceeded")
        now = datetime.now(timezone.utc)          # one clock read, reused
        entry = MemoryEntry(
            content=content, source=source, trust_level=trust_level,
            agent_id=agent_id, written_at=now,
            expires_at=now + EXPIRY_BY_TRUST[trust_level],
        )
        self.store.write(entry)                  # commit first ...
        self.audit.append_immutable(entry)       # ... then record what happened
        return entry.id

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Tuple


@dataclass
class EnvelopeEvent:
    agent_id: str
    session_id: str
    tool_name: str
    param_hash: str          # hash of sanitized parameters
    duration_ms: float
    return_size_bytes: int
    requested_memory_write: bool
    timestamp: float = field(default_factory=time.time)


class AgentBaseline:
    """Per-agent rolling baseline. Anomalous events are scored against the
    baseline and then EXCLUDED from it, so gradual poisoning cannot drag the
    baseline along with it (a "boiling frog" attack)."""

    WARMUP = 50               # events before the baseline is trusted
    ABSORB_BELOW = 0.3        # only events scoring under this update the baseline

    def __init__(self, window_size: int = 500):
        self.n_seen = 0
        self.tool_sequences: deque = deque(maxlen=window_size)
        self.bigrams: Dict[Tuple[str, str], int] = defaultdict(int)
        self.duration_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.memory_write_rate: deque = deque(maxlen=window_size)
        self.return_size_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.param_hashes: Dict[str, set] = defaultdict(set)

    def warmed_up(self) -> bool:
        return self.n_seen >= self.WARMUP

    def update(self, event: EnvelopeEvent):
        self.n_seen += 1
        if self.tool_sequences:
            self.bigrams[(self.tool_sequences[-1], event.tool_name)] += 1
        self.tool_sequences.append(event.tool_name)
        self.duration_history[event.tool_name].append(event.duration_ms)
        self.memory_write_rate.append(1 if event.requested_memory_write else 0)
        self.return_size_history[event.tool_name].append(event.return_size_bytes)
        self.param_hashes[event.tool_name].add(event.param_hash)

    # ---- individual signals, each in [0, 1] ----
    def _duration_signal(self, e: EnvelopeEvent) -> float:
        d = list(self.duration_history[e.tool_name])
        if len(d) < 10:
            return 0.0
        mean = sum(d) / len(d)
        std = (sum((x - mean) ** 2 for x in d) / len(d)) ** 0.5
        if std == 0:                       # constant history: any change is maximal
            return 1.0 if e.duration_ms != mean else 0.0
        z = abs(e.duration_ms - mean) / std
        # 5 sigma saturates. 3 sigma happens ~1 in 370 normal events and
        # would alert on its own; 5 sigma does not occur by chance in practice.
        return min(z / 5.0, 1.0)

    def _memory_signal(self, e: EnvelopeEvent) -> float:
        if not e.requested_memory_write or len(self.memory_write_rate) < self.WARMUP:
            return 0.0
        rate = sum(self.memory_write_rate) / len(self.memory_write_rate)
        # The rarer memory writes are for this agent, the louder a new one is.
        return max(0.0, 1.0 - rate / 0.10)  # rate >= 10% -> 0, rate 0% -> 1

    def _size_signal(self, e: EnvelopeEvent) -> float:
        s = list(self.return_size_history[e.tool_name])
        if len(s) < 10:
            return 0.0
        mean = sum(s) / len(s)
        if mean <= 0:
            return 0.0
        ratio = e.return_size_bytes / mean
        return min(max(ratio - 1.0, 0.0) / 4.0, 1.0)   # 5x mean -> 1.0

    def _sequence_signal(self, e: EnvelopeEvent) -> float:
        if not self.tool_sequences or sum(self.bigrams.values()) < self.WARMUP:
            return 0.0
        prev = self.tool_sequences[-1]
        seen = self.bigrams.get((prev, e.tool_name), 0)
        total_from_prev = sum(c for (a, _), c in self.bigrams.items() if a == prev)
        if total_from_prev == 0:
            return 0.0
        return 1.0 - (seen / total_from_prev)         # never-seen transition -> 1.0

    def _param_signal(self, e: EnvelopeEvent) -> float:
        known = self.param_hashes[e.tool_name]
        if len(known) < 10:
            return 0.0
        return 0.0 if e.param_hash in known else 1.0

    def score_event(self, e: EnvelopeEvent) -> Dict[str, float]:
        """Returns per-signal scores plus a combined score. The combined score
        is the MAXIMUM signal blended with the mean, so a single strong signal
        (a 50x duration spike) can alert on its own, which a pure weighted sum
        could not do when its weight caps it below the threshold."""
        if not self.warmed_up():
            return {"combined": 0.0, "warming_up": 1.0}
        sig = {
            "duration": self._duration_signal(e),
            "memory":   self._memory_signal(e),
            "size":     self._size_signal(e),
            "sequence": self._sequence_signal(e),
            "params":   self._param_signal(e),
        }
        strongest = max(sig.values())
        mean = sum(sig.values()) / len(sig)
        sig["combined"] = round(0.7 * strongest + 0.3 * mean, 3)
        return sig


class WatcherAgent:
    """Read-only observer. Holds no write capability; its only side effect is
    invoking the injected containment_trigger (Chapter 2's kill switch)."""

    def __init__(
        self,
        containment_trigger: Callable[[str, float], None],
        alert_threshold: float = 0.7,
        containment_threshold: float = 0.9,
    ):
        self.baselines: Dict[str, AgentBaseline] = {}
        self.containment_trigger = containment_trigger
        self.alert_threshold = alert_threshold
        self.containment_threshold = containment_threshold
        self.alert_log: List[dict] = []
        self.contained: set = set()

    def _get_baseline(self, agent_id: str) -> AgentBaseline:
        return self.baselines.setdefault(agent_id, AgentBaseline())

    def process_event(self, event: EnvelopeEvent) -> Optional[dict]:
        if event.agent_id in self.contained:
            return None                                 # already isolated; do not re-fire
        baseline = self._get_baseline(event.agent_id)
        scores = baseline.score_event(event)
        score = scores["combined"]
        # Only benign-looking events shape the baseline.
        if score < AgentBaseline.ABSORB_BELOW or not baseline.warmed_up():
            baseline.update(event)
        if score < self.alert_threshold:
            return None
        action = "CONTAINED" if score >= self.containment_threshold else "FLAGGED"
        alert = {
            "agent_id": event.agent_id, "session_id": event.session_id,
            "anomaly_score": score, "signals": scores, "tool": event.tool_name,
            "timestamp": event.timestamp, "action": action,
        }
        self.alert_log.append(alert)
        if action == "CONTAINED":
            self.contained.add(event.agent_id)
            self.containment_trigger(event.agent_id, score)
        return alert

    def correlate(self, window_s: float = 60.0) -> List[List[dict]]:
        """Cross-agent correlation: alerts from different agents inside the
        same window are grouped, which is the shape a propagating compromise
        (Chapter 7) takes."""
        groups, cur = [], []
        for a in sorted(self.alert_log, key=lambda x: x["timestamp"]):
            if cur and a["timestamp"] - cur[-1]["timestamp"] > window_s:
                groups.append(cur); cur = []
            cur.append(a)
        if cur:
            groups.append(cur)
        return [g for g in groups if len({a["agent_id"] for a in g}) > 1]

# Expected output for the Exercise 14.1 scenarios with these defaults:
#   normal agent       -> 0 alerts across 200 events
#   duration spike     -> 5000 ms against a ~100 ms baseline scores 0.76 -> FLAGGED
#   gradual poisoning  -> memory writes rising 0% -> 40% over 300 events: 50 alerts.
#                         Anomalous writes are not absorbed into the baseline, so
#                         the alerts persist instead of fading as writes become "normal".

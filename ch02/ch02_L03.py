from enum import Enum

class CircuitState(Enum):
    ALLOW = "allow"
    PAUSE = "pause"
    HALT  = "halt"

class AlgorithmicCircuitBreaker:
    """Stateful, deterministic. Returns ALLOW/PAUSE/HALT
    independent of model output. Target: HALT in <60 seconds."""
    PAUSE_TOKEN_RATIO = 2.0   # 200% of baseline -> PAUSE
    HALT_TOKEN_RATIO  = 4.0   # 400% of baseline -> HALT
    HALT_DENIED_CALLS = 3     # >3 gateway denials in 60s -> HALT
    HALT_ANOMALY_SCORE = 0.85 # behavioral anomaly score -> HALT

    def evaluate(self, metrics) -> CircuitState:
        ratio = metrics.tokens_last_60s / max(metrics.baseline, 1)
        if (ratio >= self.HALT_TOKEN_RATIO or
            metrics.denied_calls >= self.HALT_DENIED_CALLS or
            metrics.anomaly_score >= self.HALT_ANOMALY_SCORE):
            self._trigger_staged_shutdown(metrics.agent_id)
            return CircuitState.HALT
        if ratio >= self.PAUSE_TOKEN_RATIO:
            return CircuitState.PAUSE
        return CircuitState.ALLOW
# Full implementation: github.com/mastering-agentic-security/ch2

# Full implementation: github.com/mastering-agentic-security/ch7

import math, time

class AgentCircuitBreaker:
    THRESHOLD = 0.75          # trip at combined anomaly score in [0, 1]
    HALF_OPEN_AFTER_S = 600   # probe recovery after 10 minutes
    HALF_OPEN_CLEAN_N = 50    # consecutive clean windows to close again

    def __init__(self, agent_id, trust_graph, containment_bus):
        self.agent_id = agent_id
        self.graph = trust_graph
        self.bus = containment_bus
        self.state = 'CLOSED'   # CLOSED -> OPEN -> HALF_OPEN -> CLOSED
        self.opened_at = None
        self.clean_streak = 0

    # KL divergence is unbounded; PSI is unbounded above too. Squash both into
    # [0, 1) before weighting, otherwise one metric swamps the threshold.
    @staticmethod
    def _squash(x, scale):
        return 1.0 - math.exp(-max(x, 0.0) / scale)

    def record_metrics(self, kl_divergence, psi_score, call_rate_anomaly=0.0):
        score = (0.5 * self._squash(kl_divergence, scale=0.5)
                 + 0.3 * self._squash(psi_score, scale=0.25)
                 + 0.2 * min(max(call_rate_anomaly, 0.0), 1.0))

        if self.state == 'OPEN':
            if time.time() - self.opened_at >= self.HALF_OPEN_AFTER_S:
                self.state = 'HALF_OPEN'; self.clean_streak = 0
            return
        if self.state == 'HALF_OPEN':
            if score > self.THRESHOLD:
                self._trip(score)                       # re-open, reset timer
            else:
                self.clean_streak += 1
                if self.clean_streak >= self.HALF_OPEN_CLEAN_N:
                    self._reset()
            return
        if score > self.THRESHOLD:
            self._trip(score)

    def _trip(self, score):
        self.state = 'OPEN'; self.opened_at = time.time()
        dependents = self.graph.get_downstream(self.agent_id, transitive=True)
        # Ordering constraints from the containment cascade:
        #   isolation MUST complete before memory quarantine (no new writes),
        #   token revocation MUST complete before dependents resume.
        # Everything else is independent and fans out.
        self.bus.publish_and_wait('ISOLATE', self.agent_id, timeout_s=5)
        self.bus.publish_and_wait('REVOKE_TOKENS', self.agent_id, timeout_s=5)
        self.bus.publish('QUARANTINE_MEMORY', self.agent_id)
        for dep in dependents:
            self.bus.publish('DEFENSIVE_POSTURE', dep)
        self.bus.publish('UPSTREAM_NOTIFY', self.agent_id, score=score)
        self.bus.publish('FREEZE_BUDGET', self.agent_id)
        self.bus.publish('NETWORK_CONTAIN', self.agent_id)

    def _reset(self):
        self.state = 'CLOSED'; self.opened_at = None; self.clean_streak = 0
        self.bus.publish('RESTORE', self.agent_id)      # begins Chapter 12 ladder

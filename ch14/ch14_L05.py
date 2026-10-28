from dataclasses import dataclass, field
from typing import List, Dict, Callable, Any


@dataclass
class SecurityCheck:
    check_id: str
    description: str
    latency_ms: float          # measured overhead per invocation
    threat_weight: float       # 0.0-1.0, updated by threat intelligence
    mandatory: bool = False    # never subject to the budget optimisation
    enabled: bool = True
    run: Callable[[Any], bool] = field(default=lambda _: True)


class SecurityBudget:
    """Choose which checks run so that total latency stays within budget while
    the sum of threat_weight is maximised. With tens of checks and a budget in
    whole milliseconds the exact 0/1 knapsack is trivial to compute, so there
    is no reason to accept the greedy ratio heuristic, which can be arbitrarily
    bad (budget 50 ms, A = 1 ms/0.05, B = 50 ms/1.0: greedy takes A and scores
    0.05; the optimum is B at 1.0)."""

    RESOLUTION_MS = 0.1        # knapsack granularity

    def __init__(self, budget_ms: float):
        self.budget_ms = budget_ms
        self.checks: Dict[str, SecurityCheck] = {}

    def register(self, check: SecurityCheck):
        self.checks[check.check_id] = check
        self._optimize()

    def update_threat_weight(self, check_id: str, new_weight: float) -> bool:
        if check_id not in self.checks:
            raise KeyError(f"unknown check_id {check_id!r}; register it first")
        self.checks[check_id].threat_weight = max(0.0, min(1.0, new_weight))
        self._optimize()
        return True

    def _optimize(self):
        # 1. Mandatory controls are pinned ON and paid for first. A threat feed
        #    lowering their weight must never silently switch off a defence.
        mandatory = [c for c in self.checks.values() if c.mandatory]
        optional = [c for c in self.checks.values() if not c.mandatory]
        for c in mandatory:
            c.enabled = True
        remaining_ms = self.budget_ms - sum(c.latency_ms for c in mandatory)
        if remaining_ms < 0:
            raise ValueError("mandatory checks alone exceed the latency budget")

        # 2. Exact 0/1 knapsack over the optional checks.
        cap = int(remaining_ms / self.RESOLUTION_MS)
        w = [max(1, int(round(c.latency_ms / self.RESOLUTION_MS))) for c in optional]
        v = [c.threat_weight for c in optional]
        n = len(optional)
        best = [[0.0] * (cap + 1) for _ in range(n + 1)]
        for i in range(1, n + 1):
            for b in range(cap + 1):
                best[i][b] = best[i - 1][b]
                if w[i - 1] <= b:
                    cand = best[i - 1][b - w[i - 1]] + v[i - 1]
                    if cand > best[i][b]:
                        best[i][b] = cand
        # 3. Back-trace the chosen set.
        b = cap
        for i in range(n, 0, -1):
            take = best[i][b] != best[i - 1][b]
            optional[i - 1].enabled = take
            if take:
                b -= w[i - 1]

    def run_checks(self, request: Any) -> Dict[str, bool]:
        return {cid: c.run(request) for cid, c in self.checks.items() if c.enabled}

    def enabled_checks_summary(self) -> List[str]:
        return [f"{c.check_id} (latency={c.latency_ms}ms, weight={c.threat_weight}"
                f"{', mandatory' if c.mandatory else ''})"
                for c in self.checks.values() if c.enabled]

# Expected (budget 50 ms, A = 1 ms / 0.05, B = 50 ms / 1.0): B enabled, A disabled.
# The greedy ratio heuristic would have chosen A.

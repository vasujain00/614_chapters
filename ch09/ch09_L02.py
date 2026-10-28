import numpy as np
from collections import Counter

def compute_psi(baseline: Counter, current: Counter,
                epsilon: float = 1e-6) -> float:
    """Population Stability Index over categorical routing distributions.
    Each bin is Laplace-smoothed by epsilon, so the totals must be smoothed
    by epsilon * number_of_bins or the proportions will not sum to one."""
    all_keys = set(baseline) | set(current)
    k = len(all_keys)
    b_total = sum(baseline.values()) + epsilon * k
    c_total = sum(current.values())  + epsilon * k
    psi = 0.0
    for key in all_keys:
        b = (baseline.get(key, 0) + epsilon) / b_total
        c = (current.get(key, 0)  + epsilon) / c_total
        psi += (c - b) * np.log(c / b)
    return float(psi)

def alert_on_drift(baseline: Counter, window: Counter,
                   threshold: float = 0.25) -> bool:
    psi = compute_psi(baseline, window)
    if psi > threshold:
        print(f"DRIFT ALERT: PSI={psi:.3f} exceeds {threshold}")
        return True
    return False

# Full implementation: github.com/mastering-agentic-security/ch9

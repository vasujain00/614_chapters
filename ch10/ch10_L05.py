import statistics

def compute_evasion_trend(evasion_rates: list[float],
                          window: int = 30,
                          min_probes_per_point: int = 200) -> dict:
    """Track rolling evasion rate; alert on upward trends.

    Each entry in evasion_rates must come from a probe set of at least
    min_probes_per_point attempts. A 2-point rise computed from 20 probes is
    noise; the same rise from 500 probes is a signal. Enforce the floor at the
    point of collection, not here, and keep the probe set FIXED across the
    window -- a growing probe set makes the rate drift for reasons that have
    nothing to do with the system under test (see the coverage-drift
    anecdote above)."""
    if len(evasion_rates) < 2 * window:
        return {"status": "insufficient_data", "need": 2 * window}
    recent   = evasion_rates[-window:]
    baseline = evasion_rates[-(window * 2):-window]
    rm, bm = statistics.mean(recent), statistics.mean(baseline)
    # Require the rise to clear both an absolute floor and the baseline's noise.
    noise = statistics.pstdev(baseline)
    delta = rm - bm
    return {
        "current_mean":  rm,
        "baseline_mean": bm,
        "delta": delta,
        "alert": delta > max(0.02, 2 * noise),  # >2ppt AND >2 sigma
    }

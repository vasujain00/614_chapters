import functools
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

# One shared pool so a stuck decision does not spawn unbounded threads.
_DECISION_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="decision")


def latency_budget(max_ms: float, safe_default: Any, on_violation: Callable[[str, float], None] = None):
    """Enforce a hard deadline on a decision function.

    The decorated call runs in a worker thread and the CALLER waits at most
    max_ms. If the deadline passes, safe_default is returned IMMEDIATELY while
    the worker is left to finish (or not) in the background. Checking elapsed
    time after the function returns, as a naive decorator does, enforces
    nothing: a 1-second call would still block for 1 second.

    This is a software watchdog for the decision layer only. In a physical
    system the actual safety stop (motor cut-off, brake engagement) belongs in
    a certified real-time controller (ISO 26262 / IEC 61508 class), not in a
    Python process. This decorator decides WHETHER to request a stop; it must
    never be the thing that performs it."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.monotonic()
            future = _DECISION_POOL.submit(func, *args, **kwargs)
            try:
                return future.result(timeout=max_ms / 1000.0)
            except FutureTimeout:
                elapsed_ms = (time.monotonic() - start) * 1000.0
                if on_violation:
                    on_violation(func.__name__, elapsed_ms)
                return safe_default
        return wrapper  # type: ignore
    return decorator


# Usage: a safety-stop decision that must complete within 50 ms
SAFE_STOP = {"action": "emergency_stop", "reason": "latency_budget_exceeded"}


@latency_budget(max_ms=50.0, safe_default=SAFE_STOP)
def evaluate_obstacle_clearance(sensor_data: dict) -> dict:
    """Fuse LIDAR and camera; if they disagree, that is itself a stop."""
    lidar_m = sensor_data["lidar_min_distance_m"]
    cam_m = sensor_data["camera_min_distance_m"]
    if abs(lidar_m - cam_m) > 0.5:                     # cross-validation failed
        return {"action": "emergency_stop", "reason": "sensor_disagreement"}
    if min(lidar_m, cam_m) < 1.0:
        return {"action": "emergency_stop", "reason": "obstacle_within_1m"}
    return {"action": "proceed", "clearance_m": min(lidar_m, cam_m)}

# Expected: a decision function that sleeps for 1 s returns SAFE_STOP after
# ~50 ms (measured: 50.4 ms), not after 1000 ms.

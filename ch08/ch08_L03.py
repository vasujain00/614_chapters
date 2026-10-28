# Full implementation: github.com/mastering-agentic-security/ch8

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from enum import IntEnum

def _now() -> datetime:
    return datetime.now(timezone.utc)

class TrustLevel(IntEnum):
    L1_FULL_REVIEW   = 1
    L2_ROUTINE_AUTO  = 2
    L3_ANOMALY_FLAG  = 3
    L4_POST_HOC_ONLY = 4

@dataclass
class TrustState:
    level: TrustLevel = TrustLevel.L1_FULL_REVIEW
    level_since: datetime = field(default_factory=_now)
    error_count: int = 0
    action_count: int = 0
    incidents: List[str] = field(default_factory=list)

# (minimum time at level, max error rate, minimum actions at level)
PROMO_CRITERIA = {
    TrustLevel.L1_FULL_REVIEW:  (timedelta(days=14), 0.005, 100),
    TrustLevel.L2_ROUTINE_AUTO: (timedelta(days=90), 0.003, 4000),
    TrustLevel.L3_ANOMALY_FLAG: (timedelta(days=180), 0.001, 10000),
}

def record_action(state: TrustState, errored: bool) -> None:
    state.action_count += 1
    if errored:
        state.error_count += 1

def can_promote(state: TrustState, now: Optional[datetime] = None) -> bool:
    if state.level == TrustLevel.L4_POST_HOC_ONLY:
        return False
    min_time, max_err_rate, min_actions = PROMO_CRITERIA[state.level]
    now = now or _now()
    if now - state.level_since < min_time:
        return False
    if state.action_count < min_actions:
        return False
    return (state.error_count / state.action_count) <= max_err_rate

def promote(state: TrustState) -> TrustState:
    """Promotion is the ONLY path up the ladder, and it is one level at a time.
    Any scope change (new tool, wider data access) must call demote() first:
    the track record was earned under the old scope."""
    if not can_promote(state):
        raise ValueError("promotion criteria not met")
    state.level = TrustLevel(state.level + 1)
    state.level_since = _now()
    state.error_count = 0
    state.action_count = 0
    return state

def demote(state: TrustState, reason: str) -> TrustState:
    state.incidents.append(reason)
    state.level = TrustLevel.L1_FULL_REVIEW
    state.level_since = _now()
    state.error_count = 0
    state.action_count = 0
    return state                    # restart the clock

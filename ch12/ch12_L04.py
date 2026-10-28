# Full implementation: github.com/mastering-agentic-security/ch12
from enum import Enum, auto

class RecoveryState(Enum):
    CONTAINED    = auto()  # cascade fired, agent isolated
    INVESTIGATED = auto()  # root cause confirmed
    REMEDIATED   = auto()  # memory purged, entry vector patched
    RING3        = auto()  # read-only, full human oversight
    RING2        = auto()  # bounded writes, limited budget
    RING1        = auto()  # private data access, bounded delegation
    RESTORED     = auto()  # Ring 0: full production capability

# (minimum clean days, minimum canary pass rate) required to LEAVE this state.
# REMEDIATED -> RING3 is the entry to the ladder; without it the agent can
# never start climbing. CONTAINED and INVESTIGATED are human-gated, not
# metric-gated, so they are deliberately absent here.
PROMOTION_THRESHOLDS = {
    RecoveryState.REMEDIATED: (0, 0.95),  # enter Ring 3 once canaries pass
    RecoveryState.RING3:      (2, 0.98),  # 2 days, 98% canary pass
    RecoveryState.RING2:      (2, 0.99),  # 2 days, 99% canary pass
    RecoveryState.RING1:      (2, 1.00),  # 2 days, 100% canary pass
}

NEXT = {
    RecoveryState.REMEDIATED: RecoveryState.RING3,
    RecoveryState.RING3:      RecoveryState.RING2,
    RecoveryState.RING2:      RecoveryState.RING1,
    RecoveryState.RING1:      RecoveryState.RESTORED,
}

def can_promote(state: RecoveryState, days_clean: int,
                canary_pass_rate: float) -> bool:
    if state not in PROMOTION_THRESHOLDS:
        return False                         # human gate, not a metric gate
    d, r = PROMOTION_THRESHOLDS[state]
    return days_clean >= d and canary_pass_rate >= r

def promote(state: RecoveryState) -> RecoveryState:
    return NEXT[state]

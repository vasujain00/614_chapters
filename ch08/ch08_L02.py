# Full implementation: github.com/mastering-agentic-security/ch8

import asyncio, uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

class GateOutcome(Enum):
    APPROVED = "approved"
    DENIED   = "denied"
    ESCALATED = "escalated"
    TIMED_OUT = "timed_out"

@dataclass
class ApprovalRequest:
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    summary: str = ""
    context: dict = field(default_factory=dict)
    confidence: float = 0.0
    sla_seconds: int = 300          # 5-minute default
    timeout_behavior: str = "deny"  # "deny" | "escalate"  (never "approve")
    escalation_tier: int = 0        # bumped on each escalation

async def async_approval_gate(
    request: ApprovalRequest,
    notify: Callable[[ApprovalRequest], Awaitable[None]],
    resolve: Callable[[str], Awaitable[Optional[bool]]],
    escalate: Callable[[ApprovalRequest], Awaitable[None]],
    max_escalations: int = 2) -> GateOutcome:
    """Blocks a single coroutine until a human answers or the SLA chain ends.
    Suitable for request/response agents that hold the connection. For
    checkpointed graphs where the process does not stay resident, see the
    SLA sweeper in the LangGraph listing below."""
    await notify(request)
    while True:
        try:
            result = await asyncio.wait_for(
                resolve(request.action_id), timeout=request.sla_seconds)
            return GateOutcome.APPROVED if result else GateOutcome.DENIED
        except asyncio.TimeoutError:
            if request.timeout_behavior != "escalate":
                return GateOutcome.TIMED_OUT          # safe default = deny
            if request.escalation_tier >= max_escalations:
                return GateOutcome.TIMED_OUT          # chain exhausted = deny
            request.escalation_tier += 1
            await escalate(request)                   # actually page the next tier
            # loop: wait another SLA window for the escalated reviewer

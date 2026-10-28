# Full implementation: github.com/mastering-agentic-security/ch8

import logging
log = logging.getLogger("saga")

class SagaCompensator:
    def __init__(self):
        self.completed_steps: list[tuple[str, dict]] = []

    def record(self, step_name: str, forward_params: dict):
        if step_name not in COMPENSATION_REGISTRY:
            # Fail at RECORD time, before the forward action runs. A step with
            # no compensator must be classified as a pivot (Chapter 4, Tool Use
            # and Action Safety), never silently accepted here.
            raise ValueError(f"No compensator registered for {step_name}")
        self.completed_steps.append((step_name, forward_params))

    async def compensate_all(self, reason: str) -> list[str]:
        """Reverse every completed step. Never stop at the first failure: a
        step that cannot be undone must not leave later steps un-reverted.
        Returns the list of steps that still need manual follow-up."""
        unresolved = []
        for step_name, params in reversed(self.completed_steps):
            handler = COMPENSATION_REGISTRY[step_name]
            try:
                await handler(params, reason=reason)   # idempotent by contract
            except Exception as exc:                   # noqa: BLE001
                log.error("compensation failed step=%s err=%s", step_name, exc)
                unresolved.append(step_name)
        if unresolved:
            await page_oncall("saga_compensation_incomplete", unresolved)
        return unresolved

# In approval_node, on denial:
#   unresolved = await state["saga"].compensate_all(reason=decision["reason"])
# Compensation runs in reverse step order, durably persisted at each step.

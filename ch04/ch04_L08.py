# Saga orchestrator with compensation
from enum import Enum

class StepType(Enum):
    COMPENSATABLE = "compensatable"   # reversible by a compensation action
    PIVOT         = "pivot"           # point of no return; forward-only after this
    RETRIABLE     = "retriable"       # succeeds eventually if retried; no compensation

class SagaOrchestrator:
    MAX_RETRIES = 3

    def execute(self, steps: list[SagaStep]) -> SagaResult:
        completed: list[SagaStep] = []
        past_pivot = False
        for step in steps:
            result = self._run_with_retry(step)
            if result.success:
                completed.append(step)
                if step.step_type == StepType.PIVOT:
                    past_pivot = True          # forward-only from here
                continue

            # --- failure handling ---
            if kill_switch.is_active():
                return self._fail(completed, past_pivot, "kill switch")
            if step.step_type == StepType.RETRIABLE:
                # _run_with_retry already exhausted MAX_RETRIES
                return self._fail(completed, past_pivot,
                                  f"retriable step exhausted: {result.error}")
            # COMPENSATABLE or PIVOT failed
            return self._fail(completed, past_pivot, result.error)
        return SagaResult.success(completed)

    def _run_with_retry(self, step: SagaStep) -> StepResult:
        attempts = self.MAX_RETRIES if step.step_type == StepType.RETRIABLE else 1
        result = step.execute()
        for _ in range(attempts - 1):
            if result.success:
                break
            result = step.execute()
        return result

    def _fail(self, completed, past_pivot, reason) -> SagaResult:
        if past_pivot:
            # Pivot already committed: compensation is NOT allowed. Escalate
            # to a human with the exact state so forward recovery can start.
            return SagaResult.escalate(completed, reason)
        return self._compensate(completed, reason)

    def _compensate(self, completed, reason) -> SagaResult:
        for step in reversed(completed):
            if step.step_type == StepType.COMPENSATABLE:
                step.compensate()  # idempotent by contract
        return SagaResult.compensated(reason)
# Full implementation: github.com/mastering-agentic-security/ch4

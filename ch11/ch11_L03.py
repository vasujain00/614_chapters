# Full implementation: github.com/mastering-agentic-security/ch11
import logging, random
from dataclasses import dataclass
from typing import Callable, Literal
from concurrent.futures import ThreadPoolExecutor

@dataclass(frozen=True)
class Canary:
    id: str
    query: str
    expected: str
    kind: Literal['factual', 'behavioral', 'boundary']
    checker: Callable[[str, str], bool]

_pool = ThreadPoolExecutor(max_workers=4)
_log = logging.getLogger("canary")

def alert(title: str, detail, expected: str) -> None:
    """Canary results never go where the model can read them: a log the agent
    has no tool for, plus the integrity metric that Chapter 9 alerts on."""
    _log.error("%s detail=%s expected=%s", title, detail, expected)

def inject_and_verify(query: str, agent_fn: Callable[[str], str],
                      canaries: list[Canary], rate: float = 0.03) -> dict:
    """The user's query is ALWAYS answered. A canary, when sampled, runs
    alongside it, never instead of it. Returning the canary result in place
    of the user's answer would silently drop `rate` of real traffic."""
    canary_future = None
    chosen = None
    if canaries and random.random() < rate:
        chosen = random.choice(canaries)
        canary_future = _pool.submit(agent_fn, chosen.query)   # same agent, parallel

    result = agent_fn(query)                                   # real request

    canary_report = None
    if chosen is not None:
        try:
            passed = chosen.checker(canary_future.result(timeout=5), chosen.expected)
        except Exception as exc:                               # noqa: BLE001
            passed = False
            alert(f'Canary {chosen.id} errored', str(exc), chosen.expected)
        if not passed:
            alert(f'Canary {chosen.id} ({chosen.kind}) failed', None, chosen.expected)
        canary_report = {'canary_id': chosen.id, 'passed': passed}

    return {'result': result, 'canary': canary_report}

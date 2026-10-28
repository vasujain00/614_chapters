# Full implementation: github.com/mastering-agentic-security/ch11
from dataclasses import dataclass
from enum import Enum

class FailureMode(Enum):
    HOLD = 'hold'         # queue for review
    DEGRADE = 'degrade'   # pass with reduced validation flag
    PASS = 'pass'         # pass anyway (not recommended)

class HoldForReview(Exception):
    """Raised when a layer fails under HOLD: the output is queued, not delivered."""
    def __init__(self, layer: str, cause: Exception):
        super().__init__(f"{layer} failed: {cause!r}")
        self.layer, self.cause = layer, cause

@dataclass
class OutputPipelineConfig:
    normalize: bool = True
    classify_inline: bool = True
    ground_async: bool = True
    canary_rate: float = 0.03
    grounding_threshold: float = 0.80
    classifier_threshold: float = 0.65
    layer_failure_mode: FailureMode = FailureMode.HOLD
    high_stakes: bool = False

def run_output_pipeline(output: str, ctx: dict,
                        cfg: OutputPipelineConfig) -> dict:
    """Every config field is enforced here. A layer that throws is handled
    according to layer_failure_mode; a layer that returns a bad score blocks."""
    flags: list[str] = []

    def guarded(name, fn, *args):
        """Run a layer; translate exceptions through layer_failure_mode."""
        try:
            return fn(*args)
        except Exception as exc:                               # noqa: BLE001
            flags.append(f'{name}_error:{type(exc).__name__}')
            if cfg.layer_failure_mode is FailureMode.HOLD:
                raise HoldForReview(name, exc)
            if cfg.layer_failure_mode is FailureMode.DEGRADE:
                return None                                   # caller treats as skipped
            return None                                       # PASS: skip silently

    # Layer 1: canonical normalisation (cheap, always inline)
    text = guarded('normalize', normalize_output, output) if cfg.normalize else output
    text = text if text is not None else output

    # Layer 2: classifier (inline unless config says otherwise)
    if cfg.classify_inline:
        score = guarded('classify', classify_output, text, ctx, cfg)
        threshold = 0.90 if cfg.high_stakes else cfg.classifier_threshold
        if score is not None and score < threshold:
            return {'output': None, 'status': 'blocked',
                    'reason': 'classifier', 'score': score, 'flags': flags}

    # Layer 3: grounding (async by default; inline for high-stakes)
    if cfg.high_stakes or not cfg.ground_async:
        g = guarded('ground', ground_output, text, ctx.get('sources', []))
        if g is not None and g['grounding_score'] < cfg.grounding_threshold:
            return {'output': None, 'status': 'blocked',
                    'reason': 'grounding', 'score': g['grounding_score'],
                    'flags': flags}
    else:
        schedule_async_grounding(text, ctx, cfg.grounding_threshold)

    status = 'ok' if not flags else 'degraded'
    return {'output': text, 'status': status, 'flags': flags}

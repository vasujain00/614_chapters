import functools
import os
from pathlib import Path
from typing import Any, Callable, Dict, Literal, TypeVar
from pydantic import BaseModel, ValidationError, ConfigDict

F = TypeVar("F", bound=Callable[..., Any])


class PreconditionViolation(Exception):
    pass


def verify_precondition(check: Callable[..., bool], reason: str = ""):
    """Decorator enforcing a precondition before any tool call executes.
    The check receives the same arguments as the decorated function."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not check(*args, **kwargs):
                raise PreconditionViolation(
                    f"Precondition failed for {func.__name__}: {reason}")
            return func(*args, **kwargs)
        return wrapper  # type: ignore
    return decorator


# Example: constrain a file-write tool to an approved directory.
# Resolve symlinks and ".." BEFORE comparing; a prefix test on the raw string
# accepts "/data/agent-workspace/../../etc/passwd".
APPROVED_DIR = Path("/data/agent-workspace").resolve()


def path_in_approved_dir(path: str, *args, **kwargs) -> bool:
    try:
        candidate = Path(path).resolve(strict=False)     # collapses .. and symlinks
    except (OSError, RuntimeError):
        return False
    try:
        return candidate.is_relative_to(APPROVED_DIR)   # Python 3.9+
    except AttributeError:                               # 3.8 fallback
        return os.path.commonpath([candidate, APPROVED_DIR]) == str(APPROVED_DIR)


@verify_precondition(
    check=path_in_approved_dir,
    reason="file writes restricted to approved workspace directory")
def write_file(path: str, content: str) -> dict:
    with open(path, "w") as f:
        f.write(content)
    return {"path": path, "bytes_written": len(content)}


# Pydantic-enforced output schema. Free `str` fields reject almost nothing;
# closed enumerations and extra='forbid' are what make the schema a gate.
class AgentActionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: Literal["read", "write", "call", "delete", "notify"]
    target_resource: str
    parameters: Dict[str, Any]
    reversible: bool
    estimated_blast_radius: Literal["local", "session", "cross-session", "external"]


def validate_agent_output(raw_output: dict) -> AgentActionOutput:
    """Enforce output schema at the gateway layer before downstream consumption."""
    try:
        return AgentActionOutput(**raw_output)
    except ValidationError as e:
        raise PreconditionViolation(
            f"Agent output failed schema validation: {e}") from e

# Expected:
#   path_in_approved_dir("/data/agent-workspace/notes.txt")           -> True
#   path_in_approved_dir("/data/agent-workspace/../../etc/passwd")    -> False
#   validate_agent_output({"action_type": "format_disk", ...})        -> PreconditionViolation
#   validate_agent_output({..., "extra_field": 1})                    -> PreconditionViolation

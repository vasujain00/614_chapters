from dataclasses import dataclass

@dataclass(frozen=True)
class RegressionCase:
    case_id: str          # internal id, e.g. "RT-2026-047"; not a CVE
    kill_chain_stage: str # "injection"|"escalation"|"exfiltration"|...
    evasion_technique: str
    attack_payload: str
    expected_verdict: str # "BLOCK"|"FLAG"|"ALLOW"
    severity: str         # "critical"|"high"|"medium"
    discovered_by: str    # "red_team"|"automated"|"prod"
    notes: str = ""

class RatchetViolation(Exception):
    pass

# Ratchet: only append, never delete, never overwrite. Enforced with a real
# exception, not assert, so it survives python -O in CI.
def add_to_library(lib: list[RegressionCase], case: RegressionCase) -> None:
    if any(c.case_id == case.case_id for c in lib):
        raise RatchetViolation(f"{case.case_id} already in library; "
                               "add a new id rather than replacing a case")
    lib.append(case)

from dataclasses import dataclass

@dataclass
class TrustAssumption:
    assumption_id: str
    surface: str            # e.g. "tool_description"
    description: str
    breaks_on_upgrade: bool  # True if model upgrade invalidates
    exposure_window_hrs: float  # how long before detection
    financial_impact_usd: float # max damage in window
    priority_score: float = 0.0  # computed below

    def compute_priority(self):
        self.priority_score = (
            self.exposure_window_hrs * self.financial_impact_usd
        )

    # Full implementation: github.com/mastering-agentic-security/ch1

for a in inventory:
    a.compute_priority()
roadmap = sorted(inventory, key=lambda a: a.priority_score, reverse=True)[:5]

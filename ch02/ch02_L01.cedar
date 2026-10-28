// Bidding agents may read budgets. Nothing in this policy grants a write.
permit (
    principal in AgentRole::"bidding-agent",
    action == Action::"budget:Read",
    resource in ToolEndpoint::"budget-api"
)
when { principal.ring <= 2 && resource.environment == "prod" };

// Writes are an explicit, separate grant held by a different principal.
forbid (
    principal in AgentRole::"bidding-agent",
    action in [Action::"budget:Write", Action::"budget:Delete"],
    resource
);

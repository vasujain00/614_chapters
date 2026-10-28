# Pre-execution validation pipeline
def validate_tool_call(call: ToolCall, session: Session) -> ValidationResult:
    # 1. Schema enforcement
    schema = tool_registry.get_schema(call.tool_name)
    violations = schema.validate(call.params)
    if violations:
        return ValidationResult.deny(violations)

    # 2. Parameter bounds check
    bounds = tool_registry.get_bounds(call.tool_name)
    if not bounds.check(call.params):
        return ValidationResult.deny("parameter out of bounds")

    # 3. Budget/aggregate check via Dogwood -- session.events is the
    #    accumulated event log that feeds the temporal operators.
    dogwood_result = dogwood.evaluate_request(call, session.events)
    if dogwood_result.denied:
        return ValidationResult.deny(dogwood_result.reason)

    return ValidationResult.permit()
# Full implementation: github.com/mastering-agentic-security/ch4

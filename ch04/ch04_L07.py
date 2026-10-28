# Post-execution verification pipeline
def verify_tool_response(call: ToolCall, response: ToolResponse,
                         session: Session) -> VerificationResult:
    # 1. Response schema validation
    expected_schema = tool_registry.get_response_schema(call.tool_name)
    if not expected_schema.validate(response.body):
        return VerificationResult.quarantine("schema mismatch")

    # 2. Output grounding check
    if injection_scanner.scan(response.body):
        return VerificationResult.quarantine("injection pattern")

    # 3. Dogwood response-time evaluation against the same session log
    dogwood_result = dogwood.evaluate_response(call, response, session.events)
    if dogwood_result.denied:
        return VerificationResult.quarantine(dogwood_result.reason)

    return VerificationResult.pass_through()
# Full implementation: github.com/mastering-agentic-security/ch4

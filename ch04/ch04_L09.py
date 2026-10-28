# Integrated gateway: all four verification stages
class ToolGateway:
    def __init__(self, registry, dogwood, saga_orchestrator):
        self.registry = registry
        self.dogwood = dogwood
        self.orchestrator = saga_orchestrator

    def call(self, tool_call: ToolCall, session: Session) -> ToolResponse:
        # Stage 1: description hash
        if not self.registry.verify_hash(tool_call.tool_name):
            raise SecurityViolation("tool description hash mismatch")

        # Stage 2: pre-execution (Dogwood reads session.events)
        pre = validate_tool_call(tool_call, session)
        if pre.denied:
            session.events.append(Event.denied(tool_call, pre.reason))
            return ToolResponse.denied(pre.reason)

        # Stage 3: execute and verify response
        raw = self.registry.execute(tool_call)
        post = verify_tool_response(tool_call, raw, session)
        if post.quarantined:
            session.events.append(Event.quarantined(tool_call, post.reason))
            return ToolResponse.quarantined(post.reason)

        # Stage 4: record the permitted call so the next evaluation sees it
        session.events.append(Event.permitted(tool_call, raw))
        return raw
# Full implementation: github.com/mastering-agentic-security/ch4

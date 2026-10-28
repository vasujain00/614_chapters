from opentelemetry import trace

# Service-specific prefix for custom attributes, as the GenAI semantic
# conventions recommend. Bare "agent.*" collides with other instrumentations.
A = "acme.router"

tracer = trace.get_tracer("agent.router", "1.0.0")

def traced_route_decision(envelope: DecisionEnvelope):
    with tracer.start_as_current_span("router.choose") as span:
        # Standard gen_ai.* attributes (OpenTelemetry GenAI semantic conventions)
        span.set_attribute("gen_ai.operation.name",       "invoke_agent")
        span.set_attribute("gen_ai.provider.name",        envelope.model_version.split(":")[0])  # e.g. "openai"
        span.set_attribute("gen_ai.request.model",        envelope.model_version)
        span.set_attribute("gen_ai.usage.input_tokens",   envelope.tokens_in)
        span.set_attribute("gen_ai.usage.output_tokens",  envelope.tokens_out)
        # Envelope fields under the service prefix
        span.set_attribute(f"{A}.action.type",        "route")
        span.set_attribute(f"{A}.confidence.score",   envelope.confidence)
        span.set_attribute(f"{A}.prompt.hash",        envelope.prompt_version_hash)
        span.set_attribute(f"{A}.content.hash",       envelope.content_hash)
        span.set_attribute(f"{A}.sources.count",      len(envelope.retrieval_sources))
        span.set_attribute(f"{A}.status",             envelope.status)
        # Reasoning trace as a structured event, not an attribute blob
        span.add_event("routing_decision", attributes={
            "chosen":     envelope.chosen_route,
            "rejected":   ",".join(f"{r}={s:.3f}"
                                   for r, s in envelope.rejected_alternatives.items()),
            "latency_ms": envelope.latency_ms,
        })

# Full implementation: github.com/mastering-agentic-security/ch9

# Propagate W3C trace context inside an MCP tool call's _meta
from opentelemetry.propagate import inject

def mcp_call(client, tool: str, arguments: dict):
    carrier: dict = {}
    inject(carrier)                                  # {'traceparent': '00-<trace>-<span>-01'}
    return client.call_tool(tool, arguments, _meta={"traceparent": carrier["traceparent"]})

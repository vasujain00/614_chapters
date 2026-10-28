from typing import TypedDict, Literal
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import interrupt, Command

class AgentState(TypedDict):
    messages: list; trust_level: str; ring: int; audit: list
    pending_tool: dict | None

def route_by_trust(state: AgentState) -> Literal["trusted", "untrusted"]:
    return state["trust_level"]

def check_ring(state: AgentState) -> Literal["allowed", "denied", "hitl"]:
    tool = state.get("pending_tool")
    if tool is None:
        return "denied"                      # nothing to execute
    if tool["min_ring"] == 0:
        return "hitl"                        # Ring-0 tool: human must approve
    return "allowed" if state["ring"] <= tool["min_ring"] else "denied"

def hitl_checkpoint(state: AgentState):
    decision = interrupt({"approve": state["pending_tool"]})   # pauses graph
    if decision != "approve":
        return Command(goto=END, update={"audit": state["audit"] + ["hitl_denied"]})
    return Command(goto="tool_executor")

builder = StateGraph(AgentState)
builder.add_node("semantic_firewall", semantic_firewall_node)
builder.add_node("q_llm_quarantine",  quarantine_node)
builder.add_node("p_llm_reason",      privileged_reason_node)
builder.add_node("ring_gate",         ring_privilege_check)
builder.add_node("tool_executor",     execute_tools)
builder.add_node("hitl_checkpoint",   hitl_checkpoint)
builder.add_node("output_validator",  grounding_check)

builder.set_entry_point("semantic_firewall")
builder.add_conditional_edges("semantic_firewall", route_by_trust,
    {"trusted": "p_llm_reason", "untrusted": "q_llm_quarantine"})
builder.add_edge("q_llm_quarantine", "p_llm_reason")
builder.add_edge("p_llm_reason", "ring_gate")          # was missing: graph ended here
builder.add_conditional_edges("ring_gate", check_ring,
    {"allowed": "tool_executor", "denied": "output_validator",
     "hitl": "hitl_checkpoint"})
builder.add_edge("tool_executor", "output_validator")  # hitl resumes here via Command
builder.add_edge("output_validator", END)
graph = builder.compile(checkpointer=MemorySaver())

# Full implementation: github.com/mastering-agentic-security/ch6

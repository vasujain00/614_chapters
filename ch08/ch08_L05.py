# Full implementation: github.com/mastering-agentic-security/ch8

import asyncio
from datetime import datetime, timedelta, timezone
from langgraph.graph import StateGraph
from langgraph.types import interrupt, Command
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver  # async graph

async def approval_node(state: dict) -> dict:
    action = state["proposed_action"]
    review_ctx = build_review_context(action)  # five-component artifact
    decision = interrupt({                       # serializes state, suspends
        "action": action,
        "context": review_ctx,
        "sla_seconds": 300,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    })
    if decision["approved"]:
        return {"status": "approved", "action": action}
    return {"status": "denied", "reason": decision.get("reason")}

def build_graph(checkpointer: AsyncPostgresSaver):
    """An async graph needs the async checkpointer; PostgresSaver would block the loop."""
    g = StateGraph(dict)
    g.add_node("approval", approval_node)
    g.set_entry_point("approval")
    g.set_finish_point("approval")
    return g.compile(checkpointer=checkpointer)

def _deadline(result: dict) -> datetime:
    """ainvoke returns the interrupt payload under __interrupt__; the SLA lives there."""
    payload = result["__interrupt__"][0].value
    requested = datetime.fromisoformat(payload["requested_at"])
    return requested + timedelta(seconds=payload["sla_seconds"])

# interrupt() suspends the graph and ainvoke() RETURNS as soon as it pauses.
# Wrapping ainvoke in asyncio.wait_for therefore measures graph execution, not
# reviewer response time; a 300 s SLA on the reviewer is never enforced that
# way. The SLA has to be enforced by something that outlives the request: a
# sweeper that scans pending threads and acts on the ones past deadline.

async def start_review(graph, inputs, thread_id: str) -> dict:
    config = {"configurable": {"thread_id": thread_id}}
    result = await graph.ainvoke(inputs, config)     # returns at the interrupt
    await pending_reviews.add(thread_id, deadline=_deadline(result))
    return result

async def sla_sweeper(graph, interval_s: int = 15):
    """Runs forever as a separate task / cron. Enforces reviewer SLAs."""
    while True:
        now = datetime.now(timezone.utc)
        for thread_id, deadline, tier in await pending_reviews.overdue(now):
            config = {"configurable": {"thread_id": thread_id}}
            if tier < 2:
                await escalate_to_senior_reviewer(thread_id)       # Pattern 2
                await pending_reviews.bump(thread_id, tier + 1)
            else:
                # Chain exhausted: resume the graph with an explicit denial so
                # compensation runs and the thread does not sit open forever.
                await graph.ainvoke(
                    Command(resume={"approved": False, "reason": "sla_exhausted"}),
                    config)
                await pending_reviews.remove(thread_id)
        await asyncio.sleep(interval_s)

# Resume after a human decision arrives (webhook / UI handler):
#   await graph.ainvoke(Command(resume={"approved": True}), config=thread_config)
#   await pending_reviews.remove(thread_id)

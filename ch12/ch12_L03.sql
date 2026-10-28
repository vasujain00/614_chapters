-- Walk the write log backward from the first use of the stolen credential.
WITH RECURSIVE chain AS (
    SELECT w.write_id, w.agent_id, w.triggering_trace_id, w.depends_on_write_id, w.written_at, 0 AS depth
      FROM memory_writes w
     WHERE w.write_id = :first_credential_write
  UNION ALL
    SELECT p.write_id, p.agent_id, p.triggering_trace_id, p.depends_on_write_id, p.written_at, c.depth + 1
      FROM memory_writes p JOIN chain c ON p.write_id = c.depends_on_write_id
     WHERE c.depth < 20
)
SELECT c.depth, c.written_at, c.agent_id, e.chosen_route, e.rejected_routes, e.injection_score
  FROM chain c JOIN envelopes e ON e.trace_id = c.triggering_trace_id
 ORDER BY c.depth DESC;        -- oldest first: the entry vector is the last row's chosen_route

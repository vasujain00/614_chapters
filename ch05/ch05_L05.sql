-- Quarantine: tag, never delete. Runs in one statement per store.
UPDATE memory_entries
   SET status = 'quarantined', quarantined_at = now(), incident_id = :incident
 WHERE agent_id = :compromised_agent
   AND written_at >= now() - :lookback_hours * interval '1 hour'
   AND status = 'active';
-- Retrieval already filters on status = 'active', so the effect is immediate.

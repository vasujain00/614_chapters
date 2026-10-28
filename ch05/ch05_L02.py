def filter_reads(hits, trust_db, now, max_age_by_ring, activity):
    """hits: retrieved entries with provenance. Deterministic; no model consulted."""
    kept = []
    for h in hits:
        if trust_db.revoked_since(h.source_id, days=30):
            continue                                  # source lost trust: exclude
        if now - h.written_at > max_age_by_ring[h.ring]:
            continue                                  # past its TTL ceiling: exclude
        if h.needs_freshness_check and not trust_db.still_supported(h):
            continue                                  # source no longer says this
        # Sleeper monitor: dormant entry suddenly active for a new query class.
        a = activity.record(h.id, query_class=h.matched_class, at=now)
        if a.age_days > 30 and a.hits_last_30d <= 1 and a.new_query_class:
            h.flag("dormant_entry_activated")       # retrievable, but surfaced for review
            activity.alert(h)
        kept.append(h)
    return kept

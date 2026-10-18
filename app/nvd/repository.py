import json

from datetime import datetime, timedelta, timezone
from sqlalchemy import text

from app.common.database import db


def get_cache(key: str, ttl_hours: int):
    """Read a cached NVD payload only if its fetch time satisfies the TTL.

    Args:
        key (str): Exact NVD cache key.
        ttl_hours (int): Maximum allowed age of the cached response in hours.

    Returns:
        Any | None: Stored JSON payload, or None for a missing or expired cache entry.
    """
    with db.connect() as conn:
        row = conn.execute(
            text("SELECT payload, fetched_at FROM vuln_nvd_cache WHERE cache_key = :key"),
            {"key": key}
        ).mappings().first()

    if row is None: return None

    expiry = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)

    if row["fetched_at"] < expiry: return None

    return row["payload"]


def save_cache(key: str, payload):
    """Insert or replace an NVD cache payload and reset its fetch timestamp.

    Args:
        key (str): Unique NVD cache key.
        payload (Any): JSON-serializable response data to persist.

    Returns:
        None: No return value.
    """
    with db.transaction() as conn:
        conn.execute(
            text("""
                 INSERT INTO vuln_nvd_cache (cache_key, payload, fetched_at)
                 VALUES (:key, CAST(:payload AS jsonb), NOW())
                 ON CONFLICT (cache_key)
                     DO UPDATE SET payload    = EXCLUDED.payload,
                                   fetched_at = EXCLUDED.fetched_at
                 """),
            {"key": key, "payload": json.dumps(payload)}
        )

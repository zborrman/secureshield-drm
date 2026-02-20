"""
Redis session store for SecureShield DRM.

Key schema
──────────
  session:{session_id}          STRING  JSON payload  TTL = SESSION_TTL_S
  license_sessions:{license_id} SET     of session_id  TTL = SESSION_TTL_S * 2
  revoked:{session_id}          STRING  "1"            TTL = SESSION_TTL_S

Pub/Sub channel
───────────────
  drm:revocations   payload: {"session_id": int, "invoice_id": str, "action": "revoked"}
"""

import json
import os
from redis.asyncio import Redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SESSION_TTL_S = 300          # 5 minutes — keep in sync with SESSION_ACTIVE_MINUTES * 60
REVOCATION_CHANNEL = "drm:revocations"

# Module-level singleton — replaced with a FakeAsyncRedis instance in tests
_redis: Redis | None = None


# ── Connection management ─────────────────────────────────────────────────────

async def get_redis() -> Redis:
    global _redis
    if _redis is None:
        _redis = Redis.from_url(REDIS_URL, decode_responses=True)
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None


# ── Key helpers ───────────────────────────────────────────────────────────────

def _session_key(session_id: int) -> str:
    return f"session:{session_id}"

def _license_sessions_key(license_id: int) -> str:
    return f"license_sessions:{license_id}"

def _revoked_key(session_id: int) -> str:
    return f"revoked:{session_id}"


# ── Session operations ────────────────────────────────────────────────────────

async def register_session(
    session_id: int,
    license_id: int,
    invoice_id: str,
    content_id: str,
    ip_address: str,
) -> None:
    """Write session metadata to Redis after a successful DB insert."""
    r = await get_redis()
    data = json.dumps({
        "session_id": session_id,
        "license_id": license_id,
        "invoice_id": invoice_id,
        "content_id": content_id,
        "ip_address": ip_address,
    })
    async with r.pipeline(transaction=True) as pipe:
        pipe.setex(_session_key(session_id), SESSION_TTL_S, data)
        pipe.sadd(_license_sessions_key(license_id), session_id)
        pipe.expire(_license_sessions_key(license_id), SESSION_TTL_S * 2)
        await pipe.execute()


async def refresh_session(session_id: int) -> None:
    """Reset the TTL on a session's Redis key (called on every heartbeat)."""
    r = await get_redis()
    await r.expire(_session_key(session_id), SESSION_TTL_S)


async def is_revoked(session_id: int) -> bool:
    """Check the ephemeral revocation flag — O(1), sub-millisecond."""
    r = await get_redis()
    return await r.exists(_revoked_key(session_id)) > 0


async def revoke_session(
    session_id: int,
    license_id: int | None = None,
    invoice_id: str = "",
) -> None:
    """
    Set the revocation flag for `session_id` and publish the event.
    The next heartbeat from the viewer will receive {"revoked": true}.
    """
    r = await get_redis()
    async with r.pipeline(transaction=True) as pipe:
        pipe.setex(_revoked_key(session_id), SESSION_TTL_S, "1")
        pipe.delete(_session_key(session_id))
        if license_id is not None:
            pipe.srem(_license_sessions_key(license_id), session_id)
        await pipe.execute()
    await r.publish(REVOCATION_CHANNEL, json.dumps({
        "session_id": session_id,
        "invoice_id": invoice_id,
        "action": "revoked",
    }))


async def revoke_all_for_license(license_id: int, invoice_id: str) -> int:
    """
    Revoke every live session belonging to `license_id`.
    Returns the number of sessions that were revoked.
    """
    r = await get_redis()
    members = await r.smembers(_license_sessions_key(license_id))
    count = 0
    for m in members:
        await revoke_session(int(m), license_id=None, invoice_id=invoice_id)
        count += 1
    await r.delete(_license_sessions_key(license_id))
    return count


async def get_live_sessions() -> list[dict]:
    """
    Return all sessions currently tracked in Redis.
    Fast path for the admin live-sessions panel — no DB query needed.
    """
    r = await get_redis()
    keys = [k async for k in r.scan_iter("session:*")]
    if not keys:
        return []
    values = await r.mget(*keys)
    return [json.loads(v) for v in values if v]

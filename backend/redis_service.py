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

Circuit breaker
───────────────
  Opens after FAILURE_THRESHOLD consecutive Redis errors.
  Allows a probe after RECOVERY_TIMEOUT seconds (half-open).
  All public functions degrade gracefully when the circuit is open:
    - register_session / refresh_session → no-op (fire-and-forget)
    - is_revoked → False  (safe: treat session as valid)
    - get_live_sessions → []
    - revoke_session / revoke_all → logs warning, no-op
"""

import json
import os
import time
from logging_config import get_logger
from redis.asyncio import Redis, RedisError

logger = get_logger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SESSION_TTL_S = 300          # 5 minutes — keep in sync with SESSION_ACTIVE_MINUTES * 60
REVOCATION_CHANNEL = "drm:revocations"

# Module-level singleton — replaced with a FakeAsyncRedis instance in tests
_redis: Redis | None = None


# ── Circuit breaker ───────────────────────────────────────────────────────────

class _CircuitBreaker:
    """Lightweight three-state circuit breaker (CLOSED → OPEN → HALF-OPEN).

    CLOSED   — normal operation; errors are recorded
    OPEN     — Redis is considered down; callers receive fallback values
    HALF-OPEN — one probe allowed after RECOVERY_TIMEOUT; success closes circuit
    """
    FAILURE_THRESHOLD = 3    # consecutive failures before opening
    RECOVERY_TIMEOUT  = 60   # seconds before allowing a probe

    def __init__(self) -> None:
        self._failures = 0
        self._opened_at: float | None = None

    @property
    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if time.monotonic() - self._opened_at >= self.RECOVERY_TIMEOUT:
            return False   # half-open: one probe allowed
        return True

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.FAILURE_THRESHOLD and self._opened_at is None:
            self._opened_at = time.monotonic()
            logger.error("redis_circuit_opened", extra={
                "failures": self._failures,
                "recovery_in_s": self.RECOVERY_TIMEOUT,
            })


_circuit = _CircuitBreaker()


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
    """Write session metadata to Redis after a successful DB insert.

    Fire-and-forget: if Redis is unavailable the session is still valid
    (managed by the DB); we simply lose the real-time revocation capability
    until Redis recovers.
    """
    if _circuit.is_open:
        logger.warning("redis_circuit_open_skip", extra={"op": "register_session"})
        return
    try:
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
        _circuit.record_success()
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "register_session", "error": str(exc)})


async def refresh_session(session_id: int) -> None:
    """Reset the TTL on a session's Redis key (called on every heartbeat)."""
    if _circuit.is_open:
        return
    try:
        r = await get_redis()
        await r.expire(_session_key(session_id), SESSION_TTL_S)
        _circuit.record_success()
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "refresh_session", "error": str(exc)})


async def is_revoked(session_id: int) -> bool:
    """Check the ephemeral revocation flag — O(1), sub-millisecond.

    Returns False when the circuit is open (safe fallback: session treated
    as valid; worst-case a revoked user watches for up to SESSION_TTL_S more
    seconds until the Redis key would have expired anyway).
    """
    if _circuit.is_open:
        logger.warning("redis_circuit_open_skip", extra={"op": "is_revoked"})
        return False
    try:
        r = await get_redis()
        result = await r.exists(_revoked_key(session_id)) > 0
        _circuit.record_success()
        return result
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "is_revoked", "error": str(exc)})
        return False   # safe fallback


async def revoke_session(
    session_id: int,
    license_id: int | None = None,
    invoice_id: str = "",
) -> None:
    """
    Set the revocation flag for `session_id` and publish the event.
    The next heartbeat from the viewer will receive {"revoked": true}.
    """
    if _circuit.is_open:
        logger.warning("redis_circuit_open_skip", extra={"op": "revoke_session",
                                                          "session_id": session_id})
        return
    try:
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
        _circuit.record_success()
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "revoke_session", "error": str(exc)})


async def revoke_all_for_license(license_id: int, invoice_id: str) -> int:
    """
    Revoke every live session belonging to `license_id`.
    Returns the number of sessions that were revoked.
    """
    if _circuit.is_open:
        logger.warning("redis_circuit_open_skip", extra={"op": "revoke_all_for_license"})
        return 0
    try:
        r = await get_redis()
        members = await r.smembers(_license_sessions_key(license_id))
        count = 0
        for m in members:
            await revoke_session(int(m), license_id=None, invoice_id=invoice_id)
            count += 1
        await r.delete(_license_sessions_key(license_id))
        _circuit.record_success()
        return count
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "revoke_all_for_license", "error": str(exc)})
        return 0


async def get_live_sessions() -> list[dict]:
    """
    Return all sessions currently tracked in Redis.
    Fast path for the admin live-sessions panel — no DB query needed.
    """
    if _circuit.is_open:
        return []
    try:
        r = await get_redis()
        keys = [k async for k in r.scan_iter("session:*")]
        if not keys:
            return []
        values = await r.mget(*keys)
        _circuit.record_success()
        return [json.loads(v) for v in values if v]
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "get_live_sessions", "error": str(exc)})
        return []


# ── Generic key-value cache ────────────────────────────────────────────────────
# Used for caching license records to skip repeated DB SELECTs on the hot
# verify-license path.  Keys use a `lic:{invoice_id}` prefix to avoid
# collisions with session keys.

_CACHE_TTL = 60  # seconds before a cached license record is considered stale


async def cache_set(key: str, value: dict, ttl: int = _CACHE_TTL) -> None:
    """Store a dict in Redis as JSON with a TTL.  No-op when circuit is open."""
    if _circuit.is_open:
        return
    try:
        r = await get_redis()
        await r.set(key, json.dumps(value), ex=ttl)
        _circuit.record_success()
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "cache_set", "key": key, "error": str(exc)})


async def cache_get(key: str) -> dict | None:
    """Return a cached dict or None on miss / circuit-open / error."""
    if _circuit.is_open:
        return None
    try:
        r = await get_redis()
        raw = await r.get(key)
        _circuit.record_success()
        return json.loads(raw) if raw else None
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "cache_get", "key": key, "error": str(exc)})
        return None


async def cache_delete(key: str) -> None:
    """Invalidate a cache entry.  No-op when circuit is open."""
    if _circuit.is_open:
        return
    try:
        r = await get_redis()
        await r.delete(key)
        _circuit.record_success()
    except (RedisError, OSError) as exc:
        _circuit.record_failure()
        logger.error("redis_error", extra={"op": "cache_delete", "key": key, "error": str(exc)})

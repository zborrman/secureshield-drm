"""
Category D — Tenant Redis cache tests.

Tests:
  1. Before the first request for a tenant, no cache entry exists in Redis
  2. After the first request, the tenant config is stored in Redis
  3. PATCH /superadmin/tenants/{slug} invalidates the cache entry
  4. DELETE /superadmin/tenants/{slug} invalidates the cache entry
  5. _TENANT_CACHE_TTL constant equals 300 seconds
"""
import os
import pytest

import redis_service
from dependencies import _TENANT_CACHE_TTL

# ── Shared test data ──────────────────────────────────────────────────────────

_SUPER_KEY = os.environ.get("SUPER_ADMIN_KEY", "test-super-admin-key")
_SLUG = "cache-test-tenant"
_ADMIN_KEY = "cache-test-admin-key-32chars-ok!!"


async def _create_tenant(client):
    """Helper: create the shared test tenant via the superadmin API."""
    res = await client.post(
        "/superadmin/tenants",
        params={
            "name": "Cache Test Tenant",
            "slug": _SLUG,
            "admin_key": _ADMIN_KEY,
        },
        headers={"X-Super-Admin-Key": _SUPER_KEY},
    )
    assert res.status_code == 201, f"Tenant creation failed: {res.text}"
    return res.json()


async def _hit_tenant_endpoint(client):
    """Helper: trigger get_current_tenant() by calling GET /tenant/licenses."""
    res = await client.get(
        "/tenant/licenses",
        headers={
            "X-Tenant-ID": _SLUG,
            "X-Admin-Key": _ADMIN_KEY,
        },
    )
    assert res.status_code == 200, f"Tenant endpoint returned {res.status_code}: {res.text}"


# ── 1. Cold-start: no cache before first request ──────────────────────────────

@pytest.mark.asyncio
async def test_first_tenant_request_hits_db_not_cache(client, db_session, fake_redis):
    """Cache entry must not exist before the first tenant-scoped request."""
    await _create_tenant(client)

    cache_key = f"tenant:{_SLUG}"
    cached = await redis_service.cache_get(cache_key)
    assert cached is None, (
        f"Cache should be empty before first request. "
        f"Got: {cached}"
    )


# ── 2. Warm cache after first request ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_second_tenant_request_uses_cache(client, db_session, fake_redis):
    """After the first request, tenant config must be present in Redis cache."""
    await _create_tenant(client)
    await _hit_tenant_endpoint(client)

    cache_key = f"tenant:{_SLUG}"
    cached = await redis_service.cache_get(cache_key)
    assert cached is not None, (
        "Tenant config should be cached in Redis after first request"
    )
    assert cached["slug"] == _SLUG
    assert "admin_key_hash" in cached


# ── 3. Cache invalidated on tenant update ────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_cache_invalidated_on_update(client, db_session, fake_redis):
    """PATCH /superadmin/tenants/{slug} must delete the tenant's Redis cache entry."""
    await _create_tenant(client)
    await _hit_tenant_endpoint(client)

    # Confirm cache is warm
    assert await redis_service.cache_get(f"tenant:{_SLUG}") is not None

    # Update the tenant via superadmin
    res = await client.patch(
        f"/superadmin/tenants/{_SLUG}",
        params={"plan": "pro"},
        headers={"X-Super-Admin-Key": _SUPER_KEY},
    )
    assert res.status_code == 200, f"PATCH failed: {res.text}"

    # Cache must now be gone
    cached = await redis_service.cache_get(f"tenant:{_SLUG}")
    assert cached is None, (
        f"Cache was not invalidated after PATCH. Got: {cached}"
    )


# ── 4. Cache invalidated on tenant delete ────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_cache_invalidated_on_delete(client, db_session, fake_redis):
    """DELETE /superadmin/tenants/{slug} must delete the tenant's Redis cache entry."""
    await _create_tenant(client)
    await _hit_tenant_endpoint(client)

    # Confirm cache is warm
    assert await redis_service.cache_get(f"tenant:{_SLUG}") is not None

    # Delete the tenant via superadmin
    res = await client.delete(
        f"/superadmin/tenants/{_SLUG}",
        headers={"X-Super-Admin-Key": _SUPER_KEY},
    )
    assert res.status_code == 200, f"DELETE failed: {res.text}"

    # Cache must now be gone
    cached = await redis_service.cache_get(f"tenant:{_SLUG}")
    assert cached is None, (
        f"Cache was not invalidated after DELETE. Got: {cached}"
    )


# ── 5. TTL constant ───────────────────────────────────────────────────────────

def test_tenant_cache_ttl_is_300s():
    """_TENANT_CACHE_TTL must equal 300 seconds (5-minute policy)."""
    assert _TENANT_CACHE_TTL == 300, (
        f"Expected _TENANT_CACHE_TTL=300, got {_TENANT_CACHE_TTL}"
    )

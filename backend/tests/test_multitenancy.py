"""
Multi-Tenant SaaS Architecture Tests
=====================================
Tests covering:
  1. Super-admin can create a tenant
  2. Tenant admin can create licenses and they are isolated from other tenants
  3. Wrong tenant admin key → 401
  4. Deactivated tenant → 403
  5. Vault is isolated per tenant (tenant A cannot see tenant B's files)
  6. Analytics are isolated per tenant
"""
import os
import pytest
import pytest_asyncio

SUPER_ADMIN_KEY = os.environ["SUPER_ADMIN_KEY"]  # set in conftest.py


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

async def create_tenant(client, *, name, slug, admin_key, plan="starter"):
    resp = await client.post(
        "/superadmin/tenants",
        params={"name": name, "slug": slug, "admin_key": admin_key, "plan": plan},
        headers={"X-Super-Admin-Key": SUPER_ADMIN_KEY},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def tenant_headers(slug: str, admin_key: str) -> dict:
    return {"X-Tenant-ID": slug, "X-Admin-Key": admin_key}


# ─────────────────────────────────────────────────────────────
# 1. Super-admin can create and list tenants
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_superadmin_create_and_list_tenants(db_session, client):
    t = await create_tenant(client, name="Acme Corp", slug="acme", admin_key="acme-secret-123")
    assert t["slug"] == "acme"
    assert t["plan"] == "starter"
    assert t["is_active"] is True

    list_resp = await client.get(
        "/superadmin/tenants",
        headers={"X-Super-Admin-Key": SUPER_ADMIN_KEY},
    )
    assert list_resp.status_code == 200
    slugs = [t["slug"] for t in list_resp.json()]
    assert "acme" in slugs


# ─────────────────────────────────────────────────────────────
# 2. Tenant admin can create licenses — isolated from other tenants
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_license_isolation(db_session, client):
    await create_tenant(client, name="Tenant A", slug="tenant-a", admin_key="key-a-secret")
    await create_tenant(client, name="Tenant B", slug="tenant-b", admin_key="key-b-secret")

    # Tenant A creates a license
    r = await client.post(
        "/tenant/licenses",
        params={"invoice_id": "INV-A-001", "owner_id": "alice"},
        headers=tenant_headers("tenant-a", "key-a-secret"),
    )
    assert r.status_code == 201

    # Tenant A can see its own license
    r_a = await client.get(
        "/tenant/licenses",
        headers=tenant_headers("tenant-a", "key-a-secret"),
    )
    invoice_ids_a = [lic["invoice_id"] for lic in r_a.json()]
    assert "INV-A-001" in invoice_ids_a

    # Tenant B cannot see Tenant A's license
    r_b = await client.get(
        "/tenant/licenses",
        headers=tenant_headers("tenant-b", "key-b-secret"),
    )
    invoice_ids_b = [lic["invoice_id"] for lic in r_b.json()]
    assert "INV-A-001" not in invoice_ids_b


# ─────────────────────────────────────────────────────────────
# 3. Wrong admin key → 401
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_wrong_tenant_key_rejected(db_session, client):
    await create_tenant(client, name="Secure Co", slug="secure-co", admin_key="correct-key")

    r = await client.get(
        "/tenant/licenses",
        headers=tenant_headers("secure-co", "wrong-key"),
    )
    assert r.status_code == 401


# ─────────────────────────────────────────────────────────────
# 4. Deactivated tenant → 403
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_deactivated_tenant_rejected(db_session, client):
    await create_tenant(client, name="Old Co", slug="old-co", admin_key="old-key")

    # Super-admin deactivates the tenant
    patch_r = await client.patch(
        "/superadmin/tenants/old-co",
        params={"is_active": False},
        headers={"X-Super-Admin-Key": SUPER_ADMIN_KEY},
    )
    assert patch_r.status_code == 200

    # Tenant admin can no longer access
    r = await client.get(
        "/tenant/licenses",
        headers=tenant_headers("old-co", "old-key"),
    )
    assert r.status_code == 403


# ─────────────────────────────────────────────────────────────
# 5. Vault is isolated per tenant
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_vault_isolation(db_session, client, mock_s3):
    await create_tenant(client, name="Vault A", slug="vault-a", admin_key="vault-a-key", plan="starter")
    await create_tenant(client, name="Vault B", slug="vault-b", admin_key="vault-b-key", plan="starter")

    # Tenant A uploads a file
    file_content = b"secret content for vault-a"
    upload_r = await client.post(
        "/tenant/vault/upload",
        files={"file": ("report.txt", file_content, "text/plain")},
        headers=tenant_headers("vault-a", "vault-a-key"),
    )
    assert upload_r.status_code == 201, upload_r.text
    uploaded_id = upload_r.json()["content_id"]

    # Tenant A can list its own file
    list_a = await client.get(
        "/tenant/vault/contents",
        headers=tenant_headers("vault-a", "vault-a-key"),
    )
    assert list_a.status_code == 200
    ids_a = [item["content_id"] for item in list_a.json()]
    assert uploaded_id in ids_a

    # Tenant B cannot see Tenant A's file
    list_b = await client.get(
        "/tenant/vault/contents",
        headers=tenant_headers("vault-b", "vault-b-key"),
    )
    assert list_b.status_code == 200
    ids_b = [item["content_id"] for item in list_b.json()]
    assert uploaded_id not in ids_b


# ─────────────────────────────────────────────────────────────
# 6. Plan limit is enforced
# ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tenant_license_limit_enforced(db_session, client):
    # Create a tenant with max_licenses=2
    await client.post(
        "/superadmin/tenants",
        params={
            "name": "Tiny Co",
            "slug": "tiny-co",
            "admin_key": "tiny-key",
            "plan": "starter",
            "max_licenses": 2,
        },
        headers={"X-Super-Admin-Key": SUPER_ADMIN_KEY},
    )

    hdrs = tenant_headers("tiny-co", "tiny-key")

    r1 = await client.post("/tenant/licenses", params={"invoice_id": "INV-1", "owner_id": "u1"}, headers=hdrs)
    assert r1.status_code == 201

    r2 = await client.post("/tenant/licenses", params={"invoice_id": "INV-2", "owner_id": "u2"}, headers=hdrs)
    assert r2.status_code == 201

    # Third license should be rejected
    r3 = await client.post("/tenant/licenses", params={"invoice_id": "INV-3", "owner_id": "u3"}, headers=hdrs)
    assert r3.status_code == 403
    assert "limit" in r3.json()["detail"].lower()

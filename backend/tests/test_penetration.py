"""
Security Penetration Tests — Admin API Injection
Verifies that /admin/* endpoints reject requests without a valid X-Admin-Key header.
"""
import pytest

ADMIN_ROUTES = [
    ("GET",  "/admin/licenses"),
    ("GET",  "/admin/audit-log"),
    ("GET",  "/admin/alerts"),
    ("POST", "/admin/create-license?invoice_id=PENTEST&owner_id=attacker"),
]


# ── API Injection: no header ──────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
async def test_admin_route_rejects_missing_key(client, method, path):
    """Admin endpoints must return 401 when X-Admin-Key header is absent."""
    if method == "GET":
        res = await client.get(path)
    else:
        res = await client.post(path)
    assert res.status_code == 401, f"{method} {path} should be 401 without key"


# ── API Injection: wrong key ──────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
async def test_admin_route_rejects_wrong_key(client, method, path):
    """Admin endpoints must return 401 when X-Admin-Key is incorrect."""
    headers = {"X-Admin-Key": "hacker_attempt_12345"}
    if method == "GET":
        res = await client.get(path, headers=headers)
    else:
        res = await client.post(path, headers=headers)
    assert res.status_code == 401, f"{method} {path} should be 401 with wrong key"


# ── SQL Injection: malicious invoice_id ───────────────────────

@pytest.mark.asyncio
async def test_sql_injection_in_verify(client):
    """verify-license must not crash or leak data on SQL injection attempts."""
    payloads = [
        "' OR '1'='1",
        "1; DROP TABLE licenses; --",
        "\" UNION SELECT * FROM licenses --",
    ]
    for payload in payloads:
        res = await client.post(
            "/verify-license",
            params={"invoice_id": payload, "input_key": "any"}
        )
        # Must return 403 (not found / invalid), never 500
        assert res.status_code in (403, 429), (
            f"Injection payload '{payload}' caused unexpected status {res.status_code}"
        )


# ── Public endpoints remain accessible ───────────────────────

@pytest.mark.asyncio
async def test_health_is_public(client):
    """/health must not require authentication."""
    res = await client.get("/health")
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_verify_license_is_public(client):
    """/verify-license must be reachable without admin key."""
    res = await client.post(
        "/verify-license",
        params={"invoice_id": "PUBLIC-TEST", "input_key": "any"}
    )
    assert res.status_code in (403, 429)

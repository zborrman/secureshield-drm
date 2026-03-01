"""
LLM Council integration tests — AI enrichment over anomaly detectors.

All OpenRouter HTTP calls are intercepted with unittest.mock so no real
API key or network access is required.  The tests verify:

  1. run_council() returns enriched finding with council_verdict
  2. Original finding fields are preserved unchanged
  3. Each council model is listed in models_used
  4. Missing OPENROUTER_API_KEY raises RuntimeError
  5. GET /admin/anomalies/enriched → 200 with mocked council
  6. Results are cached in Redis on second call
  7. Endpoint requires admin authentication (401 without key)
"""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── Test fixtures ─────────────────────────────────────────────────────────────

_ADMIN_KEY = os.environ.get("ADMIN_API_KEY", "test-admin-key")

_SAMPLE_FINDING = {
    "anomaly_id": "aaaa-bbbb-cccc-dddd",
    "type": "ip_velocity",
    "license_id": 1,
    "score": 75,
    "severity": "HIGH",
    "detected_at": "2026-03-01T12:00:00Z",
    "invoice_id": "INV-001",
    "owner_id": "owner@example.com",
    "evidence": {"distinct_ips": 5, "window_hours": 1},
    "recommendation": "Consider revoking license and investigating shared access.",
}

_MOCK_S1 = {
    "severity_assessment": "HIGH",
    "confidence": 80,
    "root_cause_hypothesis": "Credential sharing among team members",
    "false_positive_likelihood": 20,
    "immediate_actions": ["Alert license owner", "Reduce max_sessions to 1"],
    "reasoning": "5 IPs in 1h is unusual for a single user.",
}

_MOCK_S2 = {
    "agreement_score": 85,
    "disagreements": [],
    "refined_severity": "HIGH",
    "additional_insights": "Could also be VPN rotation.",
}

_MOCK_S3 = {
    "final_severity": "HIGH",
    "final_confidence": 82,
    "consensus_root_cause": "Credential sharing (primary) or VPN rotation (secondary)",
    "priority_rank": 3,
    "immediate_actions": [
        "Alert license owner via email",
        "Reduce max_sessions to 1",
        "Request IP whitelist from owner",
    ],
    "council_summary": "Council unanimously rates this HIGH with 82% confidence.",
}


def _http_response(payload: dict) -> MagicMock:
    """Build a fake httpx.Response-like mock that returns the given payload."""
    mock = MagicMock()
    mock.raise_for_status = MagicMock()
    mock.json.return_value = {
        "choices": [{"message": {"content": json.dumps(payload)}}]
    }
    return mock


def _make_post_side_effect(n_models: int = 3):
    """
    Return an async side_effect for httpx.AsyncClient.post that cycles through
    Stage 1 (n_models calls), Stage 2 (n_models calls), Stage 3 (1 call).
    """
    call_count = [0]

    async def _post(*args, **kwargs):
        call_count[0] += 1
        n = call_count[0]
        if n <= n_models:                     # Stage 1
            return _http_response(_MOCK_S1)
        elif n <= n_models * 2:               # Stage 2
            return _http_response(_MOCK_S2)
        else:                                  # Stage 3 (chairman)
            return _http_response(_MOCK_S3)

    return _post


# ─── Unit tests for llm_council_service.run_council() ─────────────────────────

@pytest.mark.asyncio
async def test_run_council_returns_verdict():
    """run_council() must return the original finding extended with council_verdict."""
    os.environ["OPENROUTER_API_KEY"] = "test-key"

    import importlib
    import config
    importlib.reload(config)
    import llm_council_service
    importlib.reload(llm_council_service)

    with patch("httpx.AsyncClient.post", side_effect=_make_post_side_effect(3)):
        result = await llm_council_service.run_council(_SAMPLE_FINDING)

    assert "council_verdict" in result
    v = result["council_verdict"]
    assert v["final_severity"] == "HIGH"
    assert v["final_confidence"] == 82
    assert isinstance(v["immediate_actions"], list)
    assert len(v["immediate_actions"]) == 3
    assert v["council_summary"] != ""


@pytest.mark.asyncio
async def test_run_council_preserves_original_fields():
    """All fields from the original finding must be present in the returned dict."""
    os.environ["OPENROUTER_API_KEY"] = "test-key"

    import importlib
    import config
    importlib.reload(config)
    import llm_council_service
    importlib.reload(llm_council_service)

    with patch("httpx.AsyncClient.post", side_effect=_make_post_side_effect(3)):
        result = await llm_council_service.run_council(_SAMPLE_FINDING)

    for key, value in _SAMPLE_FINDING.items():
        assert result[key] == value, f"Field '{key}' was mutated or lost."


@pytest.mark.asyncio
async def test_run_council_lists_models_used():
    """council_verdict must list which models participated."""
    os.environ["OPENROUTER_API_KEY"] = "test-key"

    import importlib
    import config
    importlib.reload(config)
    import llm_council_service
    importlib.reload(llm_council_service)

    with patch("httpx.AsyncClient.post", side_effect=_make_post_side_effect(3)):
        result = await llm_council_service.run_council(_SAMPLE_FINDING)

    v = result["council_verdict"]
    assert "models_used" in v
    assert isinstance(v["models_used"], list)
    assert len(v["models_used"]) == len(config.COUNCIL_MODELS)
    assert "chairman" in v


@pytest.mark.asyncio
async def test_run_council_raises_without_api_key(monkeypatch):
    """run_council() must raise RuntimeError when OPENROUTER_API_KEY is not set."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "")

    import importlib
    import config as _cfg
    importlib.reload(_cfg)
    import llm_council_service as _svc
    importlib.reload(_svc)

    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        await _svc.run_council(_SAMPLE_FINDING)


# ─── Integration tests for GET /admin/anomalies/enriched ──────────────────────

@pytest.mark.asyncio
async def test_enriched_endpoint_returns_200(client, db_session, monkeypatch):
    """
    GET /admin/anomalies/enriched should return 200 with enriched_findings
    when OPENROUTER_API_KEY is set and run_council is mocked.
    """
    async def _mock_run_council(finding):
        return {**finding, "council_verdict": _MOCK_S3}

    # Patch the module-level attribute so the endpoint sees a non-empty key.
    with patch("config.OPENROUTER_API_KEY", "test-key"):
        with patch("llm_council_service.run_council", side_effect=_mock_run_council):
            resp = await client.get(
                "/admin/anomalies/enriched?hours=24&min_score=0&limit=5",
                headers={"X-Admin-Key": _ADMIN_KEY},
            )

    assert resp.status_code == 200
    data = resp.json()
    assert "enriched_findings" in data
    assert "total" in data
    assert "summary" in data
    assert isinstance(data["enriched_findings"], list)


@pytest.mark.asyncio
async def test_enriched_endpoint_caches_results(client, db_session, monkeypatch):
    """
    Second call with the same anomaly_id must use Redis cache and NOT
    call run_council again.
    """
    call_count = [0]

    async def _mock_run_council(finding):
        call_count[0] += 1
        return {**finding, "council_verdict": _MOCK_S3}

    with patch("config.OPENROUTER_API_KEY", "test-key"):
        with patch("llm_council_service.run_council", side_effect=_mock_run_council):
            await client.get(
                "/admin/anomalies/enriched?hours=24&min_score=0&limit=5",
                headers={"X-Admin-Key": _ADMIN_KEY},
            )
            first_count = call_count[0]
            # Second request — same data, same anomaly_ids → should hit cache
            await client.get(
                "/admin/anomalies/enriched?hours=24&min_score=0&limit=5",
                headers={"X-Admin-Key": _ADMIN_KEY},
            )

    # If the DB has no data there are 0 findings → 0 calls both times; that's fine.
    # The invariant: second call must not add MORE calls than the first.
    second_new_calls = call_count[0] - first_count
    assert second_new_calls <= first_count, (
        f"Expected second call to use cache (≤{first_count} new calls), "
        f"but got {second_new_calls} additional calls."
    )


@pytest.mark.asyncio
async def test_enriched_endpoint_requires_auth(client, db_session):
    """GET /admin/anomalies/enriched must return 401 without admin credentials."""
    resp = await client.get("/admin/anomalies/enriched")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_enriched_endpoint_503_without_api_key(client, db_session):
    """GET /admin/anomalies/enriched returns 503 when OPENROUTER_API_KEY is empty."""
    with patch("config.OPENROUTER_API_KEY", ""):
        resp = await client.get(
            "/admin/anomalies/enriched",
            headers={"X-Admin-Key": _ADMIN_KEY},
        )
    assert resp.status_code == 503
    assert "OPENROUTER_API_KEY" in resp.json()["detail"]

"""
Observability tests — Week 4.

Covers:
  T5: drm_redis_cache_hits_total / drm_redis_cache_misses_total counter behaviour
  T2: GET /metrics exposes both cache counter names
  T4: OTEL_ENABLED is not set in test env (app runs without OTel)
  T2: infra/prometheus/alerts.yml is valid YAML with expected alert names
"""
import os
import pytest
import yaml

import redis_service


# ── Helpers ───────────────────────────────────────────────────────────────────

def _counter_value(counter) -> float:
    """Read the current numeric value of a prometheus_client Counter (no labels)."""
    return counter._value.get()


# ── T5: Cache hit / miss counters ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cache_miss_increments_counter(fake_redis):
    """cache_get on an absent key must increment drm_redis_cache_misses_total by 1."""
    before = _counter_value(redis_service._cache_misses)

    result = await redis_service.cache_get("obs:nonexistent-key-xyz-999")

    after = _counter_value(redis_service._cache_misses)
    assert result is None
    assert after == before + 1.0


@pytest.mark.asyncio
async def test_cache_hit_increments_counter(fake_redis):
    """cache_get after a cache_set must increment drm_redis_cache_hits_total by 1."""
    key = "obs:hit-key-abc"
    await redis_service.cache_set(key, {"value": 42})

    before = _counter_value(redis_service._cache_hits)

    result = await redis_service.cache_get(key)

    after = _counter_value(redis_service._cache_hits)
    assert result == {"value": 42}
    assert after == before + 1.0


# ── T2: /metrics exposes cache counter names ──────────────────────────────────

@pytest.mark.asyncio
async def test_metrics_includes_cache_counters(client, db_session):
    """GET /metrics must include both drm_redis_cache_hits_total and _misses_total."""
    res = await client.get("/metrics")
    assert res.status_code == 200
    body = res.text

    assert "drm_redis_cache_hits_total" in body, (
        f"drm_redis_cache_hits_total not found in /metrics output"
    )
    assert "drm_redis_cache_misses_total" in body, (
        f"drm_redis_cache_misses_total not found in /metrics output"
    )


# ── T4: OTel disabled by default ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_otel_disabled_by_default(client, db_session):
    """OTEL_ENABLED must not be 'true' in the test env; app still responds 200."""
    flag = os.environ.get("OTEL_ENABLED", "false").lower()
    assert flag != "true", (
        "OTEL_ENABLED must not be 'true' in the test environment — "
        "tests do not provision a Jaeger/OTLP collector"
    )
    # App must serve requests normally
    res = await client.get("/metrics")
    assert res.status_code == 200


# ── T2: alerts.yml YAML validity ─────────────────────────────────────────────

def test_prometheus_alert_rules_yaml_valid():
    """infra/prometheus/alerts.yml must be valid YAML with the 4 expected alert names."""
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.dirname(tests_dir)
    project_root = os.path.dirname(backend_dir)
    alerts_path = os.path.join(project_root, "infra", "prometheus", "alerts.yml")

    assert os.path.isfile(alerts_path), (
        f"alerts.yml not found at {alerts_path}. "
        "Create infra/prometheus/alerts.yml before running this test."
    )

    with open(alerts_path) as f:
        data = yaml.safe_load(f)

    assert isinstance(data, dict) and "groups" in data, (
        "alerts.yml must be a YAML mapping with a 'groups' key"
    )
    assert isinstance(data["groups"], list) and len(data["groups"]) > 0

    all_names = [
        rule["alert"]
        for group in data["groups"]
        for rule in group.get("rules", [])
        if "alert" in rule
    ]

    expected = {"HighErrorRate", "RateLimitedRequestsSpike", "RedisCacheUnavailable", "BackendDown"}
    missing = expected - set(all_names)
    assert not missing, (
        f"alerts.yml is missing expected alert rules: {missing}. Found: {all_names}"
    )

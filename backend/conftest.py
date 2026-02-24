import os
import base64
import pytest
import pytest_asyncio
import asyncio

# Use in-memory SQLite for tests — no PostgreSQL required locally.
# Must be set BEFORE database.py / main.py are imported.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_drm.db")
# Disable rate limiting in tests — all test requests share "testclient" as the IP.
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")

# Must be set BEFORE main.py is imported — ADMIN_API_KEY is read at module level
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")
# PyJWT ≥ 2.9 requires HMAC keys ≥ 32 bytes for HS256 — set an explicit secret
# so the default derivation (ADMIN_API_KEY + "-offline-v1" = 25 bytes) is not used.
os.environ.setdefault("OFFLINE_TOKEN_SECRET", "test-offline-secret-for-jwt-hs256!")
os.environ.setdefault("VAULT_TOKEN_SECRET",   "test-vault-token-secret-for-jwt32!")

# Multi-tenant super-admin key
os.environ.setdefault("SUPER_ADMIN_KEY", "test-super-admin-key")

# Vault / S3 settings — set before any vault_service import
os.environ.setdefault(
    "VAULT_MASTER_KEY",
    base64.urlsafe_b64encode(b"test_vault_32byte_key_for_tests!").decode(),
)
os.environ.setdefault("S3_BUCKET", "test-secureshield-vault")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import fakeredis
import redis_service as _redis_service

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from database import Base, DATABASE_URL
from main import app
from dependencies import get_db
import stripe_service as _stripe_service

# NullPool: no connection caching — each call gets a fresh connection.
# This prevents "another operation is in progress" when pytest-asyncio
# creates a new event loop per test while the engine holds old connections.
# Critical for PostgreSQL (asyncpg): the default AsyncAdaptedQueuePool caches
# connections that are event-loop-bound. pytest-asyncio 1.x gives each test
# its own event loop, so a pooled connection from test N-1's loop raises
# RuntimeError in test N's loop. NullPool avoids this entirely.
test_engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
TestSessionLocal = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


async def _get_test_db():
    """Drop-in replacement for get_db that uses the test engine."""
    async with TestSessionLocal() as session:
        yield session


# Override FastAPI's get_db dependency for ALL tests
app.dependency_overrides[get_db] = _get_test_db

# stripe_service.handle_payment_success() creates sessions via database.SessionLocal
# (the app's default QueuePool engine), NOT through FastAPI's get_db dependency.
# When called directly in tests it bypasses the dependency override above, so we
# patch its module-level SessionLocal to also use the NullPool test factory.
_stripe_service.SessionLocal = TestSessionLocal


@pytest_asyncio.fixture(autouse=True)
async def fake_redis():
    """
    Replace the module-level Redis singleton with an in-memory FakeAsyncRedis
    before every test, then tear it down after.  autouse=True means every test
    automatically gets a clean Redis state without needing to request the fixture.
    """
    r = fakeredis.FakeAsyncRedis(decode_responses=True)
    _redis_service._redis = r
    yield r
    await r.aclose()
    _redis_service._redis = None


@pytest.fixture(scope="session")
def event_loop():
    """
    Session-scoped event loop — all async tests share a single loop.

    Even with NullPool, SQLAlchemy's AsyncEngine holds loop-bound internal
    asyncio state (Conditions, Events) that is bound to whichever loop first
    uses the engine.  pytest-asyncio's default function-scoped loops mean each
    test runs in a NEW loop, so later tests see asyncpg Futures from a previous
    loop and raise "Future attached to a different loop" during
    AsyncSession.close() → asyncio.shield().

    Providing a session-scoped event_loop forces every async test function and
    every async fixture to run in this single loop, eliminating the mismatch.

    Deprecated in pytest-asyncio 0.21 but still functional through 0.24+
    (produces a DeprecationWarning, which does not fail CI).
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """Recreate all tables fresh before every test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture(scope="function")
async def admin_client():
    """HTTP client pre-loaded with the test admin key header."""
    transport = ASGITransport(app=app)
    headers = {"X-Admin-Key": os.environ["ADMIN_API_KEY"]}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac


@pytest.fixture
def mock_s3():
    """
    Spin up an in-process moto S3 mock for vault tests.

    NOT autouse — only vault tests request this fixture explicitly.
    The fixture resets vault_service._s3 before and after so the lazy
    singleton is re-created inside the mock context each time.
    """
    from moto import mock_aws
    import boto3
    import vault_service

    with mock_aws():
        vault_service._s3 = None  # force re-init inside mock context
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket=vault_service.S3_BUCKET
        )
        yield
        vault_service._s3 = None  # teardown — next test gets a fresh client

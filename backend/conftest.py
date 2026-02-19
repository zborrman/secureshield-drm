import os
import pytest
import pytest_asyncio
import asyncio

# Must be set BEFORE main.py is imported — ADMIN_API_KEY is read at module level
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from database import Base, DATABASE_URL
from main import app, get_db

# NullPool: no connection caching — each call gets a fresh connection.
# This prevents "another operation is in progress" when pytest-asyncio
# creates a new event loop per test while the engine holds old connections.
test_engine = create_async_engine(DATABASE_URL, poolclass=NullPool)
TestSessionLocal = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


async def _get_test_db():
    """Drop-in replacement for get_db that uses the test engine."""
    async with TestSessionLocal() as session:
        yield session


# Override FastAPI's get_db dependency for ALL tests
app.dependency_overrides[get_db] = _get_test_db


@pytest.fixture(scope="session")
def event_loop_policy():
    return asyncio.DefaultEventLoopPolicy()


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

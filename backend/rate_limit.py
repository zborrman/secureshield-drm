"""
Rate limiting — shared Limiter instance used across all routers.

In production  (RATE_LIMIT_ENABLED=true, the default):
  /analytics/start          60 req/min  per IP
  /admin/create-license     200 req/min per IP  (admin key already guards the route)
  /superadmin/tenants POST  30 req/min  per IP
  /tenant/licenses POST     100 req/min per IP

In test / development (RATE_LIMIT_ENABLED=false):
  All limits are raised to 100 000/minute — effectively disabled.
  Set in conftest.py via os.environ.setdefault("RATE_LIMIT_ENABLED", "false").
"""
import os
from slowapi import Limiter
from slowapi.util import get_remote_address

# Evaluated once at import time.
# conftest.py sets the env var BEFORE importing main/routers, so this is safe.
_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() != "false"

limiter = Limiter(key_func=get_remote_address)


def _limit(real: str) -> str:
    """Return the real limit in production, or an effectively-unlimited value in test mode."""
    return real if _ENABLED else "100000/minute"


# Named limit strings — import these in routers for the @limiter.limit() decorator.
ANALYTICS_LIMIT     = _limit("60/minute")
ADMIN_WRITE_LIMIT   = _limit("200/minute")
SUPERADMIN_LIMIT    = _limit("30/minute")
TENANT_WRITE_LIMIT  = _limit("100/minute")

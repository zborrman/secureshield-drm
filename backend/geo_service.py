"""
Geolocation service for Dynamic Geofencing.

Public IPs  → resolved via ip-api.com (free, no key, ~1000 req/min).
Private/local IPs (127.x, 10.x, 192.168.x, ::1, 'testclient', etc.)
    → returned as "XX" without any HTTP call, keeping tests fast.

Failures (API unreachable, timeout, invalid JSON) → fail-open with "XX"
so a transient DNS blip never locks out legitimate users.
"""

import ipaddress
import httpx

# Sentinel returned for private / unresolvable addresses
LOCAL_COUNTRY = "XX"

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip: str) -> bool:
    """True for private/local/loopback addresses and non-IP strings (e.g. 'testclient')."""
    if ip in ("testclient", "localhost", ""):
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


async def get_country_code(ip: str) -> str:
    """Return ISO-3166-1 alpha-2 country code for *ip*, or LOCAL_COUNTRY ('XX') for private/local IPs."""
    if _is_private(ip):
        return LOCAL_COUNTRY
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            res = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,countryCode"},
            )
            data = res.json()
            if data.get("status") == "success":
                return data["countryCode"].upper()
    except Exception:
        pass
    return LOCAL_COUNTRY  # fail-open: never block on API errors


def is_permitted(country: str, allowed_countries: str | None) -> bool:
    """True if *country* is in the comma-separated *allowed_countries* list (or the license is unrestricted)."""
    if not allowed_countries:
        return True
    allowed = {c.strip().upper() for c in allowed_countries.split(",") if c.strip()}
    return country.upper() in allowed

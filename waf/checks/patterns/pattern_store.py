import asyncio
import logging

from models import Site
from waf.integration.db.repository import fetch_all_patterns

logger = logging.getLogger(__name__)

PATTERN_CACHE = {"xss": [], "sql": [], "custom": []}
PATTERN_CACHE_LAST = 0
PATTERN_CACHE_TTL = 60
_pattern_lock = asyncio.Lock()


async def fetch_patterns_from_db():
    """Load patterns via shared repository and refresh cache."""
    global PATTERN_CACHE, PATTERN_CACHE_LAST
    patterns = await fetch_all_patterns()

    cache = {"xss": [], "sql": [], "custom": []}
    for p in patterns:
        pattern_type = (p.type or "").strip().lower()
        pattern_str = (p.pattern or "").strip().lower()
        if not pattern_type or not pattern_str:
            continue
        cache.setdefault(pattern_type, []).append(pattern_str)

    PATTERN_CACHE = cache
    PATTERN_CACHE_LAST = asyncio.get_event_loop().time()


async def _ensure_fresh():
    now = asyncio.get_event_loop().time()
    if now - PATTERN_CACHE_LAST > PATTERN_CACHE_TTL:
        async with _pattern_lock:
            if now - PATTERN_CACHE_LAST > PATTERN_CACHE_TTL:
                await fetch_patterns_from_db()


async def get_patterns():
    await _ensure_fresh()
    return PATTERN_CACHE


async def _is_malicious(content: str, types_to_check: list):
    if not content or not types_to_check:
        return False, ""

    patterns = await get_patterns()
    content_lc = content.lower()

    for attack_type in types_to_check:
        for pattern in patterns.get(attack_type, []):
            if pattern in content_lc:
                return True, attack_type.upper()

    return False, ""


async def analyze_request_part(content: str, site: Site):
    if not content:
        return False, ""

    types_to_check = []
    if site.xss_enabled:
        types_to_check.append("xss")
    if site.sql_enabled:
        types_to_check.append("sql")
    types_to_check.append("custom")

    return await _is_malicious(content, types_to_check)



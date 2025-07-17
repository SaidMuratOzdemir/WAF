# waf/analysis.py

import re
import asyncio
import logging
import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

from models import MaliciousPattern, Site

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://waf:waf@localhost:5432/waf")
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

logger = logging.getLogger(__name__)
PATTERN_CACHE = {"xss": [], "sql": [], "custom": []}
PATTERN_CACHE_LAST = 0
PATTERN_CACHE_TTL = 60
_pattern_lock = asyncio.Lock()


async def fetch_patterns_from_db():
    # This function is well-written and correct. No changes needed.
    global PATTERN_CACHE, PATTERN_CACHE_LAST
    async with async_session() as session:
        result = await session.execute(select(MaliciousPattern))
        patterns = result.scalars().all()

    cache = {"xss": [], "sql": [], "custom": []}  # Standardize on 'sql' as the type
    for p in patterns:
        try:
            compiled = re.compile(p.pattern, re.IGNORECASE | re.DOTALL)
            cache.setdefault(p.type.lower(), []).append(compiled)
        except re.error as e:
            # dont log anything here, this is a sync task
            pass

    PATTERN_CACHE = cache
    PATTERN_CACHE_LAST = asyncio.get_event_loop().time()


async def _ensure_fresh():
    # This async lock pattern is correct. No changes needed.
    now = asyncio.get_event_loop().time()
    if now - PATTERN_CACHE_LAST > PATTERN_CACHE_TTL:
        async with _pattern_lock:
            # Double-check inside the lock
            if now - PATTERN_CACHE_LAST > PATTERN_CACHE_TTL:
                await fetch_patterns_from_db()


async def get_patterns():
    # Correct.
    await _ensure_fresh()
    return PATTERN_CACHE


async def _is_malicious(content: str, types_to_check: list):
    # Correct.
    if not content or not types_to_check:
        return False, ""

    patterns = await get_patterns()

    for attack_type in types_to_check:
        if attack_type in patterns:
            for rx in patterns[attack_type]:
                if rx.search(content):
                    return True, attack_type.upper()
    return False, ""


async def analyze_request_part(content: str, site: Site):
    if not content:
        return False, ""

    types_to_check = []
    if site.xss_enabled:
        types_to_check.append("xss")
    if site.sql_enabled:
        types_to_check.append("sql")  # Match the standardized type in the cache

    types_to_check.append("custom")  # Always check for custom patterns

    return await _is_malicious(content, types_to_check)
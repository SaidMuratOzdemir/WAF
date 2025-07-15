import re
import asyncio
import logging
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
import os

from database import Site  # <-- needed for type hints

Base = declarative_base()

class MaliciousPattern(Base):
    __tablename__ = "malicious_patterns"
    id = Column(Integer, primary_key=True)
    pattern = Column(String, nullable=False)
    type = Column(String, nullable=False)
    description = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://waf:waf@localhost:5432/waf"
)
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

logger = logging.getLogger(__name__)
PATTERN_CACHE = {"xss": [], "sql": [], "custom": []}
PATTERN_CACHE_LAST = 0
PATTERN_CACHE_TTL = 60
_pattern_lock = asyncio.Lock()

async def fetch_patterns_from_db():
    global PATTERN_CACHE, PATTERN_CACHE_LAST
    async with async_session() as session:
        result = await session.execute(select(MaliciousPattern))
        patterns = result.scalars().all()

    cache = {"xss": [], "sql": [], "custom": []}
    for p in patterns:
        try:
            compiled = re.compile(p.pattern, re.IGNORECASE | re.DOTALL)
            cache.setdefault(p.type.lower(), []).append(compiled)
        except re.error as e:
            logger.warning(f"Invalid regex id={p.id}: {p.pattern} ({e})")

    PATTERN_CACHE = cache
    PATTERN_CACHE_LAST = asyncio.get_event_loop().time()
    logger.info(
        f"Pattern cache loaded: {sum(len(v) for v in PATTERN_CACHE.values())} patterns."
    )

async def _ensure_fresh():
    now = asyncio.get_event_loop().time()
    if now - PATTERN_CACHE_LAST > PATTERN_CACHE_TTL:
        async with _pattern_lock:
            if now - PATTERN_CACHE_LAST > PATTERN_CACHE_TTL:
                await fetch_patterns_from_db()

async def get_patterns():
    await _ensure_fresh()
    return PATTERN_CACHE

async def _is_malicious(content: str, xss: bool, sql: bool):
    if not content:
        return False, ""
    patterns = await get_patterns()
    if xss:
        for rx in patterns["xss"]:
            if rx.search(content):
                return True, "XSS"
    if sql:
        for rx in patterns["sql"]:
            if rx.search(content):
                return True, "SQL_INJECTION"
    for rx in patterns["custom"]:
        if rx.search(content):
            return True, "CUSTOM"
    return False, ""

async def check_body_for_malicious(body: str, site: Site):
    return await _is_malicious(body, site.xss_enabled, site.sql_enabled)

async def check_path_for_malicious(path: str, site: Site):
    return await _is_malicious(path, site.xss_enabled, site.sql_enabled)

async def check_query_for_malicious(query: str, site: Site):
    return await _is_malicious(query, site.xss_enabled, site.sql_enabled)

async def check_headers_for_malicious(headers: dict, site: Site):
    skip = {
        'user-agent','accept','accept-encoding','accept-language','cookie',
        'connection','host','cache-control','upgrade-insecure-requests',
        'sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform',
        'sec-fetch-site','sec-fetch-mode','sec-fetch-dest'
    }
    lines = [f"{h}: {v}" for h, v in headers.items() if h.lower() not in skip]
    return await _is_malicious("\n".join(lines), site.xss_enabled, site.sql_enabled)

# analysis.py
import re
import asyncio
import logging
import os
from typing import Dict, List, Tuple
from database import Site
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
logger = logging.getLogger(__name__)

class MaliciousPattern(Base):
    __tablename__ = "malicious_patterns"
    id = Column(Integer, primary_key=True)
    pattern = Column(String, nullable=False)
    type = Column(String, nullable=False)
    description = Column(String)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://waf:waf@localhost:5432/waf")
engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Cache için
PATTERN_CACHE: Dict[str, List[re.Pattern]] = {"xss": [], "sql": [], "custom": []}
PATTERN_CACHE_LAST_UPDATE: float = 0
PATTERN_CACHE_TTL: int = 60
PATTERN_CACHE_LOCK = asyncio.Lock()

async def fetch_patterns_from_db():
    global PATTERN_CACHE, PATTERN_CACHE_LAST_UPDATE
    async with PATTERN_CACHE_LOCK:
        try:
            async with async_session() as session:
                result = await session.execute(select(MaliciousPattern))
                patterns = result.scalars().all()
            new_cache: Dict[str, List[re.Pattern]] = {"xss": [], "sql": [], "custom": []}
            for p in patterns:
                category = p.type.lower() if p.type else "custom"
                try:
                    compiled = re.compile(p.pattern, re.IGNORECASE | re.DOTALL)
                    new_cache.setdefault(category, []).append(compiled)
                except re.error as err:
                    logger.warning(f"Invalid regex id={p.id}: {p.pattern} ({err})")
            PATTERN_CACHE = new_cache
            PATTERN_CACHE_LAST_UPDATE = asyncio.get_event_loop().time()
            logger.info(f"Pattern cache loaded: {{sum(len(v) for v in PATTERN_CACHE.values())}} patterns.")
        except Exception:
            logger.exception("Error fetching patterns from DB")

async def ensure_patterns_fresh():
    now = asyncio.get_event_loop().time()
    if now - PATTERN_CACHE_LAST_UPDATE > PATTERN_CACHE_TTL:
        await fetch_patterns_from_db()

async def is_malicious_content(content: str, xss_enabled: bool, sql_enabled: bool) -> Tuple[bool, str]:
    if not content:
        return False, ""
    await ensure_patterns_fresh()
    txt = content.lower()
    if xss_enabled:
        for patt in PATTERN_CACHE.get("xss", []):
            if patt.search(txt):
                return True, "XSS"
    if sql_enabled:
        for patt in PATTERN_CACHE.get("sql", []):
            if patt.search(txt):
                return True, "SQL_INJECTION"
    for patt in PATTERN_CACHE.get("custom", []):
        if patt.search(txt):
            return True, "CUSTOM"
    return False, ""

# Casper işlevleri
async def check_body_for_malicious(body: str, site: Site) -> Tuple[bool, str]:
    return await is_malicious_content(body, site.xss_enabled, site.sql_enabled)

async def check_path_for_malicious(path: str, site: Site) -> Tuple[bool, str]:
    return await is_malicious_content(path, site.xss_enabled, site.sql_enabled)

async def check_query_for_malicious(query: str, site: Site) -> Tuple[bool, str]:
    return await is_malicious_content(query, site.xss_enabled, site.sql_enabled)

async def check_headers_for_malicious(headers: dict, site: Site) -> Tuple[bool, str]:
    skip = {
        'user-agent','accept','accept-encoding','accept-language','cookie',
        'connection','host','cache-control','upgrade-insecure-requests',
        'sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform',
        'sec-fetch-site','sec-fetch-mode','sec-fetch-dest'
    }
    for h, v in headers.items():
        if h.lower() in skip:
            continue
        mal, attack = await is_malicious_content(f"{h}: {v}", site.xss_enabled, site.sql_enabled)
        if mal:
            return True, attack
    return False, ""

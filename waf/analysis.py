import re
from typing import Tuple, List, Dict
from database import Site
import aiohttp
import asyncio
import logging

logger = logging.getLogger(__name__)

PATTERN_CACHE: Dict[str, List[str]] = {"xss": [], "sql": [], "custom": []}
PATTERN_CACHE_LAST_UPDATE = 0
PATTERN_CACHE_TTL = 60  # saniye
PATTERN_API_URL = "http://api:8001/api/patterns"  # docker-compose içi erişim

async def fetch_patterns_from_api():
    print("PATTERN FETCH DENEMESİ")
    global PATTERN_CACHE, PATTERN_CACHE_LAST_UPDATE
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(PATTERN_API_URL) as resp:
                if resp.status == 200:
                    patterns = await resp.json()
                    print("PATTERN API RESPONSE:", patterns)
                    PATTERN_CACHE = {"xss": [], "sql": [], "custom": []}
                    for p in patterns:
                        t = p.get("type", "custom").lower()
                        PATTERN_CACHE.setdefault(t, []).append(p["pattern"])
                    PATTERN_CACHE_LAST_UPDATE = asyncio.get_event_loop().time()
                    logger.info(f"Pattern cache updated: {sum(len(v) for v in PATTERN_CACHE.values())} patterns.")
                    print("PATTERN CACHE:", PATTERN_CACHE)
                else:
                    logger.error(f"Pattern fetch failed: status {resp.status}")
                    print(f"Pattern fetch failed: status {resp.status}")
    except Exception as e:
        logger.error(f"Pattern fetch error: {e}")
        print(f"Pattern fetch error: {e}")

async def ensure_patterns_fresh():
    now = asyncio.get_event_loop().time()
    if now - PATTERN_CACHE_LAST_UPDATE > PATTERN_CACHE_TTL:
        await fetch_patterns_from_api()

async def get_patterns() -> Dict[str, List[str]]:
    await ensure_patterns_fresh()
    return PATTERN_CACHE

async def is_malicious_content(content: str, xss_enabled: bool, sql_enabled: bool) -> Tuple[bool, str]:
    """
    İçeriği XSS ve SQL injection açısından analiz eder.
    """
    if not content:
        return False, ""
    txt = content.lower()
    patterns = await get_patterns()
    if xss_enabled:
        for p in patterns.get("xss", []):
            if re.search(p, txt, re.IGNORECASE | re.DOTALL):
                return True, "XSS"
    if sql_enabled:
        for p in patterns.get("sql", []):
            if re.search(p, txt, re.IGNORECASE | re.DOTALL):
                return True, "SQL_INJECTION"
    for p in patterns.get("custom", []):
        if re.search(p, txt, re.IGNORECASE | re.DOTALL):
            return True, "CUSTOM"
    return False, ""

async def check_body_for_malicious(body: str, site: Site) -> Tuple[bool, str]:
    """Body içeriğini analiz eder."""
    return await is_malicious_content(body, site.xss_enabled, site.sql_enabled)

async def check_path_for_malicious(path: str, site: Site) -> Tuple[bool, str]:
    """URL path analizini yapar."""
    return await is_malicious_content(path, site.xss_enabled, site.sql_enabled)

async def check_query_for_malicious(query: str, site: Site) -> Tuple[bool, str]:
    """Query string analizini yapar."""
    return await is_malicious_content(query, site.xss_enabled, site.sql_enabled)

async def check_headers_for_malicious(headers: dict, site: Site) -> Tuple[bool, str]:
    """Header analizini yapar. Zararlı header varsa True döner."""
    skip = {'user-agent','accept','accept-encoding','accept-language','cookie',
            'connection','host','cache-control','upgrade-insecure-requests',
            'sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform',
            'sec-fetch-site','sec-fetch-mode','sec-fetch-dest'}
    for h, v in headers.items():
        if h.lower() in skip:
            continue
        mal, attack = await is_malicious_content(f"{h}: {v}", site.xss_enabled, site.sql_enabled)
        if mal:
            return True, attack
    return False, "" 
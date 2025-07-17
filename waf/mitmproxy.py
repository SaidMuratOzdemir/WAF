import asyncio
import logging
import json
import time
import os
import re
from typing import Dict, List
from mitmproxy import http

# --- Database Imports and Setup ---
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select

# <<< FIX: Import the model from the shared file to avoid duplication
from models import MaliciousPattern

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# <<< FIX: Removed the fragile string replacement. Rely on the environment variable directly.
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Fail fast if the database URL isn't configured.
    raise ValueError("DATABASE_URL environment variable is not set for mitmproxy!")

engine = create_async_engine(DATABASE_URL, echo=False)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# --- End of Database Setup ---


class SyncedAnalysisAddon:
    def __init__(self):
        self.pattern_cache: Dict[str, List[re.Pattern]] = {}
        self.pattern_fetch_interval = 60  # Fetch every 60 seconds

        # mitmproxy provides its own event loop, which we should use.
        self.loop = asyncio.get_running_loop()
        self.fetch_task = self.loop.create_task(self.pattern_updater())

    async def fetch_patterns_from_db(self):
        """Fetches the latest WAF rules from the database."""
        async with async_session() as session:
            result = await session.execute(select(MaliciousPattern))
            patterns = result.scalars().all()

        cache: Dict[str, List[re.Pattern]] = {}
        for p in patterns:
            try:
                compiled = re.compile(p.pattern, re.IGNORECASE | re.DOTALL)
                cache.setdefault(p.type.lower(), []).append(compiled)
            except re.error as e:
                pass

        self.pattern_cache = cache
        pass

    async def pattern_updater(self):
        """Background task to periodically refresh the patterns."""
        while True:
            try:
                await self.fetch_patterns_from_db()
            except Exception as e:
                # Be specific about the error
                logger.error(f"DB SYNC: Unhandled exception during pattern fetch: {e}", exc_info=True)
            await asyncio.sleep(self.pattern_fetch_interval)

    def _analyze_content(self, content: str) -> List[Dict[str, str]]:
        """Analyzes a single piece of content against the synchronized patterns."""
        suspicious_hits = []
        if not self.pattern_cache or not content:
            return suspicious_hits

        for attack_type, patterns in self.pattern_cache.items():
            for rx in patterns:
                if rx.search(content):
                    suspicious_hits.append({
                        "type": attack_type,
                        "pattern_matched": rx.pattern
                    })
        return suspicious_hits

    def request(self, flow: http.HTTPFlow) -> None:
        """Analyze incoming requests using synchronized rules. This is a sync method."""
        client_ip = flow.client_conn.address[0] if flow.client_conn.address else "unknown"

        parts_to_check = {
            "PATH": flow.request.path,
            "QUERY": flow.request.query_string,
            "BODY": flow.request.get_text(strict=False),
            **{f"HEADER_{k}": v for k, v in flow.request.headers.items()}
        }

        all_suspicious_indicators = []
        for location, content in parts_to_check.items():
            if content:
                indicators = self._analyze_content(content)
                if indicators:
                    for ind in indicators:
                        ind["location"] = location
                    all_suspicious_indicators.extend(indicators)

        if all_suspicious_indicators:
            logger.warning(
                f"[PASSIVE_ANALYSIS] Suspicious request detected from {client_ip} "
                f"to {flow.request.pretty_host}. "
                f"Indicators: {json.dumps(all_suspicious_indicators)}"
            )


# addons list is the entry point for mitmproxy
addons = [SyncedAnalysisAddon()]
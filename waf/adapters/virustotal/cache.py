# vt adapters: cache

import redis.asyncio as redis
import json
import logging
import os
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict

from waf.adapters.virustotal.sync_client import Client
from waf.ip.local import is_local_ip
from waf.ip.info_store import set_ip_info, get_ip_info

logger = logging.getLogger(__name__)


@dataclass
class IPCacheEntry:
    ip: str
    is_malicious: bool
    reputation: int
    threat_types: list
    detection_count: int
    total_engines: int
    cached_date: str  # YYYY-MM-DD
    timestamp: float


class VirusTotalCache:
    """Redis-backed daily cache for VT IP results."""

    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379")
        self.redis_client: Optional[redis.Redis] = None
        self.cache_prefix = "vt_ip_cache"
        self.date_format = "%Y-%m-%d"

    async def init_redis(self):
        try:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            await self.redis_client.ping()
            logger.info("VT cache Redis connected")
        except Exception as e:
            logger.error(f"VT cache Redis fail: {e}")
            self.redis_client = None

    async def _get_cache_key(self, ip: str) -> str:
        today = datetime.now().strftime(self.date_format)
        return f"{self.cache_prefix}:{today}:{ip}"

    async def get_cached_result(self, ip: str) -> Optional[IPCacheEntry]:
        if not self.redis_client:
            return None
        try:
            info = await get_ip_info(self.redis_client, ip)
            vt = info.get('vt')
            if vt:
                return IPCacheEntry(
                    ip=ip,
                    is_malicious=vt.get('is_malicious', False),
                    reputation=vt.get('reputation', 0),
                    threat_types=vt.get('threat_types', []),
                    detection_count=vt.get('detection_count', 0),
                    total_engines=vt.get('total_engines', 0),
                    cached_date=vt.get('cached_date', ''),
                    timestamp=vt.get('timestamp', 0)
                )
        except Exception as e:
            logger.error(f"VT cache get error for {ip}: {e}")
        return None

    async def set_cache_result(self, ip: str, is_malicious: bool, ts: Dict[str, Any]) -> None:
        if not self.redis_client:
            return
        try:
            entry = IPCacheEntry(
                ip=ip,
                is_malicious=is_malicious,
                reputation=ts.get("reputation", 0),
                threat_types=ts.get("threat_types", []),
                detection_count=ts.get("detection_count", 0),
                total_engines=ts.get("total_engines", 0),
                cached_date=datetime.now().strftime(self.date_format),
                timestamp=datetime.now().timestamp()
            )
            vt = asdict(entry)
            await set_ip_info(self.redis_client, ip, vt=vt)
            logger.debug(f"VT cache set for {ip}")
        except Exception as e:
            logger.error(f"VT cache set error for {ip}: {e}")

    async def clean_old_cache(self) -> int:
        if not self.redis_client:
            return 0
        deleted = 0
        try:
            keys = await self.redis_client.keys('ip_info:*')
            for key in keys:
                val = await self.redis_client.get(key)
                if val:
                    try:
                        info = json.loads(val)
                        if 'vt' in info:
                            del info['vt']
                            await self.redis_client.set(key, json.dumps(info))
                            deleted += 1
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"Error cleaning VT cache: {e}")
        return deleted

    async def get_cache_stats(self) -> Dict[str, Any]:
        if not self.redis_client:
            return {"error": "Redis unavailable"}
        stats = {"date": datetime.now().strftime(self.date_format),
                 "total_entries": 0, "malicious_count": 0,
                 "clean_count": 0, "error_count": 0}
        try:
            pattern = f"{self.cache_prefix}:{stats['date']}:*"
            keys = await self.redis_client.keys(pattern)
            stats["total_entries"] = len(keys)
            for k in keys:
                val = await self.redis_client.get(k)
                if val:
                    entry = json.loads(val)
                    if entry.get("is_malicious"):
                        stats["malicious_count"] += 1
                    else:
                        stats["clean_count"] += 1
        except Exception as e:
            stats["error_count"] += 1
            logger.error(f"Error fetching VT cache stats: {e}")
        return stats


async def cleanup_old_cache_task(redis_url: str = None):
    cache = VirusTotalCache(redis_url)
    await cache.init_redis()
    while True:
        now = datetime.now()
        nxt = now.replace(hour=2, minute=0, second=0, microsecond=0)
        if now.hour >= 2:
            nxt += timedelta(days=1)
        await asyncio.sleep((nxt - now).total_seconds())
        await cache.clean_old_cache()



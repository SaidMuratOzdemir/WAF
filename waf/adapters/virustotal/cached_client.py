from typing import Dict, Any, Optional

from waf.adapters.virustotal.sync_client import Client
from waf.adapters.virustotal.cache import VirusTotalCache
from waf.ip.local import is_local_ip


class CachedVirusTotalClient:
    """Wrap Client + VirusTotalCache + local-IP logic (interface preserved)."""

    def __init__(self, ip: str, redis_url: Optional[str] = None):
        self.ip = ip
        self.vt_client = Client(ip)
        self.cache = VirusTotalCache(redis_url)

    async def init(self):
        await self.cache.init_redis()

    async def is_ip_malicious(self) -> bool:
        cached = await self.cache.get_cached_result(self.ip)
        if cached:
            return cached.is_malicious
        if is_local_ip(self.ip):
            await self.cache.set_cache_result(self.ip, False, {
                "reputation": 0, "threat_types": [], "detection_count": 0, "total_engines": 0
            })
            return False
        mal = self.vt_client.is_ip_malicious()
        summary = self.vt_client.get_threat_summary()
        await self.cache.set_cache_result(self.ip, mal, summary)
        return mal

    async def get_threat_summary(self) -> Dict[str, Any]:
        cached = await self.cache.get_cached_result(self.ip)
        if cached:
            return {
                "ip": cached.ip,
                "is_malicious": cached.is_malicious,
                "reputation": cached.reputation,
                "threat_types": cached.threat_types,
                "detection_count": cached.detection_count,
                "total_engines": cached.total_engines,
                "cached": True,
                "cached_date": cached.cached_date,
            }
        if is_local_ip(self.ip):
            return {
                "ip": self.ip,
                "is_malicious": False,
                "reputation": 0,
                "threat_types": [],
                "detection_count": 0,
                "total_engines": 0,
                "cached": True,
                "cached_date": "local_ip",
            }
        summary = self.vt_client.get_threat_summary()
        summary["cached"] = False
        return summary

    async def check_ip(self):
        return await self.is_ip_malicious()



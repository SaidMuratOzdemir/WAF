from typing import Any, Dict
from ip_utils import is_local_ip
from vt_cache import CachedVirusTotalClient

async def check_ip_with_virustotal(ip: str, redis_url: str = None) -> Dict[str, Any]:
    """IP'yi VirusTotal ile kontrol eder. Lokal ise False döner."""
    if is_local_ip(ip):
        return {"is_malicious": False, "reason": "local_ip"}
    vt = CachedVirusTotalClient(ip, redis_url)
    await vt.init()
    mal = await vt.is_ip_malicious()
    summary = await vt.get_threat_summary()
    return {"is_malicious": mal, "summary": summary} 
"""Redis-backed storage for non-banning IP information (e.g., VirusTotal summaries)."""

import json
from typing import Any, Dict


async def set_ip_info(redis_client, ip: str, vt: Dict[str, Any] | None = None, clean: Dict[str, Any] | None = None):
    key = f"ip_info:{ip}"
    info: Dict[str, Any] = {}
    val = await redis_client.get(key)
    if val:
        try:
            info = json.loads(val)
        except Exception:
            info = {}
    if vt is not None:
        info["vt"] = vt
    if clean is not None:
        info["clean"] = clean
    await redis_client.set(key, json.dumps(info))


async def get_ip_info(redis_client, ip: str) -> Dict[str, Any]:
    key = f"ip_info:{ip}"
    val = await redis_client.get(key)
    if val:
        try:
            return json.loads(val)
        except Exception:
            return {}
    return {}



# api/app/services/ip_service.py

import json
from datetime import datetime, timezone
from typing import List
import redis.asyncio as redis
from app.schemas import BannedIP, CleanIP


async def get_banned_ips(client: redis.Redis) -> List[BannedIP]:
    """Retrieves all banned IPs from Redis."""
    banned_ips = []
    async for key in client.scan_iter("ip_info:*"):
        val = await client.get(key)
        if val:
            try:
                info = json.loads(val)
                ban_info = info.get("ban")
                if ban_info and ban_info.get("banned"):
                    ip = key.split(":", 1)[1]
                    banned_ips.append(
                        BannedIP(ip=ip, banned_at=ban_info.get("banned_at"))
                    )
            except (json.JSONDecodeError, TypeError):
                continue
    return banned_ips


async def get_clean_ips(client: redis.Redis) -> List[CleanIP]:
    """Retrieves all clean (whitelisted) IPs from Redis."""
    clean_ips = []
    async for key in client.scan_iter("clean_ip:*"):
        val = await client.get(key)
        if val:
            ip = key.split(":", 1)[1]
            clean_ips.append(CleanIP(ip=ip, added_at=val))
    return clean_ips


async def ban_ip(ip: str, client: redis.Redis) -> bool:
    """Bans an IP address by updating its info in Redis."""
    key = f"ip_info:{ip}"
    val = await client.get(key)
    info = {}
    if val:
        try:
            info = json.loads(val)
        except (json.JSONDecodeError, TypeError):
            info = {}

    info['ban'] = {"banned": True, "banned_at": datetime.now(timezone.utc).isoformat()}
    # Ensure a banned IP is not also whitelisted
    if 'clean' in info:
        del info['clean']
    await client.delete(f"clean_ip:{ip}")

    await client.set(key, json.dumps(info))
    return True


async def unban_ip(ip: str, client: redis.Redis) -> bool:
    """Unbans an IP address by removing the ban info in Redis."""
    key = f"ip_info:{ip}"
    val = await client.get(key)
    if not val:
        return False
    try:
        info = json.loads(val)
        if 'ban' in info:
            del info['ban']
            await client.set(key, json.dumps(info))
            return True
    except (json.JSONDecodeError, TypeError):
        return False
    return False
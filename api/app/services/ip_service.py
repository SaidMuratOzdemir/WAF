# api/app/services/ip_service.py

import json
from datetime import datetime, timezone
from typing import List

import redis.asyncio as redis
from fastapi import HTTPException

from app.schemas import BannedIP, CleanIP

# Redis key prefixes (single source of truth for this module)
BAN_KEY_PREFIX = "banned_ip:"
CLEAN_KEY_PREFIX = "clean_ip:"
IP_INFO_PREFIX = "ip_info:"

async def _load_ip_info(client: redis.Redis, ip: str) -> dict:
    key = f"{IP_INFO_PREFIX}{ip}"
    val = await client.get(key)
    if not val:
        return {}
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return {}

async def _save_ip_info(client: redis.Redis, ip: str, info: dict) -> None:
    key = f"{IP_INFO_PREFIX}{ip}"
    await client.set(key, json.dumps(info))


async def get_banned_ips(client: redis.Redis) -> List[BannedIP]:
    """Retrieves all banned IPs from Redis using both ip_info:* JSON entries and banned_ip:* keys."""
    banned_ips: List[BannedIP] = []
    try:
        # Bağlantının ayakta olduğundan emin olalım
        await client.ping()

        # 1. Check ip_info:* keys for JSON-based bans
        async for raw_key in client.scan_iter(match=f"{IP_INFO_PREFIX}*", count=100):
            key: str = raw_key
            val = await client.get(key)
            if not val:
                continue

            try:
                info = json.loads(val)
                ban_info = info.get("ban", {})
                if ban_info.get("banned"):
                    ip = key.split(":", 1)[1]
                    banned_ips.append(
                        BannedIP(ip=ip, banned_at=ban_info.get("banned_at"))
                    )
            except (json.JSONDecodeError, KeyError):
                continue

        # 2. Check banned_ip:* keys for WAF service bans
        async for raw_key in client.scan_iter(match=f"{BAN_KEY_PREFIX}*", count=100):
            key: str = raw_key
            ip = key.split(":", 1)[1]
            
            # Check if this IP is not already in the list (avoid duplicates)
            if not any(banned_ip.ip == ip for banned_ip in banned_ips):
                # Get TTL to determine if it's still banned
                ttl = await client.ttl(key)
                if ttl > 0:  # Still banned
                    banned_ips.append(
                        BannedIP(ip=ip, banned_at=datetime.now(timezone.utc).isoformat())
                    )

    except Exception as e:
        raise HTTPException(status_code=500, detail="Redis bağlantı hatası")

    return banned_ips


async def get_clean_ips(client: redis.Redis) -> List[CleanIP]:
    """Retrieves all clean (whitelisted) IPs from Redis."""
    clean_ips: List[CleanIP] = []
    try:
        await client.ping()

        async for raw_key in client.scan_iter(match=f"{CLEAN_KEY_PREFIX}*", count=100):
            key: str = raw_key
            val = await client.get(key)
            if not val:
                continue

            ip = key.split(":", 1)[1]
            clean_ips.append(CleanIP(ip=ip, added_at=val))
    except Exception as e:

        raise HTTPException(status_code=500, detail="Redis bağlantı hatası")
    return clean_ips


async def ban_ip(ip: str, client: redis.Redis) -> bool:
    """Bans an IP address by updating its info in Redis."""
    # 1. Update ip_info:* key with ban information
    info = await _load_ip_info(client, ip)

    info["ban"] = {
        "banned": True,
        "banned_at": datetime.now(timezone.utc).isoformat(),
    }
    # Eğer whitelist bilgisi varsa kaldır
    info.pop("clean", None)
    await client.delete(f"{CLEAN_KEY_PREFIX}{ip}")

    # Tek JSON kaynağını güncelle
    await _save_ip_info(client, ip, info)
    
    # 2. Also create banned_ip:* key for WAF service compatibility
    ban_key = f"{BAN_KEY_PREFIX}{ip}"
    await client.setex(ban_key, 3600, "banned")  # 1 hour default ban duration
    
    return True


async def unban_ip(ip: str, client: redis.Redis) -> bool:
    """Unbans an IP address by removing the ban info in Redis."""
    success = False
    
    # 1. Try to unban from ip_info:* keys
    info = await _load_ip_info(client, ip)
    if info.pop("ban", None) is not None:
        await _save_ip_info(client, ip, info)
        success = True
    
    # 2. Try to unban from banned_ip:* keys (WAF service bans)
    ban_key = f"{BAN_KEY_PREFIX}{ip}"
    if await client.exists(ban_key):
        await client.delete(ban_key)
        success = True
    
    return success


async def whitelist_ip(ip: str, client: redis.Redis) -> bool:
    """Adds an IP to whitelist by creating clean key and updating ip_info."""
    try:
        await client.ping()
        added_at = datetime.now(timezone.utc).isoformat()
        # 1) set clean key
        await client.set(f"{CLEAN_KEY_PREFIX}{ip}", added_at)
        # 2) update ip_info
        info = await _load_ip_info(client, ip)
        info["clean"] = {"added_at": added_at}
        # remove ban if exists
        info.pop("ban", None)
        await _save_ip_info(client, ip, info)
        # 3) remove banned key if exists
        await client.delete(f"{BAN_KEY_PREFIX}{ip}")
        return True
    except Exception:
        raise HTTPException(status_code=500, detail="Redis bağlantı hatası")


async def unwhitelist_ip(ip: str, client: redis.Redis) -> bool:
    """Removes an IP from whitelist by deleting clean key and updating ip_info."""
    try:
        await client.ping()
        await client.delete(f"{CLEAN_KEY_PREFIX}{ip}")
        info = await _load_ip_info(client, ip)
        if info.pop("clean", None) is not None:
            await _save_ip_info(client, ip, info)
        return True
    except Exception:
        raise HTTPException(status_code=500, detail="Redis bağlantı hatası")

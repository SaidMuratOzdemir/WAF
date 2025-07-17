# api/app/services/ip_service.py

import json
from datetime import datetime, timezone
from typing import List

import redis.asyncio as redis
from fastapi import HTTPException

from app.schemas import BannedIP, CleanIP


async def get_banned_ips(client: redis.Redis) -> List[BannedIP]:
    """Retrieves all banned IPs from Redis using only the ip_info:* JSON entries."""
    banned_ips: List[BannedIP] = []
    try:
        # Bağlantının ayakta olduğundan emin olalım
        await client.ping()

        # Sadece ip_info:* altındaki JSON'dan 'ban' alanını oku
        async for raw_key in client.scan_iter(match="ip_info:*", count=100):
            key: str = raw_key
            val = await client.get(key)
            if not val:
                continue

            info = json.loads(val)
            ban_info = info.get("ban", {})
            if ban_info.get("banned"):
                ip = key.split(":", 1)[1]
                banned_ips.append(
                    BannedIP(ip=ip, banned_at=ban_info.get("banned_at"))
                )

    except Exception as e:
        print(f"[ip_service.get_banned_ips] Redis hata: {e}")
        raise HTTPException(status_code=500, detail="Redis bağlantı hatası")

    return banned_ips


async def get_clean_ips(client: redis.Redis) -> List[CleanIP]:
    """Retrieves all clean (whitelisted) IPs from Redis."""
    clean_ips: List[CleanIP] = []
    try:
        await client.ping()

        async for raw_key in client.scan_iter(match="clean_ip:*", count=100):
            key: str = raw_key
            val = await client.get(key)
            if not val:
                continue

            ip = key.split(":", 1)[1]
            clean_ips.append(CleanIP(ip=ip, added_at=val))
    except Exception as e:
        print(f"[ip_service.get_clean_ips] Redis hata: {e}")
        raise HTTPException(status_code=500, detail="Redis bağlantı hatası")
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

    info["ban"] = {
        "banned": True,
        "banned_at": datetime.now(timezone.utc).isoformat(),
    }
    # Eğer whitelist bilgisi varsa kaldır
    info.pop("clean", None)
    await client.delete(f"clean_ip:{ip}")

    # Tek JSON kaynağını güncelle
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
        if "ban" in info:
            del info["ban"]
            await client.set(key, json.dumps(info))
            return True
    except (json.JSONDecodeError, TypeError):
        return False
    return False

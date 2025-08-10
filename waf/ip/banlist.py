"""IP ban/whitelist utilities using Redis with fixed key prefixes."""

from typing import Any

BAN_KEY_PREFIX = "banned_ip:"
CLEAN_KEY_PREFIX = "clean_ip:"


async def ban_ip_for_duration(redis_client: Any, ip: str, duration: int) -> None:
    ban_key = f"{BAN_KEY_PREFIX}{ip}"
    await redis_client.setex(ban_key, duration, "banned")


async def is_banned_ip(redis_client: Any, ip: str) -> bool:
    ban_key = f"{BAN_KEY_PREFIX}{ip}"
    return await redis_client.exists(ban_key)


async def unban_ip(redis_client: Any, ip: str) -> None:
    ban_key = f"{BAN_KEY_PREFIX}{ip}"
    await redis_client.delete(ban_key)


async def is_whitelisted_ip(redis_client: Any, ip: str) -> bool:
    clean_key = f"{CLEAN_KEY_PREFIX}{ip}"
    return await redis_client.exists(clean_key)



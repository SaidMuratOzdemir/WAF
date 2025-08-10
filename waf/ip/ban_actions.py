"""Actions that operate on ban/whitelist state for higher-level flows."""

from typing import Any
from aiohttp import web

from waf.ip.banlist import ban_ip_for_duration

DEFAULT_BAN_DURATION_SECONDS = 3600


async def ban_and_log(
    redis_client: Any,
    ip: str,
    reason: str,
    request: web.Request,
    body_bytes: bytes,
    duration: int = DEFAULT_BAN_DURATION_SECONDS,
) -> None:
    # Behavior intentionally minimal: ban in Redis (evidence logging handled elsewhere)
    await ban_ip_for_duration(redis_client, ip, duration)



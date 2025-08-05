# ./waf/ban.py

import logging
import json
import time
from typing import Any
from aiohttp import web



# This is the general-purpose logger for console warnings
logger = logging.getLogger(__name__)

# Define the default ban duration in seconds (e.g., 1 hour)
DEFAULT_BAN_DURATION_SECONDS = 3600


async def ban_and_log(
        redis_client: Any,
        ip: str,
        reason: str,
        request: web.Request,
        body_bytes: bytes,
        duration: int = DEFAULT_BAN_DURATION_SECONDS
) -> None:
    """
    Bans an IP and creates a detailed evidence log in ban_log.json.
    """
    from ip_utils import ban_ip_for_duration

    # 1. Ban the IP in Redis
    await ban_ip_for_duration(redis_client, ip, duration)


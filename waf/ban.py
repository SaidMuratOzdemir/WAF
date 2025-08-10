# ./waf/ban.py (shim)

import logging
from typing import Any
from aiohttp import web

from waf.ip.ban_actions import ban_and_log as _ban_and_log

logger = logging.getLogger(__name__)

DEFAULT_BAN_DURATION_SECONDS = 3600


async def ban_and_log(
    redis_client: Any,
    ip: str,
    reason: str,
    request: web.Request,
    body_bytes: bytes,
    duration: int = DEFAULT_BAN_DURATION_SECONDS,
) -> None:
    """Shim to keep legacy import path; delegates to waf.ip.ban_actions.ban_and_log."""
    await _ban_and_log(redis_client, ip, reason, request, body_bytes, duration)


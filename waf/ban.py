import logging
from typing import Any

logger = logging.getLogger(__name__)

async def ban_and_log(redis_client: Any, ip: str, reason: str) -> None:
    """IP'yi banlar ve loglar."""
    from ip_utils import ban_ip
    await ban_ip(redis_client, ip)
    logger.warning(f"Banned IP {ip} for reason: {reason}") 
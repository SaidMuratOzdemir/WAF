# ./waf/ban.py

import logging
import json
import time
from typing import Any
from aiohttp import web

# --- Setup for the dedicated ban log ---
# This logger will write only the requests that caused a ban.
ban_logger = logging.getLogger("ban_logger")
ban_logger.setLevel(logging.INFO)

# Prevent adding duplicate handlers if the module is reloaded
if not ban_logger.handlers:
    # Use a FileHandler to write to a dedicated log file
    file_handler = logging.FileHandler("ban_log.json")
    # The formatter just outputs the message, as it will be a complete JSON string
    formatter = logging.Formatter('%(message)s')
    file_handler.setFormatter(formatter)
    ban_logger.addHandler(file_handler)
# --- End of ban log setup ---

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

    # 2. Log the simple warning to the main console
    logger.warning(f"BANNED IP {ip} for {duration}s. Reason: {reason}")

    # 3. Create and write the detailed evidence log to ban_log.json
    body_str = body_bytes.decode('utf-8', errors='ignore')

    evidence = {
        "timestamp": time.time(),
        "banned_ip": ip,
        "ban_reason": reason,
        "offending_request": {
            "method": request.method,
            "host": request.host,
            "path": request.path,
            "query_string": str(request.query_string),
            "headers": dict(request.headers),
            # Truncate the body to avoid massive log files
            "body": body_str[:5000] + "... (truncated)" if len(body_str) > 5000 else body_str,
        }
    }
    # Use indent=2 for human-readable JSON in the log file
    ban_logger.info(json.dumps(evidence, indent=2))
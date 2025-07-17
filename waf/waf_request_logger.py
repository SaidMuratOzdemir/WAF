# waf/waf_request_logger.py

import logging
import json
import time
from aiohttp import web

# Maximum size of the request body to log (in characters) to prevent log flooding
MAX_BODY_LOG_SIZE = 10000

activity_logger = logging.getLogger("waf_activity_logger")
activity_logger.setLevel(logging.INFO)

if not activity_logger.handlers:
    file_handler = logging.FileHandler("waf_activity.json")
    formatter = logging.Formatter('%(message)s')
    file_handler.setFormatter(formatter)
    activity_logger.addHandler(file_handler)


async def log_request_activity(request: web.Request, body: bytes, action: str, reason: str = "") -> None:
    client_ip = request.remote or "unknown"

    # Decode body and truncate it to prevent log file explosion
    body_str = body.decode('utf-8', errors='ignore')
    if len(body_str) > MAX_BODY_LOG_SIZE:
        body_str = body_str[:MAX_BODY_LOG_SIZE] + "... (truncated)"

    log_data = {
        "timestamp": time.time(),
        "client_ip": client_ip,
        "method": request.method,
        "host": request.host,
        "path": request.path,
        "query_string": str(request.query_string),  # Ensure it's a string
        "headers": dict(request.headers),
        "body": body_str,  # Use the potentially truncated body
        "action": action,
        "block_reason": reason if reason else None,
    }

    activity_logger.info(json.dumps(log_data))
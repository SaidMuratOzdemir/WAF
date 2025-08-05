# ./waf/waf_logic.py

import logging
import os
from typing import Tuple
from aiohttp import web
from models import Site
from vt_cache import CachedVirusTotalClient
from analysis import analyze_request_part
from ip_utils import is_banned_ip, is_local_ip
from ban import ban_and_log

logger = logging.getLogger(__name__)
_vt_clients_cache: dict = {}


async def get_vt_client(ip: str) -> CachedVirusTotalClient:
    if ip not in _vt_clients_cache:
        client = CachedVirusTotalClient(ip, os.getenv("REDIS_URL"))
        await client.init()
        _vt_clients_cache[ip] = client
    return _vt_clients_cache[ip]


async def is_malicious_request(request: web.Request, site: Site, body_bytes: bytes) -> Tuple[bool, str]:
    """
    Orchestrates all security checks for a given request.
    """
    client_ip = request.remote or "unknown"
    redis_client = request.app['waf_manager'].redis_client

    if redis_client and await is_banned_ip(redis_client, client_ip):
        return True, "BANNED_IP"

    if site.vt_enabled and client_ip and client_ip != "unknown" and not is_local_ip(client_ip):
        vt_client = await get_vt_client(client_ip)
        try:
            vt_result = await vt_client.check_ip()
            if getattr(vt_result, 'is_malicious', False):
                reason = "MALICIOUS_IP_VT"
                if redis_client:
                    await ban_and_log(redis_client, client_ip, reason, request, body_bytes)
                return True, reason
        except Exception:
            logger.exception(f"VirusTotal check failed for IP: {client_ip}")

    body_str = body_bytes.decode('utf-8', errors='ignore')

    # Consolidate all parts of the request to be scanned.
    parts_to_check = {
        "BODY": body_str,
        "PATH": request.path,
        "QUERY": str(request.query_string),
        **{f"HEADER_{k.upper()}": v for k, v in request.headers.items()}
    }

    # Loop through each part and analyze it for threats.
    for location, content in parts_to_check.items():
        if not content:
            continue

        is_mal, attack_type = await analyze_request_part(content, site)
        if is_mal:
            reason = f"{attack_type}_IN_{location}"
            if redis_client:
                # This is the call that triggers the ban and the detailed log entry.
                await ban_and_log(redis_client, client_ip, reason, request, body_bytes)
            return True, reason

    # If all checks pass, the request is clean.
    return False, ""


def create_block_response(attack_type: str, client_ip: str = "unknown") -> web.Response:
    import time
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    html = f"""\
<!DOCTYPE html>
<html>
  <head><meta charset="UTF-8"><title>Blocked</title></head>
  <body style="font-family:Arial,sans-serif;">
    <h1 style="color:#d73527;">🛡️ Request Blocked</h1>
    <p><strong>Reason:</strong> {attack_type}</p>
    <p><strong>Your IP:</strong> {client_ip}</p>
    <p><strong>Time:</strong> {ts}</p>
    <p>If you believe this is an error, please contact the site administrator.</p>
  </body>
</html>
"""
    return web.Response(text=html, status=403, content_type="text/html",
                        headers={"X-WAF-Block-Reason": attack_type})
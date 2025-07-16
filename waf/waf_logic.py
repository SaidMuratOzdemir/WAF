import logging
import os
from typing import Tuple
from aiohttp import web
from database import Site
from vt_cache import CachedVirusTotalClient
from analysis import (
    check_body_for_malicious,
    check_path_for_malicious,
    check_query_for_malicious,
    check_headers_for_malicious,
)
from ip_utils import is_banned_ip
from ban import ban_and_log

logger = logging.getLogger(__name__)
_vt_clients_cache: dict = {}

async def get_vt_client(ip: str) -> CachedVirusTotalClient:
    if ip not in _vt_clients_cache:
        client = CachedVirusTotalClient(ip, os.getenv("REDIS_URL"))
        await client.init()
        _vt_clients_cache[ip] = client
    return _vt_clients_cache[ip]

async def is_malicious_request(request, site: Site, body_bytes=None) -> Tuple[bool, str]:
    client_ip = request.remote or "unknown"
    redis_client = request.app['waf_manager'].redis_client

    # 1) IP ban check
    if redis_client and await is_banned_ip(redis_client, client_ip):
        return True, "BANNED_IP"

    # 2) Read body once
    if body_bytes is None:
        body_bytes = await request.read()
    try:
        body = body_bytes.decode('utf-8', errors='ignore')
    except Exception:
        body = ""

    # 3) DB‑driven pattern checks
    for checker in (
        check_body_for_malicious,
        check_path_for_malicious,
        check_query_for_malicious,
        check_headers_for_malicious,
    ):
        target = (
            body if checker is check_body_for_malicious else
            request.path if checker is check_path_for_malicious else
            str(request.query_string) if checker is check_query_for_malicious else
            dict(request.headers)
        )
        mal, attack = await checker(target, site)
        if mal:
            if redis_client:
                await ban_and_log(redis_client, client_ip, attack)
            return True, attack

    # 4) VirusTotal IP reputation
    if site.vt_enabled and client_ip:
        vt_client = await get_vt_client(client_ip)
        try:
            vt_result = await vt_client.check_ip()
            if getattr(vt_result, 'is_malicious', False):
                if redis_client:
                    await ban_and_log(redis_client, client_ip, "MALICIOUS_IP")
                return True, "MALICIOUS_IP"
        except Exception:
            logger.exception("VT check failed")

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
    <p><strong>Type:</strong> {attack_type}</p>
    <p><strong>IP:</strong> {client_ip}</p>
    <p><strong>Time:</strong> {ts}</p>
    <p>Contact admin if you believe this is an error.</p>
  </body>
</html>
"""
    return web.Response(text=html, status=403, content_type="text/html",
                        headers={"X-WAF-Block-Reason": attack_type})

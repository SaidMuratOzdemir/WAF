# waf_logic.py
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
from ban import ban_and_log

logger = logging.getLogger(__name__)
_vt_clients_cache: dict = {}

async def get_vt_client(ip: str) -> CachedVirusTotalClient:
    """Get or create a cached VT client for this IP."""
    if ip not in _vt_clients_cache:
        client = CachedVirusTotalClient(ip, os.getenv("REDIS_URL"))
        await client.init()
        _vt_clients_cache[ip] = client
    return _vt_clients_cache[ip]

async def is_malicious_request(request, site: Site, body_bytes=None) -> Tuple[bool, str]:
    """
    İsteği veritabanındaki desenlere ve VT/IP reputasyonuna göre analiz eder.
    """
    client_ip = request.remote or "unknown"
    try:
        # Body bir kez okunmuşsa parametre olarak gelir
        if body_bytes is None:
            body_bytes = await request.read()
        body = body_bytes.decode('utf-8', errors='ignore')

        # 1) İçerik kontrolleri (DB desenleri)
        for checker in (
            check_body_for_malicious,
            check_path_for_malicious,
            check_query_for_malicious,
            check_headers_for_malicious,
        ):
            target = (
                body if checker is check_body_for_malicious else
                (request.path if checker is check_path_for_malicious else
                 (str(request.query_string) if checker is check_query_for_malicious else
                  request.headers))
            )
            mal, attack = await checker(target, site)
            if mal:
                await ban_and_log(request.app['waf_manager'].redis_client, client_ip, attack)
                return True, attack

        # 2) VirusTotal IP kontrolü
        if site.vt_enabled and client_ip:
            vt_client = await get_vt_client(client_ip)
            vt_result = await vt_client.check_ip()
            if vt_result.is_malicious:
                await ban_and_log(request.app['waf_manager'].redis_client, client_ip, "MALICIOUS_IP")
                return True, "MALICIOUS_IP"

        return False, ""
    except Exception as e:
        logger.exception("Error in is_malicious_request")
        return False, "analysis_error"


def create_block_response(attack_type: str, client_ip: str = "unknown") -> web.Response:
    import time
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    body = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Blocked</title>
        <style>
        body {{ font-family:Arial,sans-serif; background:#f5f5f5; padding:40px }}
        .c {{ background:white; padding:30px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,0.1) }}
        .e {{ color:#d73527 }}
        .i {{ color:#666; margin-top:20px }}
        </style>
    </head>
    <body>
      <div class="c">
        <h1 class="e">🛡️ Request Blocked</h1>
        <p><strong>Type:</strong> {attack_type}</p>
        <p><strong>IP:</strong> {client_ip}</p>
        <p><strong>Time:</strong> {ts}</p>
        <div class="i">
          <p>Contact admin if you believe this is an error.</p>\ n        </div>
      </div>
    </body>
    </html>
    """
    return web.Response(text=body, status=403, content_type="text/html",
                        headers={"X-WAF-Block-Reason": attack_type})


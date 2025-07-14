# waf_logic.py

import re
import logging
import os
from typing import Tuple
from aiohttp import web
from database import Site
from vt_cache import CachedVirusTotalClient
from ip_utils import is_local_ip, ban_ip, is_banned_ip

# Global cache for VT client instances
_vt_clients_cache: dict = {}

async def get_vt_client(ip: str) -> CachedVirusTotalClient:
    """Get or create a cached VT client for this IP."""
    if ip not in _vt_clients_cache:
        client = CachedVirusTotalClient(ip, os.getenv("REDIS_URL"))
        await client.init()
        _vt_clients_cache[ip] = client
    return _vt_clients_cache[ip]

# XSS and SQL injection patterns
XSS_PATTERNS = [
    r'<script\b',
    r'</script>',
    r'javascript\s*:',
    r'on\w+\s*=\s*["\'][^"\']*["\']',
    r'<iframe\b',
    r'document\.cookie',
    r'alert\s*\(',
    r'eval\s*\(',
]

SQL_PATTERNS = [
    r'\bunion\s+select\b',
    r'\bor\s+1\s*=\s*1\b',
    r'\band\s+1\s*=\s*1\b',
    r"'\s*or\s*'",
    r'"\s*or\s*"',
    r';\s*(drop|delete|update|insert)\b',
    r'--\s',
    r'/\*.*\*/',
]

async def is_malicious_content(content: str, xss_enabled: bool, sql_enabled: bool) -> Tuple[bool, str]:
    if not content:
        return False, ""
    txt = content.lower()
    if xss_enabled:
        for p in XSS_PATTERNS:
            if re.search(p, txt, re.IGNORECASE | re.DOTALL):
                logging.warning(f"XSS detected: {p}")
                return True, "XSS"
    if sql_enabled:
        for p in SQL_PATTERNS:
            if re.search(p, txt, re.IGNORECASE | re.DOTALL):
                logging.warning(f"SQL injection detected: {p}")
                return True, "SQL_INJECTION"
    return False, ""

async def is_malicious_request(request: web.Request, site: Site, body_bytes: bytes = None) -> Tuple[bool, str]:
    """
    Returns (blocked, attack_type).
    On detection, also bans the client IP in Redis.
    """
    client_ip = request.remote or "unknown"
    # 1) Body
    if body_bytes is None:
        body_bytes = await request.read()
    try:
        body = body_bytes.decode('utf-8', errors='ignore')
    except:
        body = ""
    mal, attack = await is_malicious_content(body, site.xss_enabled, site.sql_enabled)
    if mal:
        await ban_ip(request.app['waf_manager'].redis_client, client_ip)
        return True, attack

    # 2) URL path
    mal, attack = await is_malicious_content(request.path, site.xss_enabled, site.sql_enabled)
    if mal:
        await ban_ip(request.app['waf_manager'].redis_client, client_ip)
        logging.warning(f"Malicious in path '{request.path}'")
        return True, attack

    # 3) Query
    mal, attack = await is_malicious_content(str(request.query_string), site.xss_enabled, site.sql_enabled)
    if mal:
        await ban_ip(request.app['waf_manager'].redis_client, client_ip)
        logging.warning(f"Malicious in query '{request.query_string}'")
        return True, attack

    # 4) Headers
    skip = {'user-agent','accept','accept-encoding','accept-language','cookie',
            'connection','host','cache-control','upgrade-insecure-requests',
            'sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform',
            'sec-fetch-site','sec-fetch-mode','sec-fetch-dest'}
    for h, v in request.headers.items():
        if h.lower() in skip:
            continue
        mal, attack = await is_malicious_content(f"{h}: {v}", site.xss_enabled, site.sql_enabled)
        if mal:
            await ban_ip(request.app['waf_manager'].redis_client, client_ip)
            logging.warning(f"Malicious header '{h}'")
            return True, attack

    # 5) VirusTotal IP check
    if site.vt_enabled and client_ip and not is_local_ip(client_ip):
        vt = await get_vt_client(client_ip)
        if await vt.is_ip_malicious():
            await ban_ip(request.app['waf_manager'].redis_client, client_ip)
            logging.warning(f"Malicious IP via VT: {client_ip}")
            return True, "MALICIOUS_IP"
    return False, ""

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
          <p>Contact admin if you believe this is an error.</p>
        </div>
      </div>
    </body>
    </html>
    """
    return web.Response(text=body, status=403, content_type="text/html",
                        headers={"X-WAF-Block-Reason": attack_type})

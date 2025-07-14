# waf_logic.py

import re
import logging
import os
from typing import Tuple
from aiohttp import web
from database import Site
from vt_cache import CachedVirusTotalClient
from ip_utils import is_local_ip, ban_ip, is_banned_ip
from analysis import check_body_for_malicious, check_path_for_malicious, check_query_for_malicious, check_headers_for_malicious
from ban import ban_and_log
from virustotal import check_ip_with_virustotal

logger = logging.getLogger(__name__)

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

async def is_malicious_request(request, site, body_bytes=None) -> Tuple[bool, str]:
    """
    İsteği analiz eder, zararlı bulursa banlar ve sebebini döner.
    """
    client_ip = request.remote or "unknown"
    try:
        if body_bytes is None:
            body_bytes = await request.read()
        try:
            body = body_bytes.decode('utf-8', errors='ignore')
        except Exception:
            body = ""
        # Body
        mal, attack = await check_body_for_malicious(body, site)
        if mal:
            await ban_and_log(request.app['waf_manager'].redis_client, client_ip, attack)
            return True, attack
        # Path
        mal, attack = await check_path_for_malicious(request.path, site)
        if mal:
            await ban_and_log(request.app['waf_manager'].redis_client, client_ip, attack)
            return True, attack
        # Query
        mal, attack = await check_query_for_malicious(str(request.query_string), site)
        if mal:
            await ban_and_log(request.app['waf_manager'].redis_client, client_ip, attack)
            return True, attack
        # Headers
        mal, attack = await check_headers_for_malicious(request.headers, site)
        if mal:
            await ban_and_log(request.app['waf_manager'].redis_client, client_ip, attack)
            return True, attack
        # VirusTotal
        if site.vt_enabled and client_ip:
            vt_result = await check_ip_with_virustotal(client_ip, redis_url=request.app['waf_manager'].redis_client.connection_pool.connection_kwargs.get('address'))
            if vt_result.get('is_malicious'):
                await ban_and_log(request.app['waf_manager'].redis_client, client_ip, "MALICIOUS_IP")
                return True, "MALICIOUS_IP"
        return False, ""
    except Exception as e:
        logger.error(f"Error in is_malicious_request: {e}")
        return False, "error"

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

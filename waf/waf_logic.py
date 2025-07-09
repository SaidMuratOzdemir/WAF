import re
import asyncio
from typing import Dict, List, Tuple
from aiohttp import web
from database import Site
from client import Client
import logging

# Suspicious patterns for different attack types
XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'on\w+\s*=',
    r'<iframe[^>]*>',
    r'<object[^>]*>',
    r'<embed[^>]*>',
    r'%3cscript%3e',
    r'&lt;script&gt;',
    r'eval\(',
    r'alert\(',
    r'document\.cookie',
    r'document\.write'
]

SQL_PATTERNS = [
    r'\bunion\b.*\bselect\b',
    r'\bselect\b.*\bfrom\b',
    r'\binsert\b.*\binto\b',
    r'\bupdate\b.*\bset\b',
    r'\bdelete\b.*\bfrom\b',
    r'\bdrop\b.*\btable\b',
    r'\bcreate\b.*\btable\b',
    r'\balter\b.*\btable\b',
    r"'.*or.*'.*'",
    r'".*or.*".*"',
    r'\bor\b.*1\s*=\s*1',
    r'\band\b.*1\s*=\s*1',
    r'--',
    r'/\*.*\*/',
    r'\bexec\(',
    r'\bexecute\(',
    r'\bsp_\w+',
    r'\bxp_\w+'
]

async def is_malicious_content(content: str, xss_enabled: bool = True, sql_enabled: bool = True) -> Tuple[bool, str]:
    """
    Check if content contains malicious patterns.
    Returns (is_malicious, attack_type)
    """
    if not content:
        return False, ""
    
    content_lower = content.lower()
    
    # Check for XSS patterns
    if xss_enabled:
        for pattern in XSS_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE | re.DOTALL):
                logging.warning(f"XSS pattern detected: {pattern}")
                return True, "XSS"
    
    # Check for SQL injection patterns
    if sql_enabled:
        for pattern in SQL_PATTERNS:
            if re.search(pattern, content_lower, re.IGNORECASE | re.DOTALL):
                logging.warning(f"SQL injection pattern detected: {pattern}")
                return True, "SQL_INJECTION"
    
    return False, ""

async def is_malicious_request(request: web.Request, site: Site, body_bytes: bytes = None) -> Tuple[bool, str]:
    """
    Comprehensive request analysis for malicious content.
    Returns (is_malicious, attack_type)
    """
    try:
        # Get request body - use provided bytes or read if not provided
        if body_bytes is None:
            body_bytes = await request.read()
        
        try:
            body = body_bytes.decode('utf-8', errors='ignore')
        except:
            body = ""
        
        # Check body content
        is_mal, attack_type = await is_malicious_content(
            body, site.xss_enabled, site.sql_enabled
        )
        if is_mal:
            return True, attack_type
        
        # Check URL path
        is_mal, attack_type = await is_malicious_content(
            request.path, site.xss_enabled, site.sql_enabled
        )
        if is_mal:
            logging.warning(f"Malicious content detected in URL path '{request.path}'. Attack type: {attack_type}")
            return True, attack_type
        
        # Check query string
        is_mal, attack_type = await is_malicious_content(
            str(request.query_string), site.xss_enabled, site.sql_enabled
        )
        if is_mal:
            logging.warning(f"Malicious content detected in query string '{request.query_string}'. Attack type: {attack_type}")
            return True, attack_type
        
        # Check headers
        for header_name, header_value in request.headers.items():
            # Skip common headers that might contain false positives
            if header_name.lower() in ['user-agent', 'accept', 'accept-encoding', 'accept-language', 'cookie', 'connection', 'host', 'cache-control', 'upgrade-insecure-requests', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'accept-language']:
                continue
                
            is_mal, attack_type = await is_malicious_content(
                f"{header_name}: {header_value}", site.xss_enabled, site.sql_enabled
            )
            if is_mal:
                logging.warning(f"Malicious content detected in header '{header_name}'. Attack type: {attack_type}")
                return True, attack_type
        
        # Check client IP using VirusTotal (if enabled)
        if site.vt_enabled:
            client_ip = request.remote
            if client_ip and client_ip not in ['127.0.0.1', 'localhost']:
                try:
                    vt_client = Client(client_ip)
                    # Perform the check but don't block, only log if malicious
                    if vt_client.is_ip_malicious():
                        logging.warning(f"Malicious IP detected via VirusTotal: {client_ip}")
                    # If the check fails (e.g., API error), log it but do not block the request.
                    # This makes the WAF resilient to VirusTotal outages.
                except Exception as e:
                    logging.warning(f"VirusTotal check failed for IP {client_ip}, but allowing request. Error: {e}")
        
        return False, ""
        
    except Exception as e:
        logging.error(f"Error in malicious request analysis: {e}")
        return False, ""

def create_block_response(attack_type: str, client_ip: str = "unknown") -> web.Response:
    """Create a standardized block response."""
    import time
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    
    block_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Request Blocked - WAF</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
            .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .error {{ color: #d73527; }}
            .info {{ color: #666; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="error">🛡️ Request Blocked by WAF</h1>
            <p><strong>Attack Type:</strong> {attack_type}</p>
            <p><strong>Client IP:</strong> {client_ip}</p>
            <p><strong>Timestamp:</strong> {timestamp}</p>
            <div class="info">
                <p>Your request has been blocked due to suspicious content that may pose a security risk.</p>
                <p>If you believe this is an error, please contact the system administrator.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return web.Response(
        text=block_message,
        status=403,
        content_type='text/html',
        headers={'X-WAF-Block-Reason': attack_type}
    )

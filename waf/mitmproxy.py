from mitmproxy import http
import logging
import json
import time
from typing import Dict, Any
import asyncio
import redis.asyncio as redis
import os
from collections import deque

# MITMProxy addon for WAF traffic analysis (NO FILTERING - ANALYSIS ONLY)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WAFAnalysisAddon:
    """
    MITMProxy addon for traffic analysis and logging.
    This does NOT block traffic - only analyzes and logs for monitoring.
    """
    
    def __init__(self):
        self.request_count = 0
        self.blocked_patterns = []
        self.traffic_log = deque(maxlen=1000)  # Fixed size queue
        
    def request(self, flow: http.HTTPFlow) -> None:
        """Analyze incoming requests - NO BLOCKING."""
        self.request_count += 1
        client_ip = flow.client_conn.address[0] if flow.client_conn.address else "unknown"
        
        # Log request details
        request_data = {
            "timestamp": time.time(),
            "client_ip": client_ip,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "headers": dict(flow.request.headers),
            "content_length": len(flow.request.content) if flow.request.content else 0,
            "user_agent": flow.request.headers.get("User-Agent", ""),
            "request_id": self.request_count
        }
        
        # Analyze for suspicious patterns (for logging only)
        suspicious_indicators = self._analyze_request(flow.request)
        if suspicious_indicators:
            request_data["suspicious_patterns"] = suspicious_indicators
            logger.warning(f"[ANALYSIS] Suspicious request detected from {client_ip}: {suspicious_indicators}")
        
        # Log to file or send to monitoring system
        logger.info(f"[ANALYSIS] {flow.request.method} {flow.request.pretty_url} from {client_ip}")
        
        # Store in traffic log (automatic size management with deque)
        self.traffic_log.append(request_data)

    def response(self, flow: http.HTTPFlow) -> None:
        """Analyze responses."""
        if flow.response:
            # Log response details
            response_data = {
                "status_code": flow.response.status_code,
                "content_type": flow.response.headers.get("Content-Type", ""),
                "content_length": len(flow.response.content) if flow.response.content else 0,
                "blocked_by_waf": "X-WAF-Block-Reason" in flow.response.headers
            }
            
            if response_data["blocked_by_waf"]:
                block_reason = flow.response.headers.get("X-WAF-Block-Reason", "unknown")
                logger.info(f"[ANALYSIS] Request blocked by WAF: {block_reason}")
            
            # Add response timing
            if hasattr(flow, 'response_timestamp') and hasattr(flow, 'request_timestamp'):
                response_data["response_time_ms"] = (flow.response_timestamp - flow.request_timestamp) * 1000

    def _analyze_request(self, request) -> list:
        """Analyze request for suspicious patterns (analysis only)."""
        suspicious = []
        
        # Get request content
        content_to_check = []
        
        # Add body content
        if request.content:
            try:
                body_text = request.get_text(strict=False)
                if body_text:
                    content_to_check.append(("body", body_text))
            except:
                pass
        
        # Add URL path
        content_to_check.append(("path", request.path))
        
        # Add query parameters
        if request.query:
            for key, value in request.query.items():
                content_to_check.append(("query", f"{key}={value}"))
        
        # Add relevant headers
        for header_name, header_value in request.headers.items():
            if header_name.lower() in ['cookie', 'authorization', 'x-forwarded-for']:
                content_to_check.append(("header", f"{header_name}: {header_value}"))
        
        # Check for suspicious patterns
        suspicious_patterns = {
            "xss": [
                r'<script[^>]*>',
                r'javascript:',
                r'on\w+\s*=',
                r'alert\(',
                r'document\.cookie'
            ],
            "sqli": [
                r'\bunion\b.*\bselect\b',
                r'\bor\b.*1\s*=\s*1',
                r'\bdrop\b.*\btable\b',
                r'--',
                r"'.*or.*'"
            ],
            "path_traversal": [
                r'\.\./.*\.\.',
                r'\.\.\\.*\.\.',
                r'/etc/passwd',
                r'\\windows\\system32'
            ],
            "command_injection": [
                r';\s*(cat|ls|pwd|whoami)',
                r'\|\s*(cat|ls|pwd|whoami)',
                r'`.*`',
                r'\$\(.*\)'
            ]
        }
        
        import re
        
        for content_type, content in content_to_check:
            content_lower = content.lower()
            
            for attack_type, patterns in suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content_lower, re.IGNORECASE):
                        suspicious.append({
                            "type": attack_type,
                            "pattern": pattern,
                            "location": content_type,
                            "matched_content": content[:100] + "..." if len(content) > 100 else content
                        })
        
        return suspicious

    def get_stats(self) -> Dict[str, Any]:
        """Get traffic analysis statistics."""
        total_requests = len(self.traffic_log)
        suspicious_requests = len([r for r in self.traffic_log if "suspicious_patterns" in r])
        
        return {
            "total_requests": total_requests,
            "suspicious_requests": suspicious_requests,
            "suspicious_percentage": (suspicious_requests / total_requests * 100) if total_requests > 0 else 0,
            "recent_requests": self.traffic_log[-10:] if self.traffic_log else []
        }

# Global addon instance
addons = [WAFAnalysisAddon()]

# Entry points for mitmproxy
def request(flow: http.HTTPFlow) -> None:
    """Entry point for mitmproxy request processing."""
    for addon in addons:
        addon.request(flow)

def response(flow: http.HTTPFlow) -> None:
    """Entry point for mitmproxy response processing."""
    for addon in addons:
        addon.response(flow)

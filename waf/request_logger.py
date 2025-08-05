# waf/request_logger.py

import logging
import uuid
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
from aiohttp import web
import pymongo

logger = logging.getLogger(__name__)


class RequestLogger:
    def __init__(self, mongodb_url: str):
        self.mongodb_url = mongodb_url
        self.client = None
        self.db = None
        self.requests_collection = None
        self.responses_collection = None

    def init_mongodb(self):
        """Initialize MongoDB connection"""
        try:
            self.client = pymongo.MongoClient(self.mongodb_url)
            self.db = self.client.waf_logs
            self.requests_collection = self.db.requests
            self.responses_collection = self.db.responses

            # Create indexes for faster queries
            for collection, fields in (
                (self.requests_collection, ["timestamp", "client_ip", "site_name", "request_id"]),
                (self.responses_collection, ["timestamp", "request_id", "status_code"])
            ):
                for field in fields:
                    try:
                        collection.create_index(field)
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            self.client = None
            self.db = None
            self.requests_collection = None
            self.responses_collection = None

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Return headers unmodified"""
        return headers

    def _sanitize_body(self, body: bytes, content_type: str = "") -> str:
        """Sanitize request/response body, only handling binary content"""
        if not body:
            return ""
        binary_types = {'image/', 'video/', 'audio/', 'application/pdf', 'application/zip'}
        if any(binary in content_type.lower() for binary in binary_types):
            return f"[BINARY_CONTENT: {len(body)} bytes]"
        try:
            body_str = body.decode('utf-8', errors='ignore')
            if len(body_str) > 10000:
                return body_str[:10000] + "...[TRUNCATED]"
            return body_str
        except Exception:
            return f"[BINARY_DATA: {len(body)} bytes]"

    def log_request(self, request: web.Request, site_name: str, body_bytes: bytes = b"") -> str:
        """Log incoming request and return request_id"""
        if self.requests_collection is None:
            return ""

        request_id = str(uuid.uuid4())
        client_ip = request.remote or "unknown"
        user_agent = request.headers.get("User-Agent", "")
        content_type = request.headers.get("Content-Type", "")
        sanitized_headers = self._sanitize_headers(dict(request.headers))
        sanitized_body = self._sanitize_body(body_bytes, content_type)

        request_log = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "client_ip": client_ip,
            "site_name": site_name,
            "method": request.method,
            "path": request.path,
            "query_string": str(request.query_string),
            "headers": sanitized_headers,
            "body": sanitized_body,
            "content_type": content_type,
            "user_agent": user_agent,
            "host": request.headers.get("Host", ""),
            "referer": request.headers.get("Referer", ""),
            "content_length": len(body_bytes),
            "is_websocket": request.headers.get("Upgrade", "").lower() == "websocket"
        }
        try:
            self.requests_collection.insert_one(request_log)
            logger.debug(f"Request logged successfully: {request_id}")
            return request_id
        except Exception as e:
            logger.error(f"Failed to log request: {e}")
            return ""

    def log_response(self, request_id: str, response: web.StreamResponse,
                     response_body: bytes = b"", processing_time_ms: float = 0) -> None:
        """Log outgoing response"""
        if self.responses_collection is None or not request_id:
            return
        content_type = response.headers.get("Content-Type", "")
        sanitized_body = self._sanitize_body(response_body, content_type)
        sanitized_headers = self._sanitize_headers(dict(response.headers))
        response_log = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "status_code": getattr(response, 'status', 0),
            "headers": sanitized_headers,
            "body": sanitized_body,
            "content_type": content_type,
            "content_length": len(response_body),
            "processing_time_ms": processing_time_ms
        }
        try:
            self.responses_collection.insert_one(response_log)
            logger.debug(f"Response logged for request: {request_id}")
        except Exception as e:
            logger.error(f"Failed to log response: {e}")

    def middleware(self, site_name: str):
        """Aiohttp middleware factory to log requests and responses"""
        @web.middleware
        async def _logger_middleware(request: web.Request, handler):
            body = await request.read()
            start = time.time()
            request_id = self.log_request(request, site_name, body)

            try:
                response = await handler(request)
                if hasattr(response, 'body'):
                    resp_body = response.body
                else:
                    resp_body = b''
            except web.HTTPException as ex:
                response = ex
                resp_body = getattr(ex, 'text', b'')
            finally:
                elapsed = (time.time() - start) * 1000
                self.log_response(request_id, response, resp_body, elapsed)

            return response

        return _logger_middleware

    def log_blocked_request(self, request: web.Request, site_name: str,
                            reason: str, body_bytes: bytes = b"") -> None:
        """Log blocked requests separately"""
        if self.requests_collection is None:
            return

        request_id = str(uuid.uuid4())
        client_ip = request.remote or "unknown"
        content_type = request.headers.get("Content-Type", "")
        sanitized_headers = self._sanitize_headers(dict(request.headers))
        sanitized_body = self._sanitize_body(body_bytes, content_type)

        blocked_log = {
            "request_id": request_id,
            "timestamp": datetime.utcnow(),
            "client_ip": client_ip,
            "site_name": site_name,
            "method": request.method,
            "path": request.path,
            "query_string": str(request.query_string),
            "headers": sanitized_headers,
            "body": sanitized_body,
            "content_type": content_type,
            "user_agent": request.headers.get("User-Agent", ""),
            "host": request.headers.get("Host", ""),
            "referer": request.headers.get("Referer", ""),
            "content_length": len(body_bytes),
            "block_reason": reason,
            "is_blocked": True
        }
        try:
            self.requests_collection.insert_one(blocked_log)
            logger.info(f"Blocked request logged: {request_id} - Reason: {reason}")
        except Exception as e:
            logger.error(f"Failed to log blocked request: {e}")

    def get_recent_requests(self, limit: int = 100, site_name: Optional[str] = None) -> List[Dict]:
        """Get recent requests for admin interface"""
        if self.requests_collection is None:
            return []
        try:
            filter_query = {}
            if site_name:
                filter_query["site_name"] = site_name
            cursor = self.requests_collection.find(filter_query)\
                                             .sort("timestamp", -1)\
                                             .limit(limit)
            requests = list(cursor)
            for req in requests:
                req["_id"] = str(req["_id"])
                req["timestamp"] = req["timestamp"].isoformat()
            return requests
        except Exception as e:
            logger.error(f"Failed to get recent requests: {e}")
            return []

    def get_request_with_response(self, request_id: str) -> Dict[str, Any]:
        """Get complete request and response data"""
        if self.requests_collection is None or self.responses_collection is None:
            return {}
        try:
            req = self.requests_collection.find_one({"request_id": request_id})
            resp = self.responses_collection.find_one({"request_id": request_id})
            if req:
                req["_id"] = str(req["_id"])
                req["timestamp"] = req["timestamp"].isoformat()
            if resp:
                resp["_id"] = str(resp["_id"])
                resp["timestamp"] = resp["timestamp"].isoformat()
            return {"request": req, "response": resp}
        except Exception as e:
            logger.error(f"Failed to get request with response: {e}")
            return {}

    def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")

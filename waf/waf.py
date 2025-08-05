# waf/waf.py

import asyncio
import logging
import os
import signal
import sys
import time
from aiohttp import web, ClientSession, WSMsgType, ClientTimeout
import redis.asyncio as redis
from dotenv import load_dotenv

from models import Site
from database import init_database, fetch_sites_from_db
from waf_logic import is_malicious_request, create_block_response
from vt_cache import VirusTotalCache
from analysis import fetch_patterns_from_db
from request_logger import RequestLogger

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017/waf_logs")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logging.getLogger('aiohttp.access').setLevel(logging.ERROR)
logging.getLogger('aiohttp.server').setLevel(logging.ERROR)


class WAFManager:
    def __init__(self):
        self.sites = {}
        self.runners = {}
        self.redis_client = None
        self.client_session = None
        self.vt_cache = None
        self.request_logger = None
        self.pattern_task = None
        self.load_lock = asyncio.Lock()
        self.running = False

    async def init_redis(self):
        try:
            self.redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            await self.redis_client.ping()
            logger.info("Redis connected")
            self.vt_cache = VirusTotalCache(REDIS_URL)
            await self.vt_cache.init_redis()
        except Exception as e:
            logger.warning(f"Redis init failed: {e}")
            self.redis_client = None
            self.vt_cache = None

    async def init_mongodb(self):
        try:
            logger.info("Initializing MongoDB logging at %s", MONGODB_URL)
            self.request_logger = RequestLogger(MONGODB_URL)
            self.request_logger.init_mongodb()
            logger.info("MongoDB logging initialized")
        except Exception as e:
            logger.warning(f"MongoDB init failed: {e}")
            self.request_logger = None

    async def load_sites(self):
        async with self.load_lock:
            new = await fetch_sites_from_db()
            for port in set(self.sites) - set(new):
                await self.stop_listener(port)
            for port, hosts in new.items():
                if port not in self.sites:
                    await self.start_listener(port, hosts)
                else:
                    runner = self.runners.get(port)
                    if runner:
                        runner._app["hosts_config"] = hosts
        self.sites = new

    async def start_listener(self, port: int, hosts: dict):
        app = web.Application()
        app["port"] = port
        app["hosts_config"] = hosts
        app["waf_manager"] = self
        app.router.add_route("*", "/{path:.*}", self.handle_request)
        app.router.add_route("POST", "/waf/restart", self.handle_restart)
        app.logger.setLevel(logging.ERROR)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()
        self.runners[port] = runner

    async def stop_listener(self, port: int):
        runner = self.runners.pop(port, None)
        if runner:
            await runner.cleanup()

    async def handle_request(self, request: web.Request) -> web.Response:
        start_time = time.time()
        body = await request.read()

        # restart endpoint
        if request.path == "/waf/restart":
            return await self.handle_restart(request)

        # find site config
        host = request.headers.get("Host", "").split(":")[0].lower()
        site = request.app["hosts_config"].get(host)
        if not site:
            for cfg, s in request.app["hosts_config"].items():
                if cfg.startswith("*.") and host.endswith(cfg[2:]):
                    site = s
                    break
        if not site:
            return web.Response(text="No site configuration found for this host.", status=404)

        # log incoming request
        request_id = ""
        if self.request_logger:
            request_id = self.request_logger.log_request(request, site.name, body)

        try:
            is_mal, reason = await is_malicious_request(request, site, body)
            if is_mal:
                if self.request_logger:
                    self.request_logger.log_blocked_request(request, site.name, reason, body)
                return create_block_response(reason, request.remote or "unknown")

            # websocket?
            if (request.headers.get("connection", "").lower() == "upgrade" and
                    request.headers.get("upgrade", "").lower() == "websocket"):
                return await self.handle_websocket(request, site)

            # proxy and collect response bytes
            response, resp_body = await self.proxy_http_request(request, site, body)

            # log the response
            if self.request_logger and request_id:
                elapsed = (time.time() - start_time) * 1000
                self.request_logger.log_response(request_id, response, resp_body, elapsed)

            return response

        except Exception:
            logger.exception("Critical error during request handling")
            return web.Response(text="Internal WAF Error", status=500,
                                headers={"X-WAF-Error": "handler_exception"})

    async def proxy_http_request(self, request: web.Request, site: Site, body: bytes):
        if not self.client_session:
            self.client_session = ClientSession(timeout=ClientTimeout(total=REQUEST_TIMEOUT))

        headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
        target = (site.backend_url if request.path.startswith("/api/") else site.frontend_url)
        if "localhost" in target:
            target = target.replace("localhost", "host.docker.internal")
        url = f"{target.rstrip('/')}{request.path_qs}"

        from urllib.parse import urlparse
        backend_host = urlparse(target).hostname
        if backend_host:
            headers["Host"] = backend_host

        async with self.client_session.request(
                method=request.method,
                url=url,
                headers=headers,
                data=body,
                allow_redirects=False
        ) as resp:

            excluded = {"Content-Length", "Transfer-Encoding", "Content-Encoding", "Connection", "Keep-Alive"}
            stream_resp = web.StreamResponse(status=resp.status)
            for k, v in resp.headers.items():
                if k not in excluded:
                    stream_resp.headers[k] = v

            # add WAF metadata
            stream_resp.headers["X-WAF-Protected"] = "true"
            stream_resp.headers["X-WAF-Site"] = site.name

            await stream_resp.prepare(request)

            buffer = bytearray()
            try:
                while True:
                    chunk = await resp.content.read(4096)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    await stream_resp.write(chunk)
                await stream_resp.write_eof()
            except (ConnectionResetError, Exception):
                try:
                    await stream_resp.write_eof()
                except:
                    pass

            return stream_resp, bytes(buffer)

    async def handle_websocket(self, request: web.Request, site: Site):
        ws_srv = web.WebSocketResponse()
        await ws_srv.prepare(request)

        target_url = (site.backend_url if request.path.startswith("/api/") else site.frontend_url)
        ws_url = target_url.replace("http://", "ws://").replace("https://", "wss://")
        async with ClientSession() as session:
            async with session.ws_connect(f"{ws_url.rstrip('/')}{request.path_qs}") as ws_client:
                async def relay_to_client():
                    async for msg in ws_client:
                        if msg.type == WSMsgType.TEXT:
                            await ws_srv.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await ws_srv.send_bytes(msg.data)

                async def relay_to_server():
                    async for msg in ws_srv:
                        if msg.type == WSMsgType.TEXT:
                            await ws_client.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY:
                            await ws_client.send_bytes(msg.data)

                await asyncio.gather(relay_to_client(), relay_to_server())
        return ws_srv

    async def handle_restart(self, request: web.Request) -> web.Response:
        """Handle restart request from API."""
        try:
            os.kill(os.getpid(), signal.SIGTERM)
            return web.Response(text="Restart initiated", status=200)
        except Exception:
            return web.Response(text="Restart failed", status=500)

    async def start(self):
        await init_database()
        await self.init_redis()
        await self.init_mongodb()
        self.pattern_task = asyncio.create_task(self._pattern_updater())
        self.running = True

        loop = asyncio.get_event_loop()
        stop = loop.create_future()
        loop.add_signal_handler(signal.SIGINT, stop.set_result, None)
        loop.add_signal_handler(signal.SIGTERM, stop.set_result, None)

        await self.load_sites()
        await stop
        await self.stop()

    async def _pattern_updater(self):
        while self.running:
            try:
                await fetch_patterns_from_db()
            except Exception:
                logger.exception("Pattern updater crashed")
            await asyncio.sleep(POLL_INTERVAL)

    async def stop(self):
        self.running = False
        if self.pattern_task:
            self.pattern_task.cancel()
        if self.client_session:
            await self.client_session.close()
        for port in list(self.runners):
            await self.stop_listener(port)
        if self.redis_client:
            await self.redis_client.close()
        if self.request_logger:
            self.request_logger.close()
        logger.info("WAF stopped gracefully.")


async def main():
    manager = WAFManager()
    try:
        await manager.start()
    except Exception:
        logger.exception("Fatal error in WAF Manager")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

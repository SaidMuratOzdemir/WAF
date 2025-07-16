import asyncio
import logging
import os
import signal
import sys
from aiohttp import web, ClientSession, WSMsgType, ClientTimeout
import redis.asyncio as redis
from dotenv import load_dotenv

from database import init_database, fetch_sites_from_db, Site
from waf_logic import is_malicious_request, create_block_response
from vt_cache import VirusTotalCache, cleanup_old_cache_task
from analysis import fetch_patterns_from_db

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "1000"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class WAFManager:
    def __init__(self):
        self.sites = {}
        self.runners = {}
        self.redis_client = None
        self.client_session = None
        self.vt_cache = None
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

    async def load_sites(self):
        async with self.load_lock:
            new = await fetch_sites_from_db()
            # stop removed ports
            for port in set(self.sites) - set(new):
                await self.stop_listener(port)
            # start or update
            for port, hosts in new.items():
                if port not in self.sites:
                    await self.start_listener(port, hosts)
                else:
                    runner = self.runners.get(port)
                    if runner:
                        runner._app["hosts_config"] = hosts
                        logger.info(f"Updated hosts config for port {port}: {list(hosts)}")
            self.sites = new
            total = sum(len(h) for h in self.sites.values())
            logger.info(f"Loaded {total} sites on {len(self.sites)} ports")

    async def start_listener(self, port: int, hosts: dict):
        app = web.Application()
        app["port"] = port
        app["hosts_config"] = hosts
        app["waf_manager"] = self
        app.router.add_route("*", "/{path:.*}", self.handle_request)
        app.router.add_get("/waf/health", self.health_check)
        app.router.add_get("/waf/metrics", self.metrics_endpoint)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()
        self.runners[port] = runner
        logger.info(f"Listening on {port} for hosts {list(hosts)}")

    async def stop_listener(self, port: int):
        runner = self.runners.pop(port, None)
        if runner:
            await runner.cleanup()
            logger.info(f"Stopped listener on {port}")

    async def handle_request(self, request: web.Request) -> web.Response:
        client_ip = request.remote or "unknown"
        from ip_utils import is_banned_ip
        # Ban check
        if self.redis_client and await is_banned_ip(self.redis_client, client_ip):
            return create_block_response("BANNED_IP", client_ip)

        # Host → Site
        host = request.headers.get("Host", "").split(":")[0].lower()
        site = request.app["hosts_config"].get(host)
        if not site:
            for cfg, s in request.app["hosts_config"].items():
                if cfg.startswith("*.") and host.endswith(cfg[2:]):
                    site = s
                    break
        if not site:
            return web.Response(text="No site config", status=404)

        body = await request.read()
        try:
            mal, reason = await is_malicious_request(request, site, body)
            if mal:
                return create_block_response(reason, client_ip)

            # WebSocket vs HTTP proxy
            if (request.headers.get("connection","").lower() == "upgrade" and
                request.headers.get("upgrade","").lower() == "websocket"):
                return await self.handle_websocket(request, site)

            return await self.proxy_http_request(request, site, body)
        except Exception:
            logger.exception("Error handling request")
            return web.Response(text="Internal error", status=500,
                                headers={"X-WAF-Error": "handler_exception"})

    async def proxy_http_request(self, request: web.Request, site: Site, body: bytes):
        if not self.client_session:
            self.client_session = ClientSession(timeout=ClientTimeout(total=REQUEST_TIMEOUT))

        headers = {k:v for k,v in request.headers.items() if k.lower() != "host"}
        target = (site.backend_url if request.path.startswith("/api/") else site.frontend_url)
        if "localhost" in target:
            target = target.replace("localhost","host.docker.internal")
        url = f"{target.rstrip('/')}{request.path_qs}"

        async with self.client_session.request(
            request.method, url, headers=headers, data=body, allow_redirects=False
        ) as resp:
            data = await resp.read()
            hdrs = dict(resp.headers)
            hdrs.update({"X-WAF-Protected": "true", "X-WAF-Site": site.name})
            return web.Response(body=data, status=resp.status, headers=hdrs)

    async def handle_websocket(self, request: web.Request, site: Site):
        ws_srv = web.WebSocketResponse()
        await ws_srv.prepare(request)
        target = (site.backend_url if request.path.startswith("/api/") else site.frontend_url)\
                 .replace("http://","ws://").replace("https://","wss://")
        async with ClientSession(timeout=ClientTimeout(total=REQUEST_TIMEOUT)) as sess:
            ws_client = await sess.ws_connect(target, headers={
                k:v for k,v in request.headers.items() if k.lower() not in ["host","origin"]
            })
            async def relay(src, dst):
                async for msg in src:
                    if msg.type == WSMsgType.TEXT:
                        await dst.send_str(msg.data)
                    elif msg.type == WSMsgType.BINARY:
                        await dst.send_bytes(msg.data)
            await asyncio.gather(relay(ws_srv, ws_client), relay(ws_client, ws_srv))
        await ws_srv.close()
        return ws_srv

    async def health_check(self, request):
        info = {
            "status": "healthy",
            "port": request.app["port"],
            "sites": [{"host":h,"name":s.name} for h,s in request.app["hosts_config"].items()],
            "time": asyncio.get_event_loop().time()
        }
        return web.json_response(info)

    async def metrics_endpoint(self, request):
        return web.json_response({
            "active_sites": sum(len(h) for h in self.sites.values()),
            "listeners": len(self.runners),
            "redis": self.redis_client is not None
        })

    async def start(self):
        await init_database()
        await self.init_redis()
        await self.load_sites()
        self.pattern_task = asyncio.create_task(self._pattern_updater())
        self.running = True
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, lambda: asyncio.create_task(self.stop()))
        loop.add_signal_handler(signal.SIGTERM, lambda: asyncio.create_task(self.stop()))
        tasks = [asyncio.create_task(self._polling_task())]
        if self.redis_client:
            tasks.extend([
                asyncio.create_task(self._redis_listener()),
                asyncio.create_task(cleanup_old_cache_task(REDIS_URL))
            ])
        await asyncio.gather(*tasks)

    async def _pattern_updater(self):
        while self.running:
            try:
                logger.info("Pattern updater: fetching patterns from DB")
                await fetch_patterns_from_db()
            except Exception:
                logger.exception("Pattern updater crashed")
            await asyncio.sleep(POLL_INTERVAL)

    async def _polling_task(self):
        while self.running:
            await asyncio.sleep(POLL_INTERVAL)
            await self.load_sites()

    async def _redis_listener(self):
        sub = self.redis_client.pubsub()
        await sub.subscribe("config_update")
        async for msg in sub.listen():
            if msg["type"] == "message":
                await self.load_sites()

    async def stop(self):
        self.running = False
        if self.client_session:
            await self.client_session.close()
        if self.redis_client:
            await self.redis_client.close()
        for port in list(self.runners):
            await self.stop_listener(port)
        if self.pattern_task:
            self.pattern_task.cancel()
        logger.info("WAF stopped")

async def main():
    manager = WAFManager()
    try:
        await manager.start()
    except Exception:
        logger.exception("Fatal error in WAF")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())

# waf.py

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
from vt_cache import cleanup_old_cache_task, VirusTotalCache
from ip_utils import is_banned_ip, ban_ip

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
        self.sites = {}              # port → {host: Site}
        self.runners = {}            # port → AppRunner
        self.redis_client = None
        self.client_session = None
        self.request_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.vt_cache = None

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
        new = await fetch_sites_from_db()
        # stop old ports
        for p in set(self.sites) - set(new):
            await self.stop_listener(p)
        
        # restart ports with changed hosts or start new ports
        for p in new:
            if p not in self.sites:
                # start completely new ports
                await self.start_listener(p, new[p])
            elif p in self.runners:
                # always update hosts config for existing ports
                self.runners[p]._app["hosts_config"] = new[p]
                logger.info(f"Updated hosts config for port {p}: {list(new[p].keys())}")
        
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
        if port in self.runners:
            await self.runners[port].cleanup()
            del self.runners[port]
            logger.info(f"Stopped listener on {port}")

    async def handle_request(self, request: web.Request) -> web.Response:
        port = request.app["port"]
        hosts = request.app["hosts_config"]
        manager = request.app["waf_manager"]
        client_ip = request.remote or "unknown"

        # 0) Ban check
        if manager.redis_client and await is_banned_ip(manager.redis_client, client_ip):
            return create_block_response("BANNED_IP", client_ip)

        # Match host → site
        host = request.headers.get("Host", "").split(":")[0].lower()
        site = hosts.get(host)
        if not site:
            # wildcard?
            for cfg, s in hosts.items():
                if cfg.startswith("*.") and (host.endswith(cfg[2:]) or host == cfg[2:]):
                    site = s
                    break
        if not site:
            return web.Response(text="No site config", status=404)

        # Read body once
        body = await request.read()

        try:
            is_mal, attack = await is_malicious_request(request, site, body)
            if is_mal:
                # global ban if not already
                if manager.redis_client:
                    await ban_ip(manager.redis_client, client_ip)
                logger.warning(f"Blocked & banned {client_ip} for {attack}")
                return create_block_response(attack, client_ip)

            # WebSocket?
            if request.headers.get("connection","").lower() == "upgrade" and \
               request.headers.get("upgrade","").lower() == "websocket":
                return await self.handle_websocket(request, site)

            # Proxy HTTP
            return await self.proxy_http_request(request, site, body)

        except Exception as e:
            logger.error(f"Error handling req: {e}")
            return web.Response(text="Internal error", status=500,
                                headers={"X-WAF-Error": str(e)})

    async def handle_websocket(self, request: web.Request, site: Site):
        ws_srv = web.WebSocketResponse()
        await ws_srv.prepare(request)
        target = self.get_target_url(request, site).replace("http://", "ws://").replace("https://", "wss://")
        try:
            async with ClientSession(timeout=ClientTimeout(total=30)) as sess:
                ws_cl = await sess.ws_connect(target, headers={k:v for k,v in request.headers.items() if k.lower() not in ["host","origin"]})
                async def srv_to_cl():
                    async for msg in ws_srv:
                        if msg.type == WSMsgType.TEXT:    await ws_cl.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY: await ws_cl.send_bytes(msg.data)
                async def cl_to_srv():
                    async for msg in ws_cl:
                        if msg.type == WSMsgType.TEXT:    await ws_srv.send_str(msg.data)
                        elif msg.type == WSMsgType.BINARY: await ws_srv.send_bytes(msg.data)
                await asyncio.gather(srv_to_cl(), cl_to_srv())
        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")
        await ws_srv.close()
        return ws_srv

    async def proxy_http_request(self, request: web.Request, site: Site, body: bytes):
        target = self.get_target_url(request, site)
        headers = {k:v for k,v in request.headers.items() if k.lower() != "host"}
        try:
            if not self.client_session:
                self.client_session = ClientSession(timeout=ClientTimeout(total=REQUEST_TIMEOUT))
            async with self.client_session.request(request.method, target, headers=headers, data=body, allow_redirects=False) as resp:
                data = await resp.read()
                hdrs = dict(resp.headers)
                hdrs.update({"X-WAF-Protected":"true","X-WAF-Site":site.name})
                return web.Response(body=data, status=resp.status, headers=hdrs)
        except asyncio.TimeoutError:
            return web.Response(text="Gateway Timeout", status=504)
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            return web.Response(text="Bad Gateway", status=502)

    def get_target_url(self, request: web.Request, site: Site) -> str:
        url = site.backend_url if request.path.startswith("/api/") else site.frontend_url
        # Docker host fix
        if "localhost" in url:
            url = url.replace("localhost","host.docker.internal")
        return f"{url.rstrip('/')}{request.path_qs}"

    async def health_check(self, request: web.Request):
        port = request.app["port"]
        hosts = request.app["hosts_config"]
        info = {"status":"healthy","port":port,"sites":[{"host":h,"name":s.name} for h,s in hosts.items()], "time": asyncio.get_event_loop().time()}
        return web.json_response(info)

    async def metrics_endpoint(self, request: web.Request):
        return web.json_response({"active_sites": sum(len(h) for h in self.sites.values()),
                                  "listeners": len(self.runners),
                                  "redis": self.redis_client is not None})

    async def start(self):
        await init_database()
        await self.init_redis()
        await self.load_sites()

        self.running = True
        tasks = [asyncio.create_task(self.polling_task())]
        if self.redis_client:
            tasks.append(asyncio.create_task(self.redis_listener()))
            tasks.append(asyncio.create_task(cleanup_old_cache_task(REDIS_URL)))

        await asyncio.gather(*tasks)

    async def stop(self):
        self.running = False
        if self.client_session: await self.client_session.close()
        if self.redis_client:  await self.redis_client.close()
        for p in list(self.runners):
            await self.stop_listener(p)

    async def redis_listener(self):
        if not self.redis_client: return
        sub = self.redis_client.pubsub()
        await sub.subscribe("config_update")
        async for msg in sub.listen():
            if msg["type"] == "message":
                await self.load_sites()

    async def polling_task(self):
        while self.running:
            await asyncio.sleep(POLL_INTERVAL)
            await self.load_sites()

async def main():
    manager = WAFManager()
    signal.signal(signal.SIGINT, lambda *_: setattr(manager, "running", False))
    signal.signal(signal.SIGTERM, lambda *_: setattr(manager, "running", False))
    try:
        await manager.start()
    except Exception as e:
        logger.error(f"Fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())

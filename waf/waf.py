import asyncio
import logging
import os
import signal
import sys
from typing import Dict, Optional, Set
from aiohttp import web, ClientSession, WSMsgType, ClientTimeout
import redis.asyncio as redis
from dotenv import load_dotenv

from database import init_database, fetch_sites_from_db, Site
from waf_logic import is_malicious_request, create_block_response

# Load environment variables
load_dotenv()

# Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "1000"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WAFManager:
    def __init__(self):
        self.sites: Dict[int, Site] = {}
        self.runners: Dict[int, web.AppRunner] = {}
        self.redis_client: Optional[redis.Redis] = None
        self.running = False
        self.client_session: Optional[ClientSession] = None
        self.request_semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        
    async def init_redis(self):
        """Initialize Redis connection."""
        try:
            self.redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Falling back to polling mode.")
            self.redis_client = None

    async def load_sites(self):
        """Load sites from database."""
        try:
            new_sites = await fetch_sites_from_db()
            
            # Find sites to stop
            sites_to_stop = set(self.sites.keys()) - set(new_sites.keys())
            for port in sites_to_stop:
                await self.stop_listener(port)
            
            # Find sites to start
            sites_to_start = set(new_sites.keys()) - set(self.sites.keys())
            for port in sites_to_start:
                await self.start_listener(port, new_sites[port])
            
            # Update sites configuration
            self.sites = new_sites
            logger.info(f"Loaded {len(self.sites)} sites")
            
        except Exception as e:
            logger.error(f"Error loading sites: {e}")

    async def start_listener(self, port: int, site: Site):
        """Start a listener for a specific port/site."""
        try:
            app = self.create_app_for_site(site)
            runner = web.AppRunner(app)
            await runner.setup()
            
            # Create TCP site
            tcp_site = web.TCPSite(runner, '0.0.0.0', port)
            await tcp_site.start()
            
            self.runners[port] = runner
            logger.info(f"Started listener for {site.name} on port {port}")
            
        except Exception as e:
            logger.error(f"Failed to start listener on port {port}: {e}")

    async def stop_listener(self, port: int):
        """Stop a listener for a specific port."""
        try:
            if port in self.runners:
                await self.runners[port].cleanup()
                del self.runners[port]
                logger.info(f"Stopped listener on port {port}")
        except Exception as e:
            logger.error(f"Error stopping listener on port {port}: {e}")

    def create_app_for_site(self, site: Site) -> web.Application:
        """Create aiohttp application for a specific site."""
        app = web.Application()
        
        # Store site info in app
        app['site'] = site
        app['waf_manager'] = self
        
        # Add routes
        app.router.add_route('*', '/{path:.*}', self.handle_request)
        
        # Add health endpoint
        app.router.add_get('/waf/health', self.health_check)
        app.router.add_get('/waf/metrics', self.metrics_endpoint)
        
        return app

    async def handle_request(self, request: web.Request) -> web.Response:
        """Main request handler with WAF protection."""
        site = request.app['site']
        client_ip = request.remote or "unknown"
        
        try:
            # Security check
            is_malicious, attack_type = await is_malicious_request(request, site)
            if is_malicious:
                logger.warning(f"Blocked {attack_type} attack from {client_ip} to {site.name}")
                return create_block_response(attack_type, client_ip)

            # Handle WebSocket requests
            if (request.headers.get("connection", "").lower() == "upgrade" and
                request.headers.get("upgrade", "").lower() == "websocket"):
                return await self.handle_websocket(request, site)

            # Regular HTTP request
            return await self.proxy_http_request(request, site)

        except Exception as e:
            logger.error(f"Error handling request: {e}")
            return web.Response(
                text="Internal server error",
                status=500,
                headers={'X-WAF-Error': str(e)}
            )

    async def handle_websocket(self, request: web.Request, site: Site) -> web.WebSocketResponse:
        """Handle WebSocket connections with proxying."""
        ws_server = web.WebSocketResponse()
        await ws_server.prepare(request)

        # Determine target URL
        target_url = self.get_target_url(request, site)
        
        try:
            # Create client WebSocket connection
            timeout = ClientTimeout(total=30)
            async with ClientSession(timeout=timeout) as session:
                headers = {k: v for k, v in request.headers.items() 
                          if k.lower() not in ['host', 'origin']}
                
                async with session.ws_connect(
                    target_url,
                    headers=headers,
                    protocols=request.headers.get('sec-websocket-protocol', '').split(',')
                ) as ws_client:
                    
                    # Bidirectional message forwarding
                    async def client_to_server():
                        async for msg in ws_client:
                            if msg.type == WSMsgType.TEXT:
                                await ws_server.send_str(msg.data)
                            elif msg.type == WSMsgType.BINARY:
                                await ws_server.send_bytes(msg.data)
                            elif msg.type == WSMsgType.ERROR:
                                break
                        await ws_server.close()

                    async def server_to_client():
                        async for msg in ws_server:
                            if msg.type == WSMsgType.TEXT:
                                await ws_client.send_str(msg.data)
                            elif msg.type == WSMsgType.BINARY:
                                await ws_client.send_bytes(msg.data)
                            elif msg.type == WSMsgType.ERROR:
                                break
                        await ws_client.close()

                    # Run both directions concurrently
                    await asyncio.gather(
                        client_to_server(),
                        server_to_client(),
                        return_exceptions=True
                    )

        except Exception as e:
            logger.error(f"WebSocket proxy error: {e}")
            await ws_server.close()

        return ws_server

    async def proxy_http_request(self, request: web.Request, site: Site) -> web.Response:
        """Proxy HTTP requests to backend."""
        target_url = self.get_target_url(request, site)
        
        # Read request body
        body = await request.read()
        
        # Prepare headers
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        
        try:
            timeout = ClientTimeout(total=30)
            
            if not self.client_session:
                self.client_session = ClientSession(timeout=timeout)
            
            async with self.client_session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False
            ) as resp:
                
                # Read response
                response_body = await resp.read()
                
                # Prepare response headers
                response_headers = dict(resp.headers)
                response_headers['X-WAF-Protected'] = 'true'
                response_headers['X-WAF-Site'] = site.name
                
                return web.Response(
                    body=response_body,
                    status=resp.status,
                    headers=response_headers
                )
                
        except asyncio.TimeoutError:
            logger.error(f"Timeout proxying request to {target_url}")
            return web.Response(text="Gateway Timeout", status=504)
        except Exception as e:
            logger.error(f"Error proxying request to {target_url}: {e}")
            return web.Response(status=502, text=f"Error connecting to backend: {e}")

    def get_target_url(self, request: web.Request, site: Site) -> str:
        """Determine target URL based on request path."""
        # API requests go to backend, everything else to frontend
        if request.path.startswith('/api'):
            base_url = site.backend_url
        else:
            base_url = site.frontend_url
        
        # Construct full URL
        target_url = f"{base_url.rstrip('/')}{request.path_qs}"
        return target_url

    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        site = request.app['site']
        health_info = {
            "status": "healthy",
            "site": site.name,
            "port": site.port,
            "xss_protection": site.xss_enabled,
            "sql_protection": site.sql_enabled,
            "timestamp": asyncio.get_event_loop().time()
        }
        return web.json_response(health_info)

    async def metrics_endpoint(self, request: web.Request) -> web.Response:
        """Metrics endpoint for monitoring."""
        metrics = {
            "active_sites": len(self.sites),
            "active_listeners": len(self.runners),
            "redis_connected": self.redis_client is not None,
        }
        return web.json_response(metrics)

    async def redis_listener(self):
        """Listen for configuration updates via Redis."""
        if not self.redis_client:
            return
        
        try:
            pubsub = self.redis_client.pubsub()
            await pubsub.subscribe('config_update')
            
            logger.info("Listening for Redis configuration updates...")
            
            async for message in pubsub.listen():
                if message['type'] == 'message':
                    try:
                        # Port number from message
                        port = int(message['data'])
                        logger.info(f"Received config update for port {port}")
                        await self.load_sites()
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid config update message: {message['data']}")
                        await self.load_sites()  # Full reload
                        
        except Exception as e:
            logger.error(f"Error in Redis listener: {e}")

    async def polling_task(self):
        """Fallback polling task for configuration updates."""
        logger.info(f"Starting polling task (interval: {POLL_INTERVAL}s)")
        
        while self.running:
            try:
                await asyncio.sleep(POLL_INTERVAL)
                await self.load_sites()
            except Exception as e:
                logger.error(f"Error in polling task: {e}")

    async def start(self):
        """Start the WAF manager."""
        logger.info("Starting WAF Manager...")
        
        # Initialize database
        await init_database()
        
        # Initialize Redis
        await self.init_redis()
        
        # Initial site loading
        await self.load_sites()
        
        self.running = True
        
        # Start background tasks
        tasks = []
        
        if self.redis_client:
            tasks.append(asyncio.create_task(self.redis_listener()))
        
        tasks.append(asyncio.create_task(self.polling_task()))
        
        logger.info("WAF Manager started successfully")
        
        # Wait for tasks
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            await self.stop()

    async def stop(self):
        """Stop the WAF manager."""
        logger.info("Stopping WAF Manager...")
        
        self.running = False
        
        # Stop all listeners
        for port in list(self.runners.keys()):
            await self.stop_listener(port)
        
        # Close client session
        if self.client_session:
            await self.client_session.close()
        
        # Close Redis connection
        if self.redis_client:
            await self.redis_client.close()
        
        logger.info("WAF Manager stopped")

# Global WAF manager instance
waf_manager = WAFManager()

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}")
    asyncio.create_task(waf_manager.stop())

async def main():
    """Main entry point."""
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        await waf_manager.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())

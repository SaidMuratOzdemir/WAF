import redis.asyncio as redis
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client = None

async def init_redis():
    """Initialize Redis connection."""
    global redis_client
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
        logger.info("Redis connection initialized for config updates")
    except Exception as e:
        logger.error(f"Failed to initialize Redis connection: {e}")
        redis_client = None

async def publish_config_update(port: int):
    """Publish a configuration update event to Redis."""
    global redis_client
    try:
        if redis_client is None:
            await init_redis()
        
        if redis_client:
            await redis_client.publish("config_update", str(port))
            logger.info(f"Published config update for port {port}")
        else:
            logger.warning(f"Redis not available, could not publish config update for port {port}")
    except Exception as e:
        logger.error(f"Error publishing config update for port {port}: {e}")

async def close_redis():
    """Close Redis connection."""
    global redis_client
    if redis_client:
        await redis_client.close()
        redis_client = None

async def get_banned_ips() -> list:
    """Get all banned IPs from Redis"""
    global redis_client
    if not redis_client:
        await init_redis()
    keys = await redis_client.keys('banned_ip:*')
    ips = []
    for key in keys:
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        ip = key.split(':', 1)[1]
        ips.append({
            'ip': ip,
            'banned_at': await redis_client.get(f'banned_ip:{ip}')
        })
    return ips

async def get_clean_ips() -> list:
    """Get all clean (whitelisted) IPs from Redis"""
    global redis_client
    if not redis_client:
        await init_redis()
    keys = await redis_client.keys('clean_ip:*')
    ips = []
    for key in keys:
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        ip = key.split(':', 1)[1]
        ips.append({
            'ip': ip,
            'added_at': await redis_client.get(f'clean_ip:{ip}')
        })
    return ips

async def ban_ip(ip: str) -> bool:
    """Manually ban an IP"""
    global redis_client
    if not redis_client:
        await init_redis()
    await redis_client.set(f'banned_ip:{ip}', str(datetime.now()))
    await redis_client.delete(f'clean_ip:{ip}')  # Remove from clean list if exists
    return True

async def unban_ip(ip: str) -> bool:
    """Remove IP from banned list"""
    global redis_client
    if not redis_client:
        await init_redis()
    return await redis_client.delete(f'banned_ip:{ip}') > 0


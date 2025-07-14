import redis.asyncio as redis
import os
import logging
from datetime import datetime
import json

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
    global redis_client
    if not redis_client:
        await init_redis()
    keys = await redis_client.keys('ip_info:*')
    ips = []
    for key in keys:
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        ip = key.split(':', 1)[1]
        val = await redis_client.get(key)
        if val:
            try:
                info = json.loads(val)
                ban = info.get('ban')
                if ban and ban.get('banned'):
                    ips.append({'ip': ip, 'banned_at': ban.get('banned_at')})
            except Exception:
                continue
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
    global redis_client
    if not redis_client:
        await init_redis()
    from datetime import datetime
    key = f"ip_info:{ip}"
    val = await redis_client.get(key)
    info = {}
    if val:
        try:
            info = json.loads(val)
        except Exception:
            info = {}
    info['ban'] = {"banned": True, "banned_at": datetime.now().isoformat()}
    await redis_client.set(key, json.dumps(info))
    # clean_ip varsa sil
    if 'clean' in info:
        del info['clean']
    return True

async def unban_ip(ip: str) -> bool:
    global redis_client
    if not redis_client:
        await init_redis()
    key = f"ip_info:{ip}"
    val = await redis_client.get(key)
    if not val:
        return False
    try:
        info = json.loads(val)
    except Exception:
        return False
    if 'ban' in info:
        del info['ban']
        await redis_client.set(key, json.dumps(info))
        return True
    return False


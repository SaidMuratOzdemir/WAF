import redis.asyncio as redis
import os
import logging

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

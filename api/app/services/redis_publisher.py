# api/app/services/redis_publisher.py

import logging
import redis.asyncio as redis

logger = logging.getLogger(__name__)

async def publish_config_update(port: int, client: redis.Redis):
    """
    Publishes a configuration update event to the 'config_update' channel.
    """
    try:
        await client.publish("config_update", str(port))
        logger.info(f"Published config update for port {port}")
    except Exception as e:
        logger.error(f"Error publishing config update for port {port}: {e}")
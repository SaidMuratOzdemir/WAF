import redis.asyncio as redis
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

async def publish_config_update(port: int):
    """Publish a configuration update event to Redis."""
    await redis_client.publish("config_update", str(port))

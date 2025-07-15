# api/app/core/dependencies.py

import redis.asyncio as redis
from typing import AsyncGenerator

# This pool will be initialized in main.py on startup
redis_pool: redis.ConnectionPool = None


async def get_redis_connection() -> AsyncGenerator[redis.Redis, None]:
    """
    Yields a Redis connection from the connection pool.
    """
    if not redis_pool:
        raise RuntimeError("Redis connection pool is not initialized.")

    async with redis.Redis.from_pool(redis_pool) as client:
        yield client
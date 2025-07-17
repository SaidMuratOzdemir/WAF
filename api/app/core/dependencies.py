# api/app/core/dependencies.py

import redis.asyncio as redis
from typing import AsyncGenerator

# Bu pool, main.py içindeki lifespan handler’da initialize ediliyor
redis_pool: redis.ConnectionPool = None


async def get_redis_connection() -> AsyncGenerator[redis.Redis, None]:
    """
    Yields a Redis client from the shared connection pool,
    with retry_on_timeout, socket_keepalive ve decode_responses=True.
    """
    if not redis_pool:
        raise RuntimeError("Redis connection pool is not initialized.")

    # Her istekte yeni bir Redis örneği alıyoruz ama gerçek TCP bağlantıları pool’dan çekiliyor
    client = redis.Redis(
        connection_pool=redis_pool,
        retry_on_timeout=True,
        socket_keepalive=True,
        decode_responses=True,
    )
    try:
        yield client
    finally:
        # Pooled client’i kapatıp kaynakları serbest bırakıyoruz
        await client.close()

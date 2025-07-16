# api/app/main.py

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as redis

from app.core.config import settings
from app.core import dependencies
from app.routers import auth, sites, ips, patterns, system


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages application startup and shutdown events.
    """
    # On startup: Initialize the Redis connection pool
    dependencies.redis_pool = redis.ConnectionPool.from_url(
        settings.REDIS_URL, max_connections=10, decode_responses=True
    )

    print("--- WAF API started ---")
    print("Redis connection pool created.")

    # The application is now ready to run
    yield

    # On shutdown: Disconnect the Redis connection pool
    if dependencies.redis_pool:
        await dependencies.redis_pool.disconnect()
        print("Redis connection pool disconnected.")
    print("--- WAF API shut down ---")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    description="Admin dashboard API for the Web Application Firewall (WAF)",
    lifespan=lifespan,  # Use the modern lifespan event handler
    openapi_tags=[
        {"name": "Authentication", "description": "User login and token management."},
        {"name": "Sites", "description": "Manage protected websites."},
        {"name": "IP Management", "description": "Manage banned and whitelisted IP addresses."},
        {"name": "Patterns", "description": "Manage malicious security patterns."},
        {"name": "System", "description": "System health, status, and cache operations."},
    ],
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(origin) for origin in settings.CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all the routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(sites.router, prefix=settings.API_V1_STR)
app.include_router(ips.router, prefix=settings.API_V1_STR)
app.include_router(patterns.router, prefix=settings.API_V1_STR)
app.include_router(system.router, prefix=settings.API_V1_STR) 
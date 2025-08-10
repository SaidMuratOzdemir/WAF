# api/app/routers/ips.py

from typing import List
from fastapi import APIRouter, Depends
import redis.asyncio as redis

from app.schemas import BannedIP, CleanIP, UserInDB
from app.core.security import get_current_admin_user
from app.core.dependencies import get_redis_connection
from app.services import ip_service

router = APIRouter(prefix="/ips", tags=["IP Management"])

@router.get("/banned", response_model=List[BannedIP])
async def list_banned_ips(
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """List all banned IP addresses."""
    return await ip_service.get_banned_ips(redis_client)

@router.get("/clean", response_model=List[CleanIP])
async def list_clean_ips(
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """List all clean (whitelisted) IPs."""
    return await ip_service.get_clean_ips(redis_client)

@router.post("/ban/{ip_address}", response_model=dict)
async def ban_ip_address(
    ip_address: str,
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Ban an IP address."""
    success = await ip_service.ban_ip(ip_address, redis_client)
    return {"status": "success", "banned": success}

@router.post("/unban/{ip_address}", response_model=dict)
async def unban_ip_address(
    ip_address: str,
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Unban an IP address."""
    success = await ip_service.unban_ip(ip_address, redis_client)
    return {"status": "success", "unbanned": success}


@router.post("/clean/{ip_address}", response_model=dict)
async def whitelist_ip_address(
    ip_address: str,
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Whitelist an IP address."""
    success = await ip_service.whitelist_ip(ip_address, redis_client)
    return {"status": "success", "whitelisted": success}


@router.delete("/clean/{ip_address}", response_model=dict)
async def unwhitelist_ip_address(
    ip_address: str,
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Remove an IP from whitelist."""
    success = await ip_service.unwhitelist_ip(ip_address, redis_client)
    return {"status": "success", "unwhitelisted": success}
# api/app/routers/system.py

import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
import redis.asyncio as redis

from app.schemas import UserInDB
from app.core.security import get_current_admin_user
from app.core.dependencies import get_redis_connection

router = APIRouter(prefix="/system", tags=["System"])

@router.get("/health")
async def health_check():
    """Return the current health status of the API."""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}

@router.get("/vt-cache/stats", response_model=dict)
async def get_vt_cache_stats(
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Get statistics about the VirusTotal IP cache in Redis."""
    stats = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "total_entries": 0, "malicious_count": 0, "clean_count": 0, "error_count": 0
    }
    try:
        async for key in redis_client.scan_iter('ip_info:*'):
            try:
                entry = await redis_client.get(key)
                if entry:
                    data = json.loads(entry)
                    if 'vt' in data:
                        stats['total_entries'] += 1
                        if data['vt'].get('is_malicious'):
                            stats['malicious_count'] += 1
                        else:
                            stats['clean_count'] += 1
            except (json.JSONDecodeError, TypeError):
                stats['error_count'] += 1
                continue
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting cache stats: {str(e)}"
        )

@router.post("/vt-cache/cleanup", response_model=dict)
async def cleanup_vt_cache(
    redis_client: redis.Redis = Depends(get_redis_connection),
    current_user: UserInDB = Depends(get_current_admin_user)
):
    """Manually clear all VirusTotal data from the IP cache in Redis."""
    cleaned_count = 0
    try:
        async for key in redis_client.scan_iter('ip_info:*'):
            entry = await redis_client.get(key)
            if entry:
                try:
                    data = json.loads(entry)
                    if 'vt' in data:
                        del data['vt']
                        await redis_client.set(key, json.dumps(data))
                        cleaned_count += 1
                except (json.JSONDecodeError, TypeError):
                    continue
        return {
            "message": "Cache cleanup completed successfully.",
            "cleaned_entries": cleaned_count
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error cleaning cache: {str(e)}"
        )
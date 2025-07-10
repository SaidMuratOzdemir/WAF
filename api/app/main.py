from fastapi import FastAPI, Depends, HTTPException, status, Form, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
import os
import redis.asyncio as redis
from datetime import datetime, timedelta

from .database import get_session
from .models import Site as SiteModel
from .schemas import SiteCreate, Site as SiteSchema
from .auth import (
    verify_token,
    create_access_token,
    TokenResponse,
    authenticate_user,
    get_current_admin_user
)
from .redis_service import (
    publish_config_update,
    init_redis,
    close_redis,
    get_banned_ips,
    get_clean_ips,
    ban_ip,
    unban_ip
)

app = FastAPI(title="WAF Admin API")

# Router for all API endpoints (requires authentication)
api_router = APIRouter(
    prefix="/api",
    dependencies=[Depends(verify_token)],
)

@app.on_event("startup")
async def startup_event():
    """Initialize Redis connection on startup."""
    await init_redis()

@app.on_event("shutdown")
async def shutdown_event():
    """Close Redis connection on shutdown."""
    await close_redis()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication endpoint (no token required)
@app.post("/login", response_model=TokenResponse)
async def login(
    username: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(get_session)
):
    """Generate JWT token for admin user."""
    user = await authenticate_user(username, password, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not an administrator",
        )
    access_token = create_access_token(data={"sub": username, "admin": True})
    return TokenResponse(access_token=access_token)

# Health check endpoint (no token required)
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

# --- API ROUTES ---

@api_router.get("/sites", response_model=List[SiteSchema])
async def list_sites(
    session: AsyncSession = Depends(get_session)
):
    """List all protected sites."""
    result = await session.execute(select(SiteModel))
    sites = result.scalars().all()
    site_dicts = []
    for site in sites:
        site_dicts.append({
            "id": site.id,
            "port": site.port,
            "name": site.name,
            "host": site.host,
            "frontend_url": site.frontend_url,
            "backend_url": site.backend_url,
            "xss_enabled": site.xss_enabled,
            "sql_enabled": site.sql_enabled,
            "vt_enabled": site.vt_enabled,
        })
    return site_dicts

@api_router.post(
    "/sites",
    response_model=SiteSchema,
    status_code=status.HTTP_201_CREATED
)
async def create_site(
    site: SiteCreate,
    session: AsyncSession = Depends(get_session)
):
    """Add a new protected site."""
    result = await session.execute(
        select(SiteModel).filter(
            SiteModel.port == site.port,
            SiteModel.host == site.host
        )
    )
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Site with port {site.port} and host '{site.host}' already exists"
        )
    new_site = SiteModel(
        port=site.port,
        host=site.host,
        name=site.name,
        frontend_url=str(site.frontend_url),
        backend_url=str(site.backend_url),
        xss_enabled=site.xss_enabled,
        sql_enabled=site.sql_enabled,
        vt_enabled=site.vt_enabled
    )
    session.add(new_site)
    await session.commit()
    await session.refresh(new_site)
    await publish_config_update(site.port)
    return new_site

@api_router.put("/sites/{site_id}", response_model=SiteSchema)
async def update_site(
    site_id: int,
    site_update: SiteCreate,
    session: AsyncSession = Depends(get_session)
):
    """Update an existing protected site."""
    result = await session.execute(
        select(SiteModel).filter(SiteModel.id == site_id)
    )
    existing = result.scalar_one_or_none()
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Site with ID {site_id} not found"
        )
    # Check for port+host conflict
    if (existing.port != site_update.port or existing.host != site_update.host):
        conflict = await session.execute(
            select(SiteModel).filter(
                SiteModel.port == site_update.port,
                SiteModel.host == site_update.host,
                SiteModel.id != site_id
            )
        )
        if conflict.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Site with port {site_update.port} and host '{site_update.host}' already exists"
            )
    old_port = existing.port
    existing.port = site_update.port
    existing.host = site_update.host
    existing.name = site_update.name
    existing.frontend_url = str(site_update.frontend_url)
    existing.backend_url = str(site_update.backend_url)
    existing.xss_enabled = site_update.xss_enabled
    existing.sql_enabled = site_update.sql_enabled
    existing.vt_enabled = site_update.vt_enabled
    await session.commit()
    await session.refresh(existing)
    await publish_config_update(old_port)
    if old_port != site_update.port:
        await publish_config_update(site_update.port)
    return existing

@api_router.delete("/sites/{port}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(
    port: int,
    session: AsyncSession = Depends(get_session)
):
    """Delete a protected site by port."""
    result = await session.execute(
        select(SiteModel).filter(SiteModel.port == port)
    )
    site = result.scalar_one_or_none()
    if not site:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Site with port {port} not found"
        )
    await session.delete(site)
    await session.commit()
    await publish_config_update(port)

@api_router.get("/vt-cache-stats")
async def get_vt_cache_stats():
    """Get VirusTotal cache statistics."""
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        client = redis.from_url(redis_url, decode_responses=True)
        await client.ping()
        today = datetime.now().strftime("%Y-%m-%d")
        pattern = f"vt_ip_cache:{today}:*"
        keys = await client.keys(pattern)
        stats = {"date": today, "total_entries": len(keys), "malicious_count": 0, "clean_count": 0, "error_count": 0}
        for key in keys:
            try:
                entry = await client.get(key)
                if entry:
                    import json
                    data = json.loads(entry)
                    if data.get('is_malicious'): stats['malicious_count'] += 1
                    else: stats['clean_count'] += 1
            except:
                stats['error_count'] += 1
        await client.close()
        return stats
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error getting cache stats: {e}")

@api_router.post("/vt-cache-cleanup")
async def cleanup_vt_cache():
    """Manually trigger VirusTotal cache cleanup."""
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        client = redis.from_url(redis_url, decode_responses=True)
        await client.ping()
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)
        pattern = f"vt_ip_cache:{yesterday.strftime('%Y-%m-%d')}:*"
        keys = await client.keys(pattern)
        cleaned = 0
        if keys: cleaned = await client.delete(*keys)
        await client.close()
        return {"message": "Cache cleanup completed", "cleaned_entries": cleaned}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error cleaning cache: {e}")

@api_router.get("/ips/banned", response_model=List[dict])
async def list_banned_ips(current_user = Depends(get_current_admin_user)):
    """List all banned IPs."""
    return await get_banned_ips()

@api_router.get("/ips/clean", response_model=List[dict])
async def list_clean_ips(current_user = Depends(get_current_admin_user)):
    """List all clean (whitelisted) IPs."""
    return await get_clean_ips()

@api_router.post("/ips/ban/{ip}")
async def ban_ip_endpoint(ip: str, current_user = Depends(get_current_admin_user)):
    """Ban an IP address."""
    success = await ban_ip(ip)
    if not success: raise HTTPException(status_code=400, detail="Failed to ban IP")
    return {"message": f"IP {ip} has been banned"}

@api_router.post("/ips/unban/{ip}")
async def unban_ip_endpoint(ip: str, current_user = Depends(get_current_admin_user)):
    """Remove IP from ban list."""
    success = await unban_ip(ip)
    if not success: raise HTTPException(status_code=404, detail="IP not found in ban list")
    return {"message": f"IP {ip} has been unbanned"}

# Include the API router
app.include_router(api_router)

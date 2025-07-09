from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from typing import List
import os
import redis.asyncio as redis

from .database import get_session
from .models import Site as SiteModel
from .schemas import SiteCreate, Site as SiteSchema
from .auth import verify_token, create_access_token, TokenResponse, authenticate_user
from .redis_service import publish_config_update, init_redis, close_redis

app = FastAPI(title="WAF Admin API")

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
    allow_origins=["http://localhost:5173"],  # Frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.get("/sites", response_model=List[SiteSchema])
async def list_sites(
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(verify_token)
):
    """List all protected sites."""
    result = await session.execute(select(SiteModel))
    sites = result.scalars().all()
    
    # Debug: Print raw data from database
    for site in sites:
        print(f"Raw site from DB: id={site.id}, port={site.port}, name={site.name}")
    
    # Manual conversion to include port field
    site_dicts = []
    for site in sites:
        site_dict = {
            "id": site.id,
            "port": site.port,
            "name": site.name,
            "host": site.host,
            "frontend_url": site.frontend_url,
            "backend_url": site.backend_url,
            "xss_enabled": site.xss_enabled,
            "sql_enabled": site.sql_enabled,
            "vt_enabled": site.vt_enabled
        }
        site_dicts.append(site_dict)
    
    return site_dicts

@app.post("/sites", response_model=SiteSchema, status_code=status.HTTP_201_CREATED)
async def create_site(
    site: SiteCreate,
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(verify_token)
):
    """Add a new protected site."""
    # Check if port+host combination already exists
    result = await session.execute(
        select(SiteModel).filter(
            SiteModel.port == site.port,
            SiteModel.host == site.host
        )
    )
    existing_site = result.scalars().first()
    if existing_site:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Site with port {site.port} and host '{site.host}' already exists"
        )
    
    # Create new site
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
    
    # Notify WAF about configuration change
    await publish_config_update(site.port)
    
    return new_site

@app.delete("/sites/{port}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(
    port: int,
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(verify_token)
):
    """Delete a protected site by port."""
    result = await session.execute(select(SiteModel).filter(SiteModel.port == port))
    site = result.scalar_one_or_none()
    
    if not site:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Site with port {port} not found"
        )
    
    await session.delete(site)
    await session.commit()
    
    # Notify WAF about configuration change
    await publish_config_update(port)

@app.put("/sites/{site_id}", response_model=SiteSchema)
async def update_site(
    site_id: int,
    site_update: SiteCreate,
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(verify_token)
):
    """Update an existing protected site."""
    # Get the existing site
    result = await session.execute(select(SiteModel).filter(SiteModel.id == site_id))
    existing_site = result.scalar_one_or_none()
    
    if not existing_site:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Site with ID {site_id} not found"
        )
    
    # Check if the new port+host combination conflicts with another site
    if (existing_site.port != site_update.port or existing_site.host != site_update.host):
        conflict_result = await session.execute(
            select(SiteModel).filter(
                SiteModel.port == site_update.port,
                SiteModel.host == site_update.host,
                SiteModel.id != site_id  # Exclude current site
            )
        )
        conflicting_site = conflict_result.scalars().first()
        if conflicting_site:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Site with port {site_update.port} and host '{site_update.host}' already exists"
            )
    
    # Store old port for notification
    old_port = existing_site.port
    
    # Update the site
    existing_site.port = site_update.port
    existing_site.host = site_update.host
    existing_site.name = site_update.name
    existing_site.frontend_url = str(site_update.frontend_url)
    existing_site.backend_url = str(site_update.backend_url)
    existing_site.xss_enabled = site_update.xss_enabled
    existing_site.sql_enabled = site_update.sql_enabled
    existing_site.vt_enabled = site_update.vt_enabled
    
    await session.commit()
    await session.refresh(existing_site)
    
    # Notify WAF about configuration changes
    await publish_config_update(old_port)  # Old port
    if old_port != site_update.port:
        await publish_config_update(site_update.port)  # New port if changed
    
    return existing_site

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

@app.get("/vt-cache-stats")
async def get_vt_cache_stats(
    _: dict = Depends(verify_token)
):
    """Get VirusTotal cache statistics."""
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        
        # Direct Redis connection for cache stats
        redis_client = redis.from_url(redis_url, decode_responses=True)
        await redis_client.ping()
        
        # Get today's cache entries
        from datetime import datetime
        today = datetime.now().strftime("%Y-%m-%d")
        pattern = f"vt_ip_cache:{today}:*"
        keys = await redis_client.keys(pattern)
        
        stats = {
            "date": today,
            "total_entries": len(keys),
            "malicious_count": 0,
            "clean_count": 0,
            "error_count": 0
        }
        
        # Count malicious vs clean
        for key in keys:
            try:
                data = await redis_client.get(key)
                if data:
                    import json
                    entry_data = json.loads(data)
                    if entry_data.get('is_malicious'):
                        stats["malicious_count"] += 1
                    else:
                        stats["clean_count"] += 1
            except:
                stats["error_count"] += 1
        
        await redis_client.close()
        return stats
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting cache stats: {str(e)}"
        )

@app.post("/vt-cache-cleanup")
async def cleanup_vt_cache(
    _: dict = Depends(verify_token)
):
    """Manually trigger VirusTotal cache cleanup."""
    try:
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        
        # Direct Redis connection for cleanup
        redis_client = redis.from_url(redis_url, decode_responses=True)
        await redis_client.ping()
        
        from datetime import datetime, timedelta
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)
        
        # Clean yesterday's cache
        yesterday_pattern = f"vt_ip_cache:{yesterday.strftime('%Y-%m-%d')}:*"
        yesterday_keys = await redis_client.keys(yesterday_pattern)
        
        cleaned_count = 0
        if yesterday_keys:
            cleaned_count = await redis_client.delete(*yesterday_keys)
        
        await redis_client.close()
        
        return {
            "message": "Cache cleanup completed",
            "cleaned_entries": cleaned_count
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error cleaning cache: {str(e)}"
        )

# api/app/routers/sites.py
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import redis.asyncio as redis
import aiohttp
import asyncio
import logging

logger = logging.getLogger(__name__)

from app.database import get_session
from app.models import Site as SiteModel
from app.schemas import SiteCreate, Site as SiteSchema, UserInDB
from app.core.security import get_current_admin_user
from app.core.dependencies import get_redis_connection
from app.services import redis_publisher

router = APIRouter(prefix="/sites", tags=["Sites"])




async def check_external_site_health(host: str, port: int = 80) -> str:
    """Check if a site is healthy by making HTTP request through WAF."""
    try:
        logger.info(f"Health check starting for {host}:{port}")
        timeout = aiohttp.ClientTimeout(total=5)  # 5 second timeout
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Use WAF as proxy to check the site
            url = f"http://waf:80/"
            headers = {"Host": host}
            logger.info(f"Making request to WAF: {url} with Host: {host}")
            async with session.get(url, headers=headers) as response:
                logger.info(f"Response status: {response.status}")
                if response.status < 500:
                    logger.info(f"Site {host}:{port} is HEALTHY")
                    return 'healthy'
                else:
                    logger.warning(f"Site {host}:{port} is UNHEALTHY (status: {response.status})")
                    return 'unhealthy'
    except Exception as e:
        logger.error(f"Error checking {host}:{port}: {str(e)}")
        return 'unhealthy'

async def check_site_health(site) -> str:
    """Check if a site is healthy by making HTTP request to the host and port."""
    try:
        logger.info(f"Starting health check for site: {site.name} ({site.host}:{site.port})")
        # Use the site's host and port to check health
        result = await check_external_site_health(site.host, site.port)
        logger.info(f"Health check result for {site.name}: {result}")
        return result
    except Exception as e:
        logger.error(f"Error in check_site_health for {site.name}: {str(e)}")
        return 'unhealthy'

@router.get("", response_model=List[SiteSchema])
async def list_sites(
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """List all protected sites with health status."""
    result = await session.execute(select(SiteModel).order_by(SiteModel.id))
    sites = result.scalars().all()
    
    # Check health status for each site concurrently
    logger.info(f"Starting health checks for {len(sites)} sites...")
    health_tasks = []
    for site in sites:
        task = check_site_health(site)
        health_tasks.append((site, task))
    
    # Run health checks concurrently and add health_status to each site
    for site, task in health_tasks:
        logger.info(f"Waiting for health check result for {site.name}...")
        site.health_status = await task
        logger.info(f"Health status for {site.name}: {site.health_status}")
    
    logger.info(f"All health checks completed!")
    
    return sites


@router.post("", response_model=SiteSchema, status_code=status.HTTP_201_CREATED)
async def create_site(
        site: SiteCreate,
        session: AsyncSession = Depends(get_session),
        redis_client: redis.Redis = Depends(get_redis_connection),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Add a new protected site."""
    existing = await session.execute(
        select(SiteModel).filter_by(port=site.port, host=site.host)
    )
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Site with port {site.port} and host '{site.host}' already exists."
        )

    data = site.model_dump()
    data["frontend_url"] = str(data["frontend_url"])
    data["backend_url"] = str(data["backend_url"])

    new_site = SiteModel(**data)
    session.add(new_site)
    await session.commit()
    await session.refresh(new_site)
    await redis_publisher.publish_config_update(site.port, redis_client)
    return new_site


@router.put("/{site_id}", response_model=SiteSchema)
async def update_site(
        site_id: int,
        site_update: SiteCreate,
        session: AsyncSession = Depends(get_session),
        redis_client: redis.Redis = Depends(get_redis_connection),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Update an existing protected site."""
    db_site = await session.get(SiteModel, site_id)
    if not db_site:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Site with ID {site_id} not found.")

    old_port = db_site.port

    if db_site.port != site_update.port or db_site.host != site_update.host:
        conflict = await session.execute(
            select(SiteModel).filter_by(port=site_update.port, host=site_update.host)
        )
        if conflict.scalars().first():
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Site with port {site_update.port} and host '{site_update.host}' already exists."
            )

    update_data = site_update.model_dump()
    update_data["frontend_url"] = str(update_data["frontend_url"])
    update_data["backend_url"] = str(update_data["backend_url"])

    for key, value in update_data.items():
        setattr(db_site, key, value)

    await session.commit()
    await session.refresh(db_site)

    await redis_publisher.publish_config_update(old_port, redis_client)
    if old_port != site_update.port:
        await redis_publisher.publish_config_update(site_update.port, redis_client)

    return db_site


@router.delete("/{site_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(
        site_id: int,
        session: AsyncSession = Depends(get_session),
        redis_client: redis.Redis = Depends(get_redis_connection),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """Delete a protected site."""
    db_site = await session.get(SiteModel, site_id)
    if not db_site:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Site with ID {site_id} not found.")

    port_to_update = db_site.port
    await session.delete(db_site)
    await session.commit()
    await redis_publisher.publish_config_update(port_to_update, redis_client)
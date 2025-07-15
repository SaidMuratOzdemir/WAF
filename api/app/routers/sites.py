# api/app/routers/sites.py

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import redis.asyncio as redis

from app.database import get_session
from app.models import Site as SiteModel
from app.schemas import SiteCreate, Site as SiteSchema, UserInDB
from app.core.security import get_current_admin_user
from app.core.dependencies import get_redis_connection
from app.services import redis_publisher

router = APIRouter(prefix="/sites", tags=["Sites"])


@router.get("", response_model=List[SiteSchema])
async def list_sites(
        session: AsyncSession = Depends(get_session),
        current_user: UserInDB = Depends(get_current_admin_user)
):
    """List all protected sites."""
    result = await session.execute(select(SiteModel).order_by(SiteModel.id))
    return result.scalars().all()


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

    new_site = SiteModel(**site.model_dump())
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

    # Check for conflicts if port/host are changing
    if db_site.port != site_update.port or db_site.host != site_update.host:
        conflict = await session.execute(
            select(SiteModel).filter_by(port=site_update.port, host=site_update.host)
        )
        if conflict.scalars().first():
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Site with port {site_update.port} and host '{site_update.host}' already exists."
            )

    for key, value in site_update.model_dump().items():
        setattr(db_site, key, value)

    await session.commit()
    await session.refresh(db_site)

    # Notify workers of config changes
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
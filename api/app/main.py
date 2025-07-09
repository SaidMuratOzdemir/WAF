from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from typing import List
import os

from .database import get_session
from .models import Site as SiteModel
from .schemas import SiteCreate, Site as SiteSchema
from .auth import verify_token, create_access_token, TokenResponse, authenticate_user
from .redis_service import publish_config_update

app = FastAPI(title="WAF Admin API")

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

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}

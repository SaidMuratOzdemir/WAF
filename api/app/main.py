from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from typing import List
import os

from .database import get_session
from .models import Site
from .schemas import SiteCreate, SiteResponse
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

@app.get("/sites", response_model=List[SiteResponse])
async def list_sites(
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(verify_token)
):
    """List all protected sites."""
    result = await session.execute(select(Site))
    sites = result.scalars().all()
    return sites

@app.post("/sites", response_model=SiteResponse, status_code=status.HTTP_201_CREATED)
async def create_site(
    site: SiteCreate,
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(verify_token)
):
    """Add a new protected site."""
    # Check if port, frontend_url, or backend_url are already in use
    result = await session.execute(
        select(Site).filter(
            or_(
                Site.port == site.port,
                Site.frontend_url == str(site.frontend_url),
                Site.backend_url == str(site.backend_url)
            )
        )
    )
    existing_site = result.scalars().first()
    if existing_site:
        if existing_site.port == site.port:
            detail = f"Port {site.port} is already in use"
        elif existing_site.frontend_url == str(site.frontend_url):
            detail = f"Frontend URL {site.frontend_url} is already in use"
        else:
            detail = f"Backend URL {site.backend_url} is already in use"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail
        )
    
    # Convert HttpUrl objects to strings for database storage
    site_data = site.model_dump()
    site_data['frontend_url'] = str(site_data['frontend_url'])
    site_data['backend_url'] = str(site_data['backend_url'])
    
    db_site = Site(**site_data)
    session.add(db_site)
    await session.commit()
    await session.refresh(db_site)
    
    # Notify WAF about configuration change
    await publish_config_update(site.port)
    
    return db_site

@app.delete("/sites/{port}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_site(
    port: int,
    session: AsyncSession = Depends(get_session),
    _: dict = Depends(verify_token)
):
    """Delete a protected site."""
    result = await session.execute(select(Site).filter(Site.port == port))
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

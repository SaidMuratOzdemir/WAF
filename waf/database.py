import os
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Boolean, select
from typing import Dict, List, Optional
import logging

# Base class for SQLAlchemy models
Base = declarative_base()

class Site(Base):
    __tablename__ = "sites"
    
    port = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    frontend_url = Column(String, nullable=False)
    backend_url = Column(String, nullable=False)
    xss_enabled = Column(Boolean, default=True)
    sql_enabled = Column(Boolean, default=True)

# Database configuration - Use PostgreSQL in production, SQLite for development
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://waf:waf@localhost:5432/waf")

# Create async engine
engine = create_async_engine(DATABASE_URL, echo=False, pool_size=20, max_overflow=30)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def init_database():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_session() -> AsyncSession:
    """Get database session."""
    async with async_session() as session:
        return session

async def fetch_sites_from_db() -> Dict[int, Site]:
    """Fetch all sites from database and return as dict keyed by port."""
    sites_dict = {}
    async with async_session() as session:
        try:
            result = await session.execute(select(Site))
            sites = result.scalars().all()
            for site in sites:
                sites_dict[site.port] = site
            logging.info(f"Loaded {len(sites_dict)} sites from database")
        except Exception as e:
            logging.error(f"Error fetching sites from database: {e}")
    return sites_dict

async def get_site_by_port(port: int) -> Optional[Site]:
    """Get a specific site by port."""
    async with async_session() as session:
        try:
            result = await session.execute(select(Site).filter(Site.port == port))
            return result.scalar_one_or_none()
        except Exception as e:
            logging.error(f"Error fetching site for port {port}: {e}")
            return None

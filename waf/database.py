import os
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Boolean, select, UniqueConstraint
from typing import Dict, List, Optional
import logging

# Base class for SQLAlchemy models
Base = declarative_base()

class Site(Base):
    __tablename__ = "sites"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    port = Column(Integer, nullable=False)
    host = Column(String, nullable=False)  # Host header to match
    name = Column(String, nullable=False)
    frontend_url = Column(String, nullable=False)
    backend_url = Column(String, nullable=False)
    xss_enabled = Column(Boolean, default=True)
    sql_enabled = Column(Boolean, default=True)
    vt_enabled = Column(Boolean, default=False)  # Add this line
    
    # Composite unique constraint for port+host combination
    __table_args__ = (
        UniqueConstraint('port', 'host', name='unique_port_host'),
        {'extend_existing': True}
    )

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

async def fetch_sites_from_db() -> Dict[int, Dict[str, Site]]:
    """Fetch all sites from database and return as nested dict keyed by port and host."""
    sites_dict = {}
    async with async_session() as session:
        try:
            result = await session.execute(select(Site))
            sites = result.scalars().all()
            for site in sites:
                if site.port not in sites_dict:
                    sites_dict[site.port] = {}
                sites_dict[site.port][site.host] = site
            logging.info(f"Loaded {len(sites)} sites from database across {len(sites_dict)} ports")
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

async def get_site_by_port_and_host(port: int, host: str) -> Optional[Site]:
    """Get a specific site by port and host."""
    async with async_session() as session:
        try:
            result = await session.execute(
                select(Site).filter(Site.port == port, Site.host == host)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            logging.error(f"Error fetching site for port {port} and host {host}: {e}")
            return None

async def get_sites_by_port(port: int) -> List[Site]:
    """Get all sites for a specific port."""
    async with async_session() as session:
        try:
            result = await session.execute(select(Site).filter(Site.port == port))
            return result.scalars().all()
        except Exception as e:
            logging.error(f"Error fetching sites for port {port}: {e}")
            return []

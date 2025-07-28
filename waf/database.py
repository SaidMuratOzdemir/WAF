# waf/database.py

import os
import logging
from datetime import datetime
from dotenv import load_dotenv
from typing import Dict, List, Optional

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    UniqueConstraint,
    select,
)
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker, declarative_base

# Load environment variables if present
load_dotenv()

# SQLAlchemy Base model
Base = declarative_base()

# --- MODELS ---

class Site(Base):
    __tablename__ = "sites"

    id = Column(Integer, primary_key=True, autoincrement=True)
    port = Column(Integer, nullable=False)
    host = Column(String, nullable=False)
    name = Column(String, nullable=False)
    frontend_url = Column(String, nullable=False)
    backend_url = Column(String, nullable=False)
    xss_enabled = Column(Boolean, default=True)
    sql_enabled = Column(Boolean, default=True)
    vt_enabled = Column(Boolean, default=False)

    __table_args__ = (
        UniqueConstraint('port', 'host', name='unique_port_host'),
    )

class MaliciousPattern(Base):
    __tablename__ = "malicious_patterns"

    id = Column(Integer, primary_key=True, autoincrement=True)
    pattern = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow,
                        onupdate=datetime.utcnow, nullable=False)

# --- DATABASE CONFIGURATION ---

DATABASE_URL = os.getenv("DATABASE_URL") or (
    f"postgresql+asyncpg://{os.getenv('POSTGRES_USER')}:{os.getenv('POSTGRES_PASSWORD')}@postgres:5432/{os.getenv('POSTGRES_DB')}"
)

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=20,
    max_overflow=30
)

AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# --- INIT FUNCTION ---

async def init_database():
    """Create all tables defined by Base models."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logging.info("Database initialized.")

# --- SESSION UTILITY ---

async def get_session() -> AsyncSession:
    """Get a new async database session."""
    async with AsyncSessionLocal() as session:
        yield session

# --- DATA ACCESS HELPERS ---

async def fetch_sites_from_db() -> Dict[int, Dict[str, Site]]:
    """Fetch all sites and organize by port and host."""
    sites_dict = {}
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(Site))
            sites = result.scalars().all()
            for site in sites:
                if site.port not in sites_dict:
                    sites_dict[site.port] = {}
                sites_dict[site.port][site.host] = site
            logging.info(f"Loaded {len(sites)} sites across {len(sites_dict)} ports.")
        except Exception as e:
            logging.error(f"Error fetching sites: {e}")
    return sites_dict

async def get_site_by_port(port: int) -> Optional[Site]:
    """Fetch a site by its port."""
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(Site).filter(Site.port == port))
            return result.scalar_one_or_none()
        except Exception as e:
            logging.error(f"Error fetching site on port {port}: {e}")
            return None

async def get_site_by_port_and_host(port: int, host: str) -> Optional[Site]:
    """Fetch a site by port and host."""
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(
                select(Site).filter(Site.port == port, Site.host == host)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            logging.error(f"Error fetching site for port {port} and host '{host}': {e}")
            return None

async def get_sites_by_port(port: int) -> List[Site]:
    """Get all sites on a given port."""
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(Site).filter(Site.port == port))
            return result.scalars().all()
        except Exception as e:
            logging.error(f"Error fetching sites on port {port}: {e}")
            return []

async def fetch_all_patterns() -> List[MaliciousPattern]:
    """Fetch all malicious patterns from the database."""
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(MaliciousPattern))
            return result.scalars().all()
        except Exception as e:
            logging.error(f"Error fetching malicious patterns: {e}")
            return []

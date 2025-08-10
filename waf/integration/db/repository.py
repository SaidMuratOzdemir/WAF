from typing import Dict, List, Optional
import logging
from sqlalchemy import select

from models import Site, MaliciousPattern
from waf.integration.db.connection import AsyncSessionLocal


async def fetch_sites_from_db() -> Dict[int, Dict[str, Site]]:
    sites_dict: Dict[int, Dict[str, Site]] = {}
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
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(Site).filter(Site.port == port))
            return result.scalar_one_or_none()
        except Exception as e:
            logging.error(f"Error fetching site on port {port}: {e}")
            return None


async def get_site_by_port_and_host(port: int, host: str) -> Optional[Site]:
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(Site).filter(Site.port == port, Site.host == host))
            return result.scalar_one_or_none()
        except Exception as e:
            logging.error(f"Error fetching site for port {port} and host '{host}': {e}")
            return None


async def get_sites_by_port(port: int) -> List[Site]:
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(Site).filter(Site.port == port))
            return result.scalars().all()
        except Exception as e:
            logging.error(f"Error fetching sites on port {port}: {e}")
            return []


async def fetch_all_patterns() -> List[MaliciousPattern]:
    async with AsyncSessionLocal() as session:
        try:
            result = await session.execute(select(MaliciousPattern))
            return result.scalars().all()
        except Exception as e:
            logging.error(f"Error fetching malicious patterns: {e}")
            return []



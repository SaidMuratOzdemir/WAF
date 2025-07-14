from sqlalchemy import Column, Integer, String, Boolean, DateTime, UniqueConstraint
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

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
    )

class MaliciousPattern(Base):
    __tablename__ = "malicious_patterns"
    id = Column(Integer, primary_key=True, autoincrement=True)
    pattern = Column(String, nullable=False)
    type = Column(String, nullable=False)  # xss, sql, custom
    description = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)

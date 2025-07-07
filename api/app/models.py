from sqlalchemy import Column, Integer, String, Boolean, DateTime
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
    
    port = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    frontend_url = Column(String, nullable=False)
    backend_url = Column(String, nullable=False)
    xss_enabled = Column(Boolean, default=True)
    sql_enabled = Column(Boolean, default=True)

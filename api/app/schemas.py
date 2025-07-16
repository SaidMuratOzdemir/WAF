# api/app/schemas.py

from __future__ import annotations
from pydantic import BaseModel, HttpUrl, Field, field_validator, ConfigDict
from typing import Optional, List
from datetime import datetime

# --- Token Schemas ---
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None

# --- User Schemas ---
class UserBase(BaseModel):
    username: str

class UserInDB(UserBase):
    id: int
    is_admin: bool
    model_config = ConfigDict(from_attributes=True)

# --- Site Schemas ---
class SiteBase(BaseModel):
    port: int = Field(..., ge=1, le=65535, description="Port number for the site")
    name: str
    host: str = Field(..., description='Host header to match (e.g., "api.example.com")')
    frontend_url: HttpUrl
    backend_url: HttpUrl
    xss_enabled: bool = True
    sql_enabled: bool = True
    vt_enabled: bool = False

    @field_validator('host')
    def validate_host(cls, v):
        if not v or v.isspace():
            raise ValueError("Host cannot be empty")
        return v.lower()

class SiteCreate(SiteBase):
    pass

class Site(SiteBase):
    id: int
    model_config = ConfigDict(from_attributes=True)

# --- Malicious Pattern Schemas ---
class MaliciousPatternBase(BaseModel):
    pattern: str
    type: str
    description: Optional[str] = None

class MaliciousPatternCreate(MaliciousPatternBase):
    pass

class MaliciousPatternUpdate(BaseModel):
    pattern: Optional[str] = None
    type: Optional[str] = None
    description: Optional[str] = None

class MaliciousPatternOut(MaliciousPatternBase):
    id: int
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)

class PatternPage(BaseModel):
    items: List[MaliciousPatternOut]
    total: int

# --- IP Management Schemas ---
class BannedIP(BaseModel):
    ip: str
    banned_at: Optional[datetime] = None

class CleanIP(BaseModel):
    ip: str
    added_at: Optional[datetime] = None
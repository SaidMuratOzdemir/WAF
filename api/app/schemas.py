from pydantic import BaseModel, HttpUrl, conint, field_validator
from typing import Optional

class SiteBase(BaseModel):
    port: int
    name: str
    host: str  # Host header to match (e.g., "api.example.com" or "*.example.com")
    frontend_url: HttpUrl
    backend_url: HttpUrl
    xss_enabled: bool = True
    sql_enabled: bool = True
    vt_enabled: bool = False


class SiteCreate(SiteBase):
    pass  # Inherits all fields from SiteBase including port validation


class Site(SiteBase):
    id: int

    class Config:
        from_attributes = True

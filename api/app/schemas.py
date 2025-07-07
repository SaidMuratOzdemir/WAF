from pydantic import BaseModel, HttpUrl, conint, field_validator
from typing import Optional

class SiteBase(BaseModel):
    name: str
    frontend_url: HttpUrl
    backend_url: HttpUrl
    xss_enabled: bool = True
    sql_enabled: bool = True

class SiteCreate(SiteBase):
    port: conint(ge=1024, le=65535)  # Port range validation

class SiteResponse(SiteBase):
    port: int
    
    @field_validator('frontend_url', 'backend_url', mode='before')
    @classmethod
    def validate_urls(cls, v):
        if isinstance(v, str):
            return v
        return str(v)

    class Config:
        from_attributes = True

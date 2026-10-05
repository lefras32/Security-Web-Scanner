from pydantic import BaseModel, HttpUrl, Field
from typing import Dict, List

class ScanRequest(BaseModel):
    url: HttpUrl = Field(
        ...,
        examples=["https://example.com"]
    )

class ScanResponse(BaseModel):
    target_url: str = Field(
        ...,
        examples=["https://example.com"]
    )
    security_score: int = Field(
        ...,
        ge=0,
        le=100,
        examples=[67]
    )
    headers_found: Dict[str, str] = Field(
        ...,
        examples=[{
            "Content-Security-Policy": "frame-ancestors 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff"
        }]
    )
    headers_missing: List[str] = Field(
        ...,
        examples=[["Referrer-Policy", "Permissions-Policy"]]
    )
    recommendations: List[str] = Field(
        ...,
        examples=[[
            "Missing security header: Referrer-Policy",
            "Missing security header: Permissions-Policy"
        ]]
    )

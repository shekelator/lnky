"""
Lnky - URL shortener service built with FastAPI.

Runs in AWS AppRunner with DynamoDB backend.
Supports local development with DynamoDB Local.
"""
import hashlib
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Optional

import boto3
import shortuuid
from botocore.config import Config
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")
    aws_endpoint: Optional[str] = Field(default=None, alias="AWS_ENDPOINT")
    port: int = Field(default=8080, alias="PORT")
    urls_table: str = Field(default="URLs", alias="URLS_TABLE")
    analytics_table: str = Field(default="Analytics", alias="ANALYTICS_TABLE")

    # Endpoint feature flags
    enable_admin_endpoints: bool = Field(default=True, alias="ENABLE_ADMIN_ENDPOINTS")

    model_config = {"populate_by_name": True}


settings = Settings()


# Pydantic models
class ShortenRequest(BaseModel):
    """Request model for URL shortening."""

    url: str = Field(..., min_length=1)
    title: Optional[str] = Field(default=None)
    short_id: Optional[str] = Field(default=None, alias="shortId")


class ShortenResponse(BaseModel):
    """Response model for URL shortening."""

    short_id: str
    short_url: str
    target_url: str


class URLEntry(BaseModel):
    """Model for URL entries stored in DynamoDB."""

    short_id: str
    target_url: str
    created_at: str
    title: Optional[str] = None


class AnalyticsEntry(BaseModel):
    """Model for analytics entries stored in DynamoDB."""

    short_id: str
    timestamp: str
    user_agent: str
    referrer: str
    ip_hash: str


class StatsResponse(BaseModel):
    """Response model for stats endpoint."""

    short_id: str
    clicks: int
    details: list[dict[str, Any]]


# Global variable for DynamoDB client
dynamodb_client = None


def get_dynamodb_client():
    """Create and return a DynamoDB client."""
    client_config = Config(
        region_name=settings.aws_region,
    )

    kwargs = {"config": client_config}

    if settings.aws_endpoint:
        kwargs["endpoint_url"] = settings.aws_endpoint
        # For local development, we can use dummy credentials
        kwargs["aws_access_key_id"] = os.environ.get("AWS_ACCESS_KEY_ID", "dummy")
        kwargs["aws_secret_access_key"] = os.environ.get(
            "AWS_SECRET_ACCESS_KEY", "dummy"
        )
        logger.info(f"Using custom DynamoDB endpoint: {settings.aws_endpoint}")

    return boto3.client("dynamodb", **kwargs)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages application startup and shutdown sequence.

    On startup:
        - Initializes the global DynamoDB client.

    On shutdown:
        - Logs shutdown message.
    """
    global dynamodb_client

    # Startup
    dynamodb_client = get_dynamodb_client()
    logger.info(f"Server starting on port {settings.port}")

    yield

    # Shutdown
    logger.info("Server shut down gracefully")


app = FastAPI(
    title="Lnky",
    description="URL shortener service",
    lifespan=lifespan,
)


def is_valid_url(url: str) -> bool:
    """Validate that URL starts with http:// or https://."""
    return url.startswith("http://") or url.startswith("https://")


def hash_ip(ip: str) -> str:
    """Hash an IP address for privacy."""
    # Remove port if present
    ip_address = ip.split(":")[0]
    return hashlib.sha256(ip_address.encode()).hexdigest()


@app.post("/api/shorten", response_model=ShortenResponse)
async def shorten_url(request: Request, body: ShortenRequest):
    """Create a shortened URL."""
    if not settings.enable_admin_endpoints:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin endpoints are disabled"
        )

    if not is_valid_url(body.url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL"
        )

    # Use provided shortId or generate a new one
    short_id = body.short_id
    if short_id:
        # Check if the provided shortId is already in use
        try:
            result = dynamodb_client.get_item(
                TableName=settings.urls_table,
                Key={"short_id": {"S": short_id}},
            )
            if "Item" in result:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The provided ShortID is already in use",
                )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error checking ShortID existence: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify ShortID availability",
            )
    else:
        short_id = shortuuid.uuid()[:9]  # Generate a short unique ID

    # Create URL entry
    url_entry = URLEntry(
        short_id=short_id,
        target_url=body.url,
        created_at=datetime.now().isoformat(),
        title=body.title,
    )

    # Store in DynamoDB
    try:
        item = {
            "short_id": {"S": url_entry.short_id},
            "target_url": {"S": url_entry.target_url},
            "created_at": {"S": url_entry.created_at},
        }
        if url_entry.title:
            item["title"] = {"S": url_entry.title}

        dynamodb_client.put_item(
            TableName=settings.urls_table,
            Item=item,
        )
    except Exception as e:
        logger.error(f"Error putting item in DynamoDB: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create short URL",
        )

    # Create response with short URL
    # Use X-Forwarded-Host if available (for proxies), otherwise use request host
    host = request.headers.get("x-forwarded-host") or request.headers.get(
        "host", "localhost"
    )
    # Use X-Forwarded-Proto if available (for proxies), otherwise use request scheme
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    short_url = f"{proto}://{host}/s/{short_id}"

    return ShortenResponse(
        short_id=short_id,
        short_url=short_url,
        target_url=body.url,
    )


@app.get("/api/stats/{short_id}", response_model=StatsResponse)
async def get_stats(short_id: str):
    """Get analytics stats for a shortened URL."""
    if not settings.enable_admin_endpoints:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin endpoints are disabled"
        )

    if not short_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Short ID is required"
        )

    try:
        result = dynamodb_client.query(
            TableName=settings.analytics_table,
            KeyConditionExpression="short_id = :sid",
            ExpressionAttributeValues={":sid": {"S": short_id}},
        )

        analytics = []
        for item in result.get("Items", []):
            analytics.append(
                {
                    "short_id": item.get("short_id", {}).get("S", ""),
                    "timestamp": item.get("timestamp", {}).get("S", ""),
                    "user_agent": item.get("user_agent", {}).get("S", ""),
                    "referrer": item.get("referrer", {}).get("S", ""),
                    "ip_hash": item.get("ip_hash", {}).get("S", ""),
                }
            )

        return StatsResponse(
            short_id=short_id,
            clicks=len(analytics),
            details=analytics,
        )
    except Exception as e:
        logger.error(f"Error querying analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch stats",
        )


@app.get("/s/{short_id}")
async def redirect_url(short_id: str, request: Request):
    """Redirect to the target URL for a shortened URL."""
    if not short_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Not found"
        )

    # Look up the URL in DynamoDB
    try:
        result = dynamodb_client.get_item(
            TableName=settings.urls_table,
            Key={"short_id": {"S": short_id}},
        )
    except Exception as e:
        logger.error(f"Error getting item from DynamoDB: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server error",
        )

    # Check if URL was found
    if "Item" not in result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Short URL not found"
        )

    target_url = result["Item"].get("target_url", {}).get("S", "")

    # Track analytics (write directly to DynamoDB)
    try:
        client_ip = request.client.host if request.client else ""
        timestamp = datetime.now().isoformat()
        
        dynamodb_client.put_item(
            TableName=settings.analytics_table,
            Item={
                "short_id": {"S": short_id},
                "timestamp": {"S": timestamp},
                "user_agent": {"S": request.headers.get("user-agent", "")},
                "referrer": {"S": request.headers.get("referer", "")},
                "ip_hash": {"S": hash_ip(client_ip)},
            },
        )
    except Exception as e:
        # Log analytics errors but don't fail the redirect
        logger.error(f"Error storing analytics for {short_id}: {e}")

    return RedirectResponse(url=target_url, status_code=status.HTTP_302_FOUND)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=settings.port)

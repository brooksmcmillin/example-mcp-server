"""OAuth 2.0 Authorization Server for the example MCP notes API.

Implements:
- RFC 7591: Dynamic Client Registration
- RFC 6749: Token endpoint (client_credentials grant)
- RFC 7662: Token Introspection
- RFC 8414: Authorization Server Metadata
"""

import os
import secrets
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from mcp_auth_framework import (
    MemoryTokenStorage,
    SlidingWindowRateLimiter,
    TokenStorage,
    invalid_client,
    invalid_request,
    invalid_scope,
    rate_limit_exceeded,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://localhost:9000")
DATABASE_URL = os.environ.get("DATABASE_URL")
TOKEN_TTL = 3600  # 1 hour

AVAILABLE_SCOPES = {"notes:read", "notes:write"}

# ---------------------------------------------------------------------------
# State (populated during lifespan)
# ---------------------------------------------------------------------------

storage: TokenStorage | None = None

# In-memory client registry. Production servers should use a database.
registered_clients: dict[str, dict[str, str | list[str] | int]] = {}

# Rate limiter: 60 requests per 5 minutes per client
token_limiter = SlidingWindowRateLimiter(requests_per_window=60, window_seconds=300)

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


async def register_handler(request: Request) -> JSONResponse:
    """RFC 7591: Dynamic Client Registration."""
    try:
        body = await request.json()
    except Exception:
        return invalid_request("Request body must be valid JSON")

    client_name = body.get("client_name", "")
    if not client_name:
        return invalid_request("client_name is required")

    # Generate credentials
    client_id = f"client_{secrets.token_hex(8)}"
    client_secret = secrets.token_urlsafe(32)

    # Determine scopes
    requested_scopes = body.get("scope", "notes:read notes:write")
    if isinstance(requested_scopes, list):
        requested_scopes = " ".join(requested_scopes)
    scope_set = set(str(requested_scopes).split())
    invalid = scope_set - AVAILABLE_SCOPES
    if invalid:
        return invalid_scope(f"Unknown scopes: {', '.join(sorted(invalid))}")

    registered_clients[client_id] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "scopes": sorted(scope_set),
        "created_at": int(time.time()),
    }

    return JSONResponse(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "scope": " ".join(sorted(scope_set)),
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        },
        status_code=201,
    )


async def token_handler(request: Request) -> JSONResponse:
    """RFC 6749: Token endpoint (client_credentials grant)."""
    assert storage is not None
    form = await request.form()

    grant_type = str(form.get("grant_type", ""))
    if grant_type != "client_credentials":
        return invalid_request(f"Unsupported grant_type: {grant_type!r}. Use 'client_credentials'.")

    client_id = str(form.get("client_id", ""))
    client_secret = str(form.get("client_secret", ""))
    if not client_id or not client_secret:
        return invalid_client("client_id and client_secret are required")

    # Rate limit
    if not token_limiter.is_allowed(client_id):
        return rate_limit_exceeded(
            "Too many token requests",
            retry_after=token_limiter.get_retry_after(client_id),
        )

    # Authenticate
    client = registered_clients.get(client_id)
    if not client or not secrets.compare_digest(str(client["client_secret"]), client_secret):
        return invalid_client("Invalid client credentials")

    # Resolve scopes
    requested_scope = str(form.get("scope", ""))
    allowed_scopes = set(client["scopes"]) if isinstance(client["scopes"], list) else set()
    if requested_scope:
        scopes = set(requested_scope.split())
        if not scopes.issubset(allowed_scopes):
            return invalid_scope("Requested scopes exceed client authorization")
    else:
        scopes = allowed_scopes

    # Issue token
    access_token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + TOKEN_TTL

    await storage.store_token(
        token=access_token,
        client_id=client_id,
        scopes=sorted(scopes),
        expires_at=expires_at,
    )

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": TOKEN_TTL,
            "scope": " ".join(sorted(scopes)),
        }
    )


async def introspect_handler(request: Request) -> JSONResponse:
    """RFC 7662: Token Introspection."""
    assert storage is not None
    form = await request.form()
    token = str(form.get("token", ""))

    if not token:
        return JSONResponse({"active": False})

    token_data = await storage.load_token(token)
    if not token_data or token_data["expires_at"] < time.time():
        return JSONResponse({"active": False})

    return JSONResponse(
        {
            "active": True,
            "client_id": token_data["client_id"],
            "scope": " ".join(token_data["scopes"]),
            "exp": token_data["expires_at"],
            "token_type": "bearer",
        }
    )


async def metadata_handler(request: Request) -> JSONResponse:
    """RFC 8414: OAuth 2.0 Authorization Server Metadata."""
    base = AUTH_SERVER_URL.rstrip("/")
    return JSONResponse(
        {
            "issuer": base,
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "introspection_endpoint": f"{base}/introspect",
            "scopes_supported": sorted(AVAILABLE_SCOPES),
            "response_types_supported": ["code"],
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
        }
    )


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(_app: Starlette) -> AsyncGenerator[None]:
    global storage
    new_storage: TokenStorage
    if DATABASE_URL:
        from mcp_auth_framework import PostgresTokenStorage

        new_storage = PostgresTokenStorage(database_url=DATABASE_URL)
    else:
        new_storage = MemoryTokenStorage()
    storage = new_storage
    await new_storage.initialize()
    try:
        yield
    finally:
        await new_storage.close()


app = Starlette(
    routes=[
        Route("/.well-known/oauth-authorization-server", metadata_handler, methods=["GET"]),
        Route("/.well-known/openid-configuration", metadata_handler, methods=["GET"]),
        Route("/register", register_handler, methods=["POST"]),
        Route("/token", token_handler, methods=["POST"]),
        Route("/introspect", introspect_handler, methods=["POST"]),
    ],
    lifespan=lifespan,
)

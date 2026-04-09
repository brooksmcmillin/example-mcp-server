"""OAuth 2.0 Authorization Server for the example MCP notes API.

Implements:
- RFC 6749: Authorization Code + Client Credentials grants
- RFC 7591: Dynamic Client Registration
- RFC 7636: PKCE (Proof Key for Code Exchange)
- RFC 7662: Token Introspection
- RFC 8414: Authorization Server Metadata
"""

import base64
import hashlib
import html
import os
import secrets
import time
import urllib.parse
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
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://localhost:9000")
DATABASE_URL = os.environ.get("DATABASE_URL")
TOKEN_TTL = 3600  # 1 hour
AUTH_CODE_TTL = 600  # 10 minutes

AVAILABLE_SCOPES = {"notes:read", "notes:write"}

# ---------------------------------------------------------------------------
# State (populated during lifespan)
# ---------------------------------------------------------------------------

storage: TokenStorage | None = None

# In-memory registries. Production servers should use a database.
registered_clients: dict[str, dict[str, str | list[str] | int | None]] = {}
authorization_codes: dict[str, dict[str, str | list[str] | int]] = {}

# Rate limiter: 60 requests per 5 minutes per client
token_limiter = SlidingWindowRateLimiter(requests_per_window=60, window_seconds=300)


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify PKCE code_verifier against stored code_challenge (S256 only)."""
    if method != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


def redirect_uri_matches(registered: str, requested: str) -> bool:
    """Check if a requested redirect URI matches a registered one.

    For loopback URIs (127.0.0.1, [::1], localhost) the port is ignored
    per RFC 8252 section 7.3, since native apps bind an ephemeral port.
    """
    reg = urllib.parse.urlparse(registered)
    req = urllib.parse.urlparse(requested)
    loopback = {"127.0.0.1", "::1", "localhost"}
    if reg.hostname in loopback:
        return reg.scheme == req.scheme and reg.hostname == req.hostname and reg.path == req.path
    return registered == requested


# ---------------------------------------------------------------------------
# Registration endpoint
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

    # Grant types (default: authorization_code for MCP clients)
    grant_types = body.get("grant_types", ["authorization_code"])
    if isinstance(grant_types, str):
        grant_types = [grant_types]

    # Auth method: "none" for public clients (MCP default), "client_secret_post" for confidential
    auth_method = body.get("token_endpoint_auth_method", "none")

    # Generate credentials
    client_id = f"client_{secrets.token_hex(8)}"
    client_secret = secrets.token_urlsafe(32) if auth_method != "none" else None

    # Redirect URIs (required for authorization_code grant)
    redirect_uris = body.get("redirect_uris", [])
    if "authorization_code" in grant_types and not redirect_uris:
        return invalid_request("redirect_uris required for authorization_code grant")

    # Scopes
    requested_scopes = body.get("scope", "notes:read notes:write")
    if isinstance(requested_scopes, list):
        requested_scopes = " ".join(requested_scopes)
    scope_set = set(str(requested_scopes).split())
    invalid = scope_set - AVAILABLE_SCOPES
    if invalid:
        return invalid_scope(f"Unknown scopes: {', '.join(sorted(invalid))}")

    response_types = body.get(
        "response_types", ["code"] if "authorization_code" in grant_types else []
    )

    registered_clients[client_id] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": client_name,
        "scopes": sorted(scope_set),
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "token_endpoint_auth_method": auth_method,
        "created_at": int(time.time()),
    }

    response: dict[str, str | list[str] | None] = {
        "client_id": client_id,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types,
        "response_types": response_types,
        "scope": " ".join(sorted(scope_set)),
        "token_endpoint_auth_method": auth_method,
    }
    if client_secret:
        response["client_secret"] = client_secret

    return JSONResponse(response, status_code=201)


# ---------------------------------------------------------------------------
# Authorization endpoint
# ---------------------------------------------------------------------------

CONSENT_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize {client_name}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 420px; margin: 60px auto;
         padding: 0 20px; color: #1a1a1a; }}
  h1 {{ font-size: 1.3rem; }}
  .scopes {{ background: #f5f5f5; border-radius: 6px; padding: 12px 16px; margin: 16px 0; }}
  .scopes li {{ margin: 4px 0; font-family: monospace; }}
  .buttons {{ display: flex; gap: 12px; margin-top: 24px; }}
  button {{ padding: 10px 24px; border-radius: 6px; border: 1px solid #ccc;
           cursor: pointer; font-size: 1rem; }}
  button[value="approve"] {{ background: #2563eb; color: white; border-color: #2563eb; }}
  button[value="deny"] {{ background: white; }}
</style>
</head>
<body>
<h1>Authorization Request</h1>
<p><strong>{client_name}</strong> is requesting access:</p>
<ul class="scopes">{scope_items}</ul>
<form method="POST" action="/authorize">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
  <div class="buttons">
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </div>
</form>
</body>
</html>"""


async def authorize_handler(request: Request) -> HTMLResponse | JSONResponse | RedirectResponse:
    """RFC 6749 section 4.1: Authorization endpoint.

    GET  -- validate parameters and show consent form.
    POST -- process the user's decision and redirect with an authorization code.
    """
    if request.method == "POST":
        return await _authorize_post(request)

    # --- GET: validate and show consent form ---
    params = request.query_params
    response_type = params.get("response_type", "")
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    scope = params.get("scope", "")
    state = params.get("state", "")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "S256")

    if response_type != "code":
        return invalid_request("response_type must be 'code'")
    if not client_id:
        return invalid_request("client_id is required")
    if not redirect_uri:
        return invalid_request("redirect_uri is required")
    if not code_challenge or code_challenge_method != "S256":
        return invalid_request("PKCE with S256 is required")

    client = registered_clients.get(client_id)
    if not client:
        return invalid_client("Unknown client_id")

    # Validate redirect_uri (loopback port-agnostic per RFC 8252)
    client_redirects = client.get("redirect_uris")
    if isinstance(client_redirects, list) and not any(
        redirect_uri_matches(str(r), redirect_uri) for r in client_redirects
    ):
        return invalid_request("redirect_uri not registered for this client")

    client_name = str(client.get("client_name", client_id))
    allowed_scopes = set(client["scopes"]) if isinstance(client["scopes"], list) else set()
    requested_scopes = set(scope.split()) if scope else allowed_scopes
    scopes = sorted(requested_scopes & allowed_scopes) or sorted(allowed_scopes)

    scope_items = "".join(f"<li>{html.escape(s)}</li>" for s in scopes)
    page = CONSENT_HTML.format(
        client_name=html.escape(client_name),
        client_id=html.escape(client_id),
        redirect_uri=html.escape(redirect_uri),
        scope=html.escape(" ".join(scopes)),
        state=html.escape(state),
        code_challenge=html.escape(code_challenge),
        code_challenge_method=html.escape(code_challenge_method),
        scope_items=scope_items,
    )
    return HTMLResponse(page)


async def _authorize_post(request: Request) -> RedirectResponse:
    """Process the consent form POST and redirect with an authorization code."""
    form = await request.form()
    action = str(form.get("action", ""))
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    scope = str(form.get("scope", ""))
    state = str(form.get("state", ""))
    code_challenge = str(form.get("code_challenge", ""))
    code_challenge_method = str(form.get("code_challenge_method", ""))

    if action == "deny":
        qs = urllib.parse.urlencode({"error": "access_denied", "state": state})
        return RedirectResponse(f"{redirect_uri}?{qs}", status_code=302)

    # Generate single-use authorization code
    code = secrets.token_urlsafe(32)
    authorization_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scopes": scope.split(),
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": int(time.time()) + AUTH_CODE_TTL,
    }

    qs = urllib.parse.urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}?{qs}", status_code=302)


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------


async def token_handler(request: Request) -> JSONResponse:
    """RFC 6749: Token endpoint (authorization_code + client_credentials)."""
    assert storage is not None
    form = await request.form()
    grant_type = str(form.get("grant_type", ""))

    if grant_type == "authorization_code":
        return await _exchange_authorization_code(form)
    if grant_type == "client_credentials":
        return await _client_credentials_grant(form)
    return invalid_request(
        f"Unsupported grant_type: {grant_type!r}. Use 'authorization_code' or 'client_credentials'."
    )


async def _exchange_authorization_code(form: FormData) -> JSONResponse:
    """Exchange an authorization code + PKCE verifier for an access token."""
    assert storage is not None

    code = str(form.get("code", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    client_id = str(form.get("client_id", ""))
    code_verifier = str(form.get("code_verifier", ""))

    if not code or not client_id or not code_verifier:
        return invalid_request("code, client_id, and code_verifier are required")

    # Pop the code (single-use)
    code_data = authorization_codes.pop(code, None)
    if not code_data:
        return invalid_request("Invalid or expired authorization code")

    if int(code_data["expires_at"]) < time.time():
        return invalid_request("Authorization code expired")

    if code_data["client_id"] != client_id:
        return invalid_client("client_id mismatch")

    if code_data["redirect_uri"] != redirect_uri:
        return invalid_request("redirect_uri mismatch")

    if not verify_pkce(
        code_verifier,
        str(code_data["code_challenge"]),
        str(code_data["code_challenge_method"]),
    ):
        return invalid_request("PKCE verification failed")

    # Issue token
    access_token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + TOKEN_TTL
    scopes = code_data["scopes"] if isinstance(code_data["scopes"], list) else []

    await storage.store_token(
        token=access_token,
        client_id=client_id,
        scopes=sorted(str(s) for s in scopes),
        expires_at=expires_at,
    )

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": TOKEN_TTL,
            "scope": " ".join(sorted(str(s) for s in scopes)),
        }
    )


async def _client_credentials_grant(form: FormData) -> JSONResponse:
    """Client credentials grant (machine-to-machine)."""
    assert storage is not None

    client_id = str(form.get("client_id", ""))
    client_secret = str(form.get("client_secret", ""))
    if not client_id or not client_secret:
        return invalid_client("client_id and client_secret are required")

    if not token_limiter.is_allowed(client_id):
        return rate_limit_exceeded(
            "Too many token requests",
            retry_after=token_limiter.get_retry_after(client_id),
        )

    client = registered_clients.get(client_id)
    if not client or not secrets.compare_digest(
        str(client.get("client_secret", "")), client_secret
    ):
        return invalid_client("Invalid client credentials")

    requested_scope = str(form.get("scope", ""))
    allowed_scopes = set(client["scopes"]) if isinstance(client["scopes"], list) else set()
    if requested_scope:
        scopes = set(requested_scope.split())
        if not scopes.issubset(allowed_scopes):
            return invalid_scope("Requested scopes exceed client authorization")
    else:
        scopes = allowed_scopes

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


# ---------------------------------------------------------------------------
# Introspection & metadata
# ---------------------------------------------------------------------------


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
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "introspection_endpoint": f"{base}/introspect",
            "scopes_supported": sorted(AVAILABLE_SCOPES),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
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
        Route("/authorize", authorize_handler, methods=["GET", "POST"]),
        Route("/token", token_handler, methods=["POST"]),
        Route("/introspect", introspect_handler, methods=["POST"]),
    ],
    lifespan=lifespan,
)

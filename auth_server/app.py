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
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from typing import cast

from mcp_authflow import (
    MemoryTokenStorage,
    SlidingWindowRateLimiter,
    TokenStorage,
    invalid_client,
    invalid_request,
    invalid_scope,
    oauth_error,
    rate_limit_exceeded,
)
from starlette.applications import Starlette
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_SERVER_URL = os.environ.get("AUTH_SERVER_URL", "http://localhost:9000")
DATABASE_URL = os.environ.get("DATABASE_URL")
TOKEN_TTL = 3600  # 1 hour
AUTH_CODE_TTL = 600  # 10 minutes

AVAILABLE_SCOPES = {"notes:read", "notes:write"}

# Credentials the calling protected resource must present on /introspect
# (RFC 7662 section 2.1). Treated as a shared secret between this server and the
# resource server(s) that introspect tokens here. The defaults suit the
# localhost demo; override BOTH in any real deployment.
INTROSPECTION_CLIENT_ID = os.environ.get("INTROSPECTION_CLIENT_ID", "resource-server")
INTROSPECTION_CLIENT_SECRET = os.environ.get(
    "INTROSPECTION_CLIENT_SECRET", "resource-server-secret"
)

# ---------------------------------------------------------------------------
# State (populated during lifespan)
# ---------------------------------------------------------------------------

storage: TokenStorage | None = None

# In-memory registries. Production servers should use a database.
registered_clients: dict[str, dict[str, str | list[str] | int | None]] = {}
authorization_codes: dict[str, dict[str, str | list[str] | int]] = {}

# Single-use CSRF tokens for the consent form: token -> expiry timestamp.
consent_csrf_tokens: dict[str, int] = {}
CSRF_TOKEN_TTL = 600  # 10 minutes

# Rate limiter: 60 requests per 5 minutes per client
token_limiter = SlidingWindowRateLimiter(requests_per_window=60, window_seconds=300)


# ---------------------------------------------------------------------------
# Rate-limiting helpers
# ---------------------------------------------------------------------------


def _client_ip(request: Request) -> str:
    """Best-effort source IP for limiter keying when no client_id is available."""
    return request.client.host if request.client else "unknown"


async def _enforce_rate_limit(scope: str, identifier: str) -> JSONResponse | None:
    """Apply the sliding-window limiter; return a 429 response if exceeded, else None.

    Keys are namespaced per endpoint ``scope`` so traffic to one endpoint cannot
    exhaust another's budget, and per ``identifier`` (a ``client_id`` when the
    request carries one, otherwise the source IP). This throttles
    registration flooding, authorization-code / PKCE brute force, and
    introspection enumeration (CWE-307, CWE-799).
    """
    rate_key = f"{scope}:{identifier}"
    if not await token_limiter.is_allowed(rate_key):
        return rate_limit_exceeded(
            "Too many requests",
            retry_after=await token_limiter.get_retry_after(rate_key),
        )
    return None


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
    # Throttle by source IP before doing any work, so the open registration
    # endpoint cannot be flooded to exhaust the in-memory client registry.
    limited = await _enforce_rate_limit("register", _client_ip(request))
    if limited is not None:
        return limited

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
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <div class="buttons">
    <button type="submit" name="action" value="approve">Approve</button>
    <button type="submit" name="action" value="deny">Deny</button>
  </div>
</form>
</body>
</html>"""


async def authorize_handler(request: Request) -> Response:
    """RFC 6749 section 4.1: Authorization endpoint.

    GET  -- validate parameters and show consent form.
    POST -- process the user's decision and redirect with an authorization code.
    """
    # Throttle by source IP across both methods so the consent flow cannot be
    # hammered to brute-force CSRF tokens or fish for valid client_ids.
    limited = await _enforce_rate_limit("authorize", _client_ip(request))
    if limited is not None:
        return limited

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

    # Issue a single-use CSRF token bound to this consent form.
    csrf_token = secrets.token_urlsafe(32)
    consent_csrf_tokens[csrf_token] = int(time.time()) + CSRF_TOKEN_TTL

    scope_items = "".join(f"<li>{html.escape(s)}</li>" for s in scopes)
    page = CONSENT_HTML.format(
        client_name=html.escape(client_name),
        client_id=html.escape(client_id),
        redirect_uri=html.escape(redirect_uri),
        scope=html.escape(" ".join(scopes)),
        state=html.escape(state),
        code_challenge=html.escape(code_challenge),
        code_challenge_method=html.escape(code_challenge_method),
        csrf_token=html.escape(csrf_token),
        scope_items=scope_items,
    )
    return HTMLResponse(page)


async def _authorize_post(request: Request) -> Response:
    """Process the consent form POST and redirect with an authorization code.

    Every security-relevant parameter is re-validated server-side here. The
    GET handler's checks are not sufficient on their own: codes are only ever
    minted on POST, and the form fields are fully attacker-controllable. Trusting
    them would allow authorization-code injection / open redirect to an arbitrary
    URI and scope escalation (CWE-601, CWE-285).
    """
    form = await request.form()
    action = str(form.get("action", ""))
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    scope = str(form.get("scope", ""))
    state = str(form.get("state", ""))
    code_challenge = str(form.get("code_challenge", ""))
    code_challenge_method = str(form.get("code_challenge_method", ""))
    csrf_token = str(form.get("csrf_token", ""))

    # Verify the single-use CSRF token issued by the GET consent form. pop()
    # consumes it; an absent/expired token defaults to 0 and is rejected.
    if not csrf_token or consent_csrf_tokens.pop(csrf_token, 0) < time.time():
        return invalid_request("Invalid or expired CSRF token")

    # Re-validate the client and redirect URI. Never redirect to the submitted
    # URI until it is confirmed registered for this client.
    client = registered_clients.get(client_id)
    if not client:
        return invalid_client("Unknown client_id")

    client_redirects = client.get("redirect_uris")
    if not isinstance(client_redirects, list) or not any(
        redirect_uri_matches(str(r), redirect_uri) for r in client_redirects
    ):
        return invalid_request("redirect_uri not registered for this client")

    # PKCE is mandatory; reject anything that could be exchanged without S256.
    if not code_challenge or code_challenge_method != "S256":
        return invalid_request("PKCE with S256 is required")

    if action == "deny":
        qs = urllib.parse.urlencode({"error": "access_denied", "state": state})
        return RedirectResponse(f"{redirect_uri}?{qs}", status_code=302)

    # Constrain granted scopes to the intersection of requested and allowed.
    allowed_scopes = set(client["scopes"]) if isinstance(client["scopes"], list) else set()
    granted_scopes = sorted(set(scope.split()) & allowed_scopes)

    # Generate single-use authorization code
    code = secrets.token_urlsafe(32)
    authorization_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scopes": granted_scopes,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "expires_at": int(time.time()) + AUTH_CODE_TTL,
    }

    qs = urllib.parse.urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}?{qs}", status_code=302)


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------


def unauthorized_client(description: str) -> JSONResponse:
    """RFC 6749 section 5.2: client is not authorized for the requested grant."""
    return oauth_error("unauthorized_client", description, 400)


def _client_allows_grant(client: Mapping[str, object], grant_type: str) -> bool:
    """True if ``grant_type`` is among the client's registered grant_types."""
    grant_types = client.get("grant_types")
    return isinstance(grant_types, list) and grant_type in grant_types


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

    # Throttle per client_id so authorization codes / PKCE verifiers cannot be
    # brute-forced by replaying the token endpoint (CWE-307).
    limited = await _enforce_rate_limit("token_code", client_id or "unknown")
    if limited is not None:
        return limited

    if not code or not client_id or not code_verifier:
        return invalid_request("code, client_id, and code_verifier are required")

    # Pop the code (single-use)
    code_data = authorization_codes.pop(code, None)
    if not code_data:
        return invalid_request("Invalid or expired authorization code")

    if cast(int, code_data["expires_at"]) < time.time():
        return invalid_request("Authorization code expired")

    if code_data["client_id"] != client_id:
        return invalid_client("client_id mismatch")

    # Enforce the client's registered grant_types (RFC 6749 section 3.2.1): a
    # client may only redeem a code if it registered for authorization_code.
    client = registered_clients.get(client_id)
    if client is None:
        return invalid_client("Unknown client_id")

    # RFC 6749 section 4.1.3: a confidential client must authenticate at the
    # token endpoint. If the client registered with an auth method other than
    # "none", require its client_secret and compare it in constant time,
    # mirroring _client_credentials_grant(). PKCE alone does not satisfy client
    # authentication for confidential clients.
    if client.get("token_endpoint_auth_method", "none") != "none":
        client_secret = str(form.get("client_secret", ""))
        if not client_secret or not secrets.compare_digest(
            str(client.get("client_secret", "")), client_secret
        ):
            return invalid_client("Invalid client credentials")

    if not _client_allows_grant(client, "authorization_code"):
        return unauthorized_client("Client is not registered for the authorization_code grant")

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

    # RFC 8707: bind the token to the resource the client is requesting access to
    # so the resource server can validate the audience on introspection.
    resource = str(form.get("resource", "")).strip() or None

    await storage.store_token(
        token=access_token,
        client_id=client_id,
        scopes=sorted(str(s) for s in scopes),
        expires_at=expires_at,
        resource=resource,
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

    if not await token_limiter.is_allowed(client_id):
        return rate_limit_exceeded(
            "Too many token requests",
            retry_after=await token_limiter.get_retry_after(client_id),
        )

    client = registered_clients.get(client_id)
    if not client or not secrets.compare_digest(
        str(client.get("client_secret", "")), client_secret
    ):
        return invalid_client("Invalid client credentials")

    # Enforce the client's registered grant_types (RFC 6749 section 3.2.1).
    if not _client_allows_grant(client, "client_credentials"):
        return unauthorized_client("Client is not registered for the client_credentials grant")

    requested_scope = str(form.get("scope", ""))
    allowed_scopes = set(client["scopes"]) if isinstance(client["scopes"], list) else set()
    if requested_scope:
        scopes = set(requested_scope.split())
        if not scopes.issubset(allowed_scopes):
            return invalid_scope("Requested scopes exceed client authorization")
    else:
        scopes = allowed_scopes

    # RFC 8707: bind the token to the requested resource (its audience) so the
    # resource server can confirm the token was issued for it on introspection.
    # ponytail: propagated as-is; a production AS would validate `resource`
    # against a registry of known resources and return `invalid_target` for
    # unknown values (RFC 8707 section 2.2).
    resource = str(form.get("resource", "")).strip() or None

    access_token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + TOKEN_TTL

    await storage.store_token(
        token=access_token,
        client_id=client_id,
        scopes=sorted(scopes),
        expires_at=expires_at,
        resource=resource,
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


def _introspection_caller_authenticated(request: Request, form: FormData) -> bool:
    """Authenticate the calling protected resource (RFC 7662 section 2.1).

    Accepts HTTP Basic credentials or ``client_id``/``client_secret`` form
    parameters and compares them in constant time against the configured
    introspection credentials. Both comparisons always run so the check does not
    leak which half was wrong via timing.
    """
    client_id = ""
    client_secret = ""

    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[len("Basic ") :]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return False
        client_id, _, client_secret = decoded.partition(":")
    else:
        client_id = str(form.get("client_id", ""))
        client_secret = str(form.get("client_secret", ""))

    id_ok = secrets.compare_digest(client_id, INTROSPECTION_CLIENT_ID)
    secret_ok = secrets.compare_digest(client_secret, INTROSPECTION_CLIENT_SECRET)
    return id_ok and secret_ok


async def introspect_handler(request: Request) -> JSONResponse:
    """RFC 7662: Token Introspection.

    The endpoint authenticates the calling protected resource (RFC 7662
    section 2.1) and is rate limited. Unauthenticated or unknown callers receive
    ``{"active": false}`` with no token metadata, so the endpoint cannot be used
    as an oracle to probe token validity or harvest ``client_id``/scope data
    (CWE-306).
    """
    assert storage is not None

    # Rate limit per caller before any token lookup, so the route cannot be
    # hammered as a token oracle (or used to brute-force the introspection
    # credentials) even by an authenticated caller.
    limited = await _enforce_rate_limit("introspect", _client_ip(request))
    if limited is not None:
        return limited

    form = await request.form()

    # Reject unauthenticated callers with active:false rather than a 401 so no
    # information (not even "this endpoint is protected for that token") leaks.
    if not _introspection_caller_authenticated(request, form):
        return JSONResponse({"active": False})

    token = str(form.get("token", ""))

    if not token:
        return JSONResponse({"active": False})

    token_data = await storage.load_token(token)
    if not token_data or token_data["expires_at"] < time.time():
        return JSONResponse({"active": False})

    response: dict[str, str | int | list[str]] = {
        "active": True,
        "client_id": token_data["client_id"],
        "scope": " ".join(token_data["scopes"]),
        "exp": token_data["expires_at"],
        "token_type": "bearer",
    }

    # RFC 8707: surface the resource the token was bound to as the `aud` claim so
    # resource servers can enforce audience restriction (RFC 7662 section 2.2).
    resource = token_data.get("resource")
    if resource:
        response["aud"] = resource

    return JSONResponse(response)


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


# mcp-authflow's PostgresTokenStorage operates on these tables but does not
# own their schema -- creating them is the consuming application's job. This is
# the DDL its access/refresh-token queries expect.
TOKEN_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS mcp_access_tokens (
    token       TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '',
    resource    TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id     INTEGER
);
CREATE TABLE IF NOT EXISTS mcp_refresh_tokens (
    token       TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '',
    resource    TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id     INTEGER
);
"""


async def _ensure_token_schema(database_url: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(database_url)
    try:
        await conn.execute(TOKEN_SCHEMA_DDL)
    finally:
        await conn.close()


@asynccontextmanager
async def lifespan(_app: Starlette) -> AsyncGenerator[None]:
    global storage
    new_storage: TokenStorage
    if DATABASE_URL:
        from mcp_authflow import PostgresTokenStorage

        await _ensure_token_schema(DATABASE_URL)
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

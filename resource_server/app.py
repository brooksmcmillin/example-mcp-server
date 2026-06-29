"""OAuth-protected MCP Notes API.

A simple notes CRUD API exposed as MCP tools, protected by OAuth 2.0 tokens
via token introspection (RFC 7662).
"""

import os

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.fastmcp.server import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp_authflow_resource import IntrospectionTokenVerifier, register_oauth_discovery_endpoints
from pydantic import AnyHttpUrl

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

AUTH_SERVER_PUBLIC_URL = os.environ.get("AUTH_SERVER_PUBLIC_URL", "http://localhost:9000")
INTROSPECTION_URL = os.environ.get(
    "INTROSPECTION_URL", f"{AUTH_SERVER_PUBLIC_URL.rstrip('/')}/introspect"
)
RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "http://localhost:9001")

# Credentials this resource server presents to the auth server's /introspect
# endpoint (RFC 7662 section 2.1). Must match the auth server's configured
# introspection credentials; the defaults suit the localhost demo.
INTROSPECTION_CLIENT_ID = os.environ.get("INTROSPECTION_CLIENT_ID", "resource-server")
INTROSPECTION_CLIENT_SECRET = os.environ.get(
    "INTROSPECTION_CLIENT_SECRET", "resource-server-secret"
)

# FastMCP's streamable-HTTP transport enables DNS-rebinding protection and only
# accepts requests whose Host header is in this allowlist. Any deployment served
# under a real hostname (or, here, the Docker Compose service name clients use to
# reach it) must list that host. Defaults cover the local-loopback case.
ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("MCP_ALLOWED_HOSTS", "localhost:*,127.0.0.1:*,[::1]:*").split(",")
    if h.strip()
]

# ---------------------------------------------------------------------------
# OAuth setup
# ---------------------------------------------------------------------------

verifier = IntrospectionTokenVerifier(
    introspection_endpoint=INTROSPECTION_URL,
    server_url=RESOURCE_SERVER_URL,
    client_id=INTROSPECTION_CLIENT_ID,
    client_secret=INTROSPECTION_CLIENT_SECRET,
    client_auth_method="client_secret_basic",
)

app = FastMCP(
    name="Notes API",
    instructions="A simple notes API protected by OAuth 2.0. Requires a valid access token.",
    stateless_http=True,
    token_verifier=verifier,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=ALLOWED_HOSTS,
    ),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(AUTH_SERVER_PUBLIC_URL),
        required_scopes=["notes:read"],
        resource_server_url=AnyHttpUrl(RESOURCE_SERVER_URL),
    ),
)

register_oauth_discovery_endpoints(
    app,
    server_url=RESOURCE_SERVER_URL,
    auth_server_public_url=AUTH_SERVER_PUBLIC_URL,
    scopes=["notes:read", "notes:write"],
)

# ---------------------------------------------------------------------------
# In-memory notes store
# ---------------------------------------------------------------------------

_notes: dict[str, dict[str, str]] = {}
_next_id: int = 1

# Expose the Starlette ASGI app for uvicorn (e.g. uvicorn resource_server.app:starlette_app)
starlette_app = app.streamable_http_app()

# ---------------------------------------------------------------------------
# Per-tool scope enforcement
# ---------------------------------------------------------------------------


def _require_scope(scope: str) -> None:
    """Enforce that the authenticated token carries ``scope``.

    ``AuthSettings.required_scopes`` gates every request on ``notes:read``, but
    that is the floor for *any* access -- it does not distinguish reads from
    writes. Tool docstrings ("Requires scope: notes:write") are documentation,
    not enforcement, so without this check a token holding only ``notes:read``
    could call the write tools (broken function-level authorization, CWE-285).
    Each write tool calls this to verify ``notes:write`` is actually granted.
    """
    token = get_access_token()
    if token is None or scope not in token.scopes:
        raise ToolError(f"insufficient_scope: this operation requires the '{scope}' scope")


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@app.tool()
async def list_notes() -> str:
    """List all notes. Requires scope: notes:read"""
    if not _notes:
        return "No notes yet."
    lines = [f"[{nid}] {n['title']}" for nid, n in _notes.items()]
    return "\n".join(lines)


@app.tool()
async def get_note(note_id: str) -> str:
    """Get a single note by ID. Requires scope: notes:read"""
    note = _notes.get(note_id)
    if not note:
        return f"Note {note_id} not found."
    return f"[{note_id}] {note['title']}\n\n{note['content']}"


@app.tool()
async def create_note(title: str, content: str) -> str:
    """Create a new note. Requires scope: notes:write"""
    _require_scope("notes:write")
    global _next_id
    note_id = str(_next_id)
    _next_id += 1
    _notes[note_id] = {"title": title, "content": content}
    return f"Created note {note_id}: {title}"


@app.tool()
async def update_note(note_id: str, title: str | None = None, content: str | None = None) -> str:
    """Update an existing note. Requires scope: notes:write"""
    _require_scope("notes:write")
    note = _notes.get(note_id)
    if not note:
        return f"Note {note_id} not found."
    if title is not None:
        note["title"] = title
    if content is not None:
        note["content"] = content
    return f"Updated note {note_id}."


@app.tool()
async def delete_note(note_id: str) -> str:
    """Delete a note by ID. Requires scope: notes:write"""
    _require_scope("notes:write")
    if note_id not in _notes:
        return f"Note {note_id} not found."
    del _notes[note_id]
    return f"Deleted note {note_id}."

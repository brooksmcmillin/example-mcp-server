"""OAuth-protected MCP Notes API.

A simple notes CRUD API exposed as MCP tools, protected by OAuth 2.0 tokens
via token introspection (RFC 7662).
"""

import os

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp.server import FastMCP
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

# ---------------------------------------------------------------------------
# OAuth setup
# ---------------------------------------------------------------------------

verifier = IntrospectionTokenVerifier(
    introspection_endpoint=INTROSPECTION_URL,
    server_url=RESOURCE_SERVER_URL,
)

app = FastMCP(
    name="Notes API",
    instructions="A simple notes API protected by OAuth 2.0. Requires a valid access token.",
    stateless_http=True,
    token_verifier=verifier,
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
    global _next_id
    note_id = str(_next_id)
    _next_id += 1
    _notes[note_id] = {"title": title, "content": content}
    return f"Created note {note_id}: {title}"


@app.tool()
async def update_note(note_id: str, title: str | None = None, content: str | None = None) -> str:
    """Update an existing note. Requires scope: notes:write"""
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
    if note_id not in _notes:
        return f"Note {note_id} not found."
    del _notes[note_id]
    return f"Deleted note {note_id}."

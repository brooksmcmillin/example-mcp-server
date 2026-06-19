"""Regression tests for per-tool write-scope enforcement.

These lock in the fix for GitHub issue #4: the write tools (create/update/
delete_note) must reject a token that only holds ``notes:read``. The global
``AuthSettings.required_scopes=["notes:read"]`` gate is the floor for any
access and does NOT distinguish reads from writes, so each write tool enforces
``notes:write`` itself (broken function-level authorization, CWE-285).
"""

import contextlib
from collections.abc import Iterator

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.fastmcp.exceptions import ToolError

from resource_server import app as rs


@contextlib.contextmanager
def token_with_scopes(*scopes: str) -> Iterator[None]:
    """Install an authenticated token carrying ``scopes`` for the duration."""
    access_token = AccessToken(
        token="test-token",
        client_id="test-client",
        scopes=list(scopes),
        expires_at=None,
    )
    reset = auth_context_var.set(AuthenticatedUser(access_token))
    try:
        yield
    finally:
        auth_context_var.reset(reset)


@pytest.fixture(autouse=True)
def clean_store() -> Iterator[None]:
    rs._notes.clear()
    rs._next_id = 1
    yield
    rs._notes.clear()


async def test_read_only_token_cannot_create() -> None:
    with token_with_scopes("notes:read"), pytest.raises(ToolError, match="notes:write"):
        await rs.create_note("title", "content")
    assert rs._notes == {}


async def test_read_only_token_cannot_update() -> None:
    rs._notes["1"] = {"title": "orig", "content": "orig"}
    with token_with_scopes("notes:read"), pytest.raises(ToolError, match="notes:write"):
        await rs.update_note("1", title="hacked")
    assert rs._notes["1"]["title"] == "orig"


async def test_read_only_token_cannot_delete() -> None:
    rs._notes["1"] = {"title": "orig", "content": "orig"}
    with token_with_scopes("notes:read"), pytest.raises(ToolError, match="notes:write"):
        await rs.delete_note("1")
    assert "1" in rs._notes


async def test_missing_token_cannot_write() -> None:
    # No token in context at all (auth_context_var default is None).
    with pytest.raises(ToolError, match="notes:write"):
        await rs.create_note("title", "content")
    assert rs._notes == {}


async def test_write_token_can_create_update_delete() -> None:
    with token_with_scopes("notes:read", "notes:write"):
        result = await rs.create_note("title", "content")
        assert "Created note 1" in result

        await rs.update_note("1", title="updated")
        assert rs._notes["1"]["title"] == "updated"

        await rs.delete_note("1")
        assert rs._notes == {}


async def test_read_token_can_still_read() -> None:
    rs._notes["1"] = {"title": "hello", "content": "world"}
    with token_with_scopes("notes:read"):
        assert "hello" in await rs.list_notes()
        assert "world" in await rs.get_note("1")

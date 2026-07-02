"""Behavioural tests for the notes CRUD tools (``resource_server``).

Scope enforcement for the write tools is covered in ``test_write_scope``; these
tests exercise the CRUD behaviour itself with a write-capable token: create then
list/get, partial update, delete, and the not-found paths. A fixture resets the
module-level store between tests.
"""

import contextlib
from collections.abc import Iterator

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

from resource_server import app as rs


@contextlib.contextmanager
def writer() -> Iterator[None]:
    """Install a token carrying both notes scopes for the duration."""
    access_token = AccessToken(
        token="test-token",
        client_id="test-client",
        scopes=["notes:read", "notes:write"],
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


async def test_create_then_list_and_get() -> None:
    with writer():
        created = await rs.create_note("Groceries", "milk, eggs")
        assert created == "Created note 1: Groceries"

        listing = await rs.list_notes()
        assert "[1] Groceries" in listing

        fetched = await rs.get_note("1")
        assert "Groceries" in fetched
        assert "milk, eggs" in fetched


async def test_ids_increment_across_notes() -> None:
    with writer():
        await rs.create_note("first", "a")
        await rs.create_note("second", "b")
    assert set(rs._notes) == {"1", "2"}


async def test_list_empty_store() -> None:
    with writer():
        assert await rs.list_notes() == "No notes yet."


async def test_partial_update_leaves_other_field_unchanged() -> None:
    with writer():
        await rs.create_note("title", "content")
        await rs.update_note("1", title="new title")
    assert rs._notes["1"] == {"title": "new title", "content": "content"}


async def test_update_content_only() -> None:
    with writer():
        await rs.create_note("title", "content")
        await rs.update_note("1", content="new content")
    assert rs._notes["1"] == {"title": "title", "content": "new content"}


async def test_delete_removes_note() -> None:
    with writer():
        await rs.create_note("title", "content")
        result = await rs.delete_note("1")
    assert result == "Deleted note 1."
    assert rs._notes == {}


async def test_get_missing_returns_not_found() -> None:
    with writer():
        assert await rs.get_note("404") == "Note 404 not found."


async def test_update_missing_returns_not_found() -> None:
    with writer():
        assert await rs.update_note("404", title="x") == "Note 404 not found."


async def test_delete_missing_returns_not_found() -> None:
    with writer():
        assert await rs.delete_note("404") == "Note 404 not found."

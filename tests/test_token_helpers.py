"""Tests for the shared token/scope helpers in ``auth_server.app``.

``_client_scopes`` narrows the loosely-typed ``registered_clients`` entries, and
``_issue_access_token`` is the single place both grants mint, store and
serialize a token -- so these cover the coercion edge cases and the invariants
the two grants rely on staying identical.
"""

import json
from collections.abc import AsyncIterator

import pytest
from mcp_authflow import MemoryTokenStorage
from starlette.responses import JSONResponse

from auth_server import app as auth_app


def _payload(response: JSONResponse) -> dict:
    return json.loads(bytes(response.body))


@pytest.fixture
async def storage() -> AsyncIterator[MemoryTokenStorage]:
    memory = MemoryTokenStorage()
    await memory.initialize()
    previous = auth_app.storage
    auth_app.storage = memory
    try:
        yield memory
    finally:
        auth_app.storage = previous
        await memory.close()


@pytest.mark.parametrize(
    ("client", "expected"),
    [
        ({"scopes": ["notes:write", "notes:read"]}, {"notes:read", "notes:write"}),
        ({"scopes": []}, set()),
        ({"scopes": None}, set()),
        ({"scopes": "notes:read notes:write"}, set()),
        ({}, set()),
    ],
)
def test_client_scopes_coercion(client: dict[str, object], expected: set[str]) -> None:
    assert auth_app._client_scopes(client) == expected


async def test_issue_access_token_stores_and_returns_token(
    storage: MemoryTokenStorage,
) -> None:
    response = await auth_app._issue_access_token(
        "client_abc", {"notes:write", "notes:read"}, "http://localhost:9001/"
    )
    assert response.status_code == 200
    payload = _payload(response)
    assert set(payload) == {"access_token", "token_type", "expires_in", "scope"}
    assert payload["token_type"] == "bearer"
    assert payload["expires_in"] == auth_app.TOKEN_TTL
    # Scopes are always emitted sorted so the response is deterministic.
    assert payload["scope"] == "notes:read notes:write"

    stored = await storage.load_token(payload["access_token"])
    assert stored is not None
    assert stored["client_id"] == "client_abc"
    assert stored["scopes"] == ["notes:read", "notes:write"]
    assert stored["resource"] == "http://localhost:9001/"


async def test_issue_access_token_without_resource(storage: MemoryTokenStorage) -> None:
    response = await auth_app._issue_access_token("client_abc", [], None)
    payload = _payload(response)
    assert payload["scope"] == ""

    stored = await storage.load_token(payload["access_token"])
    assert stored is not None
    assert stored["scopes"] == []
    assert stored["resource"] is None

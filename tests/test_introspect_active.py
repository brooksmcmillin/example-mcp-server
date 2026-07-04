"""Tests for ``introspect_handler`` token-state reporting (RFC 7662).

The caller-authentication and rate-limiting behaviour is covered in
``test_introspect_auth``; this file focuses on what an *authenticated* caller
sees for the various token states: a valid token reports ``active: true`` with
its ``client_id``, space-joined ``scope`` and ``exp``, while empty/unknown/
expired tokens report ``active: false`` with no metadata.
"""

import base64
from collections.abc import Iterator

import pytest
from mcp_authflow import MemoryTokenStorage, SlidingWindowRateLimiter
from starlette.testclient import TestClient

from auth_server import app as auth_app

CALLER_ID = auth_app.INTROSPECTION_CLIENT_ID
CALLER_SECRET = auth_app.INTROSPECTION_CLIENT_SECRET


@pytest.fixture
def client() -> Iterator[TestClient]:
    auth_app.registered_clients.clear()
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=1000, window_seconds=300)
    with TestClient(auth_app.app) as c:
        yield c


def _auth() -> dict[str, str]:
    creds = base64.b64encode(f"{CALLER_ID}:{CALLER_SECRET}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def _mint_token(
    client: TestClient,
    scope: str = "notes:read notes:write",
    resource: str | None = None,
) -> tuple[str, str]:
    reg = client.post(
        "/register",
        json={
            "client_name": "Resource",
            "scope": scope,
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    assert reg.status_code == 201
    body = reg.json()
    form = {
        "grant_type": "client_credentials",
        "client_id": body["client_id"],
        "client_secret": body["client_secret"],
        "scope": scope,
    }
    if resource is not None:
        form["resource"] = resource
    tok = client.post("/token", data=form)
    assert tok.status_code == 200
    return body["client_id"], tok.json()["access_token"]


def test_valid_token_is_active_with_metadata(client: TestClient) -> None:
    client_id, token = _mint_token(client, scope="notes:read notes:write")
    resp = client.post("/introspect", data={"token": token}, headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["active"] is True
    assert data["client_id"] == client_id
    assert data["scope"] == "notes:read notes:write"
    assert data["token_type"] == "bearer"
    assert isinstance(data["exp"], int)


def test_resource_bound_token_reports_aud(client: TestClient) -> None:
    # RFC 8707: a token requested with `resource` must introspect with a matching
    # `aud` so the resource server can validate the audience binding.
    _client_id, token = _mint_token(client, resource="http://localhost:9001/")
    resp = client.post("/introspect", data={"token": token}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json()["aud"] == "http://localhost:9001/"


def test_unbound_token_has_no_aud(client: TestClient) -> None:
    # Without a `resource`, the token carries no audience and introspection omits
    # `aud` entirely (a strict resource server rejects such a token).
    _client_id, token = _mint_token(client)
    resp = client.post("/introspect", data={"token": token}, headers=_auth())
    assert resp.status_code == 200
    assert "aud" not in resp.json()


def test_empty_token_is_inactive(client: TestClient) -> None:
    resp = client.post("/introspect", data={"token": ""}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json() == {"active": False}


def test_unknown_token_is_inactive(client: TestClient) -> None:
    resp = client.post("/introspect", data={"token": "never-issued"}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json() == {"active": False}


def test_expired_token_is_inactive(client: TestClient) -> None:
    _client_id, token = _mint_token(client)
    # Backdate the stored token so the expiry check treats it as dead. The demo
    # runs on the in-memory store, whose token table is a plain dict.
    store = auth_app.storage
    assert isinstance(store, MemoryTokenStorage)
    store._access_tokens[token]["expires_at"] = 1
    resp = client.post("/introspect", data={"token": token}, headers=_auth())
    assert resp.status_code == 200
    assert resp.json() == {"active": False}

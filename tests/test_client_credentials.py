"""Tests for the client_credentials grant (``_client_credentials_grant``).

Covers a valid machine-to-machine exchange plus the rejection branches: a wrong
secret (``invalid_client``), a scope outside the client's authorization
(``invalid_scope``), and the per-client rate limit (429 with ``Retry-After``).
"""

from collections.abc import Iterator

import httpx
import pytest
from mcp_authflow import SlidingWindowRateLimiter
from starlette.testclient import TestClient

from auth_server import app as auth_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    auth_app.registered_clients.clear()
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=1000, window_seconds=300)
    with TestClient(auth_app.app) as c:
        yield c


def _register_confidential(client: TestClient, scope: str = "notes:read notes:write") -> dict:
    resp = client.post(
        "/register",
        json={
            "client_name": "Machine Client",
            "scope": scope,
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    assert resp.status_code == 201
    return resp.json()


def _grant(client: TestClient, **overrides: str) -> httpx.Response:
    form = {"grant_type": "client_credentials"}
    form.update(overrides)
    return client.post("/token", data=form)


def test_valid_credentials_issue_token(client: TestClient) -> None:
    reg = _register_confidential(client)
    resp = _grant(client, client_id=reg["client_id"], client_secret=reg["client_secret"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == auth_app.TOKEN_TTL
    assert set(body["scope"].split()) == {"notes:read", "notes:write"}


def test_requested_subscope_is_honored(client: TestClient) -> None:
    reg = _register_confidential(client)
    resp = _grant(
        client,
        client_id=reg["client_id"],
        client_secret=reg["client_secret"],
        scope="notes:read",
    )
    assert resp.status_code == 200
    assert resp.json()["scope"] == "notes:read"


def test_wrong_secret_is_invalid_client(client: TestClient) -> None:
    reg = _register_confidential(client)
    resp = _grant(client, client_id=reg["client_id"], client_secret="not-the-secret")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_missing_credentials_is_invalid_client(client: TestClient) -> None:
    resp = _grant(client, client_id="", client_secret="")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_scope_outside_allowed_is_invalid_scope(client: TestClient) -> None:
    reg = _register_confidential(client, scope="notes:read")
    resp = _grant(
        client,
        client_id=reg["client_id"],
        client_secret=reg["client_secret"],
        scope="notes:read notes:write",
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


def test_grant_not_registered_is_unauthorized_client(client: TestClient) -> None:
    # A confidential client registered only for authorization_code must not be
    # able to redeem its credentials via the client_credentials grant.
    resp = client.post(
        "/register",
        json={
            "client_name": "Auth-Code Only",
            "scope": "notes:read",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["https://app.example.com/callback"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    assert resp.status_code == 201
    reg = resp.json()
    grant = _grant(client, client_id=reg["client_id"], client_secret=reg["client_secret"])
    assert grant.status_code == 400
    assert grant.json()["error"] == "unauthorized_client"


def test_rate_limit_exceeded_returns_retry_after(client: TestClient) -> None:
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=300)
    reg = _register_confidential(client)
    creds = {"client_id": reg["client_id"], "client_secret": reg["client_secret"]}
    assert _grant(client, **creds).status_code == 200
    assert _grant(client, **creds).status_code == 200
    throttled = _grant(client, **creds)
    assert throttled.status_code == 429
    assert "Retry-After" in throttled.headers

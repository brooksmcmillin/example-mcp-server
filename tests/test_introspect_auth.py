"""Regression tests for /introspect caller authentication and rate limiting.

These lock in the fix for GitHub issue #5: the token introspection endpoint
must authenticate the calling protected resource (RFC 7662 section 2.1) and be
rate limited. Unauthenticated or wrongly-credentialed callers get
``{"active": false}`` with no token metadata, so the endpoint cannot be used as
an oracle to probe token validity or harvest client_id/scope data (CWE-306).
"""

import base64
from collections.abc import Iterator

import pytest
from mcp_authflow import SlidingWindowRateLimiter
from starlette.testclient import TestClient

from auth_server import app as auth_app

CALLER_ID = auth_app.INTROSPECTION_CLIENT_ID
CALLER_SECRET = auth_app.INTROSPECTION_CLIENT_SECRET


@pytest.fixture
def client() -> Iterator[TestClient]:
    auth_app.registered_clients.clear()
    auth_app.authorization_codes.clear()
    # Fresh limiter per test so introspection calls don't leak across tests.
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=60, window_seconds=300)
    with TestClient(auth_app.app) as c:
        yield c


def _mint_token(client: TestClient, scope: str = "notes:read notes:write") -> str:
    """Register a confidential client and obtain an access token for it."""
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
    tok = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": body["client_id"],
            "client_secret": body["client_secret"],
            "scope": scope,
        },
    )
    assert tok.status_code == 200
    return tok.json()["access_token"]


def _basic(client_id: str, secret: str) -> dict[str, str]:
    creds = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


def test_authenticated_basic_returns_metadata(client: TestClient) -> None:
    token = _mint_token(client)
    resp = client.post(
        "/introspect", data={"token": token}, headers=_basic(CALLER_ID, CALLER_SECRET)
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["active"] is True
    assert "client_id" in data
    assert "notes:read" in data["scope"]


def test_authenticated_post_credentials_work(client: TestClient) -> None:
    token = _mint_token(client)
    resp = client.post(
        "/introspect",
        data={"token": token, "client_id": CALLER_ID, "client_secret": CALLER_SECRET},
    )
    assert resp.status_code == 200
    assert resp.json()["active"] is True


def test_unauthenticated_caller_gets_inactive_and_no_metadata(client: TestClient) -> None:
    """A valid token must not be revealed to an unauthenticated caller."""
    token = _mint_token(client)
    resp = client.post("/introspect", data={"token": token})
    assert resp.status_code == 200
    assert resp.json() == {"active": False}


def test_wrong_secret_gets_inactive(client: TestClient) -> None:
    token = _mint_token(client)
    resp = client.post(
        "/introspect", data={"token": token}, headers=_basic(CALLER_ID, "wrong-secret")
    )
    assert resp.status_code == 200
    assert resp.json() == {"active": False}


def test_wrong_client_id_gets_inactive(client: TestClient) -> None:
    token = _mint_token(client)
    resp = client.post(
        "/introspect", data={"token": token}, headers=_basic("intruder", CALLER_SECRET)
    )
    assert resp.status_code == 200
    assert resp.json() == {"active": False}


def test_malformed_basic_header_gets_inactive(client: TestClient) -> None:
    token = _mint_token(client)
    resp = client.post(
        "/introspect",
        data={"token": token},
        headers={"Authorization": "Basic not-valid-base64!!"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"active": False}


def test_introspect_is_rate_limited(client: TestClient) -> None:
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=300)
    token = _mint_token(client)
    headers = _basic(CALLER_ID, CALLER_SECRET)
    assert client.post("/introspect", data={"token": token}, headers=headers).status_code == 200
    assert client.post("/introspect", data={"token": token}, headers=headers).status_code == 200
    throttled = client.post("/introspect", data={"token": token}, headers=headers)
    assert throttled.status_code == 429


def test_rate_limit_applies_before_auth(client: TestClient) -> None:
    """Unauthenticated floods are throttled too, not just valid callers."""
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=300)
    assert client.post("/introspect", data={"token": "x"}).status_code == 200
    assert client.post("/introspect", data={"token": "x"}).status_code == 200
    assert client.post("/introspect", data={"token": "x"}).status_code == 429

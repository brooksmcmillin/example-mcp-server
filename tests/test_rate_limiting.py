"""Regression tests for endpoint rate limiting.

These lock in the fix for GitHub issue #6: the sliding-window limiter must cover
not just the client_credentials grant but also /register, /authorize, and the
authorization_code path of /token, so that client-registration flooding and
authorization-code / PKCE brute force are throttled (CWE-307, CWE-799).
"""

import re
from collections.abc import Iterator

import pytest
from mcp_authflow import SlidingWindowRateLimiter
from starlette.testclient import TestClient

from auth_server import app as auth_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    auth_app.registered_clients.clear()
    auth_app.authorization_codes.clear()
    auth_app.consent_csrf_tokens.clear()
    # Tight limiter (2/window) so a handful of requests trips the throttle.
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=300)
    with TestClient(auth_app.app) as c:
        yield c


def _register_body() -> dict[str, object]:
    return {
        "client_name": "Flooder",
        "redirect_uris": ["https://app.example.com/callback"],
        "scope": "notes:read notes:write",
    }


def test_register_is_rate_limited(client: TestClient) -> None:
    assert client.post("/register", json=_register_body()).status_code == 201
    assert client.post("/register", json=_register_body()).status_code == 201
    throttled = client.post("/register", json=_register_body())
    assert throttled.status_code == 429
    assert "Retry-After" in throttled.headers


def test_authorize_is_rate_limited(client: TestClient) -> None:
    params = {
        "response_type": "code",
        "client_id": "client_unknown",
        "redirect_uri": "https://app.example.com/callback",
        "scope": "notes:read",
        "state": "xyz",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  # pragma: allowlist secret
        "code_challenge_method": "S256",
    }
    # The limiter runs before any validation, so even invalid-client requests
    # count toward the budget.
    assert client.get("/authorize", params=params).status_code in (200, 400, 401)
    assert client.get("/authorize", params=params).status_code in (200, 400, 401)
    assert client.get("/authorize", params=params).status_code == 429


def test_token_authorization_code_is_rate_limited(client: TestClient) -> None:
    form = {
        "grant_type": "authorization_code",
        "code": "nope",
        "redirect_uri": "https://app.example.com/callback",
        "client_id": "client_bruteforce",
        "code_verifier": "verifier",
    }
    # Replaying the token endpoint with bogus codes must be throttled per client.
    assert client.post("/token", data=form).status_code == 400
    assert client.post("/token", data=form).status_code == 400
    assert client.post("/token", data=form).status_code == 429


def test_authorize_limit_is_namespaced_from_register(client: TestClient) -> None:
    """Each endpoint has its own budget; exhausting one must not block another."""
    # Exhaust /register's budget for this IP.
    assert client.post("/register", json=_register_body()).status_code == 201
    assert client.post("/register", json=_register_body()).status_code == 201
    assert client.post("/register", json=_register_body()).status_code == 429
    # /authorize is still serviceable (different key namespace).
    params = {
        "response_type": "code",
        "client_id": "client_unknown",
        "redirect_uri": "https://app.example.com/callback",
        "scope": "notes:read",
        "state": "xyz",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  # pragma: allowlist secret
        "code_challenge_method": "S256",
    }
    assert client.get("/authorize", params=params).status_code != 429


def test_client_credentials_limit_is_namespaced_from_authorization_code(
    client: TestClient,
) -> None:
    """The client_credentials grant keys the limiter like every other endpoint.

    It used to inline the limiter call with a bare ``client_id`` key, giving that
    grant an un-namespaced bucket. Exhausting one grant's budget must not spill
    over into the other for the same client.
    """
    reg = client.post(
        "/register",
        json={
            "client_name": "Machine Client",
            "scope": "notes:read",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    assert reg.status_code == 201
    creds = reg.json()
    cc_form = {
        "grant_type": "client_credentials",
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
    }
    # Exhaust the client_credentials budget for this client.
    assert client.post("/token", data=cc_form).status_code == 200
    assert client.post("/token", data=cc_form).status_code == 200
    assert client.post("/token", data=cc_form).status_code == 429
    # The authorization_code path for the same client_id has its own budget.
    code_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "nope",
            "redirect_uri": "https://app.example.com/callback",
            "client_id": creds["client_id"],
            "code_verifier": "verifier",
        },
    )
    assert code_resp.status_code != 429


def test_authorize_happy_path_within_budget(client: TestClient) -> None:
    """A normal consent round-trip (GET then POST) fits in a 2-request budget."""
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=2, window_seconds=300)
    reg = client.post("/register", json=_register_body())
    client_id = reg.json()["client_id"]
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://app.example.com/callback",
        "scope": "notes:read",
        "state": "xyz",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  # pragma: allowlist secret
        "code_challenge_method": "S256",
    }
    get_resp = client.get("/authorize", params=params)
    assert get_resp.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', get_resp.text)
    assert match is not None
    csrf = match.group(1)
    post_resp = client.post(
        "/authorize",
        data={
            "action": "approve",
            "client_id": client_id,
            "redirect_uri": params["redirect_uri"],
            "scope": params["scope"],
            "state": params["state"],
            "code_challenge": params["code_challenge"],
            "code_challenge_method": params["code_challenge_method"],
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert post_resp.status_code == 302

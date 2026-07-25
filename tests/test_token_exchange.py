"""Tests for the authorization_code -> token exchange (``_exchange_authorization_code``).

Covers the happy path plus every tampered branch: a reused/expired code, a
mismatched ``client_id`` or ``redirect_uri``, and a bad PKCE ``code_verifier``.
Each of these guards prevents an attacker from redeeming a code that was not
issued to them (RFC 6749 section 4.1.3, RFC 7636).
"""

import re
import time
import urllib.parse
from collections.abc import Iterator

import httpx
import pytest
from mcp_authflow import SlidingWindowRateLimiter
from starlette.testclient import TestClient

from auth_server import app as auth_app

# RFC 7636 Appendix B vector; the challenge is what the consent form carries.
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # pragma: allowlist secret
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # pragma: allowlist secret
REDIRECT_URI = "https://app.example.com/callback"


@pytest.fixture
def client() -> Iterator[TestClient]:
    auth_app.registered_clients.clear()
    auth_app.authorization_codes.clear()
    auth_app.consent_csrf_tokens.clear()
    # Generous limiter so a test can mint several codes without being throttled.
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=1000, window_seconds=300)
    with TestClient(auth_app.app) as c:
        yield c


def _register(client: TestClient) -> str:
    resp = client.post(
        "/register",
        json={
            "client_name": "Exchange Client",
            "redirect_uris": [REDIRECT_URI],
            "scope": "notes:read notes:write",
        },
    )
    assert resp.status_code == 201
    return resp.json()["client_id"]


def _register_confidential(client: TestClient) -> tuple[str, str]:
    """Register a confidential client and return its (client_id, client_secret)."""
    resp = client.post(
        "/register",
        json={
            "client_name": "Confidential Exchange Client",
            "redirect_uris": [REDIRECT_URI],
            "scope": "notes:read notes:write",
            "token_endpoint_auth_method": "client_secret_post",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    return body["client_id"], body["client_secret"]


def _mint_code(client: TestClient, client_id: str) -> str:
    """Drive the consent GET+POST round-trip and return a fresh authorization code."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "notes:read",
        "state": "xyz",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    get_resp = client.get("/authorize", params=params)
    assert get_resp.status_code == 200
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', get_resp.text)
    assert csrf is not None
    post_resp = client.post(
        "/authorize",
        data={**params, "action": "approve", "csrf_token": csrf.group(1)},
        follow_redirects=False,
    )
    assert post_resp.status_code == 302
    location = post_resp.headers["location"]
    return urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]


def _exchange(client: TestClient, **overrides: str) -> httpx.Response:
    form = {
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code_verifier": VERIFIER,
    }
    form.update(overrides)
    return client.post("/token", data=form)


def test_happy_path_issues_token(client: TestClient) -> None:
    client_id = _register(client)
    code = _mint_code(client, client_id)
    resp = _exchange(client, code=code, client_id=client_id)
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == auth_app.TOKEN_TTL
    assert body["scope"] == "notes:read"
    assert body["access_token"]


async def test_resource_is_bound_to_issued_token(client: TestClient) -> None:
    # RFC 8707: the `resource` passed at the token endpoint is recorded on the
    # issued token so the resource server can validate the audience.
    client_id = _register(client)
    code = _mint_code(client, client_id)
    resp = _exchange(client, code=code, client_id=client_id, resource="http://localhost:9001/")
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    assert auth_app.storage is not None
    stored = await auth_app.storage.load_token(token)
    assert stored is not None
    assert stored["resource"] == "http://localhost:9001/"


def test_reused_code_is_rejected(client: TestClient) -> None:
    client_id = _register(client)
    code = _mint_code(client, client_id)
    assert _exchange(client, code=code, client_id=client_id).status_code == 200
    # A code is single-use: the second redemption must fail.
    replay = _exchange(client, code=code, client_id=client_id)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_request"


def test_expired_code_is_rejected(client: TestClient) -> None:
    client_id = _register(client)
    code = _mint_code(client, client_id)
    auth_app.authorization_codes[code]["expires_at"] = int(time.time()) - 1
    resp = _exchange(client, code=code, client_id=client_id)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_wrong_client_id_is_rejected(client: TestClient) -> None:
    client_id = _register(client)
    other = _register(client)
    code = _mint_code(client, client_id)
    resp = _exchange(client, code=code, client_id=other)
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_wrong_redirect_uri_is_rejected(client: TestClient) -> None:
    client_id = _register(client)
    code = _mint_code(client, client_id)
    resp = _exchange(
        client, code=code, client_id=client_id, redirect_uri="https://app.example.com/other"
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_bad_code_verifier_is_rejected(client: TestClient) -> None:
    client_id = _register(client)
    code = _mint_code(client, client_id)
    resp = _exchange(
        client, code=code, client_id=client_id, code_verifier="the-wrong-verifier-entirely"
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_grant_not_registered_is_unauthorized_client(client: TestClient) -> None:
    # A client that only registered for client_credentials must not be able to
    # redeem an authorization code, even after minting one.
    resp = client.post(
        "/register",
        json={
            "client_name": "Client-Creds Only",
            "redirect_uris": [REDIRECT_URI],
            "scope": "notes:read notes:write",
            "grant_types": ["client_credentials"],
        },
    )
    assert resp.status_code == 201
    client_id = resp.json()["client_id"]
    code = _mint_code(client, client_id)
    result = _exchange(client, code=code, client_id=client_id)
    assert result.status_code == 400
    assert result.json()["error"] == "unauthorized_client"


def test_confidential_client_with_valid_secret_succeeds(client: TestClient) -> None:
    # RFC 6749 section 4.1.3: a confidential client authenticates with its
    # client_secret at the token endpoint; a valid secret still issues a token.
    client_id, client_secret = _register_confidential(client)
    code = _mint_code(client, client_id)
    resp = _exchange(client, code=code, client_id=client_id, client_secret=client_secret)
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_confidential_client_missing_secret_is_rejected(client: TestClient) -> None:
    # A confidential client that omits its secret must be rejected even though
    # the PKCE verifier is correct.
    client_id, _ = _register_confidential(client)
    code = _mint_code(client, client_id)
    resp = _exchange(client, code=code, client_id=client_id)
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_confidential_client_wrong_secret_is_rejected(client: TestClient) -> None:
    client_id, _ = _register_confidential(client)
    code = _mint_code(client, client_id)
    resp = _exchange(
        client, code=code, client_id=client_id, client_secret="the-wrong-secret-entirely"
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_public_client_ignores_client_secret(client: TestClient) -> None:
    # A public client (auth method "none") is not required to send a secret, and
    # a stray secret must not block the exchange.
    client_id = _register(client)
    code = _mint_code(client, client_id)
    resp = _exchange(client, code=code, client_id=client_id, client_secret="unexpected")
    assert resp.status_code == 200
    assert resp.json()["access_token"]


def test_missing_fields_are_rejected(client: TestClient) -> None:
    client_id = _register(client)
    code = _mint_code(client, client_id)
    resp = _exchange(client, code=code, client_id=client_id, code_verifier="")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


@pytest.mark.parametrize("grant_type", ["", "password", "refresh_token"])
def test_unsupported_grant_type_is_rejected(client: TestClient, grant_type: str) -> None:
    """Only authorization_code and client_credentials are dispatched."""
    resp = client.post("/token", data={"grant_type": grant_type})
    assert resp.status_code == 400
    body = resp.json()
    assert body["error"] == "invalid_request"
    assert "grant_type" in body["error_description"]

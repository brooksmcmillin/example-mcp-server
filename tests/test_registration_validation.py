"""Validation tests for ``register_handler`` and the ``authorize`` GET handler.

Covers input validation on the two entry points a client hits first: dynamic
client registration (RFC 7591) and the authorization request (RFC 6749 section
4.1.1). Includes an XSS regression: an attacker-chosen ``client_name`` must be
HTML-escaped before it is reflected into the consent page.
"""

from collections.abc import Iterator

import httpx
import pytest
from mcp_authflow import SlidingWindowRateLimiter
from starlette.testclient import TestClient

from auth_server import app as auth_app

CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # pragma: allowlist secret
REDIRECT_URI = "https://app.example.com/callback"


@pytest.fixture
def client() -> Iterator[TestClient]:
    auth_app.registered_clients.clear()
    auth_app.authorization_codes.clear()
    auth_app.consent_csrf_tokens.clear()
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=1000, window_seconds=300)
    with TestClient(auth_app.app) as c:
        yield c


def _register(client: TestClient, name: str = "App") -> str:
    resp = client.post(
        "/register",
        json={"client_name": name, "redirect_uris": [REDIRECT_URI], "scope": "notes:read"},
    )
    assert resp.status_code == 201
    return resp.json()["client_id"]


def _authorize_get(client: TestClient, **overrides: str) -> httpx.Response:
    params = {
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "notes:read",
        "state": "xyz",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return client.get("/authorize", params=params)


# --- register_handler validation ---------------------------------------------


def test_register_missing_client_name(client: TestClient) -> None:
    resp = client.post("/register", json={"redirect_uris": [REDIRECT_URI]})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_register_unknown_scope(client: TestClient) -> None:
    resp = client.post(
        "/register",
        json={"client_name": "App", "redirect_uris": [REDIRECT_URI], "scope": "notes:admin"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


def test_register_auth_code_grant_requires_redirect_uris(client: TestClient) -> None:
    resp = client.post(
        "/register",
        json={"client_name": "App", "grant_types": ["authorization_code"]},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_register_invalid_json_body(client: TestClient) -> None:
    resp = client.post(
        "/register", content=b"not json", headers={"content-type": "application/json"}
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


# --- register_handler input normalization ------------------------------------


def test_register_normalizes_bare_string_grant_types(client: TestClient) -> None:
    """RFC 7591 says ``grant_types`` is an array, but tolerate a bare string."""
    resp = client.post(
        "/register",
        json={
            "client_name": "App",
            "grant_types": "authorization_code",
            "redirect_uris": [REDIRECT_URI],
            "scope": "notes:read",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["grant_types"] == ["authorization_code"]
    # The wrapped value must also drive the derived defaults and the registry,
    # so a later token request passes the registered-grant check.
    assert body["response_types"] == ["code"]
    assert auth_app.registered_clients[body["client_id"]]["grant_types"] == ["authorization_code"]


def test_register_normalizes_list_form_scope(client: TestClient) -> None:
    """A list-form ``scope`` is joined into the space-delimited RFC 6749 form."""
    resp = client.post(
        "/register",
        json={
            "client_name": "App",
            "redirect_uris": [REDIRECT_URI],
            "scope": ["notes:write", "notes:read"],
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["scope"] == "notes:read notes:write"
    assert auth_app.registered_clients[body["client_id"]]["scopes"] == [
        "notes:read",
        "notes:write",
    ]


def test_register_list_form_scope_still_validated(client: TestClient) -> None:
    """Normalization must not bypass the unknown-scope check."""
    resp = client.post(
        "/register",
        json={
            "client_name": "App",
            "redirect_uris": [REDIRECT_URI],
            "scope": ["notes:read", "notes:admin"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_scope"


# --- authorize GET validation -------------------------------------------------


def test_authorize_missing_client_id(client: TestClient) -> None:
    resp = _authorize_get(client)
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_authorize_missing_redirect_uri(client: TestClient) -> None:
    client_id = _register(client)
    resp = _authorize_get(client, client_id=client_id, redirect_uri="")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_authorize_unknown_client_id(client: TestClient) -> None:
    resp = _authorize_get(client, client_id="client_does_not_exist")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"


def test_authorize_unregistered_redirect_uri(client: TestClient) -> None:
    client_id = _register(client)
    resp = _authorize_get(
        client, client_id=client_id, redirect_uri="https://attacker.example/steal"
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_authorize_requires_pkce_s256(client: TestClient) -> None:
    client_id = _register(client)
    resp = _authorize_get(client, client_id=client_id, code_challenge="")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_authorize_wrong_response_type(client: TestClient) -> None:
    client_id = _register(client)
    resp = _authorize_get(client, client_id=client_id, response_type="token")
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


def test_client_name_is_html_escaped_in_consent(client: TestClient) -> None:
    """A ``client_name`` containing markup must not be reflected raw (XSS)."""
    client_id = _register(client, name="<script>alert(1)</script>")
    resp = _authorize_get(client, client_id=client_id)
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in resp.text

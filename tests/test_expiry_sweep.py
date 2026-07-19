"""Regression tests for the expiry sweep of in-memory OAuth state (issue #28).

``consent_csrf_tokens`` and ``authorization_codes`` were previously only
shrunk by ``pop()`` on successful use, so abandoned/denied consent forms and
unredeemed authorization codes accumulated for the lifetime of the process
(CWE-401 / CWE-772). ``sweep_expired_entries()`` now drops expired entries
opportunistically on every /authorize request.
"""

import re
import time
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
    # Fresh limiter so requests from other test modules don't leak across tests.
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=1000, window_seconds=300)
    with TestClient(auth_app.app) as c:
        yield c


def _register(client: TestClient) -> str:
    resp = client.post(
        "/register",
        json={
            "client_name": "Test Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "scope": "notes:read notes:write",
        },
    )
    assert resp.status_code == 201
    return resp.json()["client_id"]


def _authorize_params(client_id: str) -> dict[str, str]:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://app.example.com/callback",
        "scope": "notes:read",
        "state": "xyz",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  # pragma: allowlist secret
        "code_challenge_method": "S256",
    }


def _stale_code(expires_at: int) -> dict[str, str | list[str] | int]:
    return {
        "client_id": "client_gone",
        "redirect_uri": "https://app.example.com/callback",
        "scopes": ["notes:read"],
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  # pragma: allowlist secret
        "code_challenge_method": "S256",
        "expires_at": expires_at,
    }


def test_sweep_drops_only_expired_entries() -> None:
    auth_app.consent_csrf_tokens.clear()
    auth_app.authorization_codes.clear()
    now = time.time()
    auth_app.consent_csrf_tokens["expired-csrf"] = int(now) - 1
    auth_app.consent_csrf_tokens["live-csrf"] = int(now) + 600
    auth_app.authorization_codes["expired-code"] = _stale_code(int(now) - 1)
    auth_app.authorization_codes["live-code"] = _stale_code(int(now) + 600)

    auth_app.sweep_expired_entries(now)

    assert set(auth_app.consent_csrf_tokens) == {"live-csrf"}
    assert set(auth_app.authorization_codes) == {"live-code"}


def test_abandoned_consent_forms_are_swept(client: TestClient) -> None:
    """CSRF tokens from consent forms that were never submitted must expire."""
    client_id = _register(client)
    auth_app.consent_csrf_tokens["abandoned"] = int(time.time()) - 1

    resp = client.get("/authorize", params=_authorize_params(client_id))
    assert resp.status_code == 200

    assert "abandoned" not in auth_app.consent_csrf_tokens
    # The token minted for this consent form is still present.
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    assert match is not None
    assert match.group(1) in auth_app.consent_csrf_tokens


def test_unredeemed_authorization_codes_are_swept(client: TestClient) -> None:
    """Codes that were issued but never exchanged must expire."""
    client_id = _register(client)
    auth_app.authorization_codes["never-redeemed"] = _stale_code(int(time.time()) - 1)

    resp = client.get("/authorize", params=_authorize_params(client_id))
    assert resp.status_code == 200

    assert "never-redeemed" not in auth_app.authorization_codes

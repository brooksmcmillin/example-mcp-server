"""Regression tests for the /authorize consent POST handler.

These lock in the fix for the authorization-code injection / open-redirect /
scope-escalation flaw (GitHub issue #3): codes are only minted on POST, so the
POST handler must re-validate the client, redirect_uri, scope, and a single-use
CSRF token rather than trusting the submitted form fields.
"""

import re
import urllib.parse

import pytest
from starlette.testclient import TestClient

from auth_server import app as auth_app


@pytest.fixture
def client() -> TestClient:
    auth_app.registered_clients.clear()
    auth_app.authorization_codes.clear()
    auth_app.consent_csrf_tokens.clear()
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


def _consent_form(client: TestClient, client_id: str, **overrides) -> dict[str, str]:
    """Drive the GET consent page and return the form fields it would submit."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://app.example.com/callback",
        "scope": "notes:read",
        "state": "xyz",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
    }
    resp = client.get("/authorize", params=params)
    assert resp.status_code == 200
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', resp.text).group(1)
    form = {
        "action": "approve",
        "client_id": client_id,
        "redirect_uri": params["redirect_uri"],
        "scope": params["scope"],
        "state": params["state"],
        "code_challenge": params["code_challenge"],
        "code_challenge_method": params["code_challenge_method"],
        "csrf_token": csrf,
    }
    form.update(overrides)
    return form


def test_happy_path_issues_code(client: TestClient) -> None:
    client_id = _register(client)
    form = _consent_form(client, client_id)
    resp = client.post("/authorize", data=form, follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://app.example.com/callback?")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]
    assert auth_app.authorization_codes[code]["scopes"] == ["notes:read"]


def test_post_without_csrf_is_rejected(client: TestClient) -> None:
    """A direct POST (no GET, no CSRF token) must not mint a code."""
    client_id = _register(client)
    form = _consent_form(client, client_id)
    form.pop("csrf_token")
    resp = client.post("/authorize", data=form, follow_redirects=False)
    assert resp.status_code == 400
    assert auth_app.authorization_codes == {}


def test_csrf_token_is_single_use(client: TestClient) -> None:
    client_id = _register(client)
    form = _consent_form(client, client_id)
    first = client.post("/authorize", data=form, follow_redirects=False)
    assert first.status_code == 302
    second = client.post("/authorize", data=form, follow_redirects=False)
    assert second.status_code == 400


def test_unregistered_redirect_uri_is_rejected(client: TestClient) -> None:
    """Open-redirect: attacker-controlled redirect_uri must be refused."""
    client_id = _register(client)
    form = _consent_form(client, client_id, redirect_uri="https://attacker.example/steal")
    resp = client.post("/authorize", data=form, follow_redirects=False)
    assert resp.status_code == 400
    assert "location" not in resp.headers
    assert auth_app.authorization_codes == {}


def test_unknown_client_is_rejected(client: TestClient) -> None:
    client_id = _register(client)
    form = _consent_form(client, client_id)
    form["client_id"] = "client_does_not_exist"
    resp = client.post("/authorize", data=form, follow_redirects=False)
    assert resp.status_code == 401
    assert auth_app.authorization_codes == {}


def test_scope_escalation_is_constrained(client: TestClient) -> None:
    """A read-only client must not be able to POST itself notes:write."""
    resp = client.post(
        "/register",
        json={
            "client_name": "ReadOnly",
            "redirect_uris": ["https://app.example.com/callback"],
            "scope": "notes:read",
        },
    )
    client_id = resp.json()["client_id"]
    form = _consent_form(client, client_id, scope="notes:read notes:write")
    resp = client.post("/authorize", data=form, follow_redirects=False)
    assert resp.status_code == 302
    code = urllib.parse.parse_qs(
        urllib.parse.urlparse(resp.headers["location"]).query
    )["code"][0]
    assert auth_app.authorization_codes[code]["scopes"] == ["notes:read"]

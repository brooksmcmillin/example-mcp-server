"""Tests for the authorization-server metadata document (RFC 8414).

Clients bootstrap the whole flow from this document: they read the endpoint URLs,
the supported grant types, and ``code_challenge_methods_supported`` to decide how
to build an authorization request. A regression here breaks discovery silently,
so the fields are asserted explicitly rather than just checking for a 200.
"""

from collections.abc import Iterator

import pytest
from mcp_authflow import SlidingWindowRateLimiter
from starlette.testclient import TestClient

from auth_server import app as auth_app

WELL_KNOWN_PATHS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
]


@pytest.fixture
def client() -> Iterator[TestClient]:
    auth_app.token_limiter = SlidingWindowRateLimiter(requests_per_window=1000, window_seconds=300)
    with TestClient(auth_app.app) as c:
        yield c


@pytest.mark.parametrize("path", WELL_KNOWN_PATHS)
def test_metadata_document_describes_the_server(client: TestClient, path: str) -> None:
    resp = client.get(path)
    assert resp.status_code == 200
    doc = resp.json()

    base = auth_app.AUTH_SERVER_URL.rstrip("/")
    assert doc["issuer"] == base
    assert doc["authorization_endpoint"] == f"{base}/authorize"
    assert doc["token_endpoint"] == f"{base}/token"
    assert doc["registration_endpoint"] == f"{base}/register"
    assert doc["introspection_endpoint"] == f"{base}/introspect"

    assert doc["response_types_supported"] == ["code"]
    assert sorted(doc["grant_types_supported"]) == ["authorization_code", "client_credentials"]
    assert sorted(doc["token_endpoint_auth_methods_supported"]) == [
        "client_secret_post",
        "none",
    ]
    assert doc["scopes_supported"] == sorted(auth_app.AVAILABLE_SCOPES)

    # PKCE is mandatory and "plain" is deliberately unsupported, so the document
    # must advertise S256 only.
    assert doc["code_challenge_methods_supported"] == ["S256"]


def test_both_well_known_paths_serve_the_same_document(client: TestClient) -> None:
    """The OpenID alias must not drift from the OAuth document."""
    docs = [client.get(path).json() for path in WELL_KNOWN_PATHS]
    assert docs[0] == docs[1]

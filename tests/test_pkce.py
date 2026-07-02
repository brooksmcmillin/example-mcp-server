"""Unit tests for the PKCE and redirect-URI matching helpers.

These are pure functions (no async/HTTP fixture needed) that sit on the
security-critical path: PKCE binds an authorization code to the client that
requested it (RFC 7636), and ``redirect_uri_matches`` decides where an
authorization code is allowed to be delivered (RFC 8252 section 7.3).
"""

import base64
import hashlib

from auth_server.app import redirect_uri_matches, verify_pkce

# RFC 7636 Appendix B known-answer vector.
APPENDIX_B_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # pragma: allowlist secret
APPENDIX_B_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # pragma: allowlist secret


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class TestVerifyPkce:
    def test_s256_happy_path(self) -> None:
        verifier = "a-perfectly-valid-code-verifier-value-123"
        assert verify_pkce(verifier, _s256(verifier), "S256") is True

    def test_appendix_b_known_vector(self) -> None:
        assert verify_pkce(APPENDIX_B_VERIFIER, APPENDIX_B_CHALLENGE, "S256") is True

    def test_wrong_verifier_rejected(self) -> None:
        assert verify_pkce("not-the-right-verifier", APPENDIX_B_CHALLENGE, "S256") is False

    def test_plain_method_rejected(self) -> None:
        # "plain" is deliberately unsupported: only S256 is accepted.
        assert verify_pkce(APPENDIX_B_CHALLENGE, APPENDIX_B_CHALLENGE, "plain") is False

    def test_empty_verifier_rejected(self) -> None:
        assert verify_pkce("", APPENDIX_B_CHALLENGE, "S256") is False

    def test_empty_verifier_only_matches_its_own_challenge(self) -> None:
        # An empty verifier hashes to a fixed value; it must not validate against
        # a challenge derived from a real verifier.
        assert verify_pkce("", _s256(""), "S256") is True
        assert verify_pkce("", APPENDIX_B_CHALLENGE, "S256") is False


class TestRedirectUriMatches:
    def test_loopback_different_port_matches(self) -> None:
        assert redirect_uri_matches(
            "http://127.0.0.1:8080/callback", "http://127.0.0.1:52734/callback"
        )
        assert redirect_uri_matches("http://localhost:8080/callback", "http://localhost:1/callback")

    def test_loopback_scheme_mismatch_rejected(self) -> None:
        assert not redirect_uri_matches(
            "http://127.0.0.1:8080/callback", "https://127.0.0.1:8080/callback"
        )

    def test_loopback_path_mismatch_rejected(self) -> None:
        assert not redirect_uri_matches(
            "http://127.0.0.1:8080/callback", "http://127.0.0.1:8080/evil"
        )

    def test_non_loopback_exact_match(self) -> None:
        uri = "https://app.example.com/callback"
        assert redirect_uri_matches(uri, uri)

    def test_non_loopback_differing_port_rejected(self) -> None:
        assert not redirect_uri_matches(
            "https://app.example.com:8443/callback", "https://app.example.com:9443/callback"
        )

    def test_host_merely_containing_localhost_rejected(self) -> None:
        # "localhost.evil.com" is not a loopback host, so the port-agnostic
        # loopback rule must not apply: it falls back to exact string matching.
        assert not redirect_uri_matches(
            "http://localhost.evil.com:8080/callback",
            "http://localhost.evil.com:9090/callback",
        )

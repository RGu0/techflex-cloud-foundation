"""Public contract tests for the HTTP transport boundary.

``transport.py`` had no test module of its own.  What coverage it had came
from ``test_public_contracts.py``, which exercised correlation IDs and the
one-shot 401 refresh -- never the TLS configuration, which is the part with
security consequences.
"""

from __future__ import annotations

import ssl

import httpx
import pytest

from techflex_cloud_foundation import (
    InsecureTransportRejected,
    SecureTransport,
    load_default_cloud_config,
)
# Private, but the TLS context is the thing under test and the public surface
# only exposes it through a live client.
from techflex_cloud_foundation.transport import _ssl_context


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(204, request=request)


class TestVerificationCannotBeDisabled:
    def test_verify_false_is_refused(self) -> None:
        """The switch that used to exist, and the reason it does not.

        ``verify: bool | str = True`` let a caller pass ``verify=False`` and
        turn certificate checking off for every request on the client -- the
        edit most likely to be made while debugging a private-CA environment
        and least likely to be reverted once things work.
        """

        with pytest.raises(InsecureTransportRejected, match="cannot be turned off"):
            SecureTransport("https://foundation.test", verify=False)

    def test_verify_true_is_refused_because_it_is_no_longer_the_spelling(self) -> None:
        """Rejecting the whole type keeps ``False`` from being a near-miss."""

        with pytest.raises(InsecureTransportRejected, match="bool"):
            SecureTransport("https://foundation.test", verify=True)

    def test_a_ca_bundle_path_names_the_replacement(self) -> None:
        with pytest.raises(InsecureTransportRejected, match="PEM bytes"):
            SecureTransport("https://foundation.test", verify="/etc/ssl/ca.pem")

    def test_a_context_that_does_not_verify_is_refused(self) -> None:
        """A prepared context is checked, not trusted -- same hole, other door."""

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with pytest.raises(InsecureTransportRejected, match="verify_mode"):
            SecureTransport("https://foundation.test", verify=context)

    def test_a_context_without_hostname_checking_is_refused(self) -> None:
        context = ssl.create_default_context()
        context.check_hostname = False

        with pytest.raises(InsecureTransportRejected, match="check_hostname"):
            SecureTransport("https://foundation.test", verify=context)

    def test_a_verifying_context_is_accepted_unchanged(self) -> None:
        context = ssl.create_default_context()

        with SecureTransport(
            "https://foundation.test",
            verify=context,
            transport=httpx.MockTransport(_ok),
        ) as transport:
            assert transport.request("GET", "/v1/check").status_code == 204


class TestBaseUrlMustBeHttps:
    @pytest.mark.parametrize(
        "base_url",
        ["http://foundation.test", "ftp://foundation.test", "foundation.test", ""],
    )
    def test_a_plaintext_base_url_is_refused(self, base_url: str) -> None:
        """Every request path is relative to the base URL, tokens included."""

        with pytest.raises(InsecureTransportRejected, match="https"):
            SecureTransport(base_url)

    def test_an_https_base_url_keeps_its_trailing_slash_stripped(self) -> None:
        with SecureTransport(
            "https://foundation.test/", transport=httpx.MockTransport(_ok)
        ) as transport:
            assert str(transport._client.base_url) == "https://foundation.test"


class TestPrivateCertificateAuthority:
    def test_pem_bytes_are_trusted_without_touching_the_disk(self) -> None:
        """The boilerplate this replaces.

        httpx only accepts a path, so every consumer wrote
        ``config.ca_bundle_pem`` to a file with ``atomic_write`` and passed the
        path -- creating a trust anchor on disk that nothing then owned or
        cleaned up.
        """

        pem = load_default_cloud_config().ca_bundle_pem

        with SecureTransport(
            "https://foundation.test",
            verify=pem,
            transport=httpx.MockTransport(_ok),
        ) as transport:
            assert transport.request("GET", "/v1/check").status_code == 204

        # The context is the observable outcome: the vendored CA is loaded into
        # the trust store, and no file was created anywhere to hold it.
        loaded = _ssl_context(pem)
        assert loaded.verify_mode == ssl.CERT_REQUIRED
        assert loaded.check_hostname is True
        assert loaded.get_ca_certs(), "the vendored CA must be in the trust store"

    def test_a_bundle_that_is_not_pem_is_refused(self) -> None:
        with pytest.raises(InsecureTransportRejected, match="PEM"):
            SecureTransport("https://foundation.test", verify=b"not a certificate")

    def test_der_bytes_are_named_rather_than_mangled(self) -> None:
        with pytest.raises(InsecureTransportRejected, match="DER"):
            SecureTransport("https://foundation.test", verify=b"\x30\x82\xff\xfe")

    def test_the_system_trust_store_is_the_default(self) -> None:
        context = _ssl_context(None)

        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True


class TestAmbientEnvironmentIsIgnored:
    def test_proxy_environment_variables_are_not_consulted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``trust_env=False`` is a security property, so it is asserted."""

        monkeypatch.setenv("HTTPS_PROXY", "http://attacker.test:8080")
        monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")

        with SecureTransport(
            "https://foundation.test", transport=httpx.MockTransport(_ok)
        ) as transport:
            assert transport._client.trust_env is False
            assert transport.request("GET", "/v1/check").status_code == 204

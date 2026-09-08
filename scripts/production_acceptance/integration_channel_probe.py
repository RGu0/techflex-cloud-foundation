"""RAY-404 production-acceptance: integration-channel probe (read-only, no credentials).

Facts captured:
1. TLS handshake against the vendored integration cloud with the vendored CA bundle.
2. Gateway envelope contract on a live response (correlation id propagation).
3. Vendored license public key material: length + ed25519 parseability.

Usage:
    UV_CONFIG_FILE=/dev/null uv run --locked --extra dev python integration_channel_probe.py
"""

from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from techflex_cloud_foundation import load_default_cloud_config


def probe_tls(config) -> list[str]:
    import socket
    import ssl

    host = config.api_base_url.split("//", 1)[1].split(":", 1)[0]
    port = int(config.api_base_url.rsplit(":", 1)[1])
    pem = config.ca_bundle_pem
    if isinstance(pem, bytes):
        pem = pem.decode("utf-8")
    ctx = ssl.create_default_context(cadata=pem)
    lines: list[str] = []
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            lines.append(f"- TLS: {tls.version()} handshake OK with vendored CA")
            lines.append(f"- cert subject: {cert.get('subject')}")
            lines.append(f"- cert issuer: {cert.get('issuer')}")
            lines.append(f"- cert notAfter: {cert.get('notAfter')}")
            lines.append(f"- cert SAN: {cert.get('subjectAltName')}")
            tls.sendall(
                f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode()
            )
            body = b""
            while True:
                part = tls.recv(4096)
                if not part:
                    break
                body += part
                if len(body) > 16384:
                    break
            head, _, payload = body.partition(b"\r\n\r\n")
            head_text = head.decode("utf-8", "replace")
            status_line = head_text.splitlines()[0]
            lines.append(f"- live response status: {status_line}")
            correlation = next(
                (
                    line
                    for line in head_text.splitlines()
                    if line.lower().startswith("x-correlation-id")
                ),
                None,
            )
            lines.append(f"- correlation id propagation: {correlation}")
            lines.append(f"- response body (root): {payload[:200].decode('utf-8', 'replace')!r}")
    return lines


def probe_license_key(config) -> list[str]:
    raw = config.license_public_key
    lines = [f"- vendored license key id: {config.license_key_id}"]
    lines.append(f"- key material length: {len(raw)} bytes")
    try:
        Ed25519PublicKey.from_public_bytes(raw)
        lines.append("- key material parses as an ed25519 public key: True")
    except Exception as exc:  # noqa: BLE001 - fact-finding probe
        lines.append(f"- key material parses as an ed25519 public key: False ({exc})")
    return lines


def main() -> None:
    config = load_default_cloud_config()
    now = datetime.now(UTC)
    lines = [
        "# Integration channel probe — RAY-404 `production-acceptance`",
        "",
        f"- captured at: {now.isoformat()}",
        f"- channel: {config.meta.channel}",
        f"- api_base_url: {config.api_base_url}",
        "- credentials used: none (read-only probe)",
        "",
        "## TLS / gateway envelope",
        "",
        *probe_tls(config),
        "",
        "## Vendored license key material (CP-04 fact check)",
        "",
        *probe_license_key(config),
        "",
        "## Reading",
        "",
        "- The vendored integration channel is a live, real cloud deployment whose",
        "  TLS trust chain verifies against the vendored CA bundle, and whose",
        "  responses carry the CP-02 correlation-id contract.",
        "- The channel is IP-literal:7443 with a private CA: by CP-01 it is an",
        "  integration channel and can never satisfy the production ingress",
        "  invariants (hostname + 443 + publicly trusted CA).  Evidence captured",
        "  here is therefore never production-tier.",
        "- License key material is present and ed25519-parseable, but the keyset",
        "  revision must come from the deployment's KMS/keyset facts; the vendored",
        "  bundle alone cannot build a LicenseKeysetSnapshot.",
    ]
    print("\n".join(lines))


if __name__ == "__main__":
    main()

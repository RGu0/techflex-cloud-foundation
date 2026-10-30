#!/usr/bin/env python3
"""Seed the uv cache with the uploaded foundation wheel, without any network.

uv keys its cache for a URL-sourced package by that URL, so the wheel cannot be
supplied through --find-links. This helper lets uv "download" the locked GitHub
release URL from a loopback TLS endpoint that serves only the already verified
uploaded file. Nothing else is reachable, and uv.lock is not touched.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urlsplit

CHUNK = 1 << 20


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def make_certificates(directory: Path, host: str) -> tuple[Path, Path, Path]:
    """Return (ca_pem, leaf_pem, leaf_key) where the leaf is valid for host only."""
    ca_key, ca_pem = directory / "ca.key", directory / "ca.pem"
    leaf_key, leaf_csr, leaf_pem = directory / "leaf.key", directory / "leaf.csr", directory / "leaf.pem"
    extensions = directory / "leaf.ext"
    extensions.write_text(f"subjectAltName=DNS:{host}\nbasicConstraints=CA:FALSE\n", encoding="utf-8")

    def run(*argv: str) -> None:
        subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key))
    run(
        "openssl", "req", "-x509", "-new", "-key", str(ca_key), "-days", "1",
        "-subj", "/CN=foundation-wheel-warmup-ca", "-out", str(ca_pem),
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign",
    )
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(leaf_key))
    run("openssl", "req", "-new", "-key", str(leaf_key), "-subj", f"/CN={host}", "-out", str(leaf_csr))
    run(
        "openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_pem), "-CAkey", str(ca_key),
        "-CAcreateserial", "-days", "1", "-extfile", str(extensions), "-out", str(leaf_pem),
    )
    return ca_pem, leaf_pem, leaf_key


class WarmupProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, wheel: Path, url: str, context: ssl.SSLContext) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        parts = urlsplit(url)
        self.wheel = wheel
        self.host = parts.netloc
        self.path = parts.path
        self.context = context


def _read_head(stream) -> list[str]:
    lines = []
    while True:
        line = stream.readline(65536)
        if line in (b"", b"\r\n", b"\n"):
            return lines
        lines.append(line.decode("latin-1").rstrip("\r\n"))


class _Handler(socketserver.StreamRequestHandler):
    server: WarmupProxy

    def handle(self) -> None:
        head = _read_head(self.rfile)
        parts = head[0].split(" ") if head else []
        if len(parts) < 2 or parts[0] != "CONNECT" or parts[1].split(":")[0] != self.server.host:
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.wfile.flush()
        try:
            tls = self.server.context.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError):
            return
        stream = tls.makefile("rwb")
        try:
            while True:
                request = _read_head(stream)
                if not request:
                    return
                method, target = (request[0].split(" ") + ["", ""])[:2]
                ok = method in ("GET", "HEAD") and target.split("?")[0] == self.server.path
                if not ok:
                    stream.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    stream.flush()
                    return
                size = self.server.wheel.stat().st_size
                stream.write(
                    (
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                        f"Content-Length: {size}\r\nConnection: close\r\n\r\n"
                    ).encode("ascii")
                )
                if method == "GET":
                    with self.server.wheel.open("rb") as source:
                        for block in iter(lambda: source.read(CHUNK), b""):
                            stream.write(block)
                stream.flush()
                return
        finally:
            try:
                stream.close()
                tls.close()
            except OSError:
                pass


def warm(wheel: Path, url: str, expected_sha256: str, uv_bin: str) -> int:
    if not wheel.is_file() or sha256_of(wheel) != expected_sha256:
        print("foundation release wheel digest mismatch", file=sys.stderr)
        return 1
    host = urlsplit(url).netloc
    with tempfile.TemporaryDirectory(prefix="foundation-warmup.") as scratch_name:
        scratch = Path(scratch_name)
        ca_pem, leaf_pem, leaf_key = make_certificates(scratch, host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(leaf_pem), str(leaf_key))
        proxy = WarmupProxy(wheel, url, context)
        threading.Thread(target=proxy.serve_forever, daemon=True).start()
        env = {key: value for key, value in os.environ.items() if key not in ("UV_OFFLINE", "NO_PROXY", "no_proxy")}
        proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
        env.update(
            HTTPS_PROXY=proxy_url,
            https_proxy=proxy_url,
            SSL_CERT_FILE=str(ca_pem),
            UV_SYSTEM_CERTS="1",
        )
        try:
            result = subprocess.run(
                [uv_bin, "pip", "install", "--no-config", "--no-deps", "--target", str(scratch / "target"), url],
                env=env,
                # The caller's directory may be unreadable to the service user
                # (a deploy runs from the operator's home); uv reads config there.
                cwd=str(scratch),
                stdout=subprocess.DEVNULL,
                check=False,
            )
        finally:
            proxy.shutdown()
            proxy.server_close()
    return result.returncode


def main() -> int:
    if len(sys.argv) != 5:
        raise SystemExit("usage: warm_foundation_wheel_cache.py WHEEL URL SHA256 UV_BIN")
    wheel, url, digest, uv_bin = sys.argv[1:]
    return warm(Path(wheel), url, digest, uv_bin)


if __name__ == "__main__":
    raise SystemExit(main())

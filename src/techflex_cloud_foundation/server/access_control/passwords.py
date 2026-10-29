"""Versioned password hashing with no plaintext persistence boundary."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os

_PREFIX = "ffp-scrypt"
_VERSION = "1"
_N = 2**15
_R = 8
_P = 1
_DKLEN = 32
_MAXMEM = 64 * 1024 * 1024


def _derive(password: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=_DKLEN,
        maxmem=_MAXMEM,
    )


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("password must contain between 12 and 256 characters")
    resolved_salt = salt if salt is not None else os.urandom(16)
    if len(resolved_salt) != 16:
        raise ValueError("password salt must contain 16 bytes")
    derived = _derive(password, resolved_salt, n=_N, r=_R, p=_P)
    encoded_salt = base64.urlsafe_b64encode(resolved_salt).decode("ascii")
    encoded_hash = base64.urlsafe_b64encode(derived).decode("ascii")
    return f"${_PREFIX}${_VERSION}$n={_N},r={_R},p={_P}${encoded_salt}${encoded_hash}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        empty, prefix, version, parameters, encoded_salt, encoded_hash = encoded.split("$")
        if empty or prefix != _PREFIX or version != _VERSION:
            return False
        parsed = dict(item.split("=", 1) for item in parameters.split(","))
        n = int(parsed["n"])
        r = int(parsed["r"])
        p = int(parsed["p"])
        if (n, r, p) != (_N, _R, _P):
            return False
        salt = base64.b64decode(encoded_salt, altchars=b"-_", validate=True)
        expected = base64.b64decode(encoded_hash, altchars=b"-_", validate=True)
        if len(salt) != 16 or len(expected) != _DKLEN:
            return False
        actual = _derive(password, salt, n=n, r=r, p=p)
    except (ValueError, KeyError, TypeError, binascii.Error):
        return False
    return hmac.compare_digest(actual, expected)


__all__ = ["hash_password", "verify_password"]

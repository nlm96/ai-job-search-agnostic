"""The encrypted identity store: ``private/identity.enc``.

The file holds the candidate's direct identifiers (name, email, phone, ...)
as JSON, encrypted with AES-256-GCM under a key derived from a passphrase
with scrypt. Agents never see the plaintext: the launcher masks
``private/``, and only the finaliser, run by the user outside the agent,
decrypts it in memory.

File layout (all integers unsigned, big-endian where multi-byte):

    magic  b"JSID"   4 bytes
    version          1 byte  (1)
    log2_n           1 byte  scrypt cost parameter N = 2**log2_n
    r                1 byte
    p                1 byte
    salt            16 bytes
    nonce           12 bytes
    ciphertext + 16-byte GCM tag

The 36-byte header is authenticated as associated data, so tampering with
the parameters fails decryption instead of silently weakening it.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"JSID"
VERSION = 1
HEADER_LEN = 4 + 1 + 3 + 16 + 12
DEFAULT_LOG2_N = 17          # N = 131072, r = 8: 128 MiB, ~0.3 s
MIN_LOG2_N, MAX_LOG2_N = 10, 22   # 10 is only for tests

# Identity field -> token. Tokens are letters only, so TeX treats them as
# ordinary text in every context (no braces, no catcode surprises), and the
# ZZ...ZZ frame makes them unmistakable in a text-layer search.
TOKENS = {
    "first_name": "ZZFIRSTNAMEZZ",
    "last_name": "ZZLASTNAMEZZ",
    "full_name": "ZZNAMEZZ",
    "email": "ZZEMAILZZ",
    "phone": "ZZPHONEZZ",
    "address": "ZZADDRESSZZ",
    "linkedin": "ZZLINKEDINZZ",
    "github": "ZZGITHUBZZ",
    "website": "ZZWEBSITEZZ",
}
REQUIRED = ("first_name", "last_name", "email", "phone")
URL_FIELDS = ("linkedin", "github", "website")
TOKEN_RE = re.compile(r"ZZ[A-Z]+ZZ")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+?[0-9][0-9 ().\-]{5,}[0-9]")
_URL_RE = re.compile(r"https://[A-Za-z0-9.\-]+(/[A-Za-z0-9._~%/\-]*)?")


class IdentityError(Exception):
    """Messages never contain identity values."""


class WrongPassphrase(IdentityError):
    pass


@dataclass(frozen=True)
class KdfParams:
    log2_n: int = DEFAULT_LOG2_N
    r: int = 8
    p: int = 1


def normalise(identity: dict) -> dict:
    """Return a cleaned copy: known fields only, stripped, full_name filled."""
    unknown = set(identity) - set(TOKENS)
    if unknown:
        raise IdentityError(f"unknown identity fields: {sorted(unknown)}")
    out = {k: str(v).strip() for k, v in identity.items() if str(v).strip()}
    if "full_name" not in out and "first_name" in out and "last_name" in out:
        out["full_name"] = f"{out['first_name']} {out['last_name']}"
    return out


def validate(identity: dict) -> list[str]:
    """Return problems as field-name messages, never echoing a value."""
    problems = [f"{f}: required" for f in REQUIRED if not identity.get(f)]
    for field, value in identity.items():
        if any(c in value for c in "\n\r\t\\{}"):
            problems.append(f"{field}: contains a newline, tab, backslash or brace")
        if TOKEN_RE.search(value):
            problems.append(f"{field}: looks like a token, not a real value")
    if identity.get("email") and not _EMAIL_RE.fullmatch(identity["email"]):
        problems.append("email: not a plain address like name@example.com")
    if identity.get("phone") and not _PHONE_RE.fullmatch(identity["phone"]):
        problems.append("phone: use digits, spaces, + ( ) . or - only")
    for field in URL_FIELDS:
        if identity.get(field) and not _URL_RE.fullmatch(identity[field]):
            problems.append(f"{field}: must be an https:// URL without query or fragment")
    return problems


def _kdf(passphrase: str, salt: bytes, params: KdfParams) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** params.log2_n,
                  r=params.r, p=params.p).derive(passphrase.encode("utf-8"))


def encrypt(identity: dict, passphrase: str, params: KdfParams = KdfParams()) -> bytes:
    if not passphrase:
        raise IdentityError("empty passphrase")
    if not MIN_LOG2_N <= params.log2_n <= MAX_LOG2_N:
        raise IdentityError("scrypt cost out of range")
    identity = normalise(identity)
    problems = validate(identity)
    if problems:
        raise IdentityError("invalid identity: " + "; ".join(problems))
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = (MAGIC + bytes([VERSION, params.log2_n, params.r, params.p])
              + salt + nonce)
    key = _kdf(passphrase, salt, params)
    body = json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return header + AESGCM(key).encrypt(nonce, body, header)


def decrypt(blob: bytes, passphrase: str) -> dict:
    if len(blob) < HEADER_LEN + 16 or blob[:4] != MAGIC:
        raise IdentityError("not an identity file")
    if blob[4] != VERSION:
        raise IdentityError(f"unsupported identity file version {blob[4]}")
    params = KdfParams(blob[5], blob[6], blob[7])
    if not MIN_LOG2_N <= params.log2_n <= MAX_LOG2_N or params.r < 1 or params.p < 1:
        raise IdentityError("identity file has invalid scrypt parameters")
    header = blob[:HEADER_LEN]
    salt, nonce = header[8:24], header[24:36]
    key = _kdf(passphrase, salt, params)
    try:
        body = AESGCM(key).decrypt(nonce, blob[HEADER_LEN:], header)
    except InvalidTag:
        raise WrongPassphrase("wrong passphrase, or the file is damaged") from None
    return json.loads(body.decode("utf-8"))


def write_file(path: str | os.PathLike, blob: bytes) -> None:
    """Write atomically with mode 0600, refusing to follow a symlink."""
    path = os.fspath(path)
    if os.path.islink(path):
        raise IdentityError("refusing to write through a symlink")
    tmp = f"{path}.tmp-{secrets.token_hex(4)}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def read_file(path: str | os.PathLike) -> bytes:
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        return f.read()

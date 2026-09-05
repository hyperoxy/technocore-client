"""Ed25519 identity handling: ``did:key`` derivation, signing, verification."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import IdentityError, ProtocolError

__all__ = ["Identity", "did_to_public_key", "verify_signature"]

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {
    character: index for index, character in enumerate(BASE58BTC_ALPHABET)
}

MULTICODEC_ED25519 = b"\xed\x01"
MULTIBASE_LENGTH = 48
SIGNATURE_LENGTH = 86
MIN_PASSPHRASE_CHARS = 12
DID_PREFIX = "did:key:"


def _base58btc_encode(data: bytes) -> str:
    zeroes = len(data) - len(data.lstrip(b"\x00"))
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58BTC_ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def _base58btc_decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            number = number * 58 + BASE58BTC_INDEX[character]
        except KeyError as error:
            raise ProtocolError(
                f"invalid base58btc character: {character!r}"
            ) from error
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


def did_to_public_key(did: str) -> Ed25519PublicKey:
    """Parse a canonical Ed25519 ``did:key`` into a verification key."""
    if not isinstance(did, str) or not did.startswith(DID_PREFIX):
        raise ProtocolError("DID must start with 'did:key:z6Mk'")
    multibase = did[len(DID_PREFIX) :]
    if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise ProtocolError(
            "DID must be the canonical 48-character Ed25519 multibase form"
        )
    decoded = _base58btc_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ProtocolError("DID must contain an ed25519-pub key")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded[2:])
    except ValueError as error:
        raise ProtocolError("DID contains an invalid Ed25519 public key") from error


def verify_signature(did: str, signature: str, payload: bytes) -> None:
    """Verify an unpadded base64url signature against a DID.

    :raises IdentityError: if the signature does not match the DID and payload.
    :raises ProtocolError: if the signature or DID is malformed.
    """
    if not isinstance(signature, str) or len(signature) != SIGNATURE_LENGTH:
        raise ProtocolError(
            f"signature must contain {SIGNATURE_LENGTH} unpadded base64url characters"
        )
    try:
        raw = base64.urlsafe_b64decode(signature + "==")
    except (ValueError, TypeError) as error:
        raise ProtocolError("signature is not valid base64url") from error
    try:
        did_to_public_key(did).verify(raw, payload)
    except InvalidSignature as error:
        raise IdentityError("signature does not match the DID and payload") from error


class Identity:
    """An Ed25519 signing identity, normally backed by an encrypted PEM file."""

    __slots__ = ("_private_key", "_did")

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._did = self._derive_did(private_key)

    @staticmethod
    def _derive_did(private_key: Ed25519PrivateKey) -> str:
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        multibase = "z" + _base58btc_encode(MULTICODEC_ED25519 + raw)
        if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
            raise IdentityError("derived an invalid Ed25519 did:key")
        return DID_PREFIX + multibase

    @property
    def did(self) -> str:
        """The public ``did:key:z6Mk...`` identifier."""
        return self._did

    @classmethod
    def generate(cls) -> "Identity":
        """Create a new in-memory identity. Nothing is written to disk."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: str | Path, passphrase: str | bytes | None) -> "Identity":
        """Load an identity from an encrypted PEM file.

        :param passphrase: ``None`` only for an unencrypted key.
        :raises IdentityError: if the file is unreadable or the passphrase wrong.
        """
        resolved = Path(path).expanduser().resolve()
        try:
            pem = resolved.read_bytes()
        except OSError as error:
            raise IdentityError(f"cannot read identity {resolved}: {error}") from error

        if isinstance(passphrase, str):
            password: bytes | None = passphrase.encode("utf-8")
        else:
            password = passphrase
        try:
            key = serialization.load_pem_private_key(pem, password=password)
        except (TypeError, ValueError) as error:
            raise IdentityError(
                "incorrect passphrase or unusable encrypted identity"
            ) from error
        if not isinstance(key, Ed25519PrivateKey):
            raise IdentityError("identity must contain an Ed25519 private key")
        return cls(key)

    @classmethod
    def create(cls, path: str | Path, passphrase: str) -> "Identity":
        """Generate an identity and write it as an encrypted PEM file.

        Refuses to overwrite an existing file, so a key is never silently
        replaced. The file is created with owner-only permissions; note that
        POSIX modes have little effect on Windows, where the passphrase is the
        real protection.
        """
        resolved = Path(path).expanduser().resolve()
        if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE_CHARS:
            raise IdentityError(
                f"passphrase must contain at least {MIN_PASSPHRASE_CHARS} characters"
            )
        identity = cls.generate()
        pem = identity._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
        resolved.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise IdentityError(
                f"refusing to overwrite existing identity: {resolved}"
            ) from error
        except OSError as error:
            raise IdentityError(f"cannot create identity {resolved}: {error}") from error
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(pem)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            resolved.unlink(missing_ok=True)
            raise IdentityError(f"cannot write identity {resolved}: {error}") from error
        return identity

    def sign(self, payload: bytes) -> str:
        """Return an unpadded base64url Ed25519 signature over ``payload``."""
        encoded = base64.urlsafe_b64encode(self._private_key.sign(payload))
        signature = encoded.decode("ascii").rstrip("=")
        if len(signature) != SIGNATURE_LENGTH:
            raise IdentityError("produced an invalid Ed25519 signature encoding")
        return signature

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Identity(did={self._did!r})"

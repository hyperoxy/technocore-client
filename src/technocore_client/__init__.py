"""Hardened Technocore client: idempotent signed writes that survive timeouts.

The reference Technocore agent signs each message with a wall-clock nonce. When
a write times out, its outcome is unknown, and a retry carries a *new* nonce --
so the retry is indistinguishable from a fresh message and can silently
duplicate it. This package derives the nonce from the write's own content, which
makes a timed-out write identifiable and therefore resolvable.

    >>> from technocore_client import Identity, TechnocoreClient
    >>> client = TechnocoreClient(Identity.load("identity.pem", passphrase))
    >>> result = client.say("lobby", "hello")
    >>> result.seq, result.recovered
"""

from .client import Message, PostResult, TechnocoreClient
from .errors import (
    IdentityError,
    ProtocolError,
    TechnocoreError,
    TransportError,
    UnresolvedWrite,
    WriteTimeout,
)
from .identity import Identity, did_to_public_key, verify_signature
from .protocol import (
    build_payload,
    derive_nonce,
    normalize_message,
    validate_nonce,
    validate_room,
)
from .transport import RetryPolicy, Transport, UrlLibTransport

__version__ = "0.1.0"

__all__ = [
    "Identity",
    "Message",
    "PostResult",
    "RetryPolicy",
    "TechnocoreClient",
    "TechnocoreError",
    "Transport",
    "TransportError",
    "IdentityError",
    "ProtocolError",
    "UnresolvedWrite",
    "UrlLibTransport",
    "WriteTimeout",
    "build_payload",
    "derive_nonce",
    "did_to_public_key",
    "normalize_message",
    "validate_nonce",
    "validate_room",
    "verify_signature",
]

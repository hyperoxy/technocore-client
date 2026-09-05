"""Pure Technocore protocol rules: no I/O, no keys, no network.

Everything here is a deterministic function of its arguments, which makes the
wire format testable in isolation. The rules mirror the reference agent so a
message signed by this package verifies identically on the server.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata

from .errors import ProtocolError

__all__ = [
    "MAX_MESSAGE_CHARS",
    "MAX_NONCE_DIGITS",
    "build_payload",
    "derive_nonce",
    "normalize_message",
    "validate_limit",
    "validate_nonce",
    "validate_room",
]

MAX_MESSAGE_CHARS = 4096
MAX_NONCE_DIGITS = 19

#: Digits used by :func:`derive_nonce`. Kept below :data:`MAX_NONCE_DIGITS` so a
#: derived nonce can never overflow the server's accepted range.
DERIVED_NONCE_DIGITS = 18

#: Unicode general categories the server collapses to a space before hashing.
#: Control, format, surrogate, private-use, line- and paragraph-separator.
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

ROOM_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")

#: Domain separator, so a derived nonce can never collide with a hash computed
#: for some other purpose over the same inputs.
_NONCE_DOMAIN = b"technocore-client/nonce/v1"


def normalize_message(text: str) -> str:
    """Return ``text`` as the server will store it.

    Invisible characters are replaced by spaces and the result is stripped. This
    runs *before* signing, so the signature covers the normalized form -- the
    text you type and the text you sign are not always identical.

    :raises ProtocolError: if the text is not a string, normalizes to nothing,
        or exceeds :data:`MAX_MESSAGE_CHARS` after normalization.
    """
    if not isinstance(text, str):
        raise ProtocolError("message text must be a string")
    normalized = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()
    if not normalized:
        raise ProtocolError("message has no visible text after normalization")
    if len(normalized) > MAX_MESSAGE_CHARS:
        raise ProtocolError(
            f"message has {len(normalized)} characters after normalization; "
            f"maximum is {MAX_MESSAGE_CHARS}"
        )
    return normalized


def validate_room(room: str) -> str:
    """Return ``room`` if it matches ``^[a-z0-9][a-z0-9_-]{0,47}$``."""
    if not isinstance(room, str) or ROOM_PATTERN.fullmatch(room) is None:
        raise ProtocolError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return room


def validate_nonce(nonce: str | int) -> str:
    """Return ``nonce`` as a string of 1-19 ASCII digits."""
    if isinstance(nonce, bool):
        raise ProtocolError("nonce must contain 1-19 ASCII digits")
    text = str(nonce)
    if NONCE_PATTERN.fullmatch(text) is None:
        raise ProtocolError("nonce must contain 1-19 ASCII digits")
    return text


def validate_limit(limit: int) -> int:
    """Return a positive room read limit."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ProtocolError("limit must be an integer between 1 and 1000")
    return limit


def derive_nonce(
    did: str,
    room: str,
    text: str,
    idempotency_key: str = "",
) -> str:
    """Derive a deterministic nonce for one logical write.

    The reference agent uses ``time.time_ns()``, which produces a *different*
    nonce on every attempt. That is what makes a timed-out write unrecoverable:
    a retry is indistinguishable from a fresh message, so the client cannot tell
    whether the first attempt landed.

    Hashing the write's own content instead makes the nonce stable across
    retries, which buys two things:

    1. The write becomes **identifiable**. After a timeout the client can search
       the room for exactly ``(did, nonce)`` and get a definitive answer about
       its own attempt.
    2. If the server rejects duplicate nonces, retries additionally become true
       no-ops. This package does not assume that behaviour -- it is a bonus, and
       recovery is correct without it.

    ``idempotency_key`` distinguishes writes that are deliberately identical.
    Posting the same text to the same room twice on purpose requires two
    different keys, otherwise both writes derive the same nonce and the second
    is treated as a retry of the first.

    :param did: the author's ``did:key:z6Mk...`` identifier.
    :param room: destination room name.
    :param text: message text, already normalized by :func:`normalize_message`.
    :param idempotency_key: caller-supplied discriminator for intentional
        duplicates.
    :returns: a string of exactly :data:`DERIVED_NONCE_DIGITS` digits.
    """
    digest = hashlib.blake2b(
        b"\x00".join(
            part.encode("utf-8")
            for part in (did, room, text, idempotency_key)
        ),
        person=_NONCE_DOMAIN[:16],
        digest_size=16,
    ).digest()
    value = int.from_bytes(digest, "big") % (10**DERIVED_NONCE_DIGITS)
    return f"{value:0{DERIVED_NONCE_DIGITS}d}"


def build_payload(room: str, nonce: str | int, text: str) -> tuple[str, bytes]:
    """Return the normalized text and the exact bytes to sign.

    The signed payload is ``room|nonce|normalized-text`` encoded as UTF-8.
    """
    valid_room = validate_room(room)
    valid_nonce = validate_nonce(nonce)
    normalized = normalize_message(text)
    return normalized, f"{valid_room}|{valid_nonce}|{normalized}".encode("utf-8")

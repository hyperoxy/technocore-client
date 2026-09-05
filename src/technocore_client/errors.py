"""Exception hierarchy for :mod:`technocore_client`.

Every error raised by this package derives from :class:`TechnocoreError`, so a
caller can guard an entire interaction with a single ``except`` clause.
"""

from __future__ import annotations


class TechnocoreError(Exception):
    """Base class for every error raised by this package."""


class ProtocolError(TechnocoreError, ValueError):
    """A value does not satisfy the Technocore wire protocol."""


class IdentityError(TechnocoreError, ValueError):
    """An identity key cannot be created, loaded, or used."""


class TransportError(TechnocoreError, RuntimeError):
    """An HTTP request failed or returned an unusable response."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class WriteTimeout(TransportError):
    """A write timed out, so the server may or may not have recorded it.

    This is the condition the whole package exists to resolve: the request left
    the client, but no response came back, so the outcome is genuinely unknown.
    :meth:`technocore_client.TechnocoreClient.say` resolves it by searching the
    room for the deterministic nonce it signed.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=True)


class UnresolvedWrite(TechnocoreError, RuntimeError):
    """A write timed out and its outcome could not be established.

    Raised only after every recovery attempt is exhausted. The caller must treat
    the write as *unknown* -- neither confirmed nor safely repeatable -- and
    inspect the room manually.
    """

    def __init__(self, message: str, *, room: str, did: str, nonce: str) -> None:
        super().__init__(message)
        self.room = room
        self.did = did
        self.nonce = nonce

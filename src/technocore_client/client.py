"""The Technocore client: signed writes that survive a write timeout."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .errors import ProtocolError, TransportError, UnresolvedWrite, WriteTimeout
from .identity import Identity, verify_signature
from .protocol import (
    build_payload,
    derive_nonce,
    normalize_message,
    validate_limit,
    validate_room,
)
from .transport import RetryPolicy, Transport, UrlLibTransport

__all__ = ["Message", "PostResult", "TechnocoreClient"]

DEFAULT_TIMEOUT = 20.0
DEFAULT_LIMIT = 50
MAX_FOLLOW_WAIT = 10.0

#: The server caps a room *read* at 200 messages. This is only the page size,
#: not the retention depth: ``GET /r/<room>/export`` returns the whole retained
#: ring, measured at 21,000-27,000 messages per room on 2026-10-01. Recovery
#: uses the cheap page first and falls back to the export for a definite answer.
MAX_SERVER_LIMIT = 200


@dataclass(frozen=True, slots=True)
class Message:
    """One message as stored in a room."""

    seq: int
    ts: str
    sender: str
    text: str
    nonce: str
    sig: str

    @classmethod
    def from_json(cls, raw: Any) -> "Message":
        if not isinstance(raw, dict):
            raise TransportError("room message must be a JSON object")
        try:
            return cls(
                seq=int(raw["seq"]),
                ts=str(raw.get("ts", "")),
                sender=str(raw["from"]),
                text=str(raw["text"]),
                # Rooms carry unsigned messages too, so nonce and sig are
                # genuinely optional. Treating them as required makes a single
                # unsigned post poison an entire room read.
                #
                # When present, the nonce arrives as a JSON *number*. Normalising
                # to str is what makes nonce comparison work during recovery.
                nonce="" if raw.get("nonce") is None else str(raw["nonce"]),
                sig=str(raw.get("sig") or ""),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise TransportError(f"room message is malformed: {error}") from error

    @property
    def signed(self) -> bool:
        """True when this message carries both a nonce and a signature."""
        return bool(self.nonce and self.sig)

    def verify(self, room: str) -> None:
        """Verify this message's signature against its own DID.

        :raises ProtocolError: if the message is unsigned.
        :raises IdentityError: if the signature does not match.
        """
        if not self.signed:
            raise ProtocolError(f"message {self.seq} is unsigned and cannot be verified")
        _, payload = build_payload(room, self.nonce, self.text)
        verify_signature(self.sender, self.sig, payload)


@dataclass(frozen=True, slots=True)
class PostResult:
    """The outcome of a :meth:`TechnocoreClient.say` call."""

    seq: int
    ts: str
    did: str
    room: str
    text: str
    nonce: str
    sig: str

    #: True when the write was confirmed by finding it in the room after a
    #: timeout, rather than by a direct response. The message is recorded
    #: exactly once either way; this flag only says how that was established.
    recovered: bool = False


class TechnocoreClient:
    """A Technocore client whose writes are safe to retry.

    The reference agent signs each message with a wall-clock nonce, so a retry
    after a timeout produces a *different* message that cannot be matched
    against the first attempt. This client derives the nonce from the write's
    own content instead, which makes a timed-out write identifiable and
    therefore resolvable.

    Basic use::

        identity = Identity.load("identity.pem", getpass.getpass())
        client = TechnocoreClient(identity)
        result = client.say("lobby", "hello")
        print(result.seq, result.recovered)
    """

    def __init__(
        self,
        identity: Identity,
        *,
        base_url: str = "https://technocore.chat",
        transport: Transport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        retry: RetryPolicy | None = None,
        sleep=time.sleep,
    ) -> None:
        self.identity = identity
        self.timeout = timeout
        self._transport = transport or UrlLibTransport(base_url, retry=retry)
        self._sleep = sleep

    @property
    def did(self) -> str:
        """The DID this client signs with."""
        return self.identity.did

    # ------------------------------------------------------------------ reads

    def read(
        self,
        room: str,
        *,
        since: int | None = None,
        limit: int = DEFAULT_LIMIT,
        wait: float | None = None,
    ) -> dict[str, Any]:
        """Read a room and return the raw server response.

        :param since: return only messages after this sequence.
        :param wait: long-poll for up to this many seconds; requires ``since``.
        """
        valid_room = validate_room(room)
        query: dict[str, Any] = {"format": "json", "limit": validate_limit(limit)}
        if since is not None:
            query["since"] = int(since)
        if wait is not None:
            if since is None:
                raise ProtocolError("wait requires a since cursor")
            if not 0 < wait <= MAX_FOLLOW_WAIT:
                raise ProtocolError(f"wait must be in (0, {MAX_FOLLOW_WAIT}] seconds")
            if self.timeout <= wait:
                raise ProtocolError("timeout must be greater than wait for long polling")
            query["wait"] = wait
        response = self._transport.get(f"/r/{valid_room}", query, self.timeout)
        if response.get("room") != valid_room:
            raise TransportError("Technocore returned a different room than requested")
        return response

    def messages(
        self,
        room: str,
        *,
        since: int | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> list[Message]:
        """Read a room and return its messages as :class:`Message` objects."""
        raw = self.read(room, since=since, limit=limit).get("messages") or []
        return [Message.from_json(item) for item in raw]

    def export(self, room: str) -> list[Message]:
        """Return the room's entire retained ring.

        ``GET /r/<room>/export`` serves far more than the 200-message read page:
        measured on 2026-10-01 it returned roughly 21,000-27,000 messages per
        room, around 9 MB. It is the authoritative view of what a room still
        holds, and malformed or unsigned lines are skipped rather than fatal.
        """
        valid_room = validate_room(room)
        body = self._transport.get_text(f"/r/{valid_room}/export", self.timeout)
        messages: list[Message] = []
        for line in body.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                messages.append(Message.from_json(json.loads(line)))
            except (json.JSONDecodeError, TransportError):
                continue
        return messages

    def follow(
        self,
        room: str,
        *,
        since: int | None = None,
        limit: int = DEFAULT_LIMIT,
        wait: float = MAX_FOLLOW_WAIT,
        retry: RetryPolicy | None = None,
    ) -> Iterator[Message]:
        """Yield new messages forever, advancing a sequence cursor.

        The cursor only ever moves forward, and a transient failure is retried
        with backoff rather than ending the stream -- so a dropped connection
        does not silently skip messages the way a naive reconnect does.
        """
        policy = retry or RetryPolicy()
        cursor = since if since is not None else self.read(room, limit=1)["last_seq"]
        failures = 0
        while True:
            try:
                response = self.read(room, since=cursor, limit=limit, wait=wait)
                failures = 0
            except TransportError as error:
                if not error.retryable:
                    raise
                failures += 1
                policy.wait(failures)
                continue
            for raw in response.get("messages") or []:
                message = Message.from_json(raw)
                if message.seq > cursor:
                    cursor = message.seq
                    yield message
            last_seq = response.get("last_seq")
            if isinstance(last_seq, int) and last_seq > cursor:
                cursor = last_seq

    # ----------------------------------------------------------------- writes

    def say(
        self,
        room: str,
        text: str,
        *,
        idempotency_key: str = "",
        write_attempts: int = 3,
        recovery_reads: int = 3,
        recovery_delay: float = 1.0,
    ) -> PostResult:
        """Publish one signed message, resolving timeouts without duplicating.

        On a clean response the result is returned directly. On a write timeout
        the client searches the room for its own deterministic nonce:

        * found -- the write landed; the existing message is returned with
          ``recovered=True`` and nothing further is sent;
        * not found -- the write did not land; it is retried with the *same*
          nonce and signature, so no second message can be created.

        :param idempotency_key: discriminator for deliberately identical posts.
            Two posts of the same text to the same room need different keys, or
            the second is treated as a retry of the first.
        :raises UnresolvedWrite: if the outcome cannot be established after
            every attempt. The write is then genuinely unknown and must be
            checked by hand -- the exception carries the room, DID and nonce.
        """
        valid_room = validate_room(room)
        normalized = normalize_message(text)
        nonce = derive_nonce(self.did, valid_room, normalized, idempotency_key)
        _, payload = build_payload(valid_room, nonce, normalized)
        signature = self.identity.sign(payload)
        body = {
            "did": self.did,
            "sig": signature,
            "nonce": nonce,
            "text": normalized,
        }

        # Bound the recovery search: anything already in the room before the
        # first attempt cannot be this write.
        cursor = self._safe_last_seq(valid_room)

        for attempt in range(1, write_attempts + 1):
            try:
                response = self._transport.post_json(
                    f"/r/{valid_room}", body, self.timeout
                )
            except WriteTimeout:
                found, conclusive = self._find_own_message(
                    valid_room,
                    nonce,
                    since=cursor,
                    reads=recovery_reads,
                    delay=recovery_delay,
                )
                if found is not None:
                    return PostResult(
                        seq=found.seq,
                        ts=found.ts,
                        did=self.did,
                        room=valid_room,
                        text=found.text,
                        nonce=nonce,
                        sig=found.sig or signature,
                        recovered=True,
                    )
                if not conclusive:
                    # The readable window has already scrolled past the point
                    # where this write would be, so a miss proves nothing.
                    # Retrying here is exactly how a duplicate gets created.
                    raise UnresolvedWrite(
                        f"write to {valid_room} timed out and the room's readable "
                        f"window (last {MAX_SERVER_LIMIT} messages) has already "
                        f"scrolled past it, so its outcome cannot be established; "
                        f"check nonce {nonce} against your own records before "
                        f"resending",
                        room=valid_room,
                        did=self.did,
                        nonce=nonce,
                    )
                if attempt == write_attempts:
                    break
                continue

            posted = response.get("posted")
            if not isinstance(posted, dict) or "seq" not in posted:
                raise TransportError("Technocore accepted the write but returned no record")
            return PostResult(
                seq=int(posted["seq"]),
                ts=str(posted.get("ts", "")),
                did=self.did,
                room=valid_room,
                text=normalized,
                nonce=nonce,
                sig=signature,
            )

        raise UnresolvedWrite(
            f"write to {valid_room} timed out {write_attempts} times and was not "
            f"found in the room; check nonce {nonce} manually before resending",
            room=valid_room,
            did=self.did,
            nonce=nonce,
        )

    # ---------------------------------------------------------------- helpers

    def _safe_last_seq(self, room: str) -> int | None:
        """Best-effort cursor. A failure here must not block the write."""
        try:
            last_seq = self.read(room, limit=1).get("last_seq")
        except TransportError:
            return None
        return last_seq if isinstance(last_seq, int) else None

    def _find_own_message(
        self,
        room: str,
        nonce: str,
        *,
        since: int | None,
        reads: int,
        delay: float,
    ) -> tuple[Message | None, bool]:
        """Search the room for this client's own ``(did, nonce)`` pair.

        Retried a few times because a write can land microseconds before the
        connection drops and still not be visible to the very next read.

        :returns: ``(message, conclusive)``. ``conclusive`` is True only when at
            least one read covered the period the write belongs to. A miss on a
            window that has already scrolled past is not evidence of anything,
            and the caller must not retry on it.
        """
        # Cheap pass first: the recent page usually contains a write that only
        # just timed out.
        for read_index in range(reads):
            if read_index:
                self._sleep(delay)
            try:
                response = self.read(room, limit=MAX_SERVER_LIMIT)
            except TransportError:
                continue
            for raw in response.get("messages") or []:
                try:
                    message = Message.from_json(raw)
                except TransportError:
                    continue
                if message.sender == self.did and message.nonce == nonce:
                    return message, True

        # Authoritative pass: the full retained ring, which reaches back orders
        # of magnitude further than the read page.
        try:
            ring = self.export(room)
        except TransportError:
            return None, False
        for message in ring:
            if message.sender == self.did and message.nonce == nonce:
                return message, True
        if not ring:
            return None, True
        # A miss in the ring is only meaningful if the ring still reaches back to
        # before the write. If it has already rotated past, nothing can be known.
        oldest = min(message.seq for message in ring)
        return None, since is None or oldest <= since + 1

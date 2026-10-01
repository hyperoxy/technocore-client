"""HTTP transport with retry classification.

The transport is deliberately a small, swappable interface. Tests substitute a
fake implementation to simulate write timeouts without touching the network,
which is how the idempotency guarantees in this package are actually verified.
"""

from __future__ import annotations

import json
import random
import socket
import time
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from .errors import ProtocolError, TransportError, WriteTimeout

__all__ = ["HttpTransport", "RetryPolicy", "Transport", "UrlLibTransport", "validate_base_url"]

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
#: A room export is the whole retained ring; measured at ~9 MB for a busy room
#: on 2026-10-01, so this ceiling leaves generous headroom.
MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_ERROR_BODY_BYTES = 16 * 1024
USER_AGENT = "technocore-client/0.1.0"


def validate_base_url(base_url: str) -> str:
    """Return the base URL with a trailing slash removed.

    HTTPS is required except for a loopback host, which keeps local test servers
    usable without weakening the default.
    """
    if not isinstance(base_url, str) or not base_url or base_url.strip() != base_url:
        raise ProtocolError("base URL must be a non-empty URL without surrounding whitespace")
    normalized = base_url.rstrip("/")
    try:
        parsed = urlsplit(normalized)
    except ValueError as error:
        raise ProtocolError("base URL is malformed") from error
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ProtocolError("base URL must use HTTPS, except for a loopback test server")
    if not parsed.netloc or parsed.query or parsed.fragment:
        raise ProtocolError("base URL must contain a host and no query or fragment")
    if parsed.username is not None or parsed.password is not None:
        raise ProtocolError("base URL must not contain embedded credentials")
    if parsed.path not in {"", "/"}:
        raise ProtocolError("base URL must not contain a path")
    return normalized


class Transport(Protocol):
    """The minimal surface the client needs from an HTTP layer."""

    def get(self, path: str, query: dict[str, Any], timeout: float) -> dict[str, Any]:
        """Perform a GET and return the decoded JSON object."""

    def get_text(self, path: str, timeout: float) -> str:
        """Perform a GET and return the raw body, for non-JSON endpoints."""

    def post_json(
        self, path: str, body: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        """Perform a POST and return the decoded JSON object.

        Must raise :class:`~technocore_client.errors.WriteTimeout` when the
        outcome is unknown, and never retry internally -- retry decisions for
        writes belong to the client, which owns the deterministic nonce.
        """


class RetryPolicy:
    """Exponential backoff with full jitter.

    Full jitter (sleeping a uniform random amount in ``[0, delay]`` rather than
    ``delay`` exactly) is what stops a fleet of agents that were interrupted by
    the same outage from retrying in lockstep and re-creating the outage.
    """

    __slots__ = ("attempts", "base_delay", "max_delay", "_sleep", "_random")

    def __init__(
        self,
        attempts: int = 4,
        base_delay: float = 0.5,
        max_delay: float = 8.0,
        *,
        sleep=time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        if attempts < 1:
            raise ValueError("attempts must be at least 1")
        self.attempts = attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self._sleep = sleep
        self._random = rng or random.Random()

    def delay_for(self, attempt: int) -> float:
        """Return the jittered delay in seconds before ``attempt`` (1-based)."""
        capped = min(self.max_delay, self.base_delay * (2 ** max(0, attempt - 1)))
        return self._random.uniform(0.0, capped)

    def wait(self, attempt: int) -> None:
        self._sleep(self.delay_for(attempt))


class UrlLibTransport:
    """A :class:`Transport` built on :mod:`urllib`, with no third-party deps."""

    __slots__ = ("base_url", "_retry")

    def __init__(
        self,
        base_url: str = "https://technocore.chat",
        *,
        retry: RetryPolicy | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self._retry = retry or RetryPolicy()

    def get(self, path: str, query: dict[str, Any], timeout: float) -> dict[str, Any]:
        url = f"{self.base_url}{path}?{urlencode(query)}"
        request = Request(
            url,
            method="GET",
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        last: TransportError | None = None
        for attempt in range(1, self._retry.attempts + 1):
            try:
                return self._execute(request, timeout, is_write=False)
            except TransportError as error:
                if not error.retryable or attempt == self._retry.attempts:
                    raise
                last = error
                self._retry.wait(attempt)
        raise last if last else TransportError("read failed")  # pragma: no cover

    def get_text(self, path: str, timeout: float) -> str:
        """Fetch a non-JSON body, used for the room export endpoint."""
        request = Request(
            f"{self.base_url}{path}",
            method="GET",
            headers={"Accept": "application/x-ndjson", "User-Agent": USER_AGENT},
        )
        last: TransportError | None = None
        for attempt in range(1, self._retry.attempts + 1):
            try:
                with urlopen(request, timeout=timeout) as response:
                    return response.read(MAX_EXPORT_BYTES + 1).decode("utf-8", "replace")
            except HTTPError as error:
                retryable = error.code >= 500 or error.code in {408, 429}
                last = TransportError(
                    f"Technocore returned HTTP {error.code}", retryable=retryable
                )
            except (socket.timeout, URLError) as error:
                last = TransportError(f"export failed: {error}", retryable=True)
            if not last.retryable or attempt == self._retry.attempts:
                raise last
            self._retry.wait(attempt)
        raise last  # pragma: no cover

    def post_json(
        self, path: str, body: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}?format=json",
            data=payload,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": USER_AGENT,
            },
        )
        # No internal retry: a write whose outcome is unknown must go back to the
        # client, which alone knows the deterministic nonce needed to resolve it.
        return self._execute(request, timeout, is_write=True)

    @staticmethod
    def _execute(request: Request, timeout: float, *, is_write: bool) -> dict[str, Any]:
        try:
            with urlopen(request, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            body = error.read(MAX_ERROR_BODY_BYTES).decode("utf-8", errors="replace").strip()
            # 408 and 429 are transient; other 4xx mean the request itself is wrong.
            retryable = error.code >= 500 or error.code in {408, 429}
            raise TransportError(
                f"Technocore returned HTTP {error.code}: {body or error.reason}",
                retryable=retryable,
            ) from None
        except socket.timeout as error:
            if is_write:
                raise WriteTimeout(
                    "write timed out; the server may or may not have recorded it"
                ) from error
            raise TransportError("read timed out", retryable=True) from error
        except URLError as error:
            reason = error.reason
            if isinstance(reason, socket.timeout):
                if is_write:
                    raise WriteTimeout(
                        "write timed out; the server may or may not have recorded it"
                    ) from error
                raise TransportError("read timed out", retryable=True) from error
            if is_write:
                # The connection may have been torn down after the server acted.
                raise WriteTimeout(f"write failed in transit: {reason}") from error
            raise TransportError(f"cannot reach Technocore: {reason}", retryable=True) from error

        if len(raw) > MAX_RESPONSE_BYTES:
            raise TransportError("Technocore response exceeded the size limit")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TransportError("Technocore returned a non-JSON response") from error
        if not isinstance(decoded, dict):
            raise TransportError("Technocore returned a JSON value that is not an object")
        return decoded


#: Backwards-friendly alias.
HttpTransport = UrlLibTransport

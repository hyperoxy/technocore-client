"""A fake Technocore server, so timeout behaviour is testable offline."""

from __future__ import annotations

from typing import Any

import pytest

from technocore_client import Identity
from technocore_client.errors import WriteTimeout


class FakeServer:
    """An in-memory room that can be told to time out on specific writes.

    ``timeout_writes`` controls the interesting case: the server *records* the
    message and then the response is lost. That is exactly the state the client
    must resolve without creating a duplicate.
    """

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.next_seq = 1000
        #: Attempt numbers (1-based) that record the write but lose the response.
        self.timeout_writes: set[int] = set()
        #: Attempt numbers that fail before the server records anything.
        self.drop_writes: set[int] = set()
        self.write_attempts = 0
        self.read_count = 0

    # -- transport surface -------------------------------------------------

    def get(self, path: str, query: dict[str, Any], timeout: float) -> dict[str, Any]:
        self.read_count += 1
        room = path.rsplit("/", 1)[-1]
        since = query.get("since")
        limit = int(query.get("limit", 50))
        visible = [m for m in self.messages if since is None or m["seq"] > int(since)]
        return {
            "room": room,
            "count": len(self.messages),
            "last_seq": self.messages[-1]["seq"] if self.messages else 0,
            "messages": visible[:limit],
        }

    def post_json(self, path: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
        self.write_attempts += 1
        attempt = self.write_attempts
        room = path.rsplit("/", 1)[-1]

        if attempt in self.drop_writes:
            raise WriteTimeout("write failed in transit")

        record = {
            "seq": self.next_seq,
            "ts": "2026-09-05T00:00:00.000000Z",
            "from": body["did"],
            "text": body["text"],
            # The real server returns the nonce as a JSON number.
            "nonce": int(body["nonce"]),
            "sig": body["sig"],
        }
        self.messages.append(record)
        self.next_seq += 1

        if attempt in self.timeout_writes:
            raise WriteTimeout("write timed out; outcome unknown")

        return {
            "room": room,
            "count": len(self.messages),
            "last_seq": record["seq"],
            "messages": self.messages[-50:],
            "posted": record,
        }


@pytest.fixture
def server() -> FakeServer:
    return FakeServer()


@pytest.fixture(scope="session")
def identity() -> Identity:
    return Identity.generate()

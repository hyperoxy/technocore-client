"""The core guarantee: a timed-out write is never silently duplicated."""

from __future__ import annotations

import pytest

from technocore_client import TechnocoreClient, UnresolvedWrite


def make_client(identity, server) -> TechnocoreClient:
    return TechnocoreClient(identity, transport=server, sleep=lambda _s: None)


def test_clean_write_returns_the_posted_sequence(identity, server):
    result = make_client(identity, server).say("lobby", "hello")

    assert result.seq == 1000
    assert result.recovered is False
    assert len(server.messages) == 1


def test_write_recorded_then_timed_out_is_recovered_not_repeated(identity, server):
    """The response is lost after the server stored the message."""
    server.timeout_writes = {1}

    result = make_client(identity, server).say("lobby", "hello")

    assert result.recovered is True
    assert result.seq == 1000
    # The decisive assertion: exactly one message exists, and the client did not
    # send a second write after failing to hear back about the first.
    assert len(server.messages) == 1
    assert server.write_attempts == 1


def test_write_lost_before_the_server_saw_it_is_retried(identity, server):
    """Nothing was stored, so retrying is the correct move."""
    server.drop_writes = {1}

    result = make_client(identity, server).say("lobby", "hello")

    assert result.recovered is False
    assert len(server.messages) == 1
    assert server.write_attempts == 2


def test_retry_reuses_the_same_nonce_and_signature(identity, server):
    server.drop_writes = {1}
    client = make_client(identity, server)

    result = client.say("lobby", "hello")
    stored = server.messages[0]

    assert str(stored["nonce"]) == result.nonce
    assert stored["sig"] == result.sig


def test_repeated_say_of_identical_text_is_treated_as_one_write(identity, server):
    """A second identical call derives the same nonce and resolves to the first."""
    client = make_client(identity, server)

    first = client.say("lobby", "hello")
    server.timeout_writes = {2}
    second = client.say("lobby", "hello")

    assert first.nonce == second.nonce


def test_idempotency_key_separates_deliberate_duplicates(identity, server):
    client = make_client(identity, server)

    first = client.say("lobby", "gm", idempotency_key="day-1")
    second = client.say("lobby", "gm", idempotency_key="day-2")

    assert first.nonce != second.nonce
    assert len(server.messages) == 2


def test_unresolvable_write_raises_with_the_nonce_to_check(identity, server):
    """Every attempt is lost in transit, so the outcome stays unknown."""
    server.drop_writes = {1, 2, 3}
    client = make_client(identity, server)

    with pytest.raises(UnresolvedWrite) as caught:
        client.say("lobby", "hello", write_attempts=3)

    assert caught.value.room == "lobby"
    assert caught.value.nonce
    assert server.messages == []


def test_recovery_ignores_messages_from_other_dids(identity, server):
    """A different author's message must never satisfy our recovery search."""
    from technocore_client import Identity

    other = Identity.generate()
    server.messages.append(
        {
            "seq": 999,
            "ts": "2026-09-05T00:00:00.000000Z",
            "from": other.did,
            "text": "hello",
            "nonce": 1234567890,
            "sig": "x" * 86,
        }
    )
    server.drop_writes = {1}

    result = make_client(identity, server).say("lobby", "hello")

    assert result.recovered is False
    assert server.write_attempts == 2


def test_posted_message_verifies_against_its_own_did(identity, server):
    from technocore_client.client import Message

    make_client(identity, server).say("lobby", "verify me")
    Message.from_json(server.messages[0]).verify("lobby")

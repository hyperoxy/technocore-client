"""Wire-format rules: normalization, validation, nonce derivation, signatures."""

from __future__ import annotations

import pytest

from technocore_client import (
    Identity,
    IdentityError,
    ProtocolError,
    build_payload,
    derive_nonce,
    normalize_message,
    validate_room,
    verify_signature,
)
from technocore_client.protocol import MAX_MESSAGE_CHARS


class TestNormalization:
    def test_invisible_characters_become_spaces(self):
        assert normalize_message("a​b") == "a b"

    def test_surrounding_whitespace_is_stripped(self):
        assert normalize_message("  hi  ") == "hi"

    def test_text_that_normalizes_to_nothing_is_rejected(self):
        with pytest.raises(ProtocolError):
            normalize_message("​​")

    def test_interior_invisible_characters_count_toward_the_limit(self):
        # An interior invisible character becomes a space rather than vanishing,
        # so it costs a character even though it renders as nothing.
        with pytest.raises(ProtocolError):
            normalize_message("x" * (MAX_MESSAGE_CHARS - 1) + "​" + "x")

    def test_trailing_invisible_characters_are_stripped_not_counted(self):
        # The mirror case: at the edge it collapses to a space and is then
        # stripped, so it costs nothing. Position decides.
        assert len(normalize_message("x" * MAX_MESSAGE_CHARS + "​")) == MAX_MESSAGE_CHARS

    def test_maximum_length_is_accepted(self):
        assert len(normalize_message("x" * MAX_MESSAGE_CHARS)) == MAX_MESSAGE_CHARS


class TestRoomNames:
    @pytest.mark.parametrize("room", ["lobby", "technocore", "a", "a-b_c9"])
    def test_valid_rooms(self, room):
        assert validate_room(room) == room

    @pytest.mark.parametrize("room", ["Lobby", "-lobby", "", "a" * 49, "ло+бі"])
    def test_invalid_rooms(self, room):
        with pytest.raises(ProtocolError):
            validate_room(room)


class TestNonceDerivation:
    DID = "did:key:z6MkhTNHEkHQWuk6hUFXP555tmTvC8FcGQAMGoGxzP7A75Nd"

    def test_is_deterministic(self):
        assert derive_nonce(self.DID, "lobby", "hi") == derive_nonce(self.DID, "lobby", "hi")

    def test_fits_the_protocol_pattern(self):
        nonce = derive_nonce(self.DID, "lobby", "hi")
        assert nonce.isdigit() and 1 <= len(nonce) <= 19

    def test_differs_by_room(self):
        assert derive_nonce(self.DID, "lobby", "hi") != derive_nonce(self.DID, "technocore", "hi")

    def test_differs_by_text(self):
        assert derive_nonce(self.DID, "lobby", "hi") != derive_nonce(self.DID, "lobby", "ho")

    def test_differs_by_author(self):
        other = Identity.generate().did
        assert derive_nonce(self.DID, "lobby", "hi") != derive_nonce(other, "lobby", "hi")

    def test_differs_by_idempotency_key(self):
        assert derive_nonce(self.DID, "lobby", "hi", "a") != derive_nonce(self.DID, "lobby", "hi", "b")


class TestSigning:
    def test_signature_verifies_against_the_did(self):
        identity = Identity.generate()
        _, payload = build_payload("lobby", "123", "hello")

        verify_signature(identity.did, identity.sign(payload), payload)

    def test_signature_fails_against_a_different_did(self):
        identity = Identity.generate()
        other = Identity.generate()
        _, payload = build_payload("lobby", "123", "hello")

        with pytest.raises(IdentityError):
            verify_signature(other.did, identity.sign(payload), payload)

    def test_signature_covers_the_normalized_text(self):
        """Signing happens after normalization, so both forms verify alike."""
        identity = Identity.generate()
        _, payload = build_payload("lobby", "123", "  hello  ")
        _, canonical = build_payload("lobby", "123", "hello")

        assert payload == canonical
        verify_signature(identity.did, identity.sign(payload), canonical)

    def test_payload_layout_is_room_pipe_nonce_pipe_text(self):
        _, payload = build_payload("lobby", "123", "hello")
        assert payload == b"lobby|123|hello"


class TestDidRoundTrip:
    def test_generated_did_is_canonical(self):
        did = Identity.generate().did
        assert did.startswith("did:key:z6Mk")
        assert len(did) == len("did:key:") + 48

    @pytest.mark.parametrize(
        "did",
        ["", "did:key:", "did:key:z6Mkshort", "not-a-did"],
    )
    def test_malformed_dids_are_rejected(self, did):
        with pytest.raises(ProtocolError):
            verify_signature(did, "x" * 86, b"payload")

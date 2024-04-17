import pytest

from signal_protocol.state import SessionRecord
from signal_protocol.kem import SerializedCiphertext, KeyPair as KyberKeyPair, KeyType

# from signal_protocol.protocol import KemSerializedCiphertext
from signal_protocol.curve import KeyPair, PrivateKey, PublicKey
from signal_protocol.identity_key import IdentityKey, IdentityKeyPair
from signal_protocol.ratchet import (
    BobSignalProtocolParameters,
    initialize_bob_session,
    AliceSignalProtocolParameters,
    initialize_alice_session,
)

PRE_KYBER_MESSAGE_VERSION = 3
KYBER_AWARE_MESSAGE_VERSION = 4
KYBER_1024_KEY_TYPE = KeyType(0)


def test_ratcheting_session_as_bob():
    bob_ephemeral_public = bytes.fromhex(
        "052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458"
    )

    bob_ephemeral_private = bytes.fromhex(
        "a1cab48f7c893fafa9880a28c3b4999d28d6329562d27a4ea4e22e9ff1bdd65a"
    )

    bob_identity_public = bytes.fromhex(
        "05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626"
    )

    bob_identity_private = bytes.fromhex(
        "4875cc69ddf8ea0719ec947d61081135868d5fd801f02c0225e516df2156605e"
    )

    alice_base_public = bytes.fromhex(
        "05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950"
    )

    alice_identity_public_bytes = bytes.fromhex(
        "05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a"
    )

    bob_signed_prekey_public = bytes.fromhex(
        "05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67"
    )

    bob_signed_prekey_private = bytes.fromhex(
        "583900131fb727998b7803fe6ac22cc591f342e4e42a8c8d5d78194209b8d253"
    )

    expected_sender_chain = (
        "9797caca53c989bbe229a40ca7727010eb2604fc14945d77958a0aeda088b44d"
    )

    bob_identity_key_public = IdentityKey(bob_identity_public)

    bob_identity_key_private = PrivateKey.deserialize(bob_identity_private)

    bob_identity_key_pair = IdentityKeyPair(
        bob_identity_key_public, bob_identity_key_private
    )

    bob_ephemeral_pair = KeyPair.from_public_and_private(
        bob_ephemeral_public, bob_ephemeral_private
    )

    bob_signed_prekey_pair = KeyPair.from_public_and_private(
        bob_signed_prekey_public, bob_signed_prekey_private
    )

    alice_base_public_key = PublicKey.deserialize(alice_base_public)

    alice_identity_public = IdentityKey(alice_identity_public_bytes)

    _kyber_ctxt = SerializedCiphertext(b"")
    _kyber_keypair = KyberKeyPair.generate(KYBER_1024_KEY_TYPE)

    bob_parameters = BobSignalProtocolParameters(
        bob_identity_key_pair,
        bob_signed_prekey_pair,
        None,
        bob_ephemeral_pair,
        None,  # todo: no kyber yet
        alice_identity_public,
        alice_base_public_key,
        None,  # and no kyber ctxt
    )

    bob_record = initialize_bob_session(bob_parameters)

    assert bob_record.local_identity_key_bytes() == bob_identity_public
    assert bob_record.remote_identity_key_bytes() == alice_identity_public_bytes
    assert bob_record.get_sender_chain_key_bytes() == bytes.fromhex(
        expected_sender_chain
    )


def test_ratcheting_session_as_alice():
    bob_ephemeral_public = bytes.fromhex(
        "052cb49776b8770205745a3a6e24f579cdb4ba7a89041005928ebbadc9c05ad458"
    )

    bob_identity_public_bytes = bytes.fromhex(
        "05f1f43874f6966956c2dd473f8fa15adeb71d1cb991b2341692324cefb1c5e626"
    )

    alice_base_public = bytes.fromhex(
        "05472d1fb1a9862c3af6beaca8920277e2b26f4a79213ec7c906aeb35e03cf8950"
    )

    alice_base_private = bytes.fromhex(
        "11ae7c64d1e61cd596b76a0db5012673391cae66edbfcf073b4da80516a47449"
    )

    alice_identity_public = bytes.fromhex(
        "05b4a8455660ada65b401007f615e654041746432e3339c6875149bceefcb42b4a"
    )

    alice_identity_private = bytes.fromhex(
        "9040f0d4e09cf38f6dc7c13779c908c015a1da4fa78737a080eb0a6f4f5f8f58"
    )

    bob_signed_prekey_public = bytes.fromhex(
        "05ac248a8f263be6863576eb0362e28c828f0107a3379d34bab1586bf8c770cd67"
    )

    # Note this may change, upstream there is a note about it deviating from the Java impl, possible bug
    expected_receiver_chain = (
        "ab9be50e5cb22a925446ab90ee5670545f4fd32902459ec274b6ad0ae5d6031a"
    )

    alice_identity_key_public = IdentityKey(alice_identity_public)

    bob_ephemeral_public = PublicKey.deserialize(bob_ephemeral_public)

    alice_identity_key_private = PrivateKey.deserialize(alice_identity_private)

    bob_signed_prekey_public = PublicKey.deserialize(bob_signed_prekey_public)

    alice_identity_key_pair = IdentityKeyPair(
        alice_identity_key_public, alice_identity_key_private
    )

    bob_identity_public = IdentityKey(bob_identity_public_bytes)

    alice_base_key = KeyPair.from_public_and_private(
        alice_base_public, alice_base_private
    )

    alice_parameters = AliceSignalProtocolParameters(
        alice_identity_key_pair,
        alice_base_key,
        bob_identity_public,
        bob_signed_prekey_public,
        None,
        bob_ephemeral_public,
        None,
    )

    alice_record = initialize_alice_session(alice_parameters)

    assert alice_record.local_identity_key_bytes() == alice_identity_public
    assert alice_record.remote_identity_key_bytes() == bob_identity_public_bytes
    assert alice_record.get_receiver_chain_key_bytes(
        bob_ephemeral_public
    ) == bytes.fromhex(expected_receiver_chain)
    assert (
        alice_record.session_version() == PRE_KYBER_MESSAGE_VERSION
    ), f"Expected PRE_KYBER communication (version: {PRE_KYBER_MESSAGE_VERSION})"


def test_alice_and_bob_agree_on_chain_keys_with_kyber():
    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_base_key_pair = KeyPair.generate()

    bob_ephemeral_key_pair = KeyPair.generate()
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_signed_pre_key_pair = KeyPair.generate()

    bob_kyber_pre_key_pair = KyberKeyPair.generate(KYBER_1024_KEY_TYPE)

    alice_parameters = AliceSignalProtocolParameters(
        alice_identity_key_pair,
        alice_base_key_pair,
        bob_identity_key_pair.identity_key(),
        bob_signed_pre_key_pair.public_key(),
        None,  # _their_one_time_pre_key
        bob_ephemeral_key_pair.public_key(),
        bob_kyber_pre_key_pair.get_public(),  # _their_kyber_pre_key
    )
    alice_record = initialize_alice_session(alice_parameters)

    assert (
        alice_record.session_version() == KYBER_AWARE_MESSAGE_VERSION
    ), f"Expected KYBER_AWARE communication (version: {KYBER_AWARE_MESSAGE_VERSION})"

    raw_kyber_ctxt = alice_record.get_kyber_ciphertext()
    assert (
        raw_kyber_ctxt != None and len(raw_kyber_ctxt) > 0
    ), "must have kyber ciphertext"

    kyber_ctxt = SerializedCiphertext(raw_kyber_ctxt)

    bob_parameters = BobSignalProtocolParameters(
        bob_identity_key_pair,
        bob_signed_pre_key_pair,
        None,
        bob_ephemeral_key_pair,
        bob_kyber_pre_key_pair,
        alice_identity_key_pair.identity_key(),
        alice_base_key_pair.public_key(),
        kyber_ctxt,
    )
    bob_record = initialize_bob_session(bob_parameters)

    assert (
        bob_record.session_version() == KYBER_AWARE_MESSAGE_VERSION
    ), f"Expected KYBER_AWARE communication (version: {KYBER_AWARE_MESSAGE_VERSION})"

    assert (
        len(bob_record.get_sender_chain_key_bytes()) > 0
    ), "alice should have chain key"
    assert (
        len(
            alice_record.get_receiver_chain_key_bytes(
                bob_ephemeral_key_pair.public_key()
            )
        )
        > 0
    ), "should have chain key"

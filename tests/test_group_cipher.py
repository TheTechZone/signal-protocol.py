import pytest
import random

from signal_protocol.address import ProtocolAddress
from signal_protocol.error import SignalProtocolException
from signal_protocol.group_cipher import (
    create_sender_key_distribution_message,
    group_decrypt,
    group_encrypt,
    process_sender_key_distribution_message,
)
from signal_protocol.identity_key import IdentityKeyPair
from signal_protocol.storage import InMemSignalProtocolStore
from signal_protocol.protocol import SenderKeyDistributionMessage
from signal_protocol.uuid import uuid_from_u128

DEVICE_ID = 1


def test_group_no_send_session():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )

    with pytest.raises(SignalProtocolException, match="missing sender key state"):
        # todo: check against rust
        group_encrypt(
            alice_store, sender_address, distribution_id, "hello".encode("utf8")
        )


def test_group_basic_encrypt_decrypt():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    sent_distribution_message = create_sender_key_distribution_message(
        sender_address, distribution_id, alice_store
    )
    recv_distribution_message = SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    alice_ciphertext = group_encrypt(
        alice_store, sender_address, distribution_id, "hello".encode("utf8")
    )

    process_sender_key_distribution_message(
        sender_address, recv_distribution_message, bob_store
    )

    bob_plaintext = group_decrypt(alice_ciphertext, bob_store, sender_address)

    assert bob_plaintext.decode("utf8") == "hello"


def test_group_no_recv_session():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    sent_distribution_message = create_sender_key_distribution_message(
        sender_address, distribution_id, alice_store
    )
    recv_distribution_message = SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    alice_ciphertext = group_encrypt(
        alice_store, sender_address, distribution_id, "hello".encode("utf8")
    )

    with pytest.raises(SignalProtocolException, match="missing sender key state"):
        # todo: check with rust
        bob_plaintext = group_decrypt(alice_ciphertext, bob_store, sender_address)


def test_group_large_message():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    sent_distribution_message = create_sender_key_distribution_message(
        sender_address, distribution_id, alice_store
    )
    recv_distribution_message = SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    large_message = bytes(1024)
    alice_ciphertext = group_encrypt(
        alice_store, sender_address, distribution_id, large_message
    )

    process_sender_key_distribution_message(
        sender_address, recv_distribution_message, bob_store
    )

    bob_plaintext = group_decrypt(alice_ciphertext, bob_store, sender_address)

    assert bob_plaintext == large_message


def test_group_basic_ratchet():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    sent_distribution_message = create_sender_key_distribution_message(
        sender_address, distribution_id, alice_store
    )
    recv_distribution_message = SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    process_sender_key_distribution_message(
        sender_address, recv_distribution_message, bob_store
    )

    alice_ciphertext_1 = group_encrypt(
        alice_store, sender_address, distribution_id, "message 1".encode("utf8")
    )
    alice_ciphertext_2 = group_encrypt(
        alice_store, sender_address, distribution_id, "message 2".encode("utf8")
    )
    alice_ciphertext_3 = group_encrypt(
        alice_store, sender_address, distribution_id, "message 3".encode("utf8")
    )

    bob_plaintext1 = group_decrypt(alice_ciphertext_1, bob_store, sender_address)
    assert bob_plaintext1.decode("utf8") == "message 1"

    with pytest.raises(SignalProtocolException, match="message with old counter 1 / 0"):
        bob_plaintext1 = group_decrypt(alice_ciphertext_1, bob_store, sender_address)

    bob_plaintext2 = group_decrypt(alice_ciphertext_2, bob_store, sender_address)
    assert bob_plaintext2.decode("utf8") == "message 2"

    bob_plaintext3 = group_decrypt(alice_ciphertext_3, bob_store, sender_address)
    assert bob_plaintext3.decode("utf8") == "message 3"


def test_group_late_join():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    sent_distribution_message = create_sender_key_distribution_message(
        sender_address, distribution_id, alice_store
    )
    recv_distribution_message = SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )

    for i in range(100):
        group_encrypt(
            alice_store,
            sender_address,
            distribution_id,
            f"message {i}/100".encode("utf8"),
        )

    process_sender_key_distribution_message(
        sender_address, recv_distribution_message, bob_store
    )

    alice_ciphertext = group_encrypt(
        alice_store, sender_address, distribution_id, "welcome Bob!".encode("utf8")
    )

    bob_plaintext = group_decrypt(alice_ciphertext, bob_store, sender_address)
    assert bob_plaintext.decode("utf8") == "welcome Bob!"


def test_group_out_of_order():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    sent_distribution_message = create_sender_key_distribution_message(
        sender_address, distribution_id, alice_store
    )
    recv_distribution_message = SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )
    process_sender_key_distribution_message(
        sender_address, recv_distribution_message, bob_store
    )

    ooo_ciphertexts = []
    for i in range(100):
        ooo_ciphertexts.append(
            group_encrypt(
                alice_store, sender_address, distribution_id, f"{i}".encode("utf8")
            )
        )
    random.shuffle(ooo_ciphertexts)

    plaintexts = []
    for ciphertext in ooo_ciphertexts:
        plaintexts.append(group_decrypt(ciphertext, bob_store, sender_address))
    plaintexts.sort(key=lambda x: int(x))

    for i, plaintext in enumerate(plaintexts):
        assert plaintext.decode("utf8") == f"{i}"


def test_group_too_far_in_the_future():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    sent_distribution_message = create_sender_key_distribution_message(
        sender_address, distribution_id, alice_store
    )
    recv_distribution_message = SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )
    process_sender_key_distribution_message(
        sender_address, recv_distribution_message, bob_store
    )

    FUTURE_LIMIT = 25001  # used to be 2001
    for i in range(FUTURE_LIMIT):
        group_encrypt(
            alice_store,
            sender_address,
            distribution_id,
            f"this is message {i}".encode("utf8"),
        )

    alice_ciphertext = group_encrypt(
        alice_store, sender_address, distribution_id, "hello????".encode("utf8")
    )

    with pytest.raises(
        SignalProtocolException, match="message from too far into the future"
    ):
        assert group_decrypt(alice_ciphertext, bob_store, sender_address)


def test_group_message_key_limit():
    sender_address = ProtocolAddress("+14159999111", DEVICE_ID)
    distribution_id = uuid_from_u128(0xD1D1D1D1_7000_11EB_B32A_33B8A8A487A6)

    alice_identity_key_pair = IdentityKeyPair.generate()
    alice_registration_id = 1
    alice_store = InMemSignalProtocolStore(
        alice_identity_key_pair, alice_registration_id
    )
    bob_identity_key_pair = IdentityKeyPair.generate()
    bob_registration_id = 2
    bob_store = InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

    sent_distribution_message = create_sender_key_distribution_message(
        sender_address, distribution_id, alice_store
    )
    recv_distribution_message = SenderKeyDistributionMessage.try_from(
        sent_distribution_message.serialized()
    )
    process_sender_key_distribution_message(
        sender_address, recv_distribution_message, bob_store
    )

    ciphertexts = []
    for i in range(2010):
        ciphertexts.append(
            group_encrypt(
                alice_store,
                sender_address,
                distribution_id,
                "too many msg".encode("utf8"),
            )
        )

    assert (
        group_decrypt(ciphertexts[1000], bob_store, sender_address).decode("utf8")
        == "too many msg"
    )
    assert (
        group_decrypt(
            ciphertexts[len(ciphertexts) - 1], bob_store, sender_address
        ).decode("utf8")
        == "too many msg"
    )

    with pytest.raises(SignalProtocolException, match="message with old counter"):
        assert group_decrypt(ciphertexts[0], bob_store, sender_address).decode("utf8")

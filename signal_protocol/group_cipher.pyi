from typing import Tuple
from .address import ProtocolAddress
from .storage import InMemSignalProtocolStore
from .protocol import SenderKeyDistributionMessage
from .uuid import UUID

def create_sender_key_distribution_message(
    protocol_store: InMemSignalProtocolStore,
    sender: ProtocolAddress,
    distribution_id: UUID,
) -> Tuple[UUID, bytes]:
    """
    Creates a sender key distribution message.

    Args:
        protocol_store (InMemSignalProtocolStore): The protocol store.
        sender (ProtocolAddress): The sender's address.
        distribution_id (UUID): The distribution ID.

    Returns:
        Tuple[UUID, bytes]: The sender key distribution message.
    """
    ...

def group_decrypt(
    skm_bytes: bytes, protocol_store: InMemSignalProtocolStore, sender: ProtocolAddress
) -> bytes:
    """
    Decrypts a group message.

    Args:
        protocol_store (InMemSignalProtocolStore): The protocol store.
        sender (ProtocolAddress): The sender's address.
        skm_bytes (bytes): The sender key message bytes.

    Returns:
        bytes: The decrypted message.
    """
    ...

def group_encrypt(
    protocol_store: InMemSignalProtocolStore,
    sender: ProtocolAddress,
    distribution_id: UUID,
    plaintext: bytes,
) -> bytes:
    """
    Encrypts a group message.

    Args:
        protocol_store (InMemSignalProtocolStore): The protocol store.
        sender (ProtocolAddress): The sender's address.
        distribution_id (UUID): The distribution ID.
        plaintext (str): The plaintext message.

    Returns:
        bytes: The encrypted message.
    """
    ...

def process_sender_key_distribution_message(
    sender: ProtocolAddress,
    skdm: SenderKeyDistributionMessage,
    protocol_store: InMemSignalProtocolStore,
) -> None:
    """
    Processes a sender key distribution message. It updated the protocol store inplace.

    Args:
        protocol_store (InMemSignalProtocolStore): The protocol store.
        sender (ProtocolAddress): The sender's address.
        skdm (Tuple[UUID, bytes]): The sender key distribution message.

    Returns:
        None
    """
    ...

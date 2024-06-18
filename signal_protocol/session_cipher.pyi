from .address import ProtocolAddress
from .protocol import CiphertextMessage, PreKeySignalMessage, SignalMessage
from .storage import InMemSignalProtocolStore

def message_decrypt(protocol_store: InMemSignalProtocolStore, remote_address: ProtocolAddress, msg: bytes) -> bytes:
    """
    Decrypts a message.

    Args:
        protocol_store (InMemSignalProtocolStore): The protocol store.
        remote_address (ProtocolAddress): The remote address.
        msg (CiphertextMessage): The ciphertext message.

    Returns:
        bytes: The decrypted message.
    """
    ...

def message_decrypt_prekey(protocol_store: InMemSignalProtocolStore, remote_address: ProtocolAddress, msg: PreKeySignalMessage) -> bytes:
    """
    Decrypts a pre-key message.

    Args:
        protocol_store (InMemSignalProtocolStore): The protocol store.
        remote_address (ProtocolAddress): The remote address.
        msg (PreKeySignalMessage): The pre-key signal message.

    Returns:
        bytes: The decrypted message.
    """
    ...

def message_decrypt_signal(protocol_store: InMemSignalProtocolStore, remote_address: ProtocolAddress, msg: SignalMessage) -> bytes:
    """
    Decrypts a signal message.

    Args:
        protocol_store (InMemSignalProtocolStore): The protocol store.
        remote_address (ProtocolAddress): The remote address.
        msg (SignalMessage): The signal message.

    Returns:
        bytes: The decrypted message.
    """
    ...

def message_encrypt(protocol_store: InMemSignalProtocolStore, remote_address: ProtocolAddress, msg: bytes) -> CiphertextMessage:
    """
    Encrypts a message.

    Args:
        protocol_store (InMemSignalProtocolStore): The protocol store.
        remote_address (ProtocolAddress): The remote address.
        msg (str): The message to encrypt.
        now2 (int): The current timestamp.

    Returns:
        CiphertextMessage: The encrypted message.
    """
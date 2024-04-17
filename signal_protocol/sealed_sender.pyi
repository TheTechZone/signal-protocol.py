from .address import ProtocolAddress
from .curve import PublicKey, PrivateKey
from .storage import InMemSignalProtocolStore
from typing import Optional, Any

class SealedSenderDecryptionResult:
    """
    This class represents the result of a sealed sender decryption operation.
    """

    def sender_uuid(self) -> str:
        """
        Returns the sender's UUID.

        Returns:
            str: The sender's UUID.
        """
        ...

    def sender_e164(self) -> Optional[str]:
        """
        Returns the sender's E164 identifier.

        Returns:
            str: The sender's E164 identifier.
        """
        ...

    def device_id(self) -> int:
        """
        Returns the sender's device ID.

        Returns:
            int: The sender's device ID.
        """
        ...

    def message(self) -> bytes:
        """
        Returns the decrypted message.

        Returns:
            bytes: The decrypted message.
        """
        ...

class SenderCertificate:
    """
    This class represents a sender's certificate.
    """

    def __init__(
        self,
        sender_uuid: str,
        sender_e164: Optional[str],
        key: PublicKey,
        sender_device_id: int,
        expiration: int,
        signer: ServerCertificate,
        signer_key: PrivateKey,
    ) -> None: ...
    def deserialize(self, data: bytes) -> SenderCertificate:
        """
        Deserializes a sender's certificate from bytes.

        Args:
            data (bytes): The serialized sender's certificate.

        Returns:
            SenderCertificate: The deserialized sender's certificate.
        """
        ...

    def validate(self, trust_root: PublicKey) -> bool:
        """
        Validates the sender's certificate against a trust root.

        Args:
            trust_root (PublicKey): The trust root to validate against.

        Returns:
            bool: True if the certificate is valid, False otherwise.
        """
        ...

    def signer(self) -> ServerCertificate:
        """
        Returns the signer's server certificate.

        Returns:
            ServerCertificate: The signer's server certificate.
        """
        ...

    def key(self) -> PublicKey:
        """
        Returns the sender's public key.

        Returns:
            PublicKey: The sender's public key.
        """
        ...

    def sender_device_id(self) -> int:
        """
        Returns the sender's device ID.

        Returns:
            int: The sender's device ID.
        """
        ...

    def sender_uuid(self) -> Optional[str]:
        """
        Returns the sender's UUID.

        Returns:
            str: The sender's UUID.
        """
        ...

    def sender_e164(self) -> Optional[str]:
        """
        Returns the sender's E164 identifier.

        Returns:
            str: The sender's E164 identifier.
        """
        ...

    def expiration(self) -> int:
        """
        Returns the expiration timestamp of the certificate.

        Returns:
            int: The expiration timestamp of the certificate.
        """
        ...

    def certificate(self) -> bytes:
        """
        Returns the certificate data.

        Returns:
            bytes: The certificate data.
        """
        ...

    def signature(self) -> bytes:
        """
        Returns the certificate signature.

        Returns:
            bytes: The certificate signature.
        """
        ...

    def serialized(self) -> bytes:
        """
        Returns the serialized certificate.

        Returns:
            bytes: The serialized certificate.
        """
        ...

class ServerCertificate:
    """
    This class represents a server's certificate.
    """

    def __init__(self, key_id: int, key: PublicKey, trust_root: PrivateKey) -> None: ...
    def deserialize(self, data: bytes) -> ServerCertificate:
        """
        Deserializes a server's certificate from bytes.

        Args:
            data (bytes): The serialized server's certificate.

        Returns:
            ServerCertificate: The deserialized server's certificate.
        """
        ...

    def validate(self, trust_root: PublicKey) -> bool:
        """
        Validates the server's certificate against a trust root.

        Args:
            trust_root (PublicKey): The trust root to validate against.

        Returns:
            bool: True if the certificate is valid, False otherwise.
        """
        ...

    def key_id(self) -> int:
        """
        Returns the key ID associated with the certificate.

        Returns:
            int: The key ID.
        """
        ...

    def public_key(self) -> PublicKey:
        """
        Returns the server's public key.

        Returns:
            PublicKey: The server's public key.
        """
        ...

    def certificate(self) -> bytes:
        """
        Returns the certificate data.

        Returns:
            bytes: The certificate data.
        """
        ...

    def signature(self) -> bytes:
        """
        Returns the certificate signature.

        Returns:
            bytes: The certificate signature.
        """
        ...

    def serialized(self) -> bytes:
        """
        Returns the serialized certificate.

        Returns:
            bytes: The serialized certificate.
        """
        ...

class UnidentifiedSenderMessageContent:
    """
    This class represents the content of a message from an unidentified sender.
    """

    def __init__(
        self,
        msg_type_value: int,
        sender: SenderCertificate,
        contents: bytes,
        content_hint: Any,
        group_id: Optional[bytes],
    ) -> None:
        """TODO: contentHint impl"""
        ...

    def deserialize(self, data: bytes) -> UnidentifiedSenderMessageContent:
        """
        Deserializes the message content from bytes.

        Args:
            data (bytes): The serialized message content.

        Returns:
            UnidentifiedSenderMessageContent: The deserialized message content.
        """
        ...

    def msg_type(self) -> int:
        """
        Returns the message type.

        Returns:
            int: The message type.
        """
        ...

    def sender(self) -> SenderCertificate:
        """
        Returns the sender's certificate.

        Returns:
            SenderCertificate: The sender's certificate.
        """
        ...

    def contents(self) -> bytes:
        """
        Returns the message contents.

        Returns:
            bytes: The message contents.
        """
        ...

    def serialized(self) -> bytes:
        """
        Returns the serialized message content.

        Returns:
            bytes: The serialized message content.
        """
        ...

def sealed_sender_decrypt(
    ciphertext: bytes,
    trust_root: PublicKey,
    timestamp: int,
    local_e164: Optional[str],
    local_uuid: str,
    local_device_id: int,
    protocol_store: InMemSignalProtocolStore,
) -> SealedSenderDecryptionResult:
    """
    Decrypts a sealed sender message.

    Args:
        ciphertext (bytes): The sealed sender message.
        trust_root (PublicKey): The trust root.
        timestamp (int): The timestamp.
        local_e164 (str): The local E164 identifier.
        local_uuid (str): The local UUID.
        local_device_id (int): The local device ID.
        protocol_store (InMemSignalProtocolStore): The protocol store.

    Returns:
        SealedSenderDecryptionResult: The result of the decryption operation.
    """
    ...

def sealed_sender_decrypt_to_usmc(
    ciphertext: bytes, trust_root: PublicKey
) -> UnidentifiedSenderMessageContent:
    """
    Decrypts a sealed sender message to an UnidentifiedSenderMessageContent.

    Args:
        ciphertext (bytes): The sealed sender message.
        trust_root (PublicKey): The trust root.

    Returns:
        UnidentifiedSenderMessageContent: The decrypted message content.
    """
    ...

def sealed_sender_encrypt(
    destination: ProtocolAddress,
    sender_cert: SenderCertificate,
    ptext: bytes,
    protocol_store: InMemSignalProtocolStore,
) -> bytes:
    """
    Encrypts a message as a sealed sender message.

    Args:
        destination (ProtocolAddress): The recipient's address.
        sender_cert (SenderCertificate): The sender's certificate.
        ptext (bytes): The message to encrypt.
        protocol_store (InMemSignalProtocolStore): The protocol store.

    Returns:
        bytes: The encrypted message.
    """
    ...

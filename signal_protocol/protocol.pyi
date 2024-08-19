from .curve import PublicKey, PrivateKey
from .identity_key import IdentityKey
from .state import PreKeyId, SignedPreKeyId, KyberPreKeyId
from .uuid import UUID
from typing import Optional, Self
import collections.abc

class CiphertextMessage(collections.abc.ByteString):
    """
    Represents a ciphertext message in the Signal Protocol.
    CiphertextMessage is a Rust enum in the upstream crate. Mapping of enums to Python enums

    is not supported in pyo3. We map the Rust enum and its variants to Python as a superclass

    (for CiphertextMessage) and subclasses (for variants of CiphertextMessage).
    """

    def serialize(self) -> bytes:
        """
        Serializes the ciphertext message into bytes.

        Returns:
            bytes: The serialized ciphertext message.
        """
        ...

    def message_type(self) -> int:
        """
        Returns the type of the ciphertext message.

        Returns:

            int: The type of the ciphertext message.

        We're using the following mapping of libsignal_protocol::CiphertextMessageType to u8:

        - CiphertextMessageType::Whisper => 2

        - CiphertextMessageType::PreKey => 3

        - CiphertextMessageType::SenderKey => 7

        - CiphertextMessageType::Plaintext => 8
        """
        ...

class PreKeySignalMessage(CiphertextMessage):
    """
    Represents a pre-key signal message in the Signal Protocol.
    CiphertextMessageType::PreKey => 3
    """

    def __new__(
        cls,
        message_version: int,
        registration_id: int,
        pre_key_id: Optional[PreKeyId],
        signed_pre_key_id: SignedPreKeyId,
        kyber_payload: KyberPayload,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: SignalMessage,
    ) -> tuple[PreKeySignalMessage, CiphertextMessage]: ...
    @staticmethod
    def try_from(data: bytes) -> PreKeySignalMessage:
        """
        Deserializes a PreKeySignalMessage from bytes.

        Args:
            data (bytes): The bytes to deserialize from.

        Returns:
            PreKeySignalMessage: The deserialized PreKeySignalMessage object.
        """
        ...

    def serialized(self) -> bytes:
        """
        Serializes the pre-key signal message into bytes.

        Returns:
            bytes: The serialized pre-key signal message.
        """
        ...

    def message_version(self) -> int:
        """
        Returns the version of the pre-key signal message.

        Returns:
            int: The version of the pre-key signal message.
        """
        ...

    def registration_id(self) -> int:
        """
        Returns the registration ID of the pre-key signal message.

        Returns:
            int: The registration ID of the pre-key signal message.
        """
        ...

    def pre_key_id(self) -> int:
        """
        Returns the pre-key ID of the pre-key signal message.

        Returns:
            int: The pre-key ID of the pre-key signal message.
        """
        ...

    def signed_pre_key_id(self) -> int:
        """
        Returns the signed pre-key ID of the pre-key signal message.

        Returns:
            int: The signed pre-key ID of the pre-key signal message.
        """
        ...

    def base_key(self) -> PublicKey:
        """
        Returns the base key of the pre-key signal message.

        Returns:
            PublicKey: The base key of the pre-key signal message.
        """
        ...

    def identity_key(self) -> IdentityKey:
        """
        Returns the identity key of the pre-key signal message.

        Returns:
            IdentityKey: The identity key of the pre-key signal message.
        """
        ...

    def message(self) -> SignalMessage:
        """
        Returns the signal message of the pre-key signal message.

        Returns:
            SignalMessage: The signal message of the pre-key signal message.
        """
        ...

class SenderKeyDistributionMessage(CiphertextMessage):
    """
    Represents a sender key distribution message in the Signal Protocol.
    CiphertextMessageType::SenderKeyDistribution => 5
    """

    def __init__(
        self,
        message_version: int,
        distribution_id: UUID,
        chain_id: int,
        iteration: int,
        chain_key_bytes: bytes,
        signing_key: PublicKey,
    ) -> None: ...
    @staticmethod
    def try_from(data: bytes) -> SenderKeyDistributionMessage:
        """
        Deserializes a SenderKeyDistributionMessage from bytes.

        Args:
            data (bytes): The bytes to deserialize from.

        Returns:
            SenderKeyDistributionMessage: The deserialized SenderKeyDistributionMessage object.
        """
        ...

    def serialized(self) -> bytes:
        """
        Serializes the sender key distribution message into bytes.

        Returns:
            bytes: The serialized sender key distribution message.
        """
        ...

    def message_version(self) -> int:
        """
        Returns the version of the sender key distribution message.

        Returns:
            int: The version of the sender key distribution message.
        """
        ...

    def iteration(self) -> int:
        """
        Returns the iteration of the sender key distribution message.

        Returns:
            int: The iteration of the sender key distribution message.
        """
        ...

    def chain_key(self) -> bytes:
        """
        Returns the chain key of the sender key distribution message.

        Returns:
            bytes: The chain key of the sender key distribution message.
        """
        ...

    def signing_key(self) -> PublicKey:
        """
        Returns the signing key of the sender key distribution message.

        Returns:
            PublicKey: The signing key of the sender key distribution message.
        """
        ...

class SenderKeyMessage(CiphertextMessage):
    """
    Represents a sender key message in the Signal Protocol.
    CiphertextMessageType::SenderKey => 4
    """

    def __new__(
        cls,
        message_version: int,
        distribution_id: UUID,
        chain_id: int,
        iteration: int,
        ciphertext: bytes,
        signature_key: PrivateKey,
    ) -> tuple[SenderKeyMessage, CiphertextMessage]: ...
    @staticmethod
    def try_from(data: bytes) -> SenderKeyMessage:
        """
        Deserializes a SenderKeyMessage from bytes.

        Args:
            data (bytes): The bytes to deserialize from.

        Returns:
            SenderKeyMessage: The deserialized SenderKeyMessage object.
        """
        ...

    def serialized(self) -> bytes:
        """
        Serializes the sender key message into bytes.

        Returns:
            bytes: The serialized sender key message.
        """
        ...

    def message_version(self) -> int:
        """
        Returns the version of the sender key message.

        Returns:
            int: The version of the sender key message.
        """
        ...

    def distribution_id(self) -> bytes:
        """
        Returns the distribution ID of the sender key message.

        Returns:
            bytes: The distribution ID of the sender key message.
        """
        ...

    def chain_id(self) -> int:
        """
        Returns the chain ID of the sender key message.

        Returns:
            int: The chain ID of the sender key message.
        """
        ...

    def iteration(self) -> int:
        """
        Returns the iteration of the sender key message.

        Returns:
            int: The iteration of the sender key message.
        """
        ...

    def ciphertext(self) -> bytes:
        """
        Returns the ciphertext of the sender key message.

        Returns:
            bytes: The ciphertext of the sender key message.
        """
        ...

    def verify_signature(self, signature_key: PublicKey, message: bytes) -> bool:
        """
        Verifies the signature of the sender key message.

        Args:
            signature_key (PublicKey): The signature key.
            message (bytes): The message.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        ...

class SignalMessage(CiphertextMessage):
    """
    Represents a signal message in the Signal Protocol.
    CiphertextMessageType::Whisper
    """

    def __init__(
        self,
        messsage_version: int,
        mac_key: bytes,
        sender_ratchet_key: PublicKey,
        counter: int,
        previous_counter: int,
        ciphertext: bytes,
        sender_identity_key: IdentityKey,
        receiver_identity_key: IdentityKey,
    ) -> None: ...
    def __new__(cls) -> tuple[Self, CiphertextMessage]: ...
    @staticmethod
    def try_from(data: bytes) -> SignalMessage:
        """
        Deserializes a SignalMessage from bytes.

        Args:
            data (bytes): The bytes to deserialize from.

        Returns:
            SignalMessage: The deserialized SignalMessage object.
        """
        ...

    def message_version(self) -> int:
        """
        Returns the version of the signal message.

        Returns:
            int: The version of the signal message.
        """
        ...

    def sender_ratchet_key(self) -> PublicKey:
        """
        Returns the sender's ratchet key of the signal message.

        Returns:
            PublicKey: The sender's ratchet key of the signal message.
        """
        ...

    def counter(self) -> int:
        """
        Returns the counter of the signal message.

        Returns:
            int: The counter of the signal message.
        """
        ...

    def serialized(self) -> bytes:
        """
        Serializes the signal message into bytes.

        Returns:
            bytes: The serialized signal message.
        """
        ...

    def body(self) -> bytes:
        """
        Returns the body of the signal message.

        Returns:
            bytes: The body of the signal message.
        """
        ...

    def verify_mac(
        self,
        sender_identity_key: IdentityKey,
        receiver_identity_key: IdentityKey,
        mac_key: bytes,
    ) -> bool:
        """
        Verifies the MAC of the signal message.

        Args:
            sender_identity_key (IdentityKey): The sender's identity key.
            receiver_identity_key (IdentityKey): The receiver's identity key.
            mac_key (bytes): The MAC key.

        Returns:
            bool: True if the MAC is valid, False otherwise.
        """
        ...

class KyberPayload:
    def __init__(self, kyber_pre_key_id: KyberPreKeyId, ciphertext: bytes) -> None: ...

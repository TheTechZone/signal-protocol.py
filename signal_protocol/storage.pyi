from .identity_key import IdentityKeyPair, IdentityKey
from .address import ProtocolAddress
from .sender_keys import SenderKeyRecord
from .uuid import UUID
from .state import (
    SessionRecord,
    PreKeyId,
    PreKeyRecord,
    SignedPreKeyId,
    SignedPreKeyRecord,
    KyberPreKeyId,
    KyberPreKeyRecord,
)
from typing import Optional

class InMemSignalProtocolStore:
    """
    In-memory signal protocol store.
    """

    def __init__(self, key_pair: IdentityKeyPair, registration_id: int) -> None: ...
    def all_pre_key_ids(self) -> list[PreKeyId]: ...
    def all_signed_pre_key_ids(self) -> list[SignedPreKeyId]: ...
    def all_kyber_pre_key_ids(self) -> list[KyberPreKeyId]: ...
    def get_identity_key_pair(self) -> IdentityKeyPair:
        """
        Gets the identity key pair.

        Returns:
            IdentityKeyPair: The identity key pair.
        """
        ...

    def get_local_registration_id(self) -> int:
        """
        Gets the local registration ID.

        Returns:
            int: The local registration ID.
        """
        ...

    def save_identity(self, address: ProtocolAddress, identity: IdentityKey) -> bool:
        """
        Saves an identity.

        Args:
            address (ProtocolAddress): The address.
            identity (IdentityKey): The identity key.
        """
        ...

    def get_identity(self, address: ProtocolAddress) -> Optional[IdentityKey]:
        """
        Gets an identity.

        Args:
            address (ProtocolAddress): The address.

        Returns:
            IdentityKey: The identity key.
        """
        ...

    def reset_identities(self): ...
    def load_session(self, address: ProtocolAddress) -> Optional[SessionRecord]:
        """
        Loads a session.

        Args:
            address (ProtocolAddress): The address.

        Returns:
            SessionRecord: The session record.
        """
        ...

    def store_session(self, address: ProtocolAddress, record: SessionRecord) -> None:
        """
        Stores a session.

        Args:
            address (ProtocolAddress): The address.
            record (SessionRecord): The session record.
        """
        ...

    def get_pre_key(self, id: PreKeyId) -> PreKeyRecord:
        """
        Gets a pre-key.

        Args:
            pre_key_id (PreKeyId): The pre-key ID.

        Returns:
            PreKeyRecord: The pre-key record.
        """
        ...

    def save_pre_key(self, id: PreKeyId, record: PreKeyRecord) -> None:
        """
        Saves a pre-key.

        Args:
            pre_key_id (PreKeyId): The pre-key ID.
            record (PreKeyRecord): The pre-key record.
        """
        ...

    def remove_pre_key(self, id: PreKeyId) -> None:
        """
        Removes a pre-key.

        Args:
            pre_key_id (PreKeyId): The pre-key ID.
        """
        ...

    def get_signed_pre_key(self, id: SignedPreKeyId) -> SignedPreKeyRecord:
        """
        Gets a signed pre-key.

        Args:
            signed_pre_key_id (SignedPreKeyId): The signed pre-key ID.

        Returns:
            SignedPreKeyRecord: The signed pre-key record.
        """
        ...

    def save_signed_pre_key(
        self, id: SignedPreKeyId, record: SignedPreKeyRecord
    ) -> None:
        """
        Saves a signed pre-key.

        Args:
            signed_pre_key_id (SignedPreKeyId): The signed pre-key ID.
            record (SignedPreKeyRecord): The signed pre-key record.
        """
        ...

    def store_sender_key(
        self, sender: ProtocolAddress, distribution_id: UUID, record: SenderKeyRecord
    ) -> None:
        """
        Stores a sender key.

        Args:
            sender_key_name (SenderKeyName): The sender key name.
            record (SenderKeyRecord): The sender key record.
        """
        ...

    def load_sender_key(
        self, sender: ProtocolAddress, distribution_id: UUID
    ) -> SenderKeyRecord:
        """
        Loads a sender key.

        Args:
            sender_key_name (SenderKeyName): The sender key name.

        Returns:
            SenderKeyRecord: The sender key record.
        """
        ...

    def get_kyber_pre_key(self, kyber_pre_key_id: KyberPreKeyId) -> KyberPreKeyRecord:
        """
        Gets a Kyber pre-key.

        Args:
            kyber_pre_key_id (KyberPreKeyId): The Kyber pre-key ID.

        Returns:
            KyberPreKeyRecord: The Kyber pre-key record.
        """
        ...

    def save_kyber_pre_key(
        self, kyber_pre_key_id: KyberPreKeyId, record: KyberPreKeyRecord
    ): ...
    def mark_kyber_pre_key_used(self, kyber_pre_key_id: KyberPreKeyId): ...

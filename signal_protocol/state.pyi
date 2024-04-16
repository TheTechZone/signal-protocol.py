from curve import PublicKey, PrivateKey, KeyPair
from address import DeviceId
from identity_key import IdentityKey

class PreKeyBundle:
    """Represents a pre-key bundle used in the X3DH key agreement protocol."""

    def registration_id(self) -> int:
        """Returns the registration ID."""
        ...

    def device_id(self) -> DeviceId:
        """Returns the device ID."""
        ...

    def pre_key_id(self) -> PreKeyId:
        """Returns the pre-key ID."""
        ...

    def pre_key_public(self) -> PublicKey:
        """Returns the pre-key public key."""
        ...

    def signed_pre_key_id(self) -> SignedPreKeyId:
        """Returns the signed pre-key ID."""
        ...

    def signed_pre_key_public(self) -> PublicKey:
        """Returns the signed pre-key public key."""
        ...

    def signed_pre_key_signature(self) -> bytes:
        """Returns the signed pre-key signature."""
        ...

    def identity_key(self) -> IdentityKey:
        """Returns the identity key."""
        ...


class PreKeyId:
    """Represents a pre-key ID."""
    ...


class PreKeyRecord:
    """Represents a pre-key record."""

    @staticmethod
    def deserialize(data: bytes) -> PreKeyRecord:
        """Deserializes a pre-key record from bytes."""
        ...

    def id(self) -> PreKeyId:
        """Returns the pre-key ID."""
        ...

    def key_pair(self) -> KeyPair:
        """Returns the pre-key key pair."""
        ...

    def public_key(self) -> PublicKey:
        """Returns the pre-key public key."""
        ...

    def private_key(self) -> PrivateKey:
        """Returns the pre-key private key."""
        ...

    def serialize(self) -> bytes:
        """Serializes the pre-key record into bytes."""
        ...


class SessionRecord:
    """Represents a session record."""

    @staticmethod
    def new_fresh() -> SessionRecord:
        """Creates a new fresh session record."""
        ...

    @staticmethod
    def deserialize(data: bytes) -> SessionRecord:
        """Deserializes a session record from bytes."""
        ...

    def archive_current_state(self):
        """Archives the current session state."""
        ...

    def serialize(self) -> bytes:
        """Serializes the session record into bytes."""
        ...

    def session_version(self) -> int:
        """Returns the session version."""
        ...

    def remote_registration_id(self) -> int:
        """Returns the remote registration ID."""
        ...

    def local_registration_id(self) -> int:
        """Returns the local registration ID."""
        ...

    def local_identity_key_bytes(self) -> bytes:
        """Returns the local identity key in bytes."""
        ...

    def remote_identity_key_bytes(self) -> bytes:
        """Returns the remote identity key in bytes."""
        ...

    def get_receiver_chain_key_bytes(self) -> bytes:
        """Returns the receiver chain key in bytes."""
        ...

    def has_usable_sender_chain(self) -> bool:
        """Checks if there is a usable sender chain."""
        ...

    def alice_base_key(self) -> bytes:
        """Returns Alice's base key."""
        ...

    def get_sender_chain_key_bytes(self) -> bytes:
        """Returns the sender chain key in bytes."""
        ...


class SignedPreKeyId:
    """Represents a signed pre-key ID."""
    ...

class SignedPreKeyRecord:
    """Represents a signed pre-key record."""

    @staticmethod
    def deserialize(data: bytes) -> SignedPreKeyRecord:
        """Deserializes a signed pre-key record from bytes."""
        ...

    def id(self) -> int:
        """Returns the signed pre-key ID."""
        ...

    def timestamp(self) -> int:
        """Returns the timestamp."""
        ...

    def signature(self) -> bytes:
        """Returns the signature."""
        ...

    def key_pair(self) -> KeyPair:
        """Returns the key pair."""
        ...

    def public_key(self) -> PublicKey:
        """Returns the public key."""
        ...

    def private_key(self) -> PrivateKey:
        """Returns the private key."""
        ...

    def serialize(self) -> bytes:
        """Serializes the signed pre-key record into bytes."""
        ...

def generate_n_prekeys(n: int) -> list[PreKeyRecord]:
    """Generates n pre-keys."""
    ...

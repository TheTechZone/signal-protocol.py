from .curve import PublicKey, PrivateKey

class IdentityKey:
    """Represents an identity key in the Signal Protocol."""

    def __init__(self, public_key_bytes: bytes) -> None: ...
    def public_key(self) -> PublicKey:
        """
        Returns the public key of the identity key.

        Returns:
            PublicKey: The public key of the identity key.
        """
        ...

    def serialize(self) -> bytes:
        """
        Serializes the identity key into bytes.

        Returns:
            bytes: The serialized identity key.
        """
        ...

    def to_base64(self) -> str:
        """Serializes the public key into base64 encoded bytes."""
        ...

    @staticmethod
    def from_base64(input: bytes) -> IdentityKey:
        """Deserializes the public key from base64 encoded bytes."""
        ...

    def verify_alternate_identity(self, other: IdentityKey, signature: bytes) -> bool:
        """Given a trusted identity `self`, verify that `other` represents an alternate identity for
        this user.

        `signature` must be calculated from `IdentityKeyPair::sign_alternate_identity`.
        """

class IdentityKeyPair:
    """Represents an identity key pair in the Signal Protocol."""

    def __init__(self, identity_key: IdentityKey, private_key: PrivateKey) -> None:
        """
        Creates a new IdentityKeyPair.

        Args:
            identity_key (IdentityKey): The identity key.
            private_key (PrivateKey): The private key.

        Returns:
            IdentityKeyPair: The created IdentityKeyPair object.
        """
        ...

    @staticmethod
    def from_bytes(identity_key_pair_bytes: bytes) -> IdentityKeyPair:
        """
        Deserializes an IdentityKeyPair from bytes.

        Args:
            identity_key_pair_bytes (bytes): The bytes to deserialize from.

        Returns:
            IdentityKeyPair: The deserialized IdentityKeyPair object.
        """
        ...

    @staticmethod
    def generate() -> IdentityKeyPair:
        """
        Generates a new IdentityKeyPair.

        Returns:
            IdentityKeyPair: The generated IdentityKeyPair object.
        """
        ...

    def to_base64(self) -> str:
        """Serializes the public key into base64 encoded bytes."""
        ...

    @staticmethod
    def from_base64(input: bytes) -> IdentityKeyPair:
        """Deserializes the public key from base64 encoded bytes."""
        ...

    def identity_key(self) -> IdentityKey:
        """
        Returns the identity key of the identity key pair.

        Returns:
            IdentityKey: The identity key of the identity key pair.
        """
        ...

    def public_key(self) -> PublicKey:
        """
        Returns the public key of the identity key pair.

        Returns:
            PublicKey: The public key of the identity key pair.
        """
        ...

    def private_key(self) -> PrivateKey:
        """
        Returns the private key of the identity key pair.

        Returns:
            PrivateKey: The private key of the identity key pair.
        """
        ...

    def serialize(self) -> bytes:
        """
        Serializes the identity key pair into bytes.

        Returns:
            bytes: The serialized identity key pair.
        """
        ...

    def sign_alternate_identity(self, other: IdentityKey) -> bytes:
        """Generate a signature claiming that `other` represents the same user as `self`."""
        ...

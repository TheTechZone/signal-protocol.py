class KeyPair:
    """Represents a pair of private and public keys."""

    def generate(self):
        """Generates a new key pair."""
        ...

    def public_key(self) -> PublicKey:
        """Returns the public key from the key pair."""
        ...

    def private_key(self) -> PrivateKey:
        """Returns the private key from the key pair."""
        ...

    def serialize(self) -> bytes:
        """Serializes the key pair into bytes."""
        ...

    def calculate_signature(self, message: bytes) -> bytes:
        """Calculates the signature for a given message using the private key."""
        ...

    def calculate_agreement(self, other_public_key: PublicKey) -> bytes:
        """Calculates the shared secret using the other party's public key."""
        ...

    @staticmethod
    def from_public_and_private(public_key: bytes, private_key: bytes) -> KeyPair:
        """Creates a key pair from a given public and private key."""
        ...

class PrivateKey:
    """Represents a private key."""

    @staticmethod
    def deserialize(key: bytes) -> PrivateKey:
        """Deserializes a private key from bytes."""
        ...

    def serialize(self) -> bytes:
        """Serializes the private key into bytes."""
        ...

    def calculate_signature(self, message: bytes) -> bytes:
        """Calculates the signature for a given message."""
        ...

    def calculate_agreement(self, their_key: PublicKey) -> bytes:
        """Calculates the shared secret using the other party's public key."""
        ...

    def public_key(self) -> PublicKey:
        """Returns the corresponding public key."""
        ...

class PublicKey:
    """Represents a public key."""

    @staticmethod
    def deserialize(data: bytes) -> PublicKey:
        """Deserializes a public key from bytes."""
        ...

    def serialize(self) -> bytes:
        """Serializes the public key into bytes."""
        ...

    def verify_signature(self, message: bytes, signature: bytes) -> bool:
        """Verifies the signature for a given message."""
        ...

def generate_keypair() -> KeyPair:
    """Generates a new key pair."""
    ...

def verify_signature(public_key: PublicKey, message: bytes, signature: bytes) -> bool:
    """Verifies the signature for a given message using the provided public key."""
    ...

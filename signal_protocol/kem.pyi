class KeyPair:
    ...

    @staticmethod
    def generate(key_type: KeyType) -> KeyPair:
        ...

    @staticmethod
    def from_public_and_private(public_key: bytes, secret_key: bytes) -> KeyPair:
        ...

    def public_key_length(self) -> int:
        ...

    def secret_key_length(self) -> int:
        ...

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Create a `SharedSecret` and a `Ciphertext`. The `Ciphertext` can be safely sent to the

        holder of the corresponding `SecretKey` who can then use it to `decapsulate` the same

        `SharedSecret`.
        """
        ...

    def decapsulate(self, ct_bytes: bytes) -> bytes:
        """
        Decapsulates a `SharedSecret` that was encapsulated into a `Ciphertext` by a holder of

        the corresponding `PublicKey`.
        """
        ...

    def get_public(self) -> PublicKey:
        ...

    def get_private(self) -> SecretKey:
        ...

class KeyType:
    ...

    def value(self) -> int:
        ...

class PublicKey:
    ...

    def serialize(self) -> bytes:
        ...

    @staticmethod
    def deserialize(key: bytes) -> PublicKey:
        ...

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Create a `SharedSecret` and a `Ciphertext`. The `Ciphertext` can be safely sent to the

        holder of the corresponding `SecretKey` who can then use it to `decapsulate` the same

        `SharedSecret`.
        """
        ...

class SecretKey:
    ...

    def serialize(self) -> bytes:
        ...

    @staticmethod
    def deserialize(key: bytes) -> PublicKey:
        ...

    def decapsulate(self, ct_bytes: bytes) -> bytes:
        """
        Decapsulates a `SharedSecret` that was encapsulated into a `Ciphertext` by a holder of

        the corresponding `PublicKey`.
        """
        ...

class SerializedCiphertext:
    """
    Represents a Kyber serialized ciphertext. The first byte is a KeyType prefix
    """
    ...

    def raw(self):
        """
        Get the raw Kyber ciphertext bytes, without the KeyType prefix.
        """
        ...
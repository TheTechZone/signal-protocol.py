from .identity_key import IdentityKey

class Fingerprint:
    """Represents a fingerprint of a Signal Protocol conversation."""

    def __init__(
        self,
        version: int,
        iterations: int,
        local_id: bytes,
        local_key: IdentityKey,
        remote_id: bytes,
        remote_key: IdentityKey,
    ) -> None:
        """
        Creates a new Fingerprint.

        Args:
            version (int): The version of the fingerprint.
            iterations (int): The number of iterations used in the generation of the fingerprint.
            local_id (bytes): The local identifier.
            local_key (IdentityKey): The local identity key.
            remote_id (bytes): The remote identifier.
            remote_key (IdentityKey): The remote identity key.

        Returns:
            Fingerprint: The created Fingerprint object.
        """
        ...

    def display_string(self) -> str:
        """
        Returns the display string of the fingerprint.

        Returns:
            str: The display string of the fingerprint.
        """
        ...

    def compare(self, combined: bytes) -> bool:
        """
        Compares the fingerprint with another one.

        Args:
            combined (bytes): The combined fingerprint to compare with.

        Returns:
            bool: True if the fingerprints match, False otherwise.
        """
        ...

    def serialize(self) -> bytes:
        """
        Serializes the fingerprint into bytes.

        Returns:
            bytes: The serialized fingerprint.
        """
        ...

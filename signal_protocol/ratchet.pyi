from .curve import KeyPair, PublicKey
from .kem import PublicKey as KemPublicKey, KeyPair as KemKeyPair
from .identity_key import IdentityKey, IdentityKeyPair
from typing import Optional, Any
from .state import SessionRecord

class AliceSignalProtocolParameters:
    """
    This class represents the protocol parameters for Alice in the Signal Protocol.
    """

    def __init__(
        self,
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        _their_one_time_pre_key: Optional[PublicKey],
        their_ratchet_key: PublicKey,
        _their_kyber_pre_key: KemPublicKey,
    ) -> None:
        """TODO: revise when their_otpk is used"""
        ...

    def our_identity_key_pair(self) -> KeyPair:
        """
        Returns Alice's identity key pair.

        Returns:
            KeyPair: Alice's identity key pair.
        """
        ...

    def our_base_key_pair(self) -> KeyPair:
        """
        Returns Alice's base key pair.

        Returns:
            KeyPair: Alice's base key pair.
        """
        ...

    def their_identity_key(self) -> IdentityKey:
        """
        Returns the other party's identity key.

        Returns:
            IdentityKey: The other party's identity key.
        """
        ...

    def their_signed_pre_key(self) -> PublicKey:
        """
        Returns the other party's signed pre-key.

        Returns:
            SignedPreKey: The other party's signed pre-key.
        """
        ...

    def their_one_time_pre_key(self) -> Optional[PublicKey]:
        """
        Returns the other party's one-time pre-key.

        Returns:
            Optional[OneTimePreKey]: The other party's one-time pre-key, if it exists.
        """
        ...

    def their_ratchet_key(self) -> PublicKey:
        """
        Returns the other party's ratchet key.

        Returns:
            RatchetKey: The other party's ratchet key.
        """
        ...

    def their_kyber_pre_key(self) -> Optional[KemPublicKey]: ...

class BobSignalProtocolParameters:
    """
    This class represents the protocol parameters for Bob in the Signal Protocol.
    """

    def __init__(
        self,
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Optional[KeyPair],
        our_ratchet_key_pair: KeyPair,
        our_kyber_pre_key_pair: Optional[Any],
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
        their_kyber_ciphertext: Optional[Any],
    ) -> None:
        """TODO: adapt when done"""
        ...

    def our_identity_key_pair(self) -> KeyPair:
        """
        Returns Bob's identity key pair.

        Returns:
            KeyPair: Bob's identity key pair.
        """
        ...

    def our_signed_pre_key_pair(self) -> KeyPair:
        """
        Returns Bob's signed pre-key pair.

        Returns:
            KeyPair: Bob's signed pre-key pair.
        """
        ...

    def our_one_time_pre_key_pair(self) -> Optional[KeyPair]:
        """
        Returns Bob's one-time pre-key pair.

        Returns:
            Optional[KeyPair]: Bob's one-time pre-key pair, if it exists.
        """
        ...

    def our_ratchet_key_pair(self) -> KeyPair:
        """
        Returns Bob's ratchet key pair.

        Returns:
            KeyPair: Bob's ratchet key pair.
        """
        ...

    def our_kyber_pre_key_pair(self) -> Optional[KemKeyPair]: ...
    def their_identity_key(self) -> IdentityKey:
        """
        Returns the other party's identity key.

        Returns:
            IdentityKey: The other party's identity key.
        """
        ...

    def their_base_key(self) -> PublicKey:
        """
        Returns the other party's base key.

        Returns:
            BaseKey: The other party's base key.
        """
        ...

    def their_kyber_ciphertext(self) -> Optional[bytes]: ...

def initialize_alice_session() -> SessionRecord:
    """
    Initializes a new session for Alice.

    Returns:
        Session: The new session for Alice.
    """
    ...

def initialize_bob_session() -> SessionRecord:
    """
    Initializes a new session for Bob.

    Returns:
        Session: The new session for Bob.
    """
    ...

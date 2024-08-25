from typing import Optional
from .identity_key import IdentityKeyPair
from .curve import KeyPair
from .kem import KeyPair as KyberKeyPair
from .state import SignedPreKeyRecord, KyberPreKeyRecord

def create_keys_data(
    num_keys: int,
    identity_key: IdentityKeyPair,
    signed_prekey: Optional[KeyPair] = None,
    last_resort_kyber: Optional[KyberKeyPair] = None,
    prekey_start_at: Optional[int] = None,
    kyber_prekey_start_at: Optional[int] = None,
) -> tuple[dict, dict]:
    """create_keys_data generates the specified number of one-time keys (PreKeys) for the client to

    upload to the server, and returns them as a tuple of dictionaries along with the secrets.

    This function is associated with the endpoint /v2/keys/.
    """
    ...

def create_registration(
    aci_identity_key: IdentityKeyPair,
    pni_identity_key: IdentityKeyPair,
    aci_spk: Optional[SignedPreKeyRecord] = None,
    pni_spk: Optional[SignedPreKeyRecord] = None,
    aci_kyber: Optional[KyberPreKeyRecord] = None,
    pni_kyber: Optional[KyberPreKeyRecord] = None,
    aci_spk_id: Optional[int] = None,
    pni_spk_id: Optional[int] = None,
    aci_kyber_id: Optional[int] = None,
    pni_kyber_id: Optional[int] = None,
) -> tuple[dict, dict]:
    """
    create_registration bundles the registration keys and secrets for aci and pni

    produced by create_registration_keys into a single dictionary for each.

    The keys are returned as a dictionary with the following keys:

    - aciIdentityKey

    - aciSignedPreKey

    - aciPqLastResortPreKey

    - pniIdentityKey

    - pniSignedPreKey

    - pniPqLastResortPreKey
    """
    ...

def create_registration_keys(
    key_type: str,
    identity_key: IdentityKeyPair,
    spk_record: Optional[SignedPreKeyRecord] = None,
    kyber_record: Optional[KyberPreKeyRecord] = None,
    spk_id: Optional[int] = None,
    kyber_id: Optional[int] = None,
) -> tuple[dict, dict]:
    """create_registration_keys creates the necessary keys for
    the registration endpoint (specifically signedPreKey and PqLastResortPreKey)
    and returns them as a tuple of dictionaries along with the identity key (keys, secrets).
    The keys are returned as a dictionary with the following keys:
    - IdentityKey
    - SignedPreKey
    - PqLastResortPreKey
    """
    ...

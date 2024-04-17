from pathlib import Path
from dataclasses import dataclass
from signal_protocol import kem

@dataclass
class KYBER_PARAMS:
    PK_LENGTH: int
    SK_LENGTH: int
    CTXT_LENGTH: int
    SHARED_SECRET_LENGTH: int

# https://openquantumsafe.org/liboqs/algorithms/kem/kyber.html#parameter-set-summary
KYBER1024_PARAMS = KYBER_PARAMS(PK_LENGTH=1568, SK_LENGTH=3168, CTXT_LENGTH=1568, SHARED_SECRET_LENGTH=32)
KEY_TYPE = kem.KeyType(0)


def test_sanity():
    keypair = kem.KeyPair.generate(KEY_TYPE)
    pub, priv = keypair.get_public(), keypair.get_private()

    len_pub, len_priv = len(pub.serialize()), len(priv.serialize())
    assert len_pub == keypair.public_key_length(), "Key does not have the reported size."
    assert len_priv == keypair.secret_key_length(), "Key does not have the reported size."
    assert len_pub == KYBER1024_PARAMS.PK_LENGTH + 1, "Key does not have the reported size."
    assert len_priv == KYBER1024_PARAMS.SK_LENGTH + 1, "Key does not have the reported size."

    ss, ctxt = keypair.encapsulate()
    assert len(ss) == KYBER1024_PARAMS.SHARED_SECRET_LENGTH, "Shared Secret: bad length."
    assert len(ctxt) == KYBER1024_PARAMS.CTXT_LENGTH + 1, "Ciphertext: bad length."

    # todo: might make more sense to expose kp.get_private().decapsulate(ctxt)
    ss2 = keypair.decapsulate(ctxt)
    assert ss == ss2, "Decapsulation failed"

def test_serialize():
    test_data_dir = Path("./data").resolve()
    pk_bytes = b"\x08" + (test_data_dir / "pk.dat").read_bytes()
    sk_bytes = b"\x08" + (test_data_dir / "sk.dat").read_bytes()
    
    assert len(pk_bytes) == KYBER1024_PARAMS.PK_LENGTH + 1
    assert len(sk_bytes) == KYBER1024_PARAMS.SK_LENGTH + 1

    kp = kem.KeyPair.from_public_and_private(pk_bytes, sk_bytes)

    serialized_pk, serialized_sk = kp.get_public().serialize(), kp.get_private().serialize()
    assert serialized_pk == pk_bytes
    assert serialized_sk == sk_bytes

    pk, sk = kem.PublicKey.deserialize(serialized_pk), kem.SecretKey.deserialize(serialized_sk)
    reserialized_pk, reserialized_sk = pk.serialize(), sk.serialize()

    assert serialized_pk == reserialized_pk
    assert serialized_sk == reserialized_sk

def test_kyber_1024():
    test_data_dir = Path("./data").resolve()
    pk_bytes = b"\x08" + (test_data_dir / "pk.dat").read_bytes()
    sk_bytes = b"\x08" + (test_data_dir / "sk.dat").read_bytes()
    
    assert len(pk_bytes) == KYBER1024_PARAMS.PK_LENGTH + 1
    assert len(sk_bytes) == KYBER1024_PARAMS.SK_LENGTH + 1

    kp = kem.KeyPair.from_public_and_private(pk_bytes, sk_bytes)
    # todo: might make more sense to expose kp.get_public().decapsulate(ctxt)
    ss_for_sender, ct = kp.encapsulate()
    ss_for_recipient = kp.decapsulate(ct)
    assert ss_for_sender == ss_for_recipient, "The two parties don't share the same secret"
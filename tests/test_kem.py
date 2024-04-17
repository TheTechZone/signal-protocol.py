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

import hmac
import hashlib
import base64
from signal_protocol.account_keys import PinHash, local_pin_hash, verify_local_pin_hash


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


AUTH_BYTES = b"auth"  # Define AUTH_BYTES and ENC_BYTES as per your requirements
ENC_BYTES = b"enc"


def encrypt_hmac_sha256_siv(k: bytes, m: bytes) -> tuple[bytes, bytes]:
    k_a = hmac_sha256(k, AUTH_BYTES)
    k_e = hmac_sha256(k, ENC_BYTES)
    iv = hmac_sha256(k_a, m)[:16]  # Python slicing is used instead of try_into
    k_x = hmac_sha256(k_e, iv)
    c = bytes(
        a ^ b for a, b in zip(k_x, m)
    )  # Python's zip and list comprehension for XOR
    return iv, c  # Return as a tuple instead of a struct


def compare_known_hash(
    pin: bytes,
    salt: bytes,
    master_key: bytes,
    expected_access_key: bytes,
    expected_encrypted: bytes,
):
    pin = PinHash.create(pin, salt)
    assert pin.access_key() == expected_access_key, "Access Key mismatch"

    iv, c = encrypt_hmac_sha256_siv(pin.encryption_key(), master_key)
    assert iv + c == expected_encrypted, "Encrypion mismatch"


def test_known_hash():
    compare_known_hash(
        b"password",
        bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ),
        bytes.fromhex(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ),
        bytes.fromhex(
            "ab7e8499d21f80a6600b3b9ee349ac6d72c07e3359fe885a934ba7aa844429f8"
        ),
        bytes.fromhex(
            "3f33ce58eb25b40436592a30eae2a8fabab1899095f4e2fba6e2d0dc43b4a2d9cac5a3931748522393951e0e54dec769"
        ),
    )


def test_known_hash2():
    compare_known_hash(
        b"anotherpassword",
        bytes.fromhex(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ),
        bytes.fromhex(
            "88a787415a2ecd79da0d1016a82a27c5c695c9a19b88b0aa1d35683280aa9a67"
        ),
        bytes.fromhex(
            "301d9dd1e96f20ce51083f67d3298fd37b97525de8324d5e12ed2d407d3d927b"
        ),
        bytes.fromhex(
            "9d9b05402ea39c17ff1c9298c8a0e86784a352aa02a74943bf8bcf07ec0f4b574a5b786ad0182c8d308d9eb06538b8c9"
        ),
    )


def test_known_phc_string():
    pin = b"apassword"
    phc_string = "$argon2i$v=19$m=512,t=64,p=1$ICEiIyQlJicoKSorLC0uLw$NeZzhiNv4cRmRMct9scf7d838bzmHJvrZtU/0BH0v/U"
    # can't set custom hash sadly
    # salt = base64.b64encode(bytes.fromhex("202122232425262728292A2B2C2D2E2F"))

    # actual = local_pin_hash_with_salt(pin, salt)
    # assert phc_string == actual, "Local pin mismatch"

    assert verify_local_pin_hash(phc_string, pin)
    assert not verify_local_pin_hash(phc_string, b"wrongpin")


def test_verify():
    pin = b"hunter2"
    phc_string = local_pin_hash(pin)

    assert verify_local_pin_hash(phc_string, pin)
    assert not verify_local_pin_hash(phc_string, b"wrongpin")


def test_known_salt():
    username = "username"
    group_id = 3862621253427332054

    assert PinHash.make_salt(username, group_id) == bytes.fromhex(
        "d6159ba30f90b6eb6ccf1ec844427f052baaf0705da849767471744cdb3f8a5e"
    )

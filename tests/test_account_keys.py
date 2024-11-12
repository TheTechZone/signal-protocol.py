from string import ascii_lowercase, digits
import binascii

from signal_protocol.account_keys import AccountEntropyPool, BackupId, BackupKey


def test_account_pool():
    chars = set(ascii_lowercase + digits)
    pool = AccountEntropyPool.generate()

    # Test that only allowed characters are used
    assert set(str(pool)).issubset(
        chars
    ), f"only {chars} characters are allowed, found {set(str(pool)).difference(chars)}"

    # Test uniqueness
    pools = {AccountEntropyPool.generate() for _ in range(1000)}
    assert len(pools) == 1000


FAKE_MASTER_KEY = binascii.unhexlify(
    "6c25a28f50f61f7ab94958cffc64164d897dab61457cceb0bb6126ca54c38cc4"
)
FAKE_ACI = binascii.unhexlify("659aa5f4a28dfcc11ea1b997537a3d95")


def test_backup_key_known():
    backup_key = BackupKey.derive_from_master_key(FAKE_MASTER_KEY)
    expected_key_bytes = binascii.unhexlify(
        "7cc5ad13a6d43ec374ae95d83dcfb86c9314d449dc926a036b38bb55fe236142"
    )
    assert (
        backup_key.serialize() == BackupKey(expected_key_bytes).serialize()
    ), f"got {backup_key}"


def test_backup_id_known():
    backup_key = BackupKey.derive_from_master_key(FAKE_MASTER_KEY)
    id = backup_key.derive_backup_id(FAKE_ACI)
    expected_id_bytes = binascii.unhexlify("5ccec70e2a141866baecd5e271413b02")
    assert id.serialize() == BackupId(expected_id_bytes).serialize(), f"got {id}"

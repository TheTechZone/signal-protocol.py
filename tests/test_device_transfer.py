from signal_protocol.device_transfer import (
    create_rsa_private_key,
    create_self_signed_cert,
)


def test_generate_and_parse():
    key = create_rsa_private_key()
    days_to_expire = 10
    cert = create_self_signed_cert(key, "test", days_to_expire)

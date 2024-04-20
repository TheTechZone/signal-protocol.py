from typing import Optional

def create_rsa_private_key(bits: Optional[int], key_format: Optional[int]):
    """
    Generate a private key of size `bits` and export to a specified format.



    Arguments:

        bits - the bitlength of the key (optional: defaults to 4096)

        key_format - key format (optional: defaults to )
    """
    ...

def create_self_signed_cert(rsa_key_pkcs8: bytes, name: str, days_to_expire: int):
    """
    Generate a self-signed certificate of name `name`, expiring in `days_to_expire`.



    `rsa_key_pkcs8` should be the output of `create_rsa_private_key`.
    """
    ...

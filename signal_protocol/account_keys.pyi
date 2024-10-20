class PinHash:
    """This library provides two pin hashing mechanisms:
      1. Transforming a pin to be suitable for use with a Secure Value Recovery service. The pin
         is hashed with Argon2 into 64 bytes. One half of these bytes are provided to the service
         as a password protecting some arbitrary data. The other half is used as an encryption key
         for that data. See `PinHash`
      2. Creating a [PHC-string encoded](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification)
         password hash of the pin that can be stored locally and validated against the pin later.

    In either case, all pins are UTF-8 encoded bytes that must be normalized *before* being provided
    to this library. Normalizing a string pin requires the following steps:
     1. The string should be trimmed for leading and trailing whitespace.
     2. If the whole string consists of digits, then non-arabic digits must be replaced with their
        arabic 0-9 equivalents.
     3. The string must then be [NFKD normalized](https://unicode.org/reports/tr15/#Norm_Forms)
    """

    @staticmethod
    def create(pin: bytes, salt: bytes) -> PinHash:
        """Hash an arbitrary pin into an encryption key and access key that can be used to interact
        with a Secure Value Recovery service.

        # Arguments
        * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first.
        * `salt` - An arbitrary 32 byte value that should be unique to the user"""

    @staticmethod
    def make_salt(username: str, group_id: int):
        """Create a salt from a username and the group id of the SVR service. This
        function should always be used to create pin salts for SVR2.

        # Arguments
        * `username` - The Basic Auth username credential retrieved from the chat service and used to authenticate with the SVR service
        * `group_id` - The attested group id returned by the SVR service"""

    def encryption_key(self) -> bytes:
        """Returns a key that can be used to encrypt or decrypt values before uploading
        them to a secure store.
        The 32 byte prefix of the 64 byte hashed pin."""

    def access_key(self) -> bytes:
        """Returns a secret that can be used to access a value in a secure store. The 32 byte suffix of
        the 64 byte hashed pin."""

def local_pin_hash(pin: bytes) -> bytes:
    """Create a PHC encoded password hash string. This string may be verified later with
    `verify_local_pin_hash`.

    # Arguments
    * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first."""

def verify_local_pin_hash(encoded_hash: str, pin) -> bool:
    """Verify an encoded password hash against a pin

    # Arguments
    * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first.
    * `encoded_hash` - A PHC-string formatted representation of the hash, as returned by `local_pin_hash`
    """

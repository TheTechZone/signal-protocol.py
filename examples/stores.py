import logging
from signal_protocol import identity_key, storage

FORMAT = "%(levelname)s %(name)s %(asctime)-15s %(filename)s:%(lineno)d %(message)s"
logging.basicConfig(format=FORMAT)
logging.getLogger().setLevel(logging.INFO)


alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
bob_identity_key_pair = identity_key.IdentityKeyPair.generate()

alice_registration_id = 1  # TODO: generate these
bob_registration_id = 2

alice_store = storage.InMemSignalProtocolStore(
    alice_identity_key_pair, alice_registration_id
)
bob_store = storage.InMemSignalProtocolStore(bob_identity_key_pair, bob_registration_id)

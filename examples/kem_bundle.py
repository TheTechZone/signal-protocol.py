from signal_protocol import curve, address, identity_key, state, storage, kem

alice_identity_key_pair = identity_key.IdentityKeyPair.generate()
alice_registration_id = 1

alice_store = storage.InMemSignalProtocolStore(
    alice_identity_key_pair, alice_registration_id
)

alice_signed_pre_key_pair = curve.KeyPair.generate()
alice_signed_pre_key_signature = (
    alice_store.get_identity_key_pair()
    .private_key()
    .calculate_signature(alice_signed_pre_key_pair.public_key().serialize())
)

signed_pre_key_id = state.SignedPreKeyId(22)
alice_pre_key_bundle = state.PreKeyBundle(
    alice_store.get_local_registration_id(),
    address.DeviceId(1),
    None,
    signed_pre_key_id,
    alice_signed_pre_key_pair.public_key(),
    alice_signed_pre_key_signature,
    alice_store.get_identity_key_pair().identity_key(),
)

print(alice_pre_key_bundle.has_kyber_pre_key())

# BUNDLE W/O KEM
kyber_pre_key_id = state.KyberPreKeyId(22)
kyber_pre_key_pair = kem.KeyPair.generate(kem.KeyType(0))
# print(kyber_pre_key_pair.get_public().serialize().hex())

kyber_pre_key_signature = alice_identity_key_pair.private_key().calculate_signature(
    kyber_pre_key_pair.get_public().serialize()
)

alice_pre_key_bundle = alice_pre_key_bundle.with_kyber_pre_key(
    kyber_pre_key_id, kyber_pre_key_pair.get_public(), kyber_pre_key_signature
)
print(alice_pre_key_bundle.has_kyber_pre_key())

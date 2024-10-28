use pyo3::prelude::*;

mod account_keys;
mod address;
mod base_crypto;
mod curve;
mod device_transfer;
mod error;
mod fingerprint;
mod group_cipher;
mod helpers;
mod identity_key;
mod kem;
mod key_transparency;
mod net;
mod protocol;
mod ratchet;
mod sealed_sender;
mod sender_keys;
mod session;
mod session_cipher;
mod state;
mod storage;
mod uuid;

/// Signal Protocol in Python
///
/// This Rust extension provides Python bindings for the Rust crate
/// libsignal-protocol-rust.
///
/// Basic usage:
///
/// >>> pub, priv = signal_protocol.curve.generate_keypair()
///
/// We do not expose a Python submodule for HKDF (a module in the upstream crate).
#[pymodule]
fn signal_protocol(py: Python, module: &Bound<'_, PyModule>) -> PyResult<()> {
    // A good place to install the Rust -> Python logger.
    pyo3_log::init();

    let account_keys = PyModule::new_bound(py, "account_keys")?;
    account_keys::init_submodule(&account_keys)?;
    module.add_submodule(&account_keys)?;

    let address_submod = PyModule::new_bound(py, "address")?;
    address::init_submodule(&address_submod)?;
    module.add_submodule(&address_submod)?;

    let curve_submod = PyModule::new_bound(py, "curve")?;
    curve::init_submodule(&curve_submod)?;
    module.add_submodule(&curve_submod)?;

    let error_submod = PyModule::new_bound(py, "error")?;
    error::init_submodule(py, &error_submod)?;
    module.add_submodule(&error_submod)?;

    let fingerprint_submod = PyModule::new_bound(py, "fingerprint")?;
    fingerprint::init_submodule(&fingerprint_submod)?;
    module.add_submodule(&fingerprint_submod)?;

    let group_cipher_submod = PyModule::new_bound(py, "group_cipher")?;
    group_cipher::init_submodule(&group_cipher_submod)?;
    module.add_submodule(&group_cipher_submod)?;

    let identity_key_submod = PyModule::new_bound(py, "identity_key")?;
    identity_key::init_submodule(&identity_key_submod)?;
    module.add_submodule(&identity_key_submod)?;

    let kem_submod = PyModule::new_bound(py, "kem")?;
    kem::init_kem_submodule(&kem_submod)?;
    module.add_submodule(&kem_submod)?;

    let protocol_submod = PyModule::new_bound(py, "protocol")?;
    protocol::init_submodule(&protocol_submod)?;
    module.add_submodule(&protocol_submod)?;

    let ratchet_submod = PyModule::new_bound(py, "ratchet")?;
    ratchet::init_submodule(&ratchet_submod)?;
    module.add_submodule(&ratchet_submod)?;

    let sealed_sender_submod = PyModule::new_bound(py, "sealed_sender")?;
    sealed_sender::init_submodule(&sealed_sender_submod)?;
    module.add_submodule(&sealed_sender_submod)?;

    let sender_keys_submod = PyModule::new_bound(py, "sender_keys")?;
    sender_keys::init_submodule(&sender_keys_submod)?;
    module.add_submodule(&sender_keys_submod)?;

    let session_cipher_submod = PyModule::new_bound(py, "session_cipher")?;
    session_cipher::init_submodule(&session_cipher_submod)?;
    module.add_submodule(&session_cipher_submod)?;

    let session_submod = PyModule::new_bound(py, "session")?;
    session::init_submodule(&session_submod)?;
    module.add_submodule(&session_submod)?;

    let state_submod = PyModule::new_bound(py, "state")?;
    state::init_submodule(&state_submod)?;
    module.add_submodule(&state_submod)?;

    let storage_submod = PyModule::new_bound(py, "storage")?;
    storage::init_submodule(&storage_submod)?;
    module.add_submodule(&storage_submod)?;

    let uuid_submod = PyModule::new_bound(py, "uuid")?;
    uuid::init_submodule(&uuid_submod)?;
    module.add_submodule(&uuid_submod)?;

    let helpers_submod = PyModule::new_bound(py, "helpers")?;
    helpers::init_submodule(&helpers_submod)?;
    module.add_submodule(&helpers_submod)?;

    let crypto_submod = PyModule::new_bound(py, "base_crypto")?;
    base_crypto::init_submodule(&crypto_submod)?;
    module.add_submodule(&crypto_submod)?;

    let device_transfer = PyModule::new_bound(py, "device_transfer")?;
    device_transfer::init_submodule(&device_transfer)?;
    module.add_submodule(&device_transfer)?;

    let key_transparency = PyModule::new_bound(py, "key_transparency")?;
    key_transparency::init_submodule(&key_transparency)?;
    module.add_submodule(&key_transparency)?;
    // Workaround to enable imports from submodules. Upstream issue: pyo3 issue #759
    // https://github.com/PyO3/pyo3/issues/759#issuecomment-653964601
    let mods = [
        "address",
        "account_keys",
        "base_crypto",
        "curve",
        "device_transfer",
        "error",
        "fingerprint",
        "group_cipher",
        "helpers",
        "identity_key",
        "kem",
        "key_transparency",
        "protocol",
        "ratchet",
        "sealed_sender",
        "sender_keys",
        "session_cipher",
        "session",
        "state",
        "storage",
        "uuid",
    ];
    for module_name in mods.iter() {
        let cmd = format!(
            "import sys; sys.modules['signal_protocol.{}'] = {}",
            module_name, module_name
        );
        py.run_bound(&cmd, None, Some(&module.dict()))?;
    }
    Ok(())
}

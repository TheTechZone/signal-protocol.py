use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use futures::executor::block_on;
use rand::TryRngCore as _;

use crate::address::ProtocolAddress;
use crate::error::Result;
use crate::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use crate::ratchet::UsePQRatchet;
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn message_encrypt(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &[u8],
    // now: SystemTime, // TODO: should SystemTime be exposed?
) -> Result<CiphertextMessage> {
    let now2 = std::time::SystemTime::now();
    let mut csprng = rand::rngs::OsRng.unwrap_err();
    let ciphertext = block_on(libsignal_protocol::message_encrypt(
        msg,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        now2,
        &mut csprng,
    ))?;
    Ok(CiphertextMessage::new(ciphertext))
}

#[pyfunction]
pub fn message_decrypt(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &CiphertextMessage,
    use_pq_ratchet: bool,
) -> Result<Py<PyAny>> {
    let mut csprng = rand::rngs::OsRng.unwrap_err();
    let plaintext = block_on(libsignal_protocol::message_decrypt(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut protocol_store.store.kyber_pre_key_store,
        &mut csprng,
        UsePQRatchet::from_bool(use_pq_ratchet).into(),
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn message_decrypt_prekey(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &PreKeySignalMessage,
    use_pq_ratchet: bool,
) -> Result<Py<PyAny>> {
    let mut csprng = rand::rngs::OsRng.unwrap_err();

    let plaintext = block_on(libsignal_protocol::message_decrypt_prekey(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut protocol_store.store.kyber_pre_key_store,
        &mut csprng,
        UsePQRatchet::from_bool(use_pq_ratchet).into(),
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn message_decrypt_signal(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &SignalMessage,
) -> Result<Py<PyAny>> {
    let mut csprng = rand::rngs::OsRng.unwrap_err();
    let plaintext = block_on(libsignal_protocol::message_decrypt_signal(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut csprng,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(message_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt_prekey))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt_signal))?;
    Ok(())
}

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use futures::executor::block_on;
use rand::rngs::OsRng;

use crate::address::ProtocolAddress;
use crate::error::Result;
use crate::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
// use crate::state::SystemTime;
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn message_encrypt(
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &[u8],
    // now: SystemTime, // todo: should SystemTime be exposed?
) -> Result<CiphertextMessage> {
    let now2 = std::time::SystemTime::now();

    let ciphertext = block_on(libsignal_protocol::message_encrypt(
        msg,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        now2,
    ))?;
    Ok(CiphertextMessage::new(ciphertext))
}

#[pyfunction]
pub fn message_decrypt(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &CiphertextMessage,
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let plaintext = block_on(libsignal_protocol::message_decrypt(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut protocol_store.store.kyber_pre_key_store,
        &mut csprng,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn message_decrypt_prekey(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &PreKeySignalMessage,
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let plaintext = block_on(libsignal_protocol::message_decrypt_prekey(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut protocol_store.store.kyber_pre_key_store,
        &mut csprng,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn message_decrypt_signal(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    remote_address: &ProtocolAddress,
    msg: &SignalMessage,
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let plaintext = block_on(libsignal_protocol::message_decrypt_signal(
        &msg.data,
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &mut csprng,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(message_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt_prekey))?;
    module.add_wrapped(wrap_pyfunction!(message_decrypt_signal))?;
    Ok(())
}

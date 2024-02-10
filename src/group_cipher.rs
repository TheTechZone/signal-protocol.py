use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use futures::executor::block_on;
use rand::rngs::OsRng;

use crate::address::ProtocolAddress;
use crate::error::{Result, SignalProtocolError};
// use crate::error::Result;
use crate::protocol::SenderKeyDistributionMessage;
// use crate::protocol::SenderKeyDistributionMessage;
use crate::storage::InMemSignalProtocolStore;
use crate::uuid::UUID;

#[pyfunction]
pub fn group_encrypt(
    py: Python,
    protocol_store: &mut InMemSignalProtocolStore,
    sender: &ProtocolAddress,
    distribution_id: UUID,
    plaintext: &[u8],
) -> Result<PyObject> {
    let mut csprng = OsRng;
    let ciphertext = block_on(libsignal_protocol::group_encrypt(
        &mut protocol_store.store.sender_key_store,
        &sender.state,
        distribution_id.handle,
        plaintext,
        &mut csprng,
    ))?;
    Ok(PyBytes::new(py, &ciphertext.serialized()).into())
}

#[pyfunction]
pub fn group_decrypt(
    py: Python,
    skm_bytes: &[u8],
    protocol_store: &mut InMemSignalProtocolStore,
    sender: &ProtocolAddress,
) -> Result<PyObject> {
    let plaintext = block_on(libsignal_protocol::group_decrypt(
        skm_bytes,
        &mut protocol_store.store.sender_key_store,
        &sender.state,
    ))?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
pub fn process_sender_key_distribution_message(
    sender: &ProtocolAddress,
    skdm: &SenderKeyDistributionMessage,
    protocol_store: &mut InMemSignalProtocolStore,
) -> Result<()> {
    Ok(block_on(
        libsignal_protocol::process_sender_key_distribution_message(
            &sender.state,
            &skdm.data,
            &mut protocol_store.store.sender_key_store,
        ),
    )?)
}

#[pyfunction]
pub fn create_sender_key_distribution_message(
    sender: &ProtocolAddress,
    distribution_id: UUID,
    protocol_store: &mut InMemSignalProtocolStore,
) -> PyResult<Py<SenderKeyDistributionMessage>> {
    let mut csprng = OsRng;
    let upstream_data = match block_on(libsignal_protocol::create_sender_key_distribution_message(
        &sender.state,
        distribution_id.handle,
        &mut protocol_store.store.sender_key_store,
        &mut csprng,
    )) {
        Ok(data) => data,
        Err(err) => return Err(SignalProtocolError::new_err(err)),
    };

    // libsignal_protocol::SenderKeyDistributionMessage::new(upstream_data., distribution_id, chain_id, iteration, chain_key, signing_key)
    // let ciphertext = libsignal_protocol::CiphertextMessage::SenderKeyMessage(
    //     upstream_data.clone(),
    // );

    // The CiphertextMessage is required as it is the base class for SenderKeyDistributionMessage
    // on the Python side, so we must create _both_ a CiphertextMessage and a SenderKeyDistributionMessage
    // on the Rust side for inheritance to work.

    // let gil = Python::acquire_gil();
    // let py = gil.python();
    Python::with_gil(|py| {
        Py::new(
            py,
            SenderKeyDistributionMessage {
                data: upstream_data,
            },
        )
    })
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(group_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(group_decrypt))?;
    module.add_wrapped(wrap_pyfunction!(process_sender_key_distribution_message))?;
    // todo: triple-check this -- they changed the api
    module.add_wrapped(wrap_pyfunction!(create_sender_key_distribution_message))?;
    Ok(())
}

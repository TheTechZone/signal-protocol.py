use std::convert::TryFrom;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use rand::rngs::OsRng;

use crate::curve::{PrivateKey, PublicKey};
use crate::error::{Result, SignalProtocolError};
use crate::identity_key::IdentityKey;
use crate::state::{PreKeyId, SignedPreKeyId};
use crate::uuid::UUID;

/// CiphertextMessage is a Rust enum in the upstream crate. Mapping of enums to Python enums
/// is not supported in pyo3. We map the Rust enum and its variants to Python as a superclass
/// (for CiphertextMessage) and subclasses (for variants of CiphertextMessage).
#[pyclass(subclass)]
pub struct CiphertextMessage {
    pub data: libsignal_protocol::CiphertextMessage,
}

impl CiphertextMessage {
    pub fn new(data: libsignal_protocol::CiphertextMessage) -> Self {
        CiphertextMessage { data }
    }
}

/// We're using the following mapping of libsignal_protocol::CiphertextMessageType to u8:
/// CiphertextMessageType::Whisper => 2
/// CiphertextMessageType::PreKey => 3
/// CiphertextMessageType::SenderKey => 4
/// CiphertextMessageType::SenderKeyDistribution => 5
#[pymethods]
impl CiphertextMessage {
    pub fn serialize(&self, py: Python) -> PyResult<PyObject> {
        Ok(PyBytes::new(py, self.data.serialize()).into())
    }

    pub fn message_type(&self) -> u8 {
        self.data.message_type() as u8
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct KyberPayload {
    pub data: libsignal_protocol::KyberPayload,
}

// TODO: handle impl

/// CiphertextMessageType::PreKey => 3
#[pyclass(extends=CiphertextMessage)]
#[derive(Clone)]
pub struct PreKeySignalMessage {
    pub data: libsignal_protocol::PreKeySignalMessage,
}

#[pymethods]
impl PreKeySignalMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<Py<PreKeySignalMessage>> {
        let upstream_data = match libsignal_protocol::PreKeySignalMessage::try_from(data) {
            Ok(data) => data,
            Err(err) => return Err(SignalProtocolError::new_err(err)),
        };
        let ciphertext =
            libsignal_protocol::CiphertextMessage::PreKeySignalMessage(upstream_data.clone());

        // Workaround to allow two constructors with pyclass inheritence
        // let gil = Python::acquire_gil();
        // let py = gil.python();
        return Python::with_gil(|py| {
            Py::new(
                py,
                (
                    PreKeySignalMessage {
                        data: upstream_data,
                    },
                    CiphertextMessage { data: ciphertext },
                ),
            )
        });
    }

    #[new]
    #[pyo3(signature = (message_version, registration_id, pre_key_id, signed_pre_key_id, kyber_payload,base_key,identity_key, message))]
    pub fn new(
        message_version: u8,
        registration_id: u32,
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        kyber_payload: Option<KyberPayload>,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: SignalMessage,
    ) -> PyResult<(Self, CiphertextMessage)> {
        let pk_id = match pre_key_id {
            None => None,
            Some(x) => Some(x.value),
        };

        let kyber_data = match kyber_payload {
            None => None,
            Some(x) => Some(x.data),
        };

        let upstream_data = match libsignal_protocol::PreKeySignalMessage::new(
            message_version,
            registration_id,
            pk_id,
            signed_pre_key_id.value,
            kyber_data,
            base_key.key,
            identity_key.key,
            message.data.clone(),
        ) {
            Ok(data) => data,
            Err(err) => return Err(SignalProtocolError::new_err(err)),
        };

        let variant_msg = PreKeySignalMessage {
            data: upstream_data.clone(),
        };
        let ciphertext_msg = CiphertextMessage::new(
            libsignal_protocol::CiphertextMessage::PreKeySignalMessage(upstream_data),
        );
        Ok((variant_msg, ciphertext_msg))
    }

    pub fn serialized(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.data.serialized()).into()
    }

    pub fn message_version(&self) -> u8 {
        self.data.message_version()
    }

    pub fn registration_id(&self) -> u32 {
        self.data.registration_id()
    }

    pub fn pre_key_id(&self) -> Option<u32> {
        // self.data.pre_key_id()
        // TODO:: check this
        let key_id = u32::from(PreKeyId {
            value: self.data.pre_key_id()?,
        });
        return Some(key_id);
    }

    pub fn signed_pre_key_id(&self) -> u32 {
        u32::from(self.data.signed_pre_key_id())
    }

    pub fn base_key(&self) -> PublicKey {
        PublicKey {
            key: *self.data.base_key(),
        }
    }

    pub fn identity_key(&self) -> IdentityKey {
        IdentityKey {
            key: *self.data.identity_key(),
        }
    }

    pub fn message(&self) -> PyResult<Py<SignalMessage>> {
        // let gil = Python::acquire_gil();
        // let py = gil.python();
        return Python::with_gil(|py| {
            let upstream_data = self.data.message().clone();
            let ciphertext =
                libsignal_protocol::CiphertextMessage::SignalMessage(upstream_data.clone());
            Py::new(
                py,
                (
                    SignalMessage {
                        data: upstream_data,
                    },
                    CiphertextMessage { data: ciphertext },
                ),
            )
        });
    }
}

/// CiphertextMessageType::Whisper
#[pyclass(extends=CiphertextMessage)]
#[derive(Clone)]
pub struct SignalMessage {
    pub data: libsignal_protocol::SignalMessage,
}

#[pymethods]
impl SignalMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<Py<SignalMessage>> {
        let upstream_data = match libsignal_protocol::SignalMessage::try_from(data) {
            Ok(data) => data,
            Err(err) => return Err(SignalProtocolError::new_err(err)),
        };
        let ciphertext =
            libsignal_protocol::CiphertextMessage::SignalMessage(upstream_data.clone());

        // Workaround to allow two constructors with pyclass inheritence
        // let gil = Python::acquire_gil();
        // let py = gil.python();
        return Python::with_gil(|py| {
            Py::new(
                py,
                (
                    SignalMessage {
                        data: upstream_data,
                    },
                    CiphertextMessage { data: ciphertext },
                ),
            )
        });
    }

    #[new]
    pub fn new(
        message_version: u8,
        mac_key: &[u8],
        sender_ratchet_key: PublicKey,
        counter: u32,
        previous_counter: u32,
        ciphertext: &[u8],
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
    ) -> PyResult<(Self, CiphertextMessage)> {
        let upstream_data = match libsignal_protocol::SignalMessage::new(
            message_version,
            mac_key,
            sender_ratchet_key.key,
            counter,
            previous_counter,
            &ciphertext,
            &sender_identity_key.key,
            &receiver_identity_key.key,
        ) {
            Ok(data) => data,
            Err(err) => return Err(SignalProtocolError::new_err(err)),
        };

        let variant_msg = SignalMessage {
            data: upstream_data.clone(),
        };
        let ciphertext_msg = CiphertextMessage::new(
            libsignal_protocol::CiphertextMessage::SignalMessage(upstream_data),
        );
        Ok((variant_msg, ciphertext_msg))
    }

    pub fn message_version(&self) -> u8 {
        self.data.message_version()
    }

    pub fn sender_ratchet_key(&self) -> PublicKey {
        PublicKey {
            key: *self.data.sender_ratchet_key(),
        }
    }

    pub fn counter(&self) -> u32 {
        self.data.counter()
    }

    pub fn serialized(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.data.serialized()).into()
    }

    pub fn body(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.data.body()).into()
    }

    pub fn verify_mac(
        &self,
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
        mac_key: &[u8],
    ) -> Result<bool> {
        Ok(self.data.verify_mac(
            &sender_identity_key.key,
            &receiver_identity_key.key,
            mac_key,
        )?)
    }
}

/// CiphertextMessageType::SenderKey => 4
#[pyclass(extends=CiphertextMessage)]
pub struct SenderKeyMessage {
    pub data: libsignal_protocol::SenderKeyMessage,
}

#[pymethods]
impl SenderKeyMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<Py<SenderKeyMessage>> {
        let upstream_data = match libsignal_protocol::SenderKeyMessage::try_from(data) {
            Ok(data) => data,
            Err(err) => return Err(SignalProtocolError::new_err(err)),
        };
        let ciphertext =
            libsignal_protocol::CiphertextMessage::SenderKeyMessage(upstream_data.clone());

        // Workaround to allow two constructors with pyclass inheritence
        // let gil = Python::acquire_gil();
        // let py = gil.python();
        return Python::with_gil(|py| {
            Py::new(
                py,
                (
                    SenderKeyMessage {
                        data: upstream_data,
                    },
                    CiphertextMessage { data: ciphertext },
                ),
            )
        });
    }

    #[new]
    pub fn new(
        message_version: u8,
        distribution_id: UUID,
        chain_id: u32,
        iteration: u32,
        ciphertext: &[u8],
        signature_key: &PrivateKey,
    ) -> PyResult<(Self, CiphertextMessage)> {
        let mut csprng = OsRng;
        let upstream_data = match libsignal_protocol::SenderKeyMessage::new(
            message_version,
            distribution_id.handle,
            chain_id,
            iteration,
            Box::from(ciphertext),
            &mut csprng,
            &signature_key.key,
        ) {
            Ok(data) => data,
            Err(err) => return Err(SignalProtocolError::new_err(err)),
        };

        let variant_msg = SenderKeyMessage {
            data: upstream_data.clone(),
        };
        let ciphertext_msg = CiphertextMessage::new(
            libsignal_protocol::CiphertextMessage::SenderKeyMessage(upstream_data),
        );
        Ok((variant_msg, ciphertext_msg))
    }

    pub fn serialized(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.data.serialized()).into()
    }

    pub fn message_version(&self) -> u8 {
        self.data.message_version()
    }

    pub fn distribution_id(&self) -> UUID {
        UUID {
            handle: self.data.distribution_id(),
        }
    }

    pub fn chain_id(&self) -> u32 {
        self.data.chain_id()
    }

    // TODO: looks deprecated
    // pub fn key_id(&self) -> u32 {
    //     self.data.key_id()
    // }

    pub fn iteration(&self) -> u32 {
        self.data.iteration()
    }

    pub fn ciphertext(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.data.ciphertext()).into()
    }

    pub fn verify_signature(&self, signature_key: &PublicKey) -> Result<bool> {
        Ok(self.data.verify_signature(&signature_key.key)?)
    }
}

/// CiphertextMessageType::SenderKeyDistribution => 5
#[pyclass]
#[derive(Debug, Clone)]
pub struct SenderKeyDistributionMessage {
    pub data: libsignal_protocol::SenderKeyDistributionMessage,
}

#[pymethods]
impl SenderKeyDistributionMessage {
    #[staticmethod]
    pub fn try_from(data: &[u8]) -> PyResult<Py<SenderKeyDistributionMessage>> {
        let upstream_data = match libsignal_protocol::SenderKeyDistributionMessage::try_from(data) {
            Ok(data) => data,
            Err(err) => return Err(SignalProtocolError::new_err(err)),
        };

        // Workaround to allow two constructors with pyclass inheritence
        // let gil = Python::acquire_gil();
        // let py = gil.python();
        return Python::with_gil(|py| {
            Py::new(
                py,
                SenderKeyDistributionMessage {
                    data: upstream_data,
                },
            )
        });
    }

    // todo :: they swapped the api -- CiphertextMessage::SenderKeyDistributionMessage is gone
    #[new]
    pub fn new(
        message_version: u8,
        distribution_id: UUID,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signing_key: &PublicKey,
    ) -> PyResult<Self> {
        let upstream_data = match libsignal_protocol::SenderKeyDistributionMessage::new(
            message_version,
            distribution_id.handle,
            chain_id,
            iteration,
            chain_key.to_vec(),
            signing_key.key,
        ) {
            Ok(data) => data,
            Err(err) => return Err(SignalProtocolError::new_err(err)),
        };

        let variant_msg = SenderKeyDistributionMessage {
            data: upstream_data.clone(),
        };
        // let ciphertext_msg = CiphertextMessage::new(
        //     libsignal_protocol::CiphertextMessage::SenderKeyDistributionMessage(upstream_data),
        // );
        Ok(variant_msg)
    }

    pub fn serialized(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.data.serialized()).into()
    }

    pub fn message_version(&self) -> u8 {
        self.data.message_version()
    }

    // pub fn id(&self) -> Result<u32> {
    //     Ok(self.data.id()?)
    // }

    pub fn iteration(&self) -> Result<u32> {
        Ok(self.data.iteration()?)
    }

    pub fn chain_key(&self, py: Python) -> Result<PyObject> {
        Ok(PyBytes::new(py, &self.data.chain_key()?).into())
    }

    pub fn signing_key(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            key: *self.data.signing_key()?,
        })
    }
}

// #[pyclass]
// #[derive(Clone, Debug)]
// pub struct KemSerializedCiphertext {
//     pub state: libsignal_protocol::kem::SerializedCiphertext,
// }

// #[pymethods]
// impl KemSerializedCiphertext {
//     // TODO: dummy for now
//     #[new]
//     pub fn new(value: &[u8]) -> PyResult<Self> {
//         let kem_ctxt = libsignal_protocol::kem::SerializedCiphertext::from(value);
//         Ok(KemSerializedCiphertext { state: kem_ctxt })
//     }
// }

/// CiphertextMessageType is an Enum that is not exposed as part
/// of the Python API.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<CiphertextMessage>()?;
    module.add_class::<PreKeySignalMessage>()?;
    module.add_class::<SignalMessage>()?;
    module.add_class::<SenderKeyMessage>()?;
    module.add_class::<SenderKeyDistributionMessage>()?;
    Ok(())
}

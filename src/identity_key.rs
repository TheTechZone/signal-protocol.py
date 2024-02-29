use std::convert::TryFrom;

use pyo3::basic::CompareOp;
use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use rand::rngs::OsRng;

use crate::curve::{PrivateKey, PublicKey};
use crate::error::{Result, SignalProtocolError};

use base64::{engine::general_purpose, Engine as _};

#[pyclass]
#[derive(Debug, Clone, Copy)]
pub struct IdentityKey {
    pub key: libsignal_protocol::IdentityKey,
}

#[pymethods]
impl IdentityKey {
    // The behavior of libsignal_protocol::IdentityKey::decode is provided
    // by the new() function.
    #[new]
    pub fn new(public_key: &[u8]) -> PyResult<Self> {
        match libsignal_protocol::IdentityKey::try_from(public_key) {
            Ok(key) => Ok(Self { key }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::deserialize(&self.key.public_key().serialize())?)
    }

    pub fn serialize(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.key.serialize()).into()
    }

    pub fn to_base64(&self) -> PyResult<String> {
        Ok(general_purpose::STANDARD.encode(&self.key.serialize()))
    }

    fn __richcmp__(&self, other: IdentityKey, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Eq => Ok(self.key.serialize() == other.key.serialize()),
            CompareOp::Ne => Ok(self.key.serialize() != other.key.serialize()),
            _ => Err(exceptions::PyNotImplementedError::new_err(())),
        }
    }

    pub fn verify_alternate_identity(
        &self,
        other: &IdentityKey,
        signature: &[u8],
    ) -> PyResult<bool> {
        match self.key.verify_alternate_identity(&other.key, signature) {
            Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
            Ok(result) => Ok(result),
        }
    }
}

#[pyclass]
#[derive(Clone, Copy)]
pub struct IdentityKeyPair {
    pub key: libsignal_protocol::IdentityKeyPair,
}

#[pymethods]
impl IdentityKeyPair {
    #[new]
    pub fn new(identity_key: IdentityKey, private_key: PrivateKey) -> Self {
        Self {
            key: libsignal_protocol::IdentityKeyPair::new(identity_key.key, private_key.key),
        }
    }

    #[staticmethod]
    pub fn from_bytes(identity_key_pair_bytes: &[u8]) -> PyResult<Self> {
        match libsignal_protocol::IdentityKeyPair::try_from(identity_key_pair_bytes) {
            Ok(key) => Ok(Self { key }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    #[staticmethod]
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let key_pair = libsignal_protocol::IdentityKeyPair::generate(&mut csprng);
        IdentityKeyPair { key: key_pair }
    }

    pub fn identity_key(&self) -> PyResult<IdentityKey> {
        match IdentityKey::new(&self.key.public_key().serialize()) {
            Ok(key) => Ok(key),
            Err(err) => Err(err),
        }
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::deserialize(&self.key.public_key().serialize())?)
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        Ok(PrivateKey::deserialize(
            &self.key.private_key().serialize(),
        )?)
    }

    pub fn serialize(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.key.serialize()).into()
    }

    // pub fn sign_alternate_identity(&self, py:Python, other: &IdentityKey) ->Result<PyBytes> {
    //     let mut csprng = OsRng;
    //     let alt = self.key.sign_alternate_identity(&other.key, &mut csprng);
    //     match alt {
    //         Err(err) => return Err(SignalProtocolError::from(err)),
    //         Ok(data) => Ok(PyBytes::new(py, &data.))
    //     }
    // }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<IdentityKey>()?;
    module.add_class::<IdentityKeyPair>()?;
    Ok(())
}

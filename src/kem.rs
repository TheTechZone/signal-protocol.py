use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::{Result, SignalProtocolError};

use base64::{engine::general_purpose, Engine as _};

#[pyclass]
#[derive(Debug, Copy, Clone)]
pub struct KeyType {
    // Kyber768 and ML-KEM are still WIP
    // TODO: update this if they become stable
    pub key_type: libsignal_protocol::kem::KeyType,
}

#[pymethods]
impl KeyType {
    #[new]
    pub fn new(key_type: u8) -> PyResult<Self> {
        let key_enum = match key_type {
            0 => libsignal_protocol::kem::KeyType::Kyber1024,
            _ => {
                // todo: wrap around SignalProtocolError::BadKEMKeyType
                return Err(SignalProtocolError::err_from_str(format!(
                    "unknown KEM key type: {}",
                    key_type
                )));
            }
        };
        Ok(KeyType { key_type: key_enum })
    }

    pub fn value(&self) -> u8 {
        match &self.key_type {
            libsignal_protocol::kem::KeyType::Kyber1024 => 0,
        }
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(String::from(format!("{}", self.key_type)))
    }

    fn __repr__(&self) -> PyResult<String> {
        let memory_address = std::ptr::addr_of!(self) as usize;
        Ok(String::from(format!(
            "KeyType({}) at 0x{:x}",
            self.key_type, memory_address
        )))
    }
}

#[pyclass]
#[derive(Clone)]
pub struct KeyPair {
    pub key: libsignal_protocol::kem::KeyPair,
}

// todo: kem::KeyPair impl

#[pymethods]
impl KeyPair {
    #[new]
    pub fn new(public_key: PublicKey, secret_key: SecretKey) -> Self {
        let keypair = libsignal_protocol::kem::KeyPair::new(public_key.key, secret_key.key);
        KeyPair { key: keypair }
    }

    #[staticmethod]
    pub fn generate(key_type: KeyType) -> Self {
        let keypair = libsignal_protocol::kem::KeyPair::generate(key_type.key_type);
        KeyPair { key: keypair }
    }

    #[staticmethod]
    pub fn from_public_and_private(public_key: &[u8], secret_key: &[u8]) -> Result<Self> {
        Ok(KeyPair {
            key: libsignal_protocol::kem::KeyPair::from_public_and_private(public_key, secret_key)?,
        })
    }

    pub fn public_key_length(&self) -> usize {
        self.key.public_key.serialize().len()
    }

    pub fn secret_key_length(&self) -> usize {
        self.key.secret_key.serialize().len()
    }

    /// Create a `SharedSecret` and a `Ciphertext`. The `Ciphertext` can be safely sent to the
    /// holder of the corresponding `SecretKey` who can then use it to `decapsulate` the same
    /// `SharedSecret`.
    pub fn encapsulate(&self, py: Python) -> (PyObject, PyObject) {
        // we could use get_public().encapsulate() but that does an extra copy operation for no good reason
        let (ss, ctxt) = self.key.public_key.encapsulate();
        return (PyBytes::new(py, &ss).into(), PyBytes::new(py, &ctxt).into());
    }

    /// Decapsulates a `SharedSecret` that was encapsulated into a `Ciphertext` by a holder of
    /// the corresponding `PublicKey`.
    pub fn decapsulate(&self, py: Python, ct_bytes: &[u8]) -> PyResult<PyObject> {
        // we could use get_private().decapsulate() but that does an extra copy operation for no good reason
        let ctxt = libsignal_protocol::kem::SerializedCiphertext::from(ct_bytes);
        let ss = self.key.secret_key.decapsulate(&ctxt);
        match ss {
            Ok(shared_secret) => Ok(PyBytes::new(py, &shared_secret).into()),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    pub fn get_public(&self) -> PublicKey {
        PublicKey {
            key: self.key.public_key.clone(),
        }
    }

    pub fn get_private(&self) -> SecretKey {
        SecretKey {
            key: self.key.secret_key.clone(),
        }
    }
}

#[pyclass]
#[derive(Clone)]

pub struct PublicKey {
    pub key: libsignal_protocol::kem::PublicKey,
}

#[pymethods]
impl PublicKey {
    pub fn serialize(&self, py: Python) -> PyObject {
        let result = self.key.serialize();
        PyBytes::new(py, &result).into()
    }

    #[staticmethod]
    pub fn deserialize(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: libsignal_protocol::kem::PublicKey::deserialize(key)?,
        })
    }

    pub fn to_base64(&self) -> PyResult<String> {
        Ok(general_purpose::STANDARD.encode(&self.key.serialize()))
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.key.eq(&other.key)
    }

    /// Create a `SharedSecret` and a `Ciphertext`. The `Ciphertext` can be safely sent to the
    /// holder of the corresponding `SecretKey` who can then use it to `decapsulate` the same
    /// `SharedSecret`.
    pub fn encapsulate(&self, py: Python) -> (PyObject, PyObject) {
        let (ss, ctxt) = self.key.encapsulate();
        return (PyBytes::new(py, &ss).into(), PyBytes::new(py, &ctxt).into());
    }
}

#[pyclass]
#[derive(Clone)]

pub struct SecretKey {
    pub key: libsignal_protocol::kem::SecretKey,
}

#[pymethods]
impl SecretKey {
    pub fn serialize(&self, py: Python) -> PyObject {
        let result = self.key.serialize();
        PyBytes::new(py, &result).into()
    }

    #[staticmethod]
    pub fn deserialize(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: libsignal_protocol::kem::SecretKey::deserialize(key)?,
        })
    }

    /// Decapsulates a `SharedSecret` that was encapsulated into a `Ciphertext` by a holder of
    /// the corresponding `PublicKey`.
    pub fn decapsulate(&self, py: Python, ct_bytes: &[u8]) -> PyResult<PyObject> {
        let ctxt = libsignal_protocol::kem::SerializedCiphertext::from(ct_bytes);
        let ss = self.key.decapsulate(&ctxt);
        match ss {
            Ok(shared_secret) => Ok(PyBytes::new(py, &shared_secret).into()),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }
}

/// Represents a Kyber serialized ciphertext. The first byte is a KeyType prefix
#[pyclass]
#[derive(Clone, Debug)]
pub struct SerializedCiphertext {
    pub state: libsignal_protocol::kem::SerializedCiphertext,
}

#[pymethods]
impl SerializedCiphertext {
    #[new]
    pub fn new(value: &[u8]) -> PyResult<Self> {
        let kem_ctxt = libsignal_protocol::kem::SerializedCiphertext::from(value);
        Ok(SerializedCiphertext { state: kem_ctxt })
    }

    /// Get the raw Kyber ciphertext bytes, without the KeyType prefix.
    fn raw(&self, py: Python) -> PyObject {
        PyBytes::new(py, &(&*self.state)[1..]).into()
    }
}

pub fn init_kem_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<KeyType>()?;
    module.add_class::<KeyPair>()?;
    module.add_class::<PublicKey>()?;
    module.add_class::<SecretKey>()?;
    module.add_class::<SerializedCiphertext>()?;
    Ok(())
}

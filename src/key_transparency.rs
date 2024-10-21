use crate::error::SignalProtocolError;
use pyo3::prelude::PyModule;
use pyo3::types::PyBytes;
use pyo3::{pyclass, pymethods, PyObject, PyResult, Python};

#[derive(Copy, Clone, Debug)]
#[pyclass]
struct VerifyingKey {
    inner: libsignal_keytrans::VerifyingKey,
}

#[pymethods]
impl VerifyingKey {
    // todo: likely we will not implement the entirety of the API as it's quite complex :c

    #[staticmethod]
    /// The caller **is responsible** for ensuring that the bytes passed into this method actually represent
    /// a curve25519_dalek::curve::CompressedEdwardsY and that said compressed point is actually a point on the curve.
    pub fn from_bytes(key: &[u8]) -> PyResult<Self> {
        if key.len() != 32 {
            return Err(SignalProtocolError::err_from_str(format!(
                "key must have 32 bytes, got {}",
                key.len()
            )));
        }
        match libsignal_keytrans::VerifyingKey::from_bytes(<&[u8; 32]>::try_from(key)?) {
            Ok(key) => Ok(VerifyingKey { inner: key }),
            Err(err) => Err(SignalProtocolError::err_from_str(format!(
                "decompression error: {:?}",
                err
            ))),
        }
    }

    // fn to_bytes(&self) -> PyObject {
    //     PyBytes::into(self.inner.to_bytes().into())
    // }
    //
    // fn as_bytes(&self) -> PyObject {
    //     PyBytes::into(self.inner.as_bytes().into())
    // }

    fn is_weak(&self) -> bool {
        self.inner.is_weak()
    }

    fn verify_strict(&self, _message: &[u8], _signature: &[u8]) -> bool {
        // todo:: this will need a serious redo of the project... probably need to add a submodule to
        // todo: port ed25519-dalek, otherwise I don't see how to make this happy...
        false
    }
}

// impl From<libsignal_keytrans::VerifyingKey> for VerifyingKey {
//     fn from(value: libsignal_keytrans::VerifyingKey) -> Self {
//         todo!()
//     }
// }

#[derive(Clone)]
#[pyclass]
struct VrfPublicKey {
    inner: libsignal_keytrans::VrfPublicKey,
}

#[pymethods]
impl VrfPublicKey {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        if key.len() != 32 {
            return Err(SignalProtocolError::err_from_str(format!(
                "vrf key must have 32 bytes, got {}",
                key.len()
            )));
        }
        let key_bytes = <[u8; 32]>::try_from(key.clone())?;
        match libsignal_keytrans::VrfPublicKey::try_from(key_bytes) {
            Ok(key) => Ok(VrfPublicKey { inner: key }),
            Err(err) => Err(SignalProtocolError::err_from_str(format!(
                "decompression error: {:?}",
                err
            ))),
        }
    }

    fn as_bytes(&self, py: Python) -> PyObject {
        // self.inner.as_bytes().to_vec()
        let data = self.inner.as_bytes().to_vec();
        PyBytes::new(py, &data).into()
    }

    fn proof_to_hash(&self, m: &[u8], proof: &[u8], py: Python) -> PyResult<PyObject> {
        match self.inner.proof_to_hash(m, <&[u8; 80]>::try_from(proof)?) {
            Ok(hash) => Ok(PyBytes::new(py, &hash).into()),
            Err(err) => Err(SignalProtocolError::err_from_str(format!(
                "proof to hash failed: {:?}",
                err
            ))),
        }
    }
}

#[derive(Clone)]
#[pyclass]
struct DeploymentMode {
    inner: libsignal_keytrans::DeploymentMode,
    byte: u8,
    key: Option<VerifyingKey>,
}

#[pymethods]
impl DeploymentMode {
    #[new]
    fn new(value: u8, key: Option<VerifyingKey>) -> PyResult<Self> {
        if value != 1 && key.is_none() {
            return Err(SignalProtocolError::err_from_str(format!(
                "invalid DeployMode: {}, no key provided",
                value
            )));
        }
        let vf = match key {
            Some(ref key) => Some(VerifyingKey {
                inner: key.inner.clone(),
            }),
            None => None,
        };
        match value {
            1 => Ok(DeploymentMode {
                inner: libsignal_keytrans::DeploymentMode::ContactMonitoring,
                byte: value,
                key: None,
            }),
            2 => Ok(DeploymentMode {
                inner: libsignal_keytrans::DeploymentMode::ThirdPartyAuditing(vf.unwrap().inner),
                byte: value,
                key: Some(VerifyingKey {
                    inner: key.unwrap().inner,
                }),
            }),
            3 => Ok(DeploymentMode {
                inner: libsignal_keytrans::DeploymentMode::ThirdPartyManagement(vf.unwrap().inner),
                byte: value,
                key: Some(VerifyingKey {
                    inner: key.unwrap().inner,
                }),
            }),
            _ => Err(SignalProtocolError::err_from_str(format!(
                "unknown DeploymentMode: {}",
                value
            ))),
        }
    }

    fn byte(&self) -> u8 {
        self.byte
    }
    // fn byte(&self) -> u8 {
    //     self.inner.byte()
    // }
    //
    fn get_associated_key(&self) -> Option<VerifyingKey> {
        self.key.clone()
    }
    // fn get_associated_key(&self) -> Option<VerifyingKey> {
    //     &self.inner.get_associated_key();
    // }
}

#[pyclass]
struct PublicConfig {
    inner: libsignal_keytrans::PublicConfig,
}

#[pymethods]
impl PublicConfig {
    #[new]
    pub fn new(mode: DeploymentMode, signature_key: VerifyingKey, vrf_key: VrfPublicKey) -> Self {
        PublicConfig {
            inner: libsignal_keytrans::PublicConfig {
                mode: mode.inner,
                signature_key: signature_key.inner,
                vrf_key: vrf_key.inner,
            },
        }
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<VerifyingKey>()?;
    module.add_class::<VrfPublicKey>()?;
    module.add_class::<DeploymentMode>()?;
    module.add_class::<PublicConfig>()?;
    // module.add_wrapped(wrap_pyfunction!(aes_256_gcm_decrypt))?;
    Ok(())
}

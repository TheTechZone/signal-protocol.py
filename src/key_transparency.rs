use crate::error::SignalProtocolError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::time::SystemTime;

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
        let key_bytes = <[u8; 32]>::try_from(key)?;
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
        PyBytes::new_bound(py, &data).into()
    }

    fn proof_to_hash(&self, m: &[u8], proof: &[u8], py: Python) -> PyResult<PyObject> {
        match self.inner.proof_to_hash(m, <&[u8; 80]>::try_from(proof)?) {
            Ok(hash) => Ok(PyBytes::new_bound(py, &hash).into()),
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
    #[pyo3(signature = (value, key=None))]
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

    fn get_associated_key(&self) -> Option<VerifyingKey> {
        self.key.clone()
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
#[pyclass]
pub struct SlimSearchRequest {
    inner: libsignal_keytrans::SlimSearchRequest,
}

#[pymethods]
impl SlimSearchRequest {
    #[new]
    fn new(search_key: &[u8]) -> Self {
        SlimSearchRequest {
            inner: libsignal_keytrans::SlimSearchRequest::new(search_key.into()),
        }
        // SlimSearchRequest {
        //     inner: libsignal_keytrans::SlimSearchRequest {
        //         search_key: Vec::from(search_key),
        //         version: None,
        //         // consistency: None,
        //         // mapped_value: Vec::from(mapped_value),
        //         // unidentified_access_key: Some(Vec::from(unidentified_access_key)),
        //     },
        // }
    }
}

// #[derive(Clone)]
// #[pyclass]
// pub struct SearchResponse {
//     inner: libsignal_keytrans::SearchResponse,
// }

// #[pymethods]
// impl SearchResponse {
//     #[new]
//     fn new() -> Self {
//         SearchResponse {
//             inner: libsignal_keytrans::SearchResponse {
//                 tree_head: None,
//                 vrf_proof: vec![],
//                 search: None,
//                 opening: vec![],
//                 value: None,
//             },
//         }
//     }
//
//     #[staticmethod]
//     fn default() -> Self {
//         SearchResponse {
//             inner: libsignal_keytrans::SearchResponse::default(),
//         }
//     }
// }

#[derive(Clone, PartialEq)]
#[pyclass]
pub struct TreeHead {
    pub inner: libsignal_keytrans::TreeHead,
}

#[pymethods]
impl TreeHead {
    #[new]
    fn new(tree_size: u64, timestamp: i64, signature: &[u8]) -> Self {
        TreeHead {
            inner: libsignal_keytrans::TreeHead {
                tree_size,
                timestamp,
                signature: signature.to_vec(),
            },
        }
    }

    fn tree_size(&self) -> u64 {
        self.inner.tree_size
    }

    fn timestamp(&self) -> i64 {
        self.inner.timestamp
    }

    fn signature(&self) -> Vec<u8> {
        self.inner.signature.to_vec()
    }
}

#[pyclass]
struct LastTreeHead {
    inner: libsignal_keytrans::LastTreeHead,
}

#[pymethods]
impl LastTreeHead {}

#[derive(Debug, Eq, PartialEq, Clone)]
#[pyclass]
pub struct MonitoringData {
    inner: libsignal_keytrans::MonitoringData,
}

impl MonitoringData {
    fn next_monitor(&self) -> u64 {
        self.inner.next_monitor()
    }

    pub fn entries(&self) -> Vec<u64> {
        self.inner.entries()
    }
}

// #[pyclass]
// pub struct SearchContext {
//     inner: libsignal_keytrans::SearchContext,
// }
//
// impl Clone for SearchContext {
//     fn clone(&self) -> Self {
//         // SearchContext {
//         //     inner: sel
//         // }
//         SearchContext::default()
//     }
// }
//
// #[pymethods]
// impl SearchContext {
//     #[new]
//     fn new() -> Self {
//         // SearchContext {
//         //     inner: libsignal_keytrans::SearchContext{
//         //         last_tree_head: Some(tree_head.inner),
//         //         data: Some(data.inner)
//         //         // last_tree_head: tree_head.inner,
//         //         // data: None
//         //     }
//         // }
//         SearchContext {
//             inner: Default::default(),
//         }
//     }
//
//     #[staticmethod]
//     fn default() -> Self {
//         SearchContext {
//             inner: libsignal_keytrans::SearchContext::default(),
//         }
//     }
// }

#[derive(Debug)]
#[pyclass]
pub struct VerifiedSearchResult {
    inner: libsignal_keytrans::VerifiedSearchResult,
}

#[pymethods]
impl VerifiedSearchResult {}

// #[pyclass]
// pub struct KeyTransparency {
//     inner: libsignal_keytrans::KeyTransparency,
// }
//
// #[pymethods]
// impl KeyTransparency {
//     #[new]
//     fn new(config: PublicConfig) -> Self {
//         KeyTransparency {
//             inner: libsignal_keytrans::KeyTransparency {
//                 config: config.inner,
//             },
//         }
//     }
//
//     /**
//     Checks that the output of a Search operation is valid and updates the client's stored data. res. value. value may only be consumed by the application if this function returns successfully.
//     */
//     fn verify_search(
//         &mut self,
//         request: SlimSearchRequest,
//         response: SearchResponse,
//         context: SearchContext,
//     ) -> PyResult<VerifiedSearchResult> {
//         match self.inner.verify_search(
//             request.inner,
//             response.inner,
//             context.inner,
//             false,
//             SystemTime::now(),
//         ) {
//             Ok(update) => Ok(VerifiedSearchResult { inner: update }),
//             Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
//         }
//     }
//
//     fn verify_distinguished(&self) {
//         todo!("not yet implemented")
//     }
//
//     fn truncate_search_response(&self) {
//         todo!()
//     }
//
//     fn verify_monitor(&self) {
//         todo!()
//     }
//
//     fn verify_update(&self) {
//         todo!()
//     }
// }

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<VerifyingKey>()?;
    module.add_class::<VrfPublicKey>()?;
    module.add_class::<DeploymentMode>()?;
    module.add_class::<PublicConfig>()?;
    module.add_class::<SlimSearchRequest>()?;
    // module.add_class::<KeyTransparency>()?;
    Ok(())
}

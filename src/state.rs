use base64::Engine;
use libsignal_protocol::GenericSignedPreKey;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;
use serde::ser::SerializeStruct;
use serde::Serialize;
use pyo3::types::IntoPyDict;
use pyo3::types::{PyDict, PyAny};
use serde_json::{Value, json};
use std::collections::HashMap;
use pyo3::conversion::FromPyObject;

// use serde_json::{json, Value};

use crate::address::DeviceId;
use crate::curve::{KeyPair, PrivateKey, PublicKey};
use crate::error::{Result, SignalProtocolError};
use crate::identity_key::IdentityKey;
use crate::kem::PublicKey as KemPublicKey;
use crate::kem::{self, SecretKey};

use std::convert;

// Newtypes from upstream crate not exposed as part of the public API
#[pyclass]
#[derive(Clone, Debug)]
pub struct SignedPreKeyId {
    pub value: libsignal_protocol::SignedPreKeyId,
}
impl convert::From<SignedPreKeyId> for u32 {
    fn from(value: SignedPreKeyId) -> Self {
        u32::from(value.value)
    }
}

#[pymethods]
impl SignedPreKeyId {
    #[new]
    fn new(id: u32) -> SignedPreKeyId {
        SignedPreKeyId {
            value: libsignal_protocol::SignedPreKeyId::from(id),
        }
    }

    fn get_id(&self) -> u32 {
        u32::from(self.value)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(String::from(format!(
            "{}",
            self.value        
        )))
    }

    fn __repr__(&self) -> PyResult<String> {
        let memory_address = std::ptr::addr_of!(self) as usize;
        Ok(String::from(format!(
            "SignedPreKeyId({}) at 0x{:x}",
            self.value,
            memory_address
        )))
    }
}

// pub type PreKeyId = u32;

#[pyclass]
#[derive(Clone, Debug)]
pub struct PreKeyId {
    pub value: libsignal_protocol::PreKeyId,
}
// TODO: handle impl
impl convert::From<PreKeyId> for u32 {
    fn from(value: PreKeyId) -> Self {
        u32::from(value.value)
    }
}

impl convert::From<u32> for PreKeyId {
    fn from(value: u32) -> Self {
        PreKeyId {
            value: libsignal_protocol::PreKeyId::from(value),
        }
    }
}

impl Serialize for PreKeyId {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(u32::from(self.value))
    }
}

#[pymethods]
impl PreKeyId {
    #[new]
    fn new(id: u32) -> PreKeyId {
        PreKeyId {
            value: libsignal_protocol::PreKeyId::from(id),
        }
    }

    fn get_id(&self) -> u32 {
        u32::from(self.value)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(String::from(format!(
            "{}",
            self.value        
        )))
    }

    fn __repr__(&self) -> PyResult<String> {
        let memory_address = std::ptr::addr_of!(self) as usize;
        Ok(String::from(format!(
            "PreKeyId({}) at 0x{:x}",
            self.value,
            memory_address
        )))
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct KyberPreKeyId {
    pub value: libsignal_protocol::KyberPreKeyId,
}

#[pymethods]
impl KyberPreKeyId {
    #[new]
    fn new(id: u32) -> KyberPreKeyId {
        KyberPreKeyId {
            value: libsignal_protocol::KyberPreKeyId::from(id),
        }
    }

    fn get_id(&self) -> u32 {
        u32::from(self.value)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(String::from(format!(
            "{}",
            self.value        
        )))
    }

    fn __repr__(&self) -> PyResult<String> {
        let memory_address = std::ptr::addr_of!(self) as usize;
        Ok(String::from(format!(
            "KyberPreKeyId({}) at 0x{:x}",
            self.value,
            memory_address
        )))
    }
}
#[pyclass]
#[derive(Clone, Debug)]
pub struct PreKeysUsed {
    pub pre_key_id: Option<PreKeyId>,
    pub kyber_pre_key_id: Option<KyberPreKeyId>,
}

#[pyclass]
#[derive(Clone)]
pub struct SystemTime {
    pub handle: std::time::SystemTime,
}

#[pyclass]
#[derive(Clone)]
pub struct PreKeyBundle {
    pub state: libsignal_protocol::PreKeyBundle,
}

#[pymethods]
impl PreKeyBundle {
    //TODO: this constructor will *likely* have to change once kyber rolls out (and it is updated upstream)
    #[new]
    #[pyo3(signature = (registration_id, device_id, pre_key_public,signed_pre_key_id,signed_pre_key_public,signed_pre_key_signature,identity_key))]
    fn new(
        registration_id: u32,
        device_id: DeviceId,
        pre_key_public: Option<(PreKeyId, PublicKey)>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: Vec<u8>,
        identity_key: IdentityKey,
    ) -> PyResult<Self> {
        let pre_key: std::option::Option<(
            libsignal_protocol::PreKeyId,
            libsignal_protocol::PublicKey,
        )> = match pre_key_public {
            Some(inner) => Some((inner.0.value, inner.1.key)),
            None => None,
        };

        let signed_pre_key = signed_pre_key_public.key;
        let identity_key_direct = identity_key.key;

        match libsignal_protocol::PreKeyBundle::new(
            registration_id,
            device_id.value,
            pre_key,
            signed_pre_key_id.value,
            signed_pre_key,
            signed_pre_key_signature,
            identity_key_direct,
        ) {
            Ok(state) => Ok(PreKeyBundle { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn registration_id(&self) -> Result<u32> {
        Ok(self.state.registration_id()?)
    }

    fn device_id(&self) -> Result<DeviceId> {
        Ok(DeviceId {
            value: self.state.device_id()?,
        })
    }

    fn pre_key_id(&self) -> Result<Option<PreKeyId>> {
        let key = self.state.pre_key_id()?;
        // Ok(PreKeyId{ value: self.state.pre_key_id()})
        match key {
            Some(key) => Ok(Some(PreKeyId { value: key })),
            None => Ok(None),
        }
    }

    fn pre_key_public(&self) -> Result<Option<PublicKey>> {
        let key = self.state.pre_key_public()?;
        match key {
            Some(key) => Ok(Some(PublicKey { key })),
            None => Ok(None),
        }
    }

    fn signed_pre_key_id(&self) -> Result<SignedPreKeyId> {
        Ok(SignedPreKeyId {
            value: self.state.signed_pre_key_id()?,
        })
    }

    fn signed_pre_key_public(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            key: self.state.signed_pre_key_public()?,
        })
    }

    fn signed_pre_key_signature(&self, py: Python) -> Result<PyObject> {
        let result = self.state.signed_pre_key_signature()?;
        Ok(PyBytes::new(py, result).into())
    }

    fn identity_key(&self) -> Result<IdentityKey> {
        Ok(IdentityKey {
            key: *self.state.identity_key()?,
        })
    }

    fn has_kyber_pre_key(&self) -> bool {
        self.state.has_kyber_pre_key()
    }

    fn kyber_pre_key_id(&self) -> Result<Option<KyberPreKeyId>> {
        // TODO: for now suppress errors as they kyber part is not initilized
        let val = match self.state.kyber_pre_key_id() {
            Err(_) => return Ok(None),
            Ok(val) => match val {
                None => return Ok(None),
                Some(val) => Some(KyberPreKeyId { value: val }),
            },
        };
        Ok(val)
    }

    fn kyber_pre_key_public(&self) -> Result<Option<KemPublicKey>> {
        // TODO: for now suppress errors as they kyber part is not initilized
        let upstream_key = match self.state.kyber_pre_key_public() {
            Err(_) => return Ok(None),
            Ok(val) => match val {
                None => return Ok(None),
                Some(val) => Some(KemPublicKey { key: val.clone() }),
            },
        };
        Ok(upstream_key)
    }

    fn kyber_pre_key_signature(&self) -> Result<Option<&[u8]>> {
        // TODO: for now suppress errors as they kyber part is not initilized
        let sig = match self.state.kyber_pre_key_signature() {
            Err(_) => return Ok(None),
            Ok(val) => val,
        };
        Ok(sig)
    }

    fn with_kyber_pre_key(
        &self,
        pre_key_id: KyberPreKeyId,
        public_key: KemPublicKey,
        signature: &[u8],
    ) -> Self {
        PreKeyBundle {
            state: self.state.clone().with_kyber_pre_key(
                pre_key_id.value,
                public_key.key,
                signature.to_vec(),
            ),
        }
    }
    
    // fn to_json(&self) -> PyResult<String> {
    //     match serde_json::to_string(&self) {
    //         Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
    //         Ok(val) => Ok(val),
    //     }
    // }

    fn to_json(&self, py: Python) -> PyResult<String> {
        let dict = self.to_dict(py)?;
        let json_module = py.import("json")?;
        let json_str = json_module.call_method1("dumps", (dict,))?.extract()?;
    
        Ok(json_str)
    }

    fn to_dict(&self, py: Python) -> PyResult<PyObject> {
        let dict: &PyDict = [
            ("registration_id", 0),
            ("device_id", 0)
            // ("registration_id", self.registration_id().unwrap().to_object(py)),
            // ("device_id", u32::from(device_id).to_object(py)),
        ].into_py_dict(py);
        
        // Helper function to set an item in the dictionary if the result is Ok and Some
        fn set_if_ok<T, F>(dict: &pyo3::types::PyDict, key: &str, result: Result<Option<T>>, f: F)
        where
            F: FnOnce(&T) -> PyObject,
        {
            if let Ok(Some(val)) = result {
                let _ = dict.set_item(key, f(&val));
            }
        }

        // Use the helper function to set items in the dictionary
        set_if_ok(&dict, "registration_id", self.registration_id().map(Some), |id| id.to_object(py));
        set_if_ok(&dict, "device_id", self.device_id().map(Some), |id: &DeviceId| id.get_id().to_object(py));
        set_if_ok(&dict, "pre_key_id", self.pre_key_id(), |key| key.get_id().to_object(py));
        set_if_ok(&dict, "pre_key_public", self.pre_key_public(), |key| key.to_base64().unwrap().to_object(py));
        set_if_ok(&dict, "signed_pre_key_id", self.signed_pre_key_id().map(Some), |val| val.get_id().to_object(py));
        set_if_ok(&dict, "signed_pre_key_public", self.signed_pre_key_public().map(Some), |val| val.to_base64().unwrap().to_object(py));
        set_if_ok(&dict, "signed_pre_key_sign", self.signed_pre_key_signature(py).map(Some), |_| base64::engine::general_purpose::STANDARD.encode(self.state.signed_pre_key_signature().unwrap()).to_object(py));
        set_if_ok(&dict, "identity_key_public", self.identity_key().map(Some), |val| val.to_base64().unwrap().to_object(py));
        set_if_ok(&dict, "kyber_pre_key_id", self.kyber_pre_key_id(), |id| id.get_id().to_object(py));
        set_if_ok(&dict, "kyber_pre_key_sign", self.kyber_pre_key_signature(), |sign| base64::engine::general_purpose::STANDARD.encode(sign).to_object(py));
        set_if_ok(&dict, "kyber_pre_key_public", self.kyber_pre_key_public(), |key| key.to_base64().unwrap().to_object(py));


        // match self.pre_key_id() {
        //     Ok(val) => {
        //         match val {
        //             Some(key) => {
        //                 let _ = dict.set_item("pre_key_id", key.get_id());
        //             },
        //             None => {}
        //         }
        //     },
        //     Err(_) => {}
        // }

        // match self.pre_key_public() {
        //     Ok(val) => {
        //         match val {
        //             Some(key) => {
        //                 let _ = dict.set_item("pre_key_public", key.to_base64().unwrap());
        //             },
        //             None => {}
        //         }
        //     },
        //     Err(_) => {}
        // }

        // match self.signed_pre_key_id() {
        //     Ok(val) => {
        //         let _ = dict.set_item("signed_pre_key_id", val.get_id());
        //     },
        //     Err(_) => {}
        // }

        // match self.signed_pre_key_public() {
        //     Ok(val) => {
        //         let _ = dict.set_item("signed_pre_key_public", val.to_base64().unwrap());
        //     },
        //     Err(_) => {}
        // }

        
        // // TODO: a bit ugly
        // match self.signed_pre_key_signature(py) {
        //     Ok(_) => {
        //         let _ = dict.set_item("signed_pre_key_sign", base64::engine::general_purpose::STANDARD.encode(
        //             self.state.signed_pre_key_signature().unwrap()
        //         ));
        //     },
        //     Err(_) => {}
        // }

        // match self.identity_key() {
        //     Ok(val) => {
        //         let _ = dict.set_item("identity_key_public", val.to_base64().unwrap());
        //     },
        //     Err(_) => {}
        // }

        // match self.kyber_pre_key_id() {
        //     Ok(val) => {
        //         match val {
        //             Some(id) => {
        //                 let _ = dict.set_item("kyber_pre_key_id", id.get_id());
        //             },
        //             None => {}
        //         }            
        //     },
        //     Err(_) => {}
        // }

        // match self.kyber_pre_key_signature() {
        //     Ok(val) => {
        //         match val {
        //             Some(sign) => {
        //                 let _ = dict.set_item("kyber_pre_key_sign", base64::engine::general_purpose::STANDARD.encode(sign));
        //             },
        //             None => {}
        //         }            
        //     },
        //     Err(_) => {}
        // }

        // // TODO: cleanup
        // match self.kyber_pre_key_public() {
        //     Ok(val) => {
        //         match val {
        //             Some(key) => {
        //                 let _ = dict.set_item("kyber_pre_key_public", key.to_base64().unwrap());
        //             },
        //             None => {}
        //         }
        //     },
        //     Err(_) => {}
        // }

        // dict.set_item("pre_key_public", )
        Ok(dict.into())
    }
}

impl Serialize for PreKeyBundle {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PreKeyBundle", 12)?;

        let rid = match self.registration_id() {
            Ok(val) => val,
            Err(err) => {
                return Err(serde::ser::Error::custom(
                    err.to_string(),
                ))
            }
        };

        let pk_id = match self.pre_key_id() {
            Ok(val) => val.unwrap(),
            Err(err) => {
                return Err(serde::ser::Error::custom(
                    err.to_string(),
                ))
            }
        };

        let pk = match self.pre_key_public() {
            Ok(val) => val.unwrap(),
            Err(err) => {
                return Err(serde::ser::Error::custom(
                    err.to_string(),
                ))
            }
        };

        let device_id = self.device_id().unwrap_or(DeviceId::from(0));

        _ = state.serialize_field("registration_id", &rid);
        _ = state.serialize_field("device_id", &device_id);
        _ = state.serialize_field("pre_key_id", &pk_id);
        _ = state.serialize_field("pre_key_public", &pk);
        // state.serialize_field(key, value)
        state.end()
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pub state: libsignal_protocol::PreKeyRecord,
}

#[pymethods]
impl PreKeyRecord {
    #[new]
    fn new(id: PreKeyId, keypair: &KeyPair) -> Self {
        let key = libsignal_protocol::KeyPair::new(keypair.key.public_key, keypair.key.private_key);
        PreKeyRecord {
            state: libsignal_protocol::PreKeyRecord::new(id.value, &key),
        }
    }

    #[staticmethod]
    fn deserialize(data: &[u8]) -> PyResult<Self> {
        match libsignal_protocol::PreKeyRecord::deserialize(data) {
            Ok(state) => Ok(PreKeyRecord { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn id(&self) -> Result<PreKeyId> {
        Ok(PreKeyId {
            value: self.state.id()?,
        })
    }

    fn key_pair(&self) -> Result<KeyPair> {
        Ok(KeyPair {
            key: self.state.key_pair()?,
        })
    }

    fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            key: self.state.public_key()?,
        })
    }

    fn private_key(&self) -> Result<PrivateKey> {
        Ok(PrivateKey::new(self.state.private_key()?))
    }

    fn serialize(&self, py: Python) -> Result<PyObject> {
        let result = self.state.serialize()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

/// Helper function for generating N prekeys.
/// Returns a list of PreKeyRecords.
///
/// # Example
///
/// ```
/// from signal_protocol import curve, state
///
/// prekeyid = 1
/// manykeys = state.generate_n_prekeys(100, prekeyid)  # generates 100 keys
/// ```
#[pyfunction]
pub fn generate_n_prekeys(n: u16, id: PreKeyId) -> Vec<PreKeyRecord> {
    let mut keyvec: Vec<PreKeyRecord> = Vec::new();
    let mut i: u32 = u32::from(id);
    for _n in 0..n {
        let keypair = KeyPair::generate();
        let prekey = PreKeyRecord::new(PreKeyId::from(i), &keypair);
        keyvec.push(prekey);
        i += 1;
    }

    keyvec
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct SignedPreKeyRecord {
    pub state: libsignal_protocol::SignedPreKeyRecord,
}

#[pymethods]
impl SignedPreKeyRecord {
    #[new]
    fn new(id: SignedPreKeyId, timestamp: u64, keypair: &KeyPair, signature: &[u8]) -> Self {
        let key = libsignal_protocol::KeyPair::new(keypair.key.public_key, keypair.key.private_key);
        SignedPreKeyRecord {
            state: libsignal_protocol::SignedPreKeyRecord::new(
                id.value, timestamp, &key, &signature,
            ),
        }
    }

    #[staticmethod]
    fn deserialize(data: &[u8]) -> PyResult<Self> {
        match libsignal_protocol::SignedPreKeyRecord::deserialize(data) {
            Ok(state) => Ok(SignedPreKeyRecord { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn id(&self) -> Result<SignedPreKeyId> {
        Ok(SignedPreKeyId {
            value: (self.state.id()?),
        })
    }

    fn timestamp(&self) -> Result<u64> {
        Ok(self.state.timestamp()?)
    }

    fn signature(&self, py: Python) -> Result<PyObject> {
        let sig = self.state.signature()?;
        Ok(PyBytes::new(py, &sig).into())
    }

    fn key_pair(&self) -> Result<KeyPair> {
        Ok(KeyPair {
            key: self.state.key_pair()?,
        })
    }

    fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            key: self.state.public_key()?,
        })
    }

    fn private_key(&self) -> Result<PrivateKey> {
        Ok(PrivateKey {
            key: self.state.private_key()?,
        })
    }

    fn serialize(&self, py: Python) -> Result<PyObject> {
        let result = self.state.serialize()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

#[pyclass]
#[derive(Clone)]
pub struct SessionRecord {
    pub state: libsignal_protocol::SessionRecord,
}

/// session_state_mut() is not exposed as part of the Python API.
#[pymethods]
impl SessionRecord {
    #[staticmethod]
    pub fn new_fresh() -> Self {
        SessionRecord {
            state: libsignal_protocol::SessionRecord::new_fresh(),
        }
    }

    #[staticmethod]
    fn deserialize(bytes: &[u8]) -> PyResult<Self> {
        match libsignal_protocol::SessionRecord::deserialize(bytes) {
            Ok(state) => Ok(SessionRecord { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn archive_current_state(&mut self) -> Result<()> {
        self.state.archive_current_state()?;
        Ok(())
    }

    fn serialize(&self, py: Python) -> Result<PyObject> {
        let result = self.state.serialize()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn session_version(&self) -> Result<u32> {
        Ok(self.state.session_version()?)
    }

    fn remote_registration_id(&self) -> Result<u32> {
        Ok(self.state.remote_registration_id()?)
    }

    fn local_registration_id(&self) -> Result<u32> {
        Ok(self.state.local_registration_id()?)
    }

    fn local_identity_key_bytes(&self, py: Python) -> Result<PyObject> {
        let result = self.state.local_identity_key_bytes()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn remote_identity_key_bytes(&self, py: Python) -> Result<Option<PyObject>> {
        match self.state.remote_identity_key_bytes()? {
            Some(result) => Ok(Some(PyBytes::new(py, &result).into())),
            None => Ok(None),
        }
    }

    // Returns bytes instead of ChainKey
    pub fn get_receiver_chain_key_bytes(
        &self,
        sender: &PublicKey,
        py: Python,
    ) -> Result<Option<PyObject>> {
        match self.state.get_receiver_chain_key_bytes(&sender.key)? {
            Some(result) => Ok(Some(PyBytes::new(py, &result[..]).into())),
            None => Ok(None),
        }
    }

    // TODO: should SystemTime be exposed?
    fn has_usable_sender_chain(&self) -> Result<bool> {
        let now = std::time::SystemTime::now();
        Ok(self.state.has_usable_sender_chain(now)?)
    }

    fn alice_base_key(&self, py: Python) -> Result<PyObject> {
        let result = self.state.alice_base_key()?;
        Ok(PyBytes::new(py, &result).into())
    }

    fn get_sender_chain_key_bytes(&self, py: Python) -> Result<PyObject> {
        let result = self.state.get_sender_chain_key_bytes()?;
        Ok(PyBytes::new(py, &result).into())
    }
}

#[pyclass]
#[derive(Clone)]
pub struct KyberPreKeyRecord {
    pub state: libsignal_protocol::KyberPreKeyRecord,
}

#[pymethods]
impl KyberPreKeyRecord {
    /// TODO: implement KyberPreKeyRecord
    #[staticmethod]
    pub fn generate(
        key_type: kem::KeyType,
        id: KyberPreKeyId,
        signing_key: PrivateKey,
    ) -> PyResult<Self> {
        let record = libsignal_protocol::KyberPreKeyRecord::generate(
            key_type.key_type,
            id.value,
            &signing_key.key,
        );
        match record {
            Ok(r) => Ok(KyberPreKeyRecord { state: r }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    fn get_storage(&self) -> PyResult<KyberPreKeyRecord> {
        let upstream = self.state.get_storage();
        let ik = libsignal_protocol::kem::KeyPair::from_public_and_private(
            &upstream.public_key,
            &upstream.private_key,
        );

        let upstream_state = libsignal_protocol::KyberPreKeyRecord::new(
            upstream.id.into(),
            upstream.timestamp,
            &ik.unwrap(),
            &upstream.signature,
        );

        Ok(KyberPreKeyRecord {
            state: upstream_state,
        })
    }

    pub fn secret_key(&self) -> PyResult<SecretKey> {
        let sk = self.state.secret_key();
        match sk {
            Ok(key) => Ok(SecretKey { key: key }),
            Err(_) => Err(SignalProtocolError::err_from_str(
                "no secret key. have you generated one?".to_string(),
            )),
        }
    }
}

/// UnacknowledgedPreKeyMessageItems is not exposed as part of the upstream public API.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<PreKeyBundle>()?;
    module.add_class::<PreKeyRecord>()?;
    module.add_class::<SessionRecord>()?;
    module.add_class::<SignedPreKeyRecord>()?;
    module.add_class::<KyberPreKeyRecord>()?;
    module.add_class::<PreKeyId>()?;
    module.add_class::<SignedPreKeyId>()?;
    module.add_class::<KyberPreKeyId>()?;
    module.add_class::<PreKeysUsed>()?;
    module
        .add_function(wrap_pyfunction!(generate_n_prekeys, module)?)
        .unwrap();
    Ok(())
}

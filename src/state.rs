use libsignal_protocol::GenericSignedPreKey;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::wrap_pyfunction;

use crate::address::DeviceId;
use crate::curve::{KeyPair, PrivateKey, PublicKey};
use crate::error::{Result, SignalProtocolError};
use crate::identity_key::IdentityKey;

use std::convert;

// Newtypes from upstream crate not exposed as part of the public API
#[pyclass]
#[derive(Clone, Debug)]
pub struct SignedPreKeyId {
    pub value: libsignal_protocol::SignedPreKeyId,
}
// todo: handle impl
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
}

// pub type PreKeyId = u32;

#[pyclass]
#[derive(Clone, Debug)]
pub struct PreKeyId {
    pub value: libsignal_protocol::PreKeyId,
}
// todo: handle impl
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

#[pymethods]
impl PreKeyId {
    #[new]
    fn new(id: u32) -> PreKeyId {
        PreKeyId {
            value: libsignal_protocol::PreKeyId::from(id),
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct KyberPreKeyId {
    pub value: libsignal_protocol::KyberPreKeyId,
}
// todo: handle impl

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
    #[new]
    #[pyo3(signature = (registration_id, device_id, pre_key_public,signed_pre_key_id,signed_pre_key_public,signed_pre_key_signature,identity_key))]
    fn new(
        registration_id: u32,
        device_id: DeviceId,
        // pre_key_id: Option<PreKeyId>,
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
                id.value,
                libsignal_protocol::Timestamp::from_epoch_millis(timestamp),
                &key,
                &signature,
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
        Ok(self.state.timestamp()?.epoch_millis())
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

    // todo: should SystemTime be exposed?
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

/// todo: implement KyberPreKeyRecord

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

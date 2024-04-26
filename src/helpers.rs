use base64::Engine;
use libsignal_protocol::GenericSignedPreKey;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rand::Rng;
use rand::rngs::OsRng;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{kem::KeyType, curve::KeyPair, error::SignalProtocolError, identity_key, state::{KyberPreKeyId, KyberPreKeyRecord, SignedPreKeyId, SignedPreKeyRecord}};

use std::convert;

struct UploadKeyType {
    key_id: u32,
    public_key: Vec<u8>,
    signature: Option<Vec<u8>>
}

impl convert::From<SignedPreKeyRecord> for UploadKeyType {
    fn from(value: SignedPreKeyRecord) -> Self {
        UploadKeyType {
            key_id: u32::from(value.id().unwrap()),
            public_key: value.state.public_key().unwrap().serialize().to_vec(),
            signature: Some(value.state.signature().unwrap())
        }
    }
}

impl convert::From<KyberPreKeyRecord> for UploadKeyType {
    fn from(value: KyberPreKeyRecord) -> Self {
        UploadKeyType {
            key_id: u32::from(value.state.id().unwrap()),
            public_key: value.state.public_key().unwrap().serialize().to_vec(),
            signature: Some(value.state.signature().unwrap())
        }
    }
}

impl UploadKeyType {
    fn to_py_dict(&self, py: Python) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("keyId", self.key_id)?;
        dict.set_item("publicKey", base64::engine::general_purpose::STANDARD.encode(&self.public_key))?.to_object(py);
        if let Some(signature) = &self.signature {
            dict.set_item("signature", base64::engine::general_purpose::STANDARD.encode(signature))?.to_object(py);
        }
        Ok(dict.into())
    }
}


#[pyfunction]
pub fn create_registration_keys(py: Python, key_kind: &str, ik: identity_key::IdentityKeyPair, spk_data: Option<SignedPreKeyRecord>) -> PyResult<PyObject> {
    match key_kind {
        "aci" | "pni" => {},
        _ => return Err(SignalProtocolError::err_from_str("invalid keyType - only aci and pni are supported".to_string())),
    };
    let dict = PyDict::new(py);
    let id_b64 = match ik.public_key() {
        Ok(res) => match res.to_base64() {
            Ok(encoded) => dict.set_item("identity_key", encoded),
            Err(err) => return Err(SignalProtocolError::err_from_str(err.to_string()))
        },
        Err(err) => return Err(SignalProtocolError::err_from_str(err.to_string()))
    };

    let spk = match spk_data {
        Some(spk) => spk,
        None => {
            let keypair = KeyPair::generate();
            let random_number: u32 = rand::thread_rng().gen_range(100..10000);
            
            // generate spk record
            let id = SignedPreKeyId::new(random_number);
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            
            let mut csprng: OsRng = OsRng;
            let sig = ik.key.private_key().calculate_signature(&keypair.key.public_key.serialize(), &mut csprng);
            let new_spk = SignedPreKeyRecord::new(id, ts, &keypair, &sig.unwrap());
            // keep track of the private key
            // TODO: also must be outputted
            new_spk
        }
    };
    dict.set_item(format!("{}SignedPreKey", key_kind), UploadKeyType::from(spk).to_py_dict(py)?);

    let random_number: u32 = rand::thread_rng().gen_range(100..10000);
    let id = KyberPreKeyId::new(random_number);
    let key_type = KeyType::new(0)?;
    // TODO: pq must also be outputted
    let pq = KyberPreKeyRecord::generate(key_type, id, ik.private_key()?)?;

    dict.set_item(format!("{}PqLastResortPreKey", key_kind), UploadKeyType::from(pq).to_py_dict(py)?);
    
    Ok(dict.into())
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(create_registration_keys))?;
    Ok(())
}

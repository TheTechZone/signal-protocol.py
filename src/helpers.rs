/// This module contains helper functions for key generation and registration in the Signal Protocol.
/// It provides functions to create registration keys, bundle them into dictionaries, and generate
/// one-time keys for client-server communication.
///
/// The main functions in this module are:
/// - `create_registration_keys`: Creates the necessary keys for the registration endpoint, including
///   the signed prekey and PqLastResortPreKey, and returns them as a tuple of dictionaries along with
///   the identity key.
/// - `create_registration`: Bundles the registration keys and secrets for aci and pni into a single
///   dictionary for each.
/// - `create_keys_data`: Generates a specified number of one-time keys (PreKeys) for the client to
///   upload to the server, and returns them as a tuple of dictionaries along with the secrets.
use base64::Engine;
use libsignal_protocol::GenericSignedPreKey;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rand::rngs::OsRng;
use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    curve::KeyPair,
    error::SignalProtocolError,
    identity_key,
    kem::{KeyPair as KemKeyPair, KeyType},
    state::{
        generate_n_prekeys, generate_n_signed_kyberkeys, KyberPreKeyId, KyberPreKeyRecord,
        PreKeyId, PreKeyRecord, SignedPreKeyId, SignedPreKeyRecord,
    },
};

use std::convert;

struct UploadKeyType {
    key_id: u32,
    public_key: Vec<u8>,
    signature: Option<Vec<u8>>,
}

impl convert::From<PreKeyRecord> for UploadKeyType {
    fn from(value: PreKeyRecord) -> Self {
        UploadKeyType {
            key_id: u32::from(value.state.id().unwrap()),
            public_key: value.state.public_key().unwrap().serialize().to_vec(),
            signature: None,
        }
    }
}

impl convert::From<SignedPreKeyRecord> for UploadKeyType {
    fn from(value: SignedPreKeyRecord) -> Self {
        UploadKeyType {
            key_id: u32::from(value.id().unwrap()),
            public_key: value.state.public_key().unwrap().serialize().to_vec(),
            signature: Some(value.state.signature().unwrap()),
        }
    }
}

impl convert::From<KyberPreKeyRecord> for UploadKeyType {
    fn from(value: KyberPreKeyRecord) -> Self {
        UploadKeyType {
            key_id: u32::from(value.state.id().unwrap()),
            public_key: value.state.public_key().unwrap().serialize().to_vec(),
            signature: Some(value.state.signature().unwrap()),
        }
    }
}

impl UploadKeyType {
    fn to_py_dict(&self, py: Python) -> PyResult<Py<PyDict>> {
        let dict: &PyDict = PyDict::new(py);
        dict.set_item("keyId", self.key_id)?;
        dict.set_item(
            "publicKey",
            base64::engine::general_purpose::STANDARD.encode(&self.public_key),
        )?
        .to_object(py);
        if let Some(signature) = &self.signature {
            dict.set_item(
                "signature",
                base64::engine::general_purpose::STANDARD.encode(signature),
            )?
            .to_object(py);
        }
        Ok(dict.into())
    }
}

fn merge_dicts(dict1: &PyDict, dict2: &PyDict) -> PyResult<()> {
    for (key, value) in dict2.iter() {
        dict1.set_item(key, value)?;
    }
    Ok(())
}

/// create_registration_keys creates the necessary keys for
/// the registration endpoint (specifically signedPreKey and PqLastResortPreKey)
/// and returns them as a tuple of dictionaries along with the identity key (keys, secrets).
/// The keys are returned as a dictionary with the following keys:
/// - IdentityKey
/// - SignedPreKey
/// - PqLastResortPreKey
#[pyfunction]
pub fn create_registration_keys(
    py: Python,
    key_kind: &str,
    ik: identity_key::IdentityKeyPair,
    spk_data: Option<SignedPreKeyRecord>,
    pq_data: Option<KyberPreKeyRecord>,
    spk_id: Option<u32>,
    pq_id: Option<u32>,
) -> PyResult<(PyObject, PyObject)> {
    match key_kind {
        "aci" | "pni" => {}
        _ => {
            return Err(SignalProtocolError::err_from_str(
                "invalid keyType - only aci and pni are supported".to_string(),
            ))
        }
    };

    let dict = PyDict::new(py);
    let secrets = PyDict::new(py);

    _ = match ik.public_key() {
        Ok(res) => match res.to_base64() {
            Ok(encoded) => dict.set_item(format!("{}IdentityKey", key_kind), encoded),
            Err(err) => return Err(SignalProtocolError::err_from_str(err.to_string())),
        },
        Err(err) => return Err(SignalProtocolError::err_from_str(err.to_string())),
    };

    let spk = match spk_data {
        Some(spk) => spk,
        None => {
            let keypair = KeyPair::generate();

            // generate spk record
            let id =
                SignedPreKeyId::new(spk_id.unwrap_or(rand::thread_rng().gen_range(100..10000)));
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut csprng: OsRng = OsRng;
            let sig = ik
                .key
                .private_key()
                .calculate_signature(&keypair.key.public_key.serialize(), &mut csprng);
            let new_spk = SignedPreKeyRecord::new(id, ts, &keypair, &sig.unwrap());
            // keep track of the private key

            _ = secrets.set_item(
                format!("{}SignedPreKeySecret", key_kind),
                base64::engine::general_purpose::STANDARD
                    .encode(new_spk.state.private_key().unwrap().serialize()),
            );
            // TODO: also must be outputted
            new_spk
        }
    };

    _ = dict.set_item(
        format!("{}SignedPreKey", key_kind),
        UploadKeyType::from(spk).to_py_dict(py)?,
    );

    let pq = match pq_data {
        Some(pq) => pq,
        None => {
            let id: KyberPreKeyId =
                KyberPreKeyId::new(pq_id.unwrap_or(rand::thread_rng().gen_range(100..10000)));
            let key_type = KeyType::new(0)?;
            // TODO: pq must also be outputted
            let pq = KyberPreKeyRecord::generate(key_type, id, ik.private_key()?)?;
            _ = secrets.set_item(
                format!("{}PqLastResortSecret", key_kind),
                base64::engine::general_purpose::STANDARD
                    .encode(pq.state.secret_key().unwrap().serialize()),
            );
            pq
        }
    };

    _ = dict.set_item(
        format!("{}PqLastResortPreKey", key_kind),
        UploadKeyType::from(pq.clone()).to_py_dict(py)?,
    );

    Ok((dict.into(), secrets.into()))
}

/// create_registration bundles the registration keys and secrets for aci and pni
/// produced by create_registration_keys into a single dictionary for each.
/// The keys are returned as a dictionary with the following keys:
/// - aciIdentityKey
/// - aciSignedPreKey
/// - aciPqLastResortPreKey
/// - pniIdentityKey
/// - pniSignedPreKey
/// - pniPqLastResortPreKey
#[pyfunction]
pub fn create_registration(
    py: Python,
    aci_ik: identity_key::IdentityKeyPair,
    pni_ik: identity_key::IdentityKeyPair,
    aci_spk: Option<SignedPreKeyRecord>,
    pni_spk: Option<SignedPreKeyRecord>,
    aci_kyber: Option<KyberPreKeyRecord>,
    pni_kyber: Option<KyberPreKeyRecord>,
    aci_spk_id: Option<u32>,
    pni_spk_id: Option<u32>,
    aci_kyber_id: Option<u32>,
    pni_kyber_id: Option<u32>,
) -> PyResult<(PyObject, PyObject)> {
    let (aci_keys, aci_secrets) = create_registration_keys(
        py,
        "aci",
        aci_ik,
        aci_spk,
        aci_kyber,
        aci_spk_id,
        aci_kyber_id,
    )?;
    let (pni_keys, pni_secrets) = create_registration_keys(
        py,
        "pni",
        pni_ik,
        pni_spk,
        pni_kyber,
        pni_spk_id,
        pni_kyber_id,
    )?;

    let aci_dict = aci_keys.downcast::<PyDict>(py)?;
    let pni_dict = pni_keys.downcast::<PyDict>(py)?;

    let aci_sdict = aci_secrets.downcast::<PyDict>(py)?;
    let pni_sdict = pni_secrets.downcast::<PyDict>(py)?;

    _ = merge_dicts(aci_dict, pni_dict);
    _ = merge_dicts(aci_sdict, pni_sdict);
    Ok((aci_keys.into(), aci_sdict.into()))
}

/// create_keys_data generates the specified number of one-time keys (PreKeys) for the client to
/// upload to the server, and returns them as a tuple of dictionaries along with the secrets.
/// This function is associated with the endpoint /v2/keys/.
#[pyfunction]
pub fn create_keys_data(
    py: Python,
    num_keys: u16,
    ik: identity_key::IdentityKeyPair,
    spk: Option<KeyPair>,
    last_resort_pqk: Option<KemKeyPair>,
    prekey_start_at: Option<u32>,
    kyber_prekey_start_at: Option<u32>,
) -> PyResult<(PyObject, PyObject)> {
    let dict = PyDict::new(py);
    match spk {
        Some(key) => {
            let _ = dict.set_item("signedPreKey", key.public_key()?.to_base64()?);
        }
        None => {
            let _ = dict.set_item("signedPreKey", py.None());
        }
    }
    match last_resort_pqk {
        Some(key) => {
            _ = dict.set_item("pqLastResortPreKey", key.get_public().to_base64()?);
        }
        None => {
            _ = dict.set_item("pqLastResortPreKey", py.None());
        }
    }

    let pre_keys = generate_n_prekeys(num_keys, PreKeyId::from(prekey_start_at.unwrap_or(0)));
    let kyber_keys = generate_n_signed_kyberkeys(
        num_keys,
        KyberPreKeyId::from(kyber_prekey_start_at.unwrap_or(0)),
        ik.private_key()?,
    );

    let secrets_dict = PyDict::new(py);
    let secrets_prekeys = PyDict::new(py);
    let secrets_kyber = PyDict::new(py);

    let mut prekey_vec: Vec<Py<PyDict>> = Vec::new();

    let mut kyberkey_vec: Vec<Py<PyDict>> = Vec::new();

    for k in pre_keys {
        prekey_vec.push(UploadKeyType::from(k.clone()).to_py_dict(py).unwrap());

        // TODO: a bit hacky
        _ = secrets_prekeys.set_item(
            format!("{}", u32::from(k.id()?)),
            base64::engine::general_purpose::STANDARD
                .encode(k.state.private_key().unwrap().serialize()),
        );
    }
    for k in kyber_keys {
        kyberkey_vec.push(UploadKeyType::from(k.clone()).to_py_dict(py).unwrap());

        // TODO: a bit hacky
        _ = secrets_kyber.set_item(
            format!("{}", u32::from(k.state.id().unwrap())),
            base64::engine::general_purpose::STANDARD
                .encode(k.state.secret_key().unwrap().serialize()),
        );
    }

    _ = dict.set_item("preKeys", prekey_vec);
    _ = dict.set_item("pqPreKeys", kyberkey_vec);

    _ = secrets_dict.set_item("preKeys", secrets_prekeys);
    _ = secrets_dict.set_item("pqPreKeys", secrets_kyber);

    Ok((dict.into(), secrets_dict.into()))
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(create_registration_keys))?;
    module.add_wrapped(wrap_pyfunction!(create_registration))?;
    module.add_wrapped(wrap_pyfunction!(create_keys_data))?;
    Ok(())
}

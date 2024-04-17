use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use rand::rngs::OsRng;

use crate::curve::{KeyPair, PublicKey};
use crate::error::Result;
use crate::identity_key::{IdentityKey, IdentityKeyPair};
use crate::kem::KeyPair as KemKeyPair;
use crate::kem::PublicKey as KemPublicKey;
use crate::kem::SerializedCiphertext;
use crate::state::SessionRecord;

#[pyclass]
pub struct AliceSignalProtocolParameters {
    inner: libsignal_protocol::AliceSignalProtocolParameters,
}

#[pymethods]
impl AliceSignalProtocolParameters {
    #[new]
    #[pyo3(signature = (our_identity_key_pair,our_base_key_pair,their_identity_key,their_signed_pre_key,_their_one_time_pre_key,their_ratchet_key,_their_kyber_pre_key))]
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        _their_one_time_pre_key: Option<PublicKey>, // todo: wth libsignal ignores this and kyber? :/
        their_ratchet_key: PublicKey,
        _their_kyber_pre_key: Option<crate::kem::PublicKey>, // todo: wth libsignal ignores this? :/
    ) -> Self {
        let _upstream_their_one_time_pre_key = match _their_one_time_pre_key {
            None => None,
            Some(x) => Some(x.key),
        };

        let _upstream_their_kyber_pre_key = match _their_kyber_pre_key {
            None => None,
            Some(x) => Some(x.key),
        };

        let mut inner = libsignal_protocol::AliceSignalProtocolParameters::new(
            our_identity_key_pair.key,
            our_base_key_pair.key,
            their_identity_key.key,
            their_signed_pre_key.key,
            their_ratchet_key.key,
        );

        if _upstream_their_one_time_pre_key.is_some() {
            inner.set_their_one_time_pre_key(_upstream_their_one_time_pre_key.unwrap())
        }

        if _upstream_their_kyber_pre_key.is_some() {
            inner.set_their_kyber_pre_key(&_upstream_their_kyber_pre_key.unwrap())
        }

        Self { inner: inner }
    }

    pub fn our_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(IdentityKeyPair {
            key: *self.inner.our_identity_key_pair(),
        })
    }

    pub fn our_base_key_pair(&self) -> Result<KeyPair> {
        Ok(KeyPair {
            key: *self.inner.our_base_key_pair(),
        })
    }

    pub fn their_identity_key(&self) -> Result<IdentityKey> {
        Ok(IdentityKey {
            key: *self.inner.their_identity_key(),
        })
    }

    pub fn their_signed_pre_key(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            key: *self.inner.their_signed_pre_key(),
        })
    }

    pub fn their_one_time_pre_key(&self) -> Result<Option<PublicKey>> {
        let key = match self.inner.their_one_time_pre_key() {
            None => return Ok(None),
            Some(key) => key,
        };

        Ok(Some(PublicKey { key: *key }))
    }

    pub fn their_kyber_pre_key(&self) -> Result<Option<KemPublicKey>> {
        let key: &libsignal_protocol::kem::Key<libsignal_protocol::kem::Public> =
            match self.inner.their_kyber_pre_key() {
                None => return Ok(None),
                Some(key) => key,
            };

        Ok(Some(KemPublicKey { key: key.clone() }))
    }

    pub fn their_ratchet_key(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            key: *self.inner.their_ratchet_key(),
        })
    }
}

#[pyfunction]
pub fn initialize_alice_session(
    parameters: &AliceSignalProtocolParameters,
) -> Result<SessionRecord> {
    let mut csprng = OsRng;
    let state =
        libsignal_protocol::initialize_alice_session_record(&parameters.inner, &mut csprng)?;
    Ok(SessionRecord { state })
}

#[pyclass]
pub struct BobSignalProtocolParameters {
    inner: libsignal_protocol::BobSignalProtocolParameters<'static>,
}

#[pymethods]
impl BobSignalProtocolParameters {
    #[new]
    #[pyo3(signature = (our_identity_key_pair,our_signed_pre_key_pair,our_one_time_pre_key_pair,our_ratchet_key_pair,our_kyber_pre_key_pair,their_identity_key,their_base_key,their_kyber_ciphertext))]
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Option<KeyPair>,
        our_ratchet_key_pair: KeyPair,
        our_kyber_pre_key_pair: Option<KemKeyPair>,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
        their_kyber_ciphertext: Option<SerializedCiphertext>, // todo:deal with this
    ) -> Self {
        let upstream_our_one_time_pre_key_pair = match our_one_time_pre_key_pair {
            None => None,
            Some(x) => Some(x.key),
        };

        let upstream_our_kyber_pre_key_pair = match our_kyber_pre_key_pair {
            None => None,
            Some(x) => Some(x.key),
        };

        let kyberctxt: Option<&'static Box<[u8]>> = match their_kyber_ciphertext {
            None => None,
            Some(ctxt) => Some(Box::leak(Box::new(
                ctxt.state.into_vec().clone().into_boxed_slice(),
            ))),
        };

        // below lines compiled

        /// let kyberctxt: Box<Box<[u8]>> = Box::new(
        ///     their_kyber_ciphertext
        ///         .unwrap()
        ///         .state
        ///         .into_vec()
        ///         .clone()
        ///         .into_boxed_slice(),
        /// );

        // unsafe {

        /// let kyberctxt_leak: &'static Box<[u8]> = Box::leak(kyberctxt); // aaa
        // }
        // let kyberctxt_box = Box::new(kyberctxt_leak.into());
        // let kyberctxt = match  their_kyber_ciphertext {
        //     None => None,
        //     Some(x) => Some(Box::new(&(*Box::leak(x.state.into_vec().clone().into_boxed_slice()))))// .clone().into_boxed_slice())
        // };
        Self {
            inner: libsignal_protocol::BobSignalProtocolParameters::new(
                our_identity_key_pair.key,
                our_signed_pre_key_pair.key,
                upstream_our_one_time_pre_key_pair,
                our_ratchet_key_pair.key,
                upstream_our_kyber_pre_key_pair,
                their_identity_key.key,
                their_base_key.key,
                kyberctxt,
            ),
        }
    }

    pub fn our_identity_key_pair(&self) -> Result<IdentityKeyPair> {
        Ok(IdentityKeyPair {
            key: *self.inner.our_identity_key_pair(),
        })
    }

    pub fn our_signed_pre_key_pair(&self) -> Result<KeyPair> {
        Ok(KeyPair {
            key: *self.inner.our_signed_pre_key_pair(),
        })
    }

    pub fn our_one_time_pre_key_pair(&self) -> Result<Option<KeyPair>> {
        let keypair = match self.inner.our_one_time_pre_key_pair() {
            None => return Ok(None),
            Some(keypair) => keypair,
        };

        Ok(Some(KeyPair { key: *keypair }))
    }

    pub fn our_ratchet_key_pair(&self) -> Result<KeyPair> {
        Ok(KeyPair {
            key: *self.inner.our_ratchet_key_pair(),
        })
    }

    pub fn our_kyber_pre_key_pair(&self) -> Result<Option<KemKeyPair>> {
        let keypair = match self.inner.our_kyber_pre_key_pair() {
            None => return Ok(None),
            Some(keypair) => keypair,
        };

        Ok(Some(KemKeyPair {
            key: keypair.clone(),
        }))
    }

    pub fn their_identity_key(&self) -> Result<IdentityKey> {
        Ok(IdentityKey {
            key: *self.inner.their_identity_key(),
        })
    }

    pub fn their_base_key(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            key: *self.inner.their_base_key(),
        })
    }

    pub fn their_kyber_ciphertext(&self) -> Result<Option<&[u8]>> {
        let ctxt = match self.inner.their_kyber_ciphertext() {
            None => return Ok(None),
            Some(c) => c,
        };
        Ok(Some(&ctxt))
    }
}

#[pyfunction]
pub fn initialize_bob_session(parameters: &BobSignalProtocolParameters) -> Result<SessionRecord> {
    let state = libsignal_protocol::initialize_bob_session_record(&parameters.inner)?;
    Ok(SessionRecord { state })
}

/// fn are_we_alice, ChainKey, RootKey, MessageKey are not exposed as part of the Python API.
pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<AliceSignalProtocolParameters>()?;
    module.add_wrapped(wrap_pyfunction!(initialize_alice_session))?;
    module.add_class::<BobSignalProtocolParameters>()?;
    module.add_wrapped(wrap_pyfunction!(initialize_bob_session))?;
    Ok(())
}

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use crate::address::ProtocolAddress;
use crate::error::Result;
use crate::protocol::PreKeySignalMessage;
use futures::executor::block_on;
use rand::TryRngCore as _;
// use crate::state::SystemTime;
use crate::state::{KyberPreKeyId, PreKeyBundle, PreKeyId, PreKeysUsed, SessionRecord};
use crate::storage::InMemSignalProtocolStore;

#[pyfunction]
pub fn process_prekey(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_record: &mut SessionRecord,
    protocol_store: &mut InMemSignalProtocolStore,
) -> Result<Option<PreKeysUsed>> {
    let (result, _identity_to_save) = match block_on(libsignal_protocol::process_prekey(
        &message.data,
        &remote_address.state,
        &mut session_record.state,
        &mut protocol_store.store.identity_store,
        &mut protocol_store.store.pre_key_store,
        &mut protocol_store.store.signed_pre_key_store,
        &mut protocol_store.store.kyber_pre_key_store,
    )) {
        Ok((result, identity)) => match result {
            Some(result) => (result, identity),
            None => return Ok(None),
        },
        Err(_err) => return Ok(None),
    };

    let pre_key_id = result.one_time_ec_pre_key_id;
    let signed_pre_key_id = result.signed_ec_pre_key_id;
    let kyber_key_id = result.kyber_pre_key_id;

    let pk_id = match pre_key_id {
        Some(pre_key_id) => Some(PreKeyId { value: pre_key_id }),
        None => None,
    };

    let ky_id: Option<KyberPreKeyId> = match kyber_key_id {
        Some(kyber_key_id) => Some(KyberPreKeyId {
            value: kyber_key_id,
        }),
        None => None,
    };

    let pre_keys_used = PreKeysUsed {
        pre_key_id: pk_id,
        kyber_pre_key_id: ky_id,
    };
    Ok(Some(pre_keys_used))
}

#[pyfunction]
pub fn process_prekey_bundle(
    remote_address: ProtocolAddress,
    protocol_store: &mut InMemSignalProtocolStore,
    bundle: PreKeyBundle,
    // now: SystemTime, // TODO: should SystemTime be exposed?
) -> Result<()> {
    let mut csprng = rand::rngs::OsRng.unwrap_err();

    let now2 = std::time::SystemTime::now();
    block_on(libsignal_protocol::process_prekey_bundle(
        &remote_address.state,
        &mut protocol_store.store.session_store,
        &mut protocol_store.store.identity_store,
        &bundle.state,
        now2,
        &mut csprng,
    ))?;
    Ok(())
}

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(process_prekey_bundle))?;
    module.add_wrapped(wrap_pyfunction!(process_prekey))?;
    Ok(())
}

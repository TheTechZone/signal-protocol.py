use pyo3::prelude::*;
use pyo3::types::PyBytes;


use crate::error::SignalProtocolError;

/// Generate a private key of size `bits` and export to a specified format.
/// 
/// Arguments:
///     bits - the bitlength of the key (optional: defaults to 4096)
///     key_format - key format (optional: defaults to )
#[pyfunction]
pub fn create_rsa_private_key(py: Python, bits: Option<usize>, key_format: Option<u8>) -> PyResult<PyObject>{
    let kf = device_transfer::KeyFormat::from(key_format.unwrap_or(0));
    match device_transfer::create_rsa_private_key(bits.unwrap_or(4096), kf) {
        Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
        Ok(key) => Ok(PyBytes::new(py, &key).into())
    }
}

/// Generate a self-signed certificate of name `name`, expiring in `days_to_expire`.
///
/// `rsa_key_pkcs8` should be the output of `create_rsa_private_key`. 
#[pyfunction]
pub fn create_self_signed_cert(py: Python, rsa_key_pkcs8: &[u8], name: &str, days_to_expire: u32) -> PyResult<PyObject>{
    match device_transfer::create_self_signed_cert(rsa_key_pkcs8, name, days_to_expire){
        Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
        Ok(key) => Ok(PyBytes::new(py, &key).into())
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_wrapped(wrap_pyfunction!(create_rsa_private_key))?;
    module.add_wrapped(wrap_pyfunction!(create_self_signed_cert))?;
    Ok(())
}
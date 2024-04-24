use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::SignalProtocolError;

/// This library provides two pin hashing mechanisms:
///   1. Transforming a pin to be suitable for use with a Secure Value Recovery service. The pin
///      is hashed with Argon2 into 64 bytes. One half of these bytes are provided to the service
///      as a password protecting some arbitrary data. The other half is used as an encryption key
///      for that data. See `PinHash`
///   2. Creating a [PHC-string encoded](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#specification)
///      password hash of the pin that can be stored locally and validated against the pin later.
///
/// In either case, all pins are UTF-8 encoded bytes that must be normalized *before* being provided
/// to this library. Normalizing a string pin requires the following steps:
///  1. The string should be trimmed for leading and trailing whitespace.
///  2. If the whole string consists of digits, then non-arabic digits must be replaced with their
///     arabic 0-9 equivalents.
///  3. The string must then be [NFKD normalized](https://unicode.org/reports/tr15/#Norm_Forms)
#[pyclass]
#[derive(Clone, Debug)]
pub struct PinHash {
    inner: signal_pin::PinHash,
}

#[pymethods]
impl PinHash {
    /// Hash an arbitrary pin into an encryption key and access key that can be used to interact
    /// with a Secure Value Recovery service.
    ///
    /// # Arguments
    /// * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first.
    /// * `salt` - An arbitrary 32 byte value that should be unique to the user
    #[staticmethod]
    pub fn create(pin: &[u8], salt: &[u8]) -> PyResult<Self> {
        // upstream only takes a &[u8; 32] salt
        if salt.len() != 32 {
            return Err(SignalProtocolError::err_from_str(String::from(
                "Data length must be 32 bytes",
            )));
        }
        let salt2: &[u8; 32] = salt.try_into()?;
        // let array: &[u8; 32] = salt.try_into().map_err(|_| "Slice length must be 32 bytes");
        match signal_pin::PinHash::create(pin, salt2) {
            Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
            Ok(res) => Ok(PinHash { inner: res }),
        }
    }

    /// Create a salt from a username and the group id of the SVR service. This
    /// function should always be used to create pin salts for SVR2.
    ///
    /// # Arguments
    /// * `username` - The Basic Auth username credential retrieved from the chat service and used to authenticate with the SVR service
    /// * `group_id` - The attested group id returned by the SVR service
    #[staticmethod]
    pub fn make_salt(py: Python, username: &str, group_id: u64) -> PyObject {
        PyBytes::new(py, &signal_pin::PinHash::make_salt(username, group_id)).into()
    }

    /// Returns a key that can be used to encrypt or decrypt values before uploading
    /// them to a secure store.
    /// The 32 byte prefix of the 64 byte hashed pin.
    pub fn encryption_key(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.inner.encryption_key).into()
    }

    /// Returns a secret that can be used to access a value in a secure store. The 32 byte suffix of
    /// the 64 byte hashed pin.
    pub fn access_key(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.inner.access_key).into()
    }
}

/// Create a PHC encoded password hash string. This string may be verified later with
/// `verify_local_pin_hash`.
///
/// # Arguments
/// * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first.
#[pyfunction]
pub fn local_pin_hash(pin: &[u8]) -> PyResult<String> {
    match signal_pin::local_pin_hash(pin) {
        Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
        Ok(res) => Ok(res),
    }
}

/// Verify an encoded password hash against a pin
///
/// # Arguments
/// * `pin` - UTF-8 encoding of the pin. The pin *must* be normalized first.
/// * `encoded_hash` - A PHC-string formatted representation of the hash, as returned by `local_pin_hash`
#[pyfunction]
pub fn verify_local_pin_hash(encoded_hash: &str, pin: &[u8]) -> PyResult<bool> {
    match signal_pin::verify_local_pin_hash(encoded_hash, pin) {
        Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
        Ok(res) => Ok(res),
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<PinHash>()?;
    module.add_wrapped(wrap_pyfunction!(local_pin_hash))?;
    module.add_wrapped(wrap_pyfunction!(verify_local_pin_hash))?;
    Ok(())
}

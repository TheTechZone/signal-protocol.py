use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::SignalProtocolError;

#[pyclass]
pub struct Aes256GcmEncryption {
    // pub state: signal_crypto::Aes256GcmEncryption,
    key: Vec<u8>,
    nonce: Vec<u8>,
    associated_data: Vec<u8>,
}

#[pymethods]
impl Aes256GcmEncryption {
    #[new]
    /// Expect to have a 32bit key and 12bit nonce
    /// nonce must be unique for the (msg,key) combination
    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            nonce: nonce.to_vec(),
            associated_data: associated_data.to_vec(),
        }
    }

    pub fn encrypt_and_tag(&self, py: Python, data: &[u8]) -> PyResult<(PyObject, PyObject)> {
        let upstream =
            signal_crypto::Aes256GcmEncryption::new(&self.key, &self.nonce, &self.associated_data);
        let mut gcm_enc = match upstream {
            Ok(upstream) => upstream,
            Err(err) => return Err(SignalProtocolError::err_from_str(err.to_string())),
        };

        let mut buf: Vec<u8> = Vec::from(data).clone();
        gcm_enc.encrypt(&mut buf);
        let tag = gcm_enc.compute_tag();
        Ok((PyBytes::new(py, &buf).into(), PyBytes::new(py, &tag).into()))
    }
}

#[pyclass]
pub struct Aes256GcmDecryption {
    key: Vec<u8>,
    nonce: Vec<u8>,
    associated_data: Vec<u8>,
}

#[pymethods]
impl Aes256GcmDecryption {
    #[new]
    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            nonce: nonce.to_vec(),
            associated_data: associated_data.to_vec(),
        }
    }

    pub fn decrypt_and_verify(&self, py: Python, data: &[u8], tag: &[u8]) -> PyResult<PyObject> {
        let upstream =
            signal_crypto::Aes256GcmDecryption::new(&self.key, &self.nonce, &self.associated_data);

        let mut gcm_dec = match upstream {
            Ok(upstream) => upstream,
            Err(err) => return Err(SignalProtocolError::err_from_str(err.to_string())),
        };

        let mut buf: Vec<u8> = Vec::from(data).clone();
        gcm_dec.decrypt(&mut buf);
        match gcm_dec.verify_tag(tag) {
            Ok(_) => Ok(PyBytes::new(py, &buf).into()),
            Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
        }
    }
}

#[pyclass]
pub struct Aes256Ctr32 {
    inner: signal_crypto::Aes256Ctr32,
}

#[pymethods]
impl Aes256Ctr32 {
    #[new]
    pub fn new(key: &[u8], nonce: &[u8], init_ctr: u32) -> PyResult<Self> {
        match signal_crypto::Aes256Ctr32::from_key(key, nonce, init_ctr) {
            Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
            Ok(algo) => Ok(Self { inner: algo }),
        }
    }

    fn process(&mut self, py: Python, data: &[u8]) -> PyResult<PyObject> {
        let mut buf: Vec<u8> = Vec::from(data).clone();
        self.inner.process(&mut buf);
        Ok(PyBytes::new(py, &buf).into())
    }
}

#[pyfunction]
pub fn aes_256_gcm_encrypt(
    py: Python,
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
    associated_data: &[u8],
) -> PyResult<(PyObject, PyObject)> {
    let instance = Aes256GcmEncryption::new(key, iv, associated_data);
    instance.encrypt_and_tag(py, ptext)
}

#[pyfunction]
pub fn aes_256_gcm_decrypt(
    py: Python,
    ctext: &[u8],
    tag: &[u8],
    key: &[u8],
    iv: &[u8],
    associated_data: &[u8],
) -> PyResult<PyObject> {
    let instance = Aes256GcmDecryption::new(key, iv, associated_data);
    instance.decrypt_and_verify(py, ctext, tag)
}

#[pyfunction]
pub fn aes_256_cbc_encrypt(py: Python, ptext: &[u8], key: &[u8], iv: &[u8]) -> PyResult<PyObject> {
    match signal_crypto::aes_256_cbc_encrypt(ptext, key, iv) {
        Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
        Ok(ctxt) => Ok(PyBytes::new(py, &ctxt).into()),
    }
}

#[pyfunction]
pub fn aes_256_cbc_decrypt(py: Python, ctext: &[u8], key: &[u8], iv: &[u8]) -> PyResult<PyObject> {
    match signal_crypto::aes_256_cbc_decrypt(ctext, key, iv) {
        Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
        Ok(ctxt) => Ok(PyBytes::new(py, &ctxt).into()),
    }
}

#[pyclass]
pub struct CryptographicHash {
    pub inner: signal_crypto::CryptographicHash,
}

#[pymethods]
impl CryptographicHash {
    #[new]
    pub fn new(algo: &str) -> PyResult<Self> {
        match signal_crypto::CryptographicHash::new(algo) {
            Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
            Ok(hash_algo) => Ok(Self { inner: hash_algo }),
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.inner.update(input)
    }

    pub fn finalize(&mut self, py: Python) -> PyObject {
        let result = self.inner.finalize();
        PyBytes::new(py, &result).into()
    }
}

#[pyclass]
pub struct CryptographicMac {
    pub inner: signal_crypto::CryptographicMac,
}

#[pymethods]
impl CryptographicMac {
    #[new]
    pub fn new(algo: &str, key: &[u8]) -> PyResult<Self> {
        match signal_crypto::CryptographicMac::new(algo, key) {
            Err(err) => Err(SignalProtocolError::err_from_str(err.to_string())),
            Ok(hash_algo) => Ok(Self { inner: hash_algo }),
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.inner.update(input)
    }

    pub fn update_and_get(&mut self, input: &[u8]) -> Self {
        CryptographicMac {
            inner: self.inner.update_and_get(input).clone(),
        }
    }

    pub fn finalize(&mut self, py: Python) -> PyObject {
        let result = self.inner.finalize();
        PyBytes::new(py, &result).into()
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<Aes256GcmEncryption>()?;
    module.add_class::<Aes256GcmDecryption>()?;
    module.add_class::<Aes256Ctr32>()?;
    module.add_class::<CryptographicHash>()?;
    module.add_class::<CryptographicMac>()?;
    module.add_wrapped(wrap_pyfunction!(aes_256_cbc_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(aes_256_cbc_decrypt))?;
    module.add_wrapped(wrap_pyfunction!(aes_256_gcm_encrypt))?;
    module.add_wrapped(wrap_pyfunction!(aes_256_gcm_decrypt))?;
    Ok(())
}

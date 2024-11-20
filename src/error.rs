use pyo3::create_exception;
use pyo3::prelude::*;
use pyo3::PyErr;

use std::fmt;

pub type Result<T> = std::result::Result<T, SignalProtocolError>;

create_exception!(
    error,
    SignalProtocolException,
    pyo3::exceptions::PyException
);

#[pyclass]
#[derive(Debug)]
pub struct SignalProtocolError {
    pub err: libsignal_protocol::SignalProtocolError,
}

impl fmt::Display for SignalProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.err.to_string())
    }
}

impl From<SignalProtocolError> for PyErr {
    fn from(err: SignalProtocolError) -> Self {
        SignalProtocolException::new_err(err.to_string())
    }
}

impl From<libsignal_protocol::SignalProtocolError> for SignalProtocolError {
    fn from(err: libsignal_protocol::SignalProtocolError) -> Self {
        SignalProtocolError { err }
    }
}

impl SignalProtocolError {
    pub fn new(err: libsignal_protocol::SignalProtocolError) -> Self {
        Self { err }
    }

    pub fn err_from_str(err: String) -> PyErr {
        SignalProtocolException::new_err(err)
    }

    pub fn new_err(err: libsignal_protocol::SignalProtocolError) -> PyErr {
        let local_error = SignalProtocolError { err };
        SignalProtocolException::new_err(local_error.to_string())
    }

    pub fn into_py_err(err: libsignal_protocol::SignalProtocolError) -> PyErr {
        SignalProtocolError::new_err(err)
    }
}

pub fn init_submodule(py: Python, module: &Bound<'_, PyModule>) -> PyResult<()> {
    // module.add(
    //     "SignalProtocolException",
    //     py.get_type_bound()::<SignalProtocolException>(),
    // )?;
    module.add(
        "SignalProtocolException",
        py.get_type_bound::<SignalProtocolException>(),
    )?;
    Ok(())
}

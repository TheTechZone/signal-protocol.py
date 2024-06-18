use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::{Result, SignalProtocolError};

#[pyclass]
#[derive(Clone, Debug)]
pub struct SenderKeyRecord {
    pub state: libsignal_protocol::SenderKeyRecord,
}

/// as_protobuf are not implemented on the Python API.
#[pymethods]
impl SenderKeyRecord {
    // #[staticmethod]
    // pub fn new_empty() -> Self {
    //     Self {
    //         state: libsignal_protocol::SenderKeyRecord::new_empty(),
    //     }
    // }

    #[staticmethod]
    pub fn deserialize(buf: &[u8]) -> PyResult<Self> {
        match libsignal_protocol::SenderKeyRecord::deserialize(buf) {
            Ok(state) => Ok(Self { state }),
            Err(err) => Err(SignalProtocolError::new_err(err)),
        }
    }

    // TODO:: look into their api -- they broke most stuff here

    pub fn serialize(&self, py: Python) -> Result<PyObject> {
        let bytes = self.state.serialize()?;
        Ok(PyBytes::new(py, &bytes).into())
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    //module.add_class::<SenderKeyName>()?;
    module.add_class::<SenderKeyRecord>()?;
    Ok(())
}

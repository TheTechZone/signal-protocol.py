use pyo3::prelude::*;

use crate::sealed_sender::DeviceId;

#[pyclass]
#[derive(Clone, Debug)]
pub struct ProtocolAddress {
    pub state: libsignal_protocol::ProtocolAddress,
}

#[pymethods]
impl ProtocolAddress {
    #[new]
    fn new(name: String, device_id: DeviceId) -> ProtocolAddress {
        ProtocolAddress {
            state: libsignal_protocol::ProtocolAddress::new(name, device_id.value),
        }
    }

    pub fn name(&self) -> &str {
        self.state.name()
    }

    pub fn device_id(&self) -> u32 {
        u32::from(self.state.device_id())
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(String::from(format!(
            "{} {}",
            self.name(),
            self.device_id()
        )))
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(String::from(format!(
            "ProtocolAddress({}, {})",
            self.name(),
            self.device_id()
        )))
    }
}

pub fn init_submodule(module: &PyModule) -> PyResult<()> {
    module.add_class::<ProtocolAddress>()?;
    Ok(())
}

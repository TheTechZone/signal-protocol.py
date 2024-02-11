use pyo3::prelude::*;
use std::convert;

#[pyclass]
#[derive(Clone, Debug)]
pub struct DeviceId {
    pub value: libsignal_protocol::DeviceId,
}

impl convert::From<DeviceId> for u32 {
    fn from(value: DeviceId) -> Self {
        u32::from(value.value)
    }
}

impl convert::From<u32> for DeviceId {
    fn from(value: u32) -> Self {
        DeviceId {
            value: libsignal_protocol::DeviceId::from(value),
        }
    }
}

#[pymethods]
impl DeviceId {
    #[new]
    fn new(device_id: u32) -> DeviceId {
        DeviceId {
            value: libsignal_protocol::DeviceId::from(device_id),
        }
    }
}

#[pyclass]
#[derive(Clone, Debug)]
pub struct ProtocolAddress {
    pub state: libsignal_protocol::ProtocolAddress,
}

#[pymethods]
impl ProtocolAddress {
    #[new]
    fn new(name: String, device_id: u32) -> ProtocolAddress {
        ProtocolAddress {
            state: libsignal_protocol::ProtocolAddress::new(
                name,
                libsignal_protocol::DeviceId::from(device_id),
            ),
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
    module.add_class::<DeviceId>()?;
    Ok(())
}

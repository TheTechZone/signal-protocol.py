use crate::error::SignalProtocolError;
use libsignal_net::infra::AsHttpHeader;
use pyo3::prelude::*;
use std::time::SystemTime;

#[pyclass]
pub struct Auth {
    inner: libsignal_net::auth::Auth,
}

#[pymethods]
impl Auth {
    #[new]
    fn new(username: String, password: String) -> Self {
        Auth {
            inner: libsignal_net::auth::Auth { username, password },
        }
    }

    #[staticmethod]
    fn from_uid_and_secret(uid: &[u8], secret: &[u8]) -> PyResult<Self> {
        if uid.len() != 16 {
            return Err(SignalProtocolError::err_from_str(String::from(
                "uid must be 16 characters long",
            )));
        }
        if secret.len() != 32 {
            return Err(SignalProtocolError::err_from_str(String::from(
                "secret must be 32 characters long",
            )));
        }
        Ok(Self {
            inner: libsignal_net::auth::Auth::from_uid_and_secret(
                <[u8; 16]>::try_from(uid).unwrap(),
                <[u8; 32]>::try_from(secret).unwrap(),
            ),
        })
    }

    #[staticmethod]
    fn otp(username: &[u8], secret: &[u8]) -> String {
        let now = SystemTime::now();
        let otp = libsignal_net::auth::Auth::otp(
            std::str::from_utf8(username).unwrap().as_ref(),
            secret,
            now,
        );
        otp.to_string()
    }

    fn username(&self) -> &[u8] {
        (&self.inner.username).as_ref()
    }

    fn password(&self) -> &[u8] {
        (&self.inner.password).as_ref()
    }

    fn as_http_header(&self) -> PyResult<(String, String)> {
        let header = &self.inner.as_header();
        let name = header.0.as_str();
        let val = match header.1.to_str() {
            Ok(val) => val,
            Err(err) => return Err(SignalProtocolError::err_from_str(err.to_string())),
        };
        Ok((name.into(), val.into()))
    }
}

// macro_rules! create_enclave_interface {
//     ($name:ident, $enclave_kind:ty, $manager:ty) => {
//         #[pyclass]
//         pub struct $name {
//             inner: EnclaveEndpointConnection<$enclave_kind, $manager>,
//         }
//
//         #[pymethods]
//         impl $name {
//             #[new]
//             pub fn new(
//                 // _domain_config: DomainConfig, // Assuming there is a type DomainConfig
//                 _mr_enclave: Vec<u8>,
//                 _connect_timeout_secs: u64,
//                 // network_change_event: &PyAny,  // Replace with the actual type used
//             ) -> PyResult<Self> {
//                 // let params = EndpointParams::<$enclave_kind> {
//                 //     mr_enclave: MrEnclave::new(&mr_enclave),
//                 //     raft_config: <Self as PyEnclaveEndpointConnection>::default_raft_config(),
//                 // };
//                 //
//                 // let endpoint = EnclaveEndpoint {
//                 //     domain_config,
//                 //     params,
//                 // };
//                 //
//                 // Ok($name {
//                 //     inner: EnclaveEndpointConnection::new(
//                 //         &endpoint,
//                 //         Duration::from_secs(connect_timeout_secs),
//                 //         network_change_event  // Adjust this line as needed
//                 //     ),
//                 // })
//             }
//
//             // Example function to demonstrate wrapping methods
//             fn dummy_method(&self) -> PyResult<String> {
//                 // Replace this logic with actual method operations you'd like to expose
//                 Ok("Dummy Response".to_string())
//             }
//         }
//     };
// }
//
// #[pyclass]
// struct SingleRouteThrottlingConnectionManager {
//     inner: libsignal_net::infra::connection_manager::SingleRouteThrottlingConnectionManager
// }
//
// #[pyclass]
// struct SgxEnclave {
//     inner: libsignal_net::enclave::Sgx
// }
//
// #[pymethods]
// impl SgxEnclave {
//
// }

// Instantiate the macro for different `EnclaveKind` types
// create_enclave_interface!(SgxConnection, SgxEnclave, SingleRouteThrottlingConnectionManager);
// create_enclave_interface!(NitroConnection, libsignal_net::enclave::Nitro, libsignal_net::infra::connection_manager::MultiRouteConnectionManager);
// Add more as needed...

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Auth>()?;
    // module.add_class::<SgxConnection>()?;
    // module.add_class::<NitroConnection>()?;
    Ok(())
}

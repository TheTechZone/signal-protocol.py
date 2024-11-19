use pyo3::prelude::*;

use crate::poksho::{ShoSha256, ShoHmacSha256};


#[pyclass]
pub struct KeyPair {
    // inner: zkcredential::attributes::KeyPair<>,
}

enum ShoApi {
    HmacSha256(ShoHmacSha256),
    Sha256(ShoSha256),
}

#[pymethods]
impl KeyPair {
    #[staticmethod]
    pub fn derive_from() -> () {
        // match sho {
        //     ShoApi::Sha256(s) => {
                
        //     }
        // }
    }
}

pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}
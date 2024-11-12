use mac_address::get_mac_address;
use pyo3::{
    exceptions::{PyTypeError, PyValueError},
    prelude::*,
    pyclass::CompareOp,
    types::{PyBytes, PyDict},
};
use rand::{random, RngCore};
use std::hash::Hasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::hash_map::DefaultHasher, hash::Hash, iter};
use uuid::{Builder, Bytes, Context, Timestamp, Uuid, Variant, Version};

static NODE: AtomicU64 = AtomicU64::new(0);

pub const RESERVED_NCS: &str = "reserved for NCS compatibility";
pub const RFC_4122: &str = "specified in RFC 4122";
pub const RESERVED_MICROSOFT: &str = "reserved for Microsoft compatibility";
pub const RESERVED_FUTURE: &str = "reserved for future definition";

#[derive(FromPyObject)]
enum StringOrBytes {
    #[pyo3(transparent, annotation = "str")]
    String(String),
    #[pyo3(transparent, annotation = "bytes")]
    Bytes(Vec<u8>),
}

#[pyclass(subclass, module = "uuid")]
#[derive(Clone, Debug)]
pub struct UUID {
    pub handle: Uuid,
}

/// Generate a random node ID.
/// In hope to be compliant with RFC4122, we set the multicast bit to 1.
/// https://www.rfc-editor.org/rfc/rfc4122.html#section-4.5
///
/// The "multicast bit" of a MAC address is defined to be "the least
/// significant bit of the first octet". This works out to be the 41st bit
/// counting from 1 being the least significant bit, or 1<<40.
///
#[inline]
fn random_node_id() -> [u8; 6] {
    let bytes = random::<u64>().to_be_bytes();
    [
        bytes[2] | 0x01, // set multicast bit
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
    ]
}

#[pymethods]
impl UUID {
    pub const NAMESPACE_DNS: UUID = UUID {
        handle: Uuid::NAMESPACE_DNS,
    };
    pub const NAMESPACE_URL: UUID = UUID {
        handle: Uuid::NAMESPACE_URL,
    };
    pub const NAMESPACE_OID: UUID = UUID {
        handle: Uuid::NAMESPACE_OID,
    };
    pub const NAMESPACE_X500: UUID = UUID {
        handle: Uuid::NAMESPACE_X500,
    };

    #[new]
    #[pyo3(signature = (hex=None, bytes=None, bytes_le=None, fields=None, int=None, version=None))]
    fn new(
        hex: Option<&str>,
        bytes: Option<&Bound<'_, PyBytes>>,
        bytes_le: Option<&Bound<'_, PyBytes>>,
        fields: Option<(u32, u16, u16, u8, u8, u64)>,
        int: Option<u128>,
        version: Option<u8>,
    ) -> PyResult<Self> {
        let result = match (hex, bytes, bytes_le, fields, int) {
            (Some(hex), None, None, None, None) => Self::from_hex(hex),
            (None, Some(bytes), None, None, None) => Self::from_bytes(bytes),
            (None, None, Some(bytes_le), None, None) => Self::from_bytes_le(bytes_le),
            (None, None, None, Some(fields), None) => Self::from_fields(fields),
            (None, None, None, None, Some(int)) => Self::from_int(int),
            _ => Err(PyTypeError::new_err(
                "one of the hex, bytes, bytes_le, fields, or int arguments must be given",
            )),
        };

        match version {
            Some(v) => result?.set_version(v),
            None => result,
        }
    }

    fn __int__(&self) -> u128 {
        self.handle.as_u128()
    }

    fn __str__(&self) -> String {
        self.handle.hyphenated().to_string()
    }

    fn __repr__(&self) -> String {
        format!("UUID('{}')", self.__str__())
    }

    fn __richcmp__(&self, other: UUID, op: CompareOp) -> PyResult<bool> {
        match op {
            CompareOp::Lt => Ok(self.handle < other.handle),
            CompareOp::Le => Ok(self.handle <= other.handle),
            CompareOp::Eq => Ok(self.handle == other.handle),
            CompareOp::Ne => Ok(self.handle != other.handle),
            CompareOp::Gt => Ok(self.handle > other.handle),
            CompareOp::Ge => Ok(self.handle >= other.handle),
        }
    }

    fn __hash__(&self) -> PyResult<isize> {
        let mut hasher = DefaultHasher::new();
        self.handle.hash(&mut hasher);
        Ok(hasher.finish() as isize)
    }

    fn set_version(&self, version: u8) -> PyResult<UUID> {
        let version = match version {
            1 => Version::Mac,
            2 => Version::Dce,
            3 => Version::Md5,
            4 => Version::Random,
            5 => Version::Sha1,
            6 => Version::SortMac,
            7 => Version::SortRand,
            8 => Version::Custom,
            _ => return Err(PyErr::new::<PyValueError, &str>("illegal version number.")),
        };

        let mut builder = Builder::from_u128(self.handle.as_u128());
        builder.set_version(version);

        Ok(UUID {
            handle: builder.into_uuid(),
        })
    }

    #[allow(unused_variables)]
    fn __setattr__(&self, name: &str, value: PyObject) -> PyResult<()> {
        Err(PyTypeError::new_err("UUID objects are immutable"))
    }

    fn __getnewargs__(&self) -> (String,) {
        (self.__str__(),)
    }

    pub fn __deepcopy__(&self, py: Python, _memo: &Bound<'_, PyDict>) -> Py<PyAny> {
        self.clone().into_py(py)
    }

    #[getter]
    fn hex(&self) -> PyResult<String> {
        Ok(self.handle.simple().to_string())
    }

    #[getter]
    fn bytes(&self) -> &[u8] {
        self.handle.as_bytes()
    }

    #[getter]
    fn bytes_le<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let bytes = *self.handle.as_bytes();
        let bytes = [
            bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7], bytes[6],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ];
        PyBytes::new_bound(py, &bytes)
    }

    #[getter]
    fn int(&self) -> u128 {
        self.handle.as_u128()
    }

    #[getter]
    fn urn(&self) -> PyResult<String> {
        Ok(self.handle.urn().to_string())
    }

    #[getter]
    fn version(&self) -> usize {
        self.handle.get_version_num()
    }

    #[getter]
    fn variant(&self) -> &str {
        match self.handle.get_variant() {
            Variant::NCS => RESERVED_NCS,
            Variant::RFC4122 => RFC_4122,
            Variant::Microsoft => RESERVED_MICROSOFT,
            Variant::Future => RESERVED_FUTURE,
            _ => RESERVED_FUTURE,
        }
    }

    #[getter]
    fn node(&self) -> u64 {
        (self.int() & 0xffffffffffff) as u64
    }

    #[getter]
    fn time_low(&self) -> u32 {
        self.int().wrapping_shr(96) as u32
    }

    #[getter]
    fn time_mid(&self) -> u16 {
        ((self.int().wrapping_shr(80)) & 0xffff) as u16
    }

    #[getter]
    fn time_hi_version(&self) -> u16 {
        ((self.int().wrapping_shr(64)) & 0xffff) as u16
    }

    #[getter]
    fn clock_seq_hi_variant(&self) -> u8 {
        ((self.int().wrapping_shr(56)) & 0xff) as u8
    }

    #[getter]
    fn clock_seq_low(&self) -> u8 {
        ((self.int().wrapping_shr(48)) & 0xff) as u8
    }

    #[getter]
    fn clock_seq(&self) -> u16 {
        let high = self.clock_seq_hi_variant() as u16 & 0x3f;
        high.wrapping_shl(8) | self.clock_seq_low() as u16
    }

    #[getter]
    fn time(&self) -> u64 {
        let high = self.time_hi_version() as u64 & 0x0fff;
        let mid = self.time_mid() as u64;
        high.wrapping_shl(48) | mid.wrapping_shl(32) | self.time_low() as u64
    }

    #[getter]
    fn timestamp(&self) -> PyResult<u64> {
        match self.handle.get_timestamp() {
            Some(timestamp) => {
                let (secs, nanos) = timestamp.to_unix();
                Ok(secs * 1_000 + nanos as u64 / 1_000 / 1_000)
            }
            _ => Err(PyErr::new::<PyValueError, &str>(
                "UUID version should be one of (v1, v6 or v7).",
            )),
        }
    }

    #[getter]
    fn fields(&self) -> PyResult<(u32, u16, u16, u8, u8, u64)> {
        Ok((
            self.time_low(),
            self.time_mid(),
            self.time_hi_version(),
            self.clock_seq_hi_variant(),
            self.clock_seq_low(),
            self.node(),
        ))
    }

    #[staticmethod]
    fn from_hex(hex: &str) -> PyResult<UUID> {
        match Uuid::parse_str(hex) {
            Ok(handle) => Ok(UUID { handle }),
            _ => Err(PyValueError::new_err(
                "badly formed hexadecimal UUID string",
            )),
        }
    }

    #[staticmethod]
    fn from_bytes(bytes: &Bound<'_, PyBytes>) -> PyResult<UUID> {
        let bytes: Bytes = bytes.extract()?;
        Ok(UUID {
            handle: Uuid::from_bytes(bytes),
        })
    }

    #[staticmethod]
    fn from_bytes_le(bytes: &Bound<'_, PyBytes>) -> PyResult<UUID> {
        let bytes: Bytes = bytes.extract()?;
        Ok(UUID {
            handle: Uuid::from_bytes_le(bytes),
        })
    }

    #[staticmethod]
    fn from_fields(fields: (u32, u16, u16, u8, u8, u64)) -> PyResult<UUID> {
        let time_low = fields.0 as u128;
        let time_mid = fields.1 as u128;
        let time_hi_version = fields.2 as u128;
        let clock_seq_hi_variant = fields.3 as u128;
        let clock_seq_low = fields.4 as u128;
        let node = fields.5 as u128;
        let clock_seq = clock_seq_hi_variant.wrapping_shl(8) | clock_seq_low;

        let value = time_low.wrapping_shl(96)
            | time_mid.wrapping_shl(80)
            | time_hi_version.wrapping_shl(64)
            | clock_seq.wrapping_shl(48)
            | node;

        Ok(UUID {
            handle: Uuid::from_u128(value),
        })
    }

    #[staticmethod]
    fn from_int(int: u128) -> PyResult<UUID> {
        Ok(UUID {
            handle: Uuid::from_u128(int),
        })
    }
}

#[pyfunction]
#[pyo3(signature = (node=None, clock_seq=None))]
fn uuid1(node: Option<u64>, clock_seq: Option<u64>) -> PyResult<UUID> {
    let node = match node {
        Some(node) => node.to_ne_bytes(),
        None => _getnode().to_ne_bytes(),
    };
    let node = &[node[0], node[1], node[2], node[3], node[4], node[5]];
    let handle = match clock_seq {
        Some(clock_seq) => {
            let ts = Timestamp::from_unix(&Context::new_random(), clock_seq, 0);
            Uuid::new_v1(ts, node)
        }
        None => Uuid::now_v1(node),
    };
    Ok(UUID { handle })
}

#[pyfunction]
fn uuid3(namespace: UUID, name: StringOrBytes) -> PyResult<UUID> {
    match name {
        StringOrBytes::String(name) => Ok(UUID {
            handle: Uuid::new_v3(&namespace.handle, name.as_bytes()),
        }),
        StringOrBytes::Bytes(name) => Ok(UUID {
            handle: Uuid::new_v3(&namespace.handle, &name),
        }),
    }
}

#[pyfunction]
fn uuid4() -> PyResult<UUID> {
    Ok(UUID {
        handle: Uuid::new_v4(),
    })
}

#[pyfunction]
fn uuid5(namespace: &UUID, name: StringOrBytes) -> PyResult<UUID> {
    match name {
        StringOrBytes::String(name) => Ok(UUID {
            handle: Uuid::new_v5(&namespace.handle, name.as_bytes()),
        }),
        StringOrBytes::Bytes(name) => Ok(UUID {
            handle: Uuid::new_v5(&namespace.handle, &name),
        }),
    }
}

#[pyfunction]
#[pyo3(signature = (node=None, timestamp=None, nanos=None))]
fn uuid6(node: Option<u64>, timestamp: Option<u64>, nanos: Option<u32>) -> PyResult<UUID> {
    let node = match node {
        Some(node) => node.to_ne_bytes(),
        None => _getnode().to_ne_bytes(),
    };
    let node = &[node[0], node[1], node[2], node[3], node[4], node[5]];

    let handle = match timestamp {
        Some(timestamp) => {
            let timestamp =
                Timestamp::from_unix(&Context::new_random(), timestamp, nanos.unwrap_or(0));
            return Ok(UUID {
                handle: Uuid::new_v6(timestamp, node),
            });
        }
        None => Uuid::now_v6(node),
    };
    Ok(UUID { handle })
}

#[pyfunction]
#[pyo3(signature = (timestamp=None, nanos=None))]
fn uuid7(timestamp: Option<u64>, nanos: Option<u32>) -> PyResult<UUID> {
    let handle = match timestamp {
        Some(timestamp) => {
            let timestamp =
                Timestamp::from_unix(&Context::new_random(), timestamp, nanos.unwrap_or(0));
            return Ok(UUID {
                handle: Uuid::new_v7(timestamp),
            });
        }
        None => Uuid::now_v7(),
    };
    Ok(UUID { handle })
}

#[pyfunction]
fn uuid8(bytes: &Bound<'_, PyBytes>) -> PyResult<UUID> {
    let bytes: Bytes = bytes.extract()?;
    Ok(UUID {
        handle: Uuid::new_v8(bytes),
    })
}

fn _getnode() -> u64 {
    let cached_node = NODE.load(Ordering::Relaxed);
    if cached_node != 0 {
        return cached_node;
    }
    let bytes = match get_mac_address() {
        Ok(Some(mac_address)) => mac_address.bytes(),
        _ => {
            let mut bytes = [0u8; 6];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes[0] = bytes[0] | 0x01;
            bytes
        }
    };

    let node = ((bytes[0] as u64).wrapping_shl(40))
        + ((bytes[1] as u64).wrapping_shl(32))
        + ((bytes[2] as u64).wrapping_shl(24))
        + ((bytes[3] as u64).wrapping_shl(16))
        + ((bytes[4] as u64).wrapping_shl(8))
        + (bytes[5] as u64);

    NODE.store(node, Ordering::Relaxed);
    node
}

// #[pyfunction]
// fn getnode() -> PyResult<u64> {
//     Ok(_getnode())
// }

/// Fast path for uuid1 with a randomly generated MAC address.
/// à la postgres' uuid extension.
/// Further Reading:
///   - https://www.postgresql.org/docs/current/uuid-ossp.html
///   - https://www.edgedb.com/docs/stdlib/uuid#function::std::uuid_generate_v1mc
///   - https://supabase.com/blog/choosing-a-postgres-primary-key#uuidv1
#[pyfunction(name = "uuid_v1mc")]
fn uuid_v1mc() -> UUID {
    UUID {
        handle: Uuid::now_v1(&random_node_id()),
    }
}

impl From<u128> for UUID {
    fn from(value: u128) -> Self {
        UUID {
            handle: Uuid::from_u128(value),
        }
    }
}

#[pyfunction(name = "uuid_from_u128")]
pub fn uuid_from_u128(value: u128) -> UUID {
    UUID::from(value)
}

#[pyfunction(name = "uuid4_bulk")]
fn uuid4_bulk(py: Python, n: usize) -> Vec<UUID> {
    py.allow_threads(|| {
        iter::repeat_with(|| UUID {
            handle: Uuid::new_v4(),
        })
        .take(n)
        .collect()
    })
}

#[pyfunction(name = "uuid4_as_strings_bulk")]
fn uuid4_as_strings_bulk(py: Python, n: usize) -> Vec<String> {
    py.allow_threads(|| {
        iter::repeat_with(|| {
            (*Uuid::new_v4()
                .simple()
                .encode_lower(&mut Uuid::encode_buffer()))
            .to_string()
        })
        .take(n)
        .collect()
    })
}

#[pymodule]
pub fn init_submodule(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add_class::<UUID>()?;
    module.add_wrapped(wrap_pyfunction!(uuid1))?;
    module.add_wrapped(wrap_pyfunction!(uuid3))?;
    module.add_wrapped(wrap_pyfunction!(uuid4))?;
    module.add_wrapped(wrap_pyfunction!(uuid5))?;
    module.add_wrapped(wrap_pyfunction!(uuid6))?;
    module.add_wrapped(wrap_pyfunction!(uuid7))?;
    module.add_wrapped(wrap_pyfunction!(uuid8))?;
    module.add_wrapped(wrap_pyfunction!(uuid4_bulk))?;
    module.add_wrapped(wrap_pyfunction!(uuid4_as_strings_bulk))?;
    module.add_wrapped(wrap_pyfunction!(uuid_v1mc))?;
    module.add_wrapped(wrap_pyfunction!(uuid_from_u128))?;
    module.add("NAMESPACE_DNS", UUID::NAMESPACE_DNS)?;
    module.add("NAMESPACE_URL", UUID::NAMESPACE_URL)?;
    module.add("NAMESPACE_OID", UUID::NAMESPACE_OID)?;
    module.add("NAMESPACE_X500", UUID::NAMESPACE_X500)?;
    module.add("RESERVED_NCS", RESERVED_NCS)?;
    module.add("RFC_4122", RFC_4122)?;
    module.add("RESERVED_MICROSOFT", RESERVED_MICROSOFT)?;
    module.add("RESERVED_FUTURE", RESERVED_FUTURE)?;
    Ok(())
}

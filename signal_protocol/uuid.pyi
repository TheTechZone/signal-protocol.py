from typing import List, Optional
from typing_extensions import TypeAlias

_Int: TypeAlias = int
_Bytes: TypeAlias = bytes
_FieldsType: TypeAlias = tuple[int, int, int, int, int, int]

class UUID:
    def __init__(
        self,
        hex: str | None = ...,
        bytes: _Bytes | None = ...,
        bytes_le: _Bytes | None = ...,
        fields: _FieldsType | None = ...,
        int: _Int | None = ...,
        version: _Int | None = ...,
    ) -> None: ...
    @property
    def int(self) -> _Int: ...
    @property
    def bytes(self) -> _Bytes: ...
    @property
    def bytes_le(self) -> _Bytes: ...
    @property
    def hex(self) -> str: ...
    @property
    def urn(self) -> str:
        """Format a Uuid as a URN string, like urn:uuid:67e55044-10b1-426f-9247-bb680e5fe0c8"""
        ...

    @property
    def variant(self) -> str:
        """Returns the variant of the UUID structure.
        This determines the interpretation of the structure of the UUID. This method simply reads the value of the variant byte. It doesn't validate the rest of the UUID as conforming to that variant.
        """
        ...

    @property
    def version(self) -> _Int | None:
        """Returns the version number of the UUID.
        # References

        * [Version in RFC4122](https://datatracker.ietf.org/doc/html/rfc4122#section-4.1.3)
        """
        ...

    @property
    def fields(self) -> _FieldsType: ...
    @property
    def time_low(self) -> _Int: ...
    @property
    def time_mid(self) -> _Int: ...
    @property
    def time_hi_version(self) -> _Int: ...
    @property
    def clock_seq_hi_variant(self) -> _Int: ...
    @property
    def clock_seq_low(self) -> _Int: ...
    @property
    def time(self) -> _Int: ...
    @property
    def node(self) -> _Int: ...
    def __int__(self) -> _Int: ...
    def __eq__(self, other: object) -> bool: ...
    def __lt__(self, other: UUID) -> bool: ...
    def __le__(self, other: UUID) -> bool: ...
    def __gt__(self, other: UUID) -> bool: ...
    def __ge__(self, other: UUID) -> bool: ...
    def __getstate__(self) -> _Bytes: ...
    def __setstate__(self, state: _Bytes) -> None: ...

def uuid1(node: Optional[int] = None, clock_seq: Optional[int] = None) -> UUID: ...
def uuid_v1mc() -> UUID:
    """Fast path for uuid1 with a randomly generated MAC address.
    à la postgres' uuid extension.
    Further Reading:
      - https://www.postgresql.org/docs/current/uuid-ossp.html
      - https://www.edgedb.com/docs/stdlib/uuid#function::std::uuid_generate_v1mc
      - https://supabase.com/blog/choosing-a-postgres-primary-key#uuidv1
      -"""
    ...

def uuid3(namespace: UUID, name: str) -> UUID: ...
def uuid4() -> UUID: ...
def uuid4_bulk(n: int) -> List[UUID]: ...
def uuid4_as_strings_bulk(n: int) -> List[str]: ...
def uuid5(namespace: UUID, name: str) -> UUID: ...
def uuid_from_u128(value: int) -> UUID: ...

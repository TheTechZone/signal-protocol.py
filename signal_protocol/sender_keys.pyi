class SenderKeyRecord:

    def deserialize(buf: bytes) -> None:
        ...

    def serialize(self) -> bytes:
        ...
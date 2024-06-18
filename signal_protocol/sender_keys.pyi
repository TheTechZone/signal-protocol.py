class SenderKeyRecord:

    @staticmethod
    def deserialize(buf: bytes) -> None:
        ...

    def serialize(self) -> bytes:
        ...
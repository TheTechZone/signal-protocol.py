from address import ProtocolAddress
from protocol import PreKeySignalMessage
from storage import InMemSignalProtocolStore
from state import PreKeyBundle, SessionRecord, PreKeysUsed
from typing import Optional

def process_prekey(message: PreKeySignalMessage, remote_address: ProtocolAddress, session_record: SessionRecord, protocol_store: InMemSignalProtocolStore) -> Optional[PreKeysUsed]:
    """
    Processes a prekey message using a session record and a protocol store.

    Args:
        message (PreKeySignalMessage): The prekey message to process.
        remote_address (ProtocolAddress): The remote address.
        session_record (SessionRecord): The session record.
        protocol_store (InMemSignalProtocolStore): The protocol store.

    Returns:
        Optional[PreKeysUsed]: The result of the processing operation.
    """
    ...

def process_prekey_bundle(remote_address: ProtocolAddress, protocol_store: InMemSignalProtocolStore, bundle: PreKeyBundle) -> None:
    """
    Processes a prekey bundle using a protocol store.

    Args:
        remote_address (ProtocolAddress): The remote address.
        protocol_store (InMemSignalProtocolStore): The protocol store.
        bundle (PreKeyBundle): The prekey bundle to process.
    """
    ...
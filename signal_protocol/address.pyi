class DeviceId:
    """The type used in memory to represent a device, i.e. a particular Signal client instance which represents some user.

    Used in ProtocolAddress.
    *N.B* the DeviceID ranges from 1 (primary device) to n (the maximum number of devices per user), Any DeviceID > 1 will implictly represent a secondary device.
    """

    def __init__(self, device_id: int) -> None: ...

class ProtocolAddress:
    """The type used to represent the identiy of one Signal client"""

    def __init__(self, name: str, device_id: int) -> None: ...
    
    def name(self) -> str: ...
    
    def device_id(self) -> int: ...

# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: username.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0eusername.proto\x12\x15signal.proto.username"1\n\x0cUsernameData\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x0f\n\x07padding\x18\x02 \x01(\x0c\x62\x06proto3'
)


_USERNAMEDATA = DESCRIPTOR.message_types_by_name["UsernameData"]
UsernameData = _reflection.GeneratedProtocolMessageType(
    "UsernameData",
    (_message.Message,),
    {
        "DESCRIPTOR": _USERNAMEDATA,
        "__module__": "username_pb2",
        # @@protoc_insertion_point(class_scope:signal.proto.username.UsernameData)
    },
)
_sym_db.RegisterMessage(UsernameData)

if _descriptor._USE_C_DESCRIPTORS == False:

    DESCRIPTOR._options = None
    _USERNAMEDATA._serialized_start = 41
    _USERNAMEDATA._serialized_end = 90
# @@protoc_insertion_point(module_scope)

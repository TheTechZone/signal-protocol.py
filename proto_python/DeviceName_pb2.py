# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: DeviceName.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10\x44\x65viceName.proto\x12\rsignalservice\"N\n\nDeviceName\x12\x17\n\x0f\x65phemeralPublic\x18\x01 \x01(\x0c\x12\x13\n\x0bsyntheticIv\x18\x02 \x01(\x0c\x12\x12\n\nciphertext\x18\x03 \x01(\x0c\x42.\n,org.thoughtcrime.securesms.devicelist.protos')



_DEVICENAME = DESCRIPTOR.message_types_by_name['DeviceName']
DeviceName = _reflection.GeneratedProtocolMessageType('DeviceName', (_message.Message,), {
  'DESCRIPTOR' : _DEVICENAME,
  '__module__' : 'DeviceName_pb2'
  # @@protoc_insertion_point(class_scope:signalservice.DeviceName)
  })
_sym_db.RegisterMessage(DeviceName)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n,org.thoughtcrime.securesms.devicelist.protos'
  _DEVICENAME._serialized_start=35
  _DEVICENAME._serialized_end=113
# @@protoc_insertion_point(module_scope)

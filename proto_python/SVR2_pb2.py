# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: SVR2.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\nSVR2.proto\"\xa2\x01\n\x07Request\x12 \n\x06\x62\x61\x63kup\x18\x02 \x01(\x0b\x32\x0e.BackupRequestH\x00\x12 \n\x06\x65xpose\x18\x05 \x01(\x0b\x32\x0e.ExposeRequestH\x00\x12\"\n\x07restore\x18\x03 \x01(\x0b\x32\x0f.RestoreRequestH\x00\x12 \n\x06\x64\x65lete\x18\x04 \x01(\x0b\x32\x0e.DeleteRequestH\x00\x42\x07\n\x05innerJ\x04\x08\x01\x10\x02\"\xa1\x01\n\x08Response\x12!\n\x06\x62\x61\x63kup\x18\x01 \x01(\x0b\x32\x0f.BackupResponseH\x00\x12!\n\x06\x65xpose\x18\x04 \x01(\x0b\x32\x0f.ExposeResponseH\x00\x12#\n\x07restore\x18\x02 \x01(\x0b\x32\x10.RestoreResponseH\x00\x12!\n\x06\x64\x65lete\x18\x03 \x01(\x0b\x32\x0f.DeleteResponseH\x00\x42\x07\n\x05inner\"<\n\rBackupRequest\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\x12\x0b\n\x03pin\x18\x02 \x01(\x0c\x12\x10\n\x08maxTries\x18\x03 \x01(\r\"j\n\x0e\x42\x61\x63kupResponse\x12&\n\x06status\x18\x01 \x01(\x0e\x32\x16.BackupResponse.Status\"0\n\x06Status\x12\t\n\x05UNSET\x10\x00\x12\x06\n\x02OK\x10\x01\x12\x13\n\x0fREQUEST_INVALID\x10\x02\"\x1d\n\x0eRestoreRequest\x12\x0b\n\x03pin\x18\x01 \x01(\x0c\"\xa8\x01\n\x0fRestoreResponse\x12\'\n\x06status\x18\x01 \x01(\x0e\x32\x17.RestoreResponse.Status\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\x0c\x12\r\n\x05tries\x18\x03 \x01(\r\"O\n\x06Status\x12\t\n\x05UNSET\x10\x00\x12\x06\n\x02OK\x10\x01\x12\x0b\n\x07MISSING\x10\x02\x12\x10\n\x0cPIN_MISMATCH\x10\x03\x12\x13\n\x0fREQUEST_INVALID\x10\x04\"\x0f\n\rDeleteRequest\"\x10\n\x0e\x44\x65leteResponse\"\x1d\n\rExposeRequest\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\"`\n\x0e\x45xposeResponse\x12&\n\x06status\x18\x01 \x01(\x0e\x32\x16.ExposeResponse.Status\"&\n\x06Status\x12\t\n\x05UNSET\x10\x00\x12\x06\n\x02OK\x10\x01\x12\t\n\x05\x45RROR\x10\x02\x42\x19\n\x15org.signal.svr2.protoP\x01\x62\x06proto3')



_REQUEST = DESCRIPTOR.message_types_by_name['Request']
_RESPONSE = DESCRIPTOR.message_types_by_name['Response']
_BACKUPREQUEST = DESCRIPTOR.message_types_by_name['BackupRequest']
_BACKUPRESPONSE = DESCRIPTOR.message_types_by_name['BackupResponse']
_RESTOREREQUEST = DESCRIPTOR.message_types_by_name['RestoreRequest']
_RESTORERESPONSE = DESCRIPTOR.message_types_by_name['RestoreResponse']
_DELETEREQUEST = DESCRIPTOR.message_types_by_name['DeleteRequest']
_DELETERESPONSE = DESCRIPTOR.message_types_by_name['DeleteResponse']
_EXPOSEREQUEST = DESCRIPTOR.message_types_by_name['ExposeRequest']
_EXPOSERESPONSE = DESCRIPTOR.message_types_by_name['ExposeResponse']
_BACKUPRESPONSE_STATUS = _BACKUPRESPONSE.enum_types_by_name['Status']
_RESTORERESPONSE_STATUS = _RESTORERESPONSE.enum_types_by_name['Status']
_EXPOSERESPONSE_STATUS = _EXPOSERESPONSE.enum_types_by_name['Status']
Request = _reflection.GeneratedProtocolMessageType('Request', (_message.Message,), {
  'DESCRIPTOR' : _REQUEST,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:Request)
  })
_sym_db.RegisterMessage(Request)

Response = _reflection.GeneratedProtocolMessageType('Response', (_message.Message,), {
  'DESCRIPTOR' : _RESPONSE,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:Response)
  })
_sym_db.RegisterMessage(Response)

BackupRequest = _reflection.GeneratedProtocolMessageType('BackupRequest', (_message.Message,), {
  'DESCRIPTOR' : _BACKUPREQUEST,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:BackupRequest)
  })
_sym_db.RegisterMessage(BackupRequest)

BackupResponse = _reflection.GeneratedProtocolMessageType('BackupResponse', (_message.Message,), {
  'DESCRIPTOR' : _BACKUPRESPONSE,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:BackupResponse)
  })
_sym_db.RegisterMessage(BackupResponse)

RestoreRequest = _reflection.GeneratedProtocolMessageType('RestoreRequest', (_message.Message,), {
  'DESCRIPTOR' : _RESTOREREQUEST,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:RestoreRequest)
  })
_sym_db.RegisterMessage(RestoreRequest)

RestoreResponse = _reflection.GeneratedProtocolMessageType('RestoreResponse', (_message.Message,), {
  'DESCRIPTOR' : _RESTORERESPONSE,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:RestoreResponse)
  })
_sym_db.RegisterMessage(RestoreResponse)

DeleteRequest = _reflection.GeneratedProtocolMessageType('DeleteRequest', (_message.Message,), {
  'DESCRIPTOR' : _DELETEREQUEST,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:DeleteRequest)
  })
_sym_db.RegisterMessage(DeleteRequest)

DeleteResponse = _reflection.GeneratedProtocolMessageType('DeleteResponse', (_message.Message,), {
  'DESCRIPTOR' : _DELETERESPONSE,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:DeleteResponse)
  })
_sym_db.RegisterMessage(DeleteResponse)

ExposeRequest = _reflection.GeneratedProtocolMessageType('ExposeRequest', (_message.Message,), {
  'DESCRIPTOR' : _EXPOSEREQUEST,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:ExposeRequest)
  })
_sym_db.RegisterMessage(ExposeRequest)

ExposeResponse = _reflection.GeneratedProtocolMessageType('ExposeResponse', (_message.Message,), {
  'DESCRIPTOR' : _EXPOSERESPONSE,
  '__module__' : 'SVR2_pb2'
  # @@protoc_insertion_point(class_scope:ExposeResponse)
  })
_sym_db.RegisterMessage(ExposeResponse)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\025org.signal.svr2.protoP\001'
  _REQUEST._serialized_start=15
  _REQUEST._serialized_end=177
  _RESPONSE._serialized_start=180
  _RESPONSE._serialized_end=341
  _BACKUPREQUEST._serialized_start=343
  _BACKUPREQUEST._serialized_end=403
  _BACKUPRESPONSE._serialized_start=405
  _BACKUPRESPONSE._serialized_end=511
  _BACKUPRESPONSE_STATUS._serialized_start=463
  _BACKUPRESPONSE_STATUS._serialized_end=511
  _RESTOREREQUEST._serialized_start=513
  _RESTOREREQUEST._serialized_end=542
  _RESTORERESPONSE._serialized_start=545
  _RESTORERESPONSE._serialized_end=713
  _RESTORERESPONSE_STATUS._serialized_start=634
  _RESTORERESPONSE_STATUS._serialized_end=713
  _DELETEREQUEST._serialized_start=715
  _DELETEREQUEST._serialized_end=730
  _DELETERESPONSE._serialized_start=732
  _DELETERESPONSE._serialized_end=748
  _EXPOSEREQUEST._serialized_start=750
  _EXPOSEREQUEST._serialized_end=779
  _EXPOSERESPONSE._serialized_start=781
  _EXPOSERESPONSE._serialized_end=877
  _EXPOSERESPONSE_STATUS._serialized_start=839
  _EXPOSERESPONSE_STATUS._serialized_end=877
# @@protoc_insertion_point(module_scope)

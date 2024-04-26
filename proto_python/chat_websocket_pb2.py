# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: chat_websocket.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x14\x63hat_websocket.proto\x12\x1bsignal.proto.chat_websocket\"`\n\x17WebSocketRequestMessage\x12\x0c\n\x04verb\x18\x01 \x01(\t\x12\x0c\n\x04path\x18\x02 \x01(\t\x12\x0c\n\x04\x62ody\x18\x03 \x01(\x0c\x12\x0f\n\x07headers\x18\x05 \x03(\t\x12\n\n\x02id\x18\x04 \x01(\x04\"f\n\x18WebSocketResponseMessage\x12\n\n\x02id\x18\x01 \x01(\x04\x12\x0e\n\x06status\x18\x02 \x01(\r\x12\x0f\n\x07message\x18\x03 \x01(\t\x12\x0f\n\x07headers\x18\x05 \x03(\t\x12\x0c\n\x04\x62ody\x18\x04 \x01(\x0c\"\x94\x02\n\x10WebSocketMessage\x12@\n\x04type\x18\x01 \x01(\x0e\x32\x32.signal.proto.chat_websocket.WebSocketMessage.Type\x12\x45\n\x07request\x18\x02 \x01(\x0b\x32\x34.signal.proto.chat_websocket.WebSocketRequestMessage\x12G\n\x08response\x18\x03 \x01(\x0b\x32\x35.signal.proto.chat_websocket.WebSocketResponseMessage\".\n\x04Type\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x0b\n\x07REQUEST\x10\x01\x12\x0c\n\x08RESPONSE\x10\x02')



_WEBSOCKETREQUESTMESSAGE = DESCRIPTOR.message_types_by_name['WebSocketRequestMessage']
_WEBSOCKETRESPONSEMESSAGE = DESCRIPTOR.message_types_by_name['WebSocketResponseMessage']
_WEBSOCKETMESSAGE = DESCRIPTOR.message_types_by_name['WebSocketMessage']
_WEBSOCKETMESSAGE_TYPE = _WEBSOCKETMESSAGE.enum_types_by_name['Type']
WebSocketRequestMessage = _reflection.GeneratedProtocolMessageType('WebSocketRequestMessage', (_message.Message,), {
  'DESCRIPTOR' : _WEBSOCKETREQUESTMESSAGE,
  '__module__' : 'chat_websocket_pb2'
  # @@protoc_insertion_point(class_scope:signal.proto.chat_websocket.WebSocketRequestMessage)
  })
_sym_db.RegisterMessage(WebSocketRequestMessage)

WebSocketResponseMessage = _reflection.GeneratedProtocolMessageType('WebSocketResponseMessage', (_message.Message,), {
  'DESCRIPTOR' : _WEBSOCKETRESPONSEMESSAGE,
  '__module__' : 'chat_websocket_pb2'
  # @@protoc_insertion_point(class_scope:signal.proto.chat_websocket.WebSocketResponseMessage)
  })
_sym_db.RegisterMessage(WebSocketResponseMessage)

WebSocketMessage = _reflection.GeneratedProtocolMessageType('WebSocketMessage', (_message.Message,), {
  'DESCRIPTOR' : _WEBSOCKETMESSAGE,
  '__module__' : 'chat_websocket_pb2'
  # @@protoc_insertion_point(class_scope:signal.proto.chat_websocket.WebSocketMessage)
  })
_sym_db.RegisterMessage(WebSocketMessage)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _WEBSOCKETREQUESTMESSAGE._serialized_start=53
  _WEBSOCKETREQUESTMESSAGE._serialized_end=149
  _WEBSOCKETRESPONSEMESSAGE._serialized_start=151
  _WEBSOCKETRESPONSEMESSAGE._serialized_end=253
  _WEBSOCKETMESSAGE._serialized_start=256
  _WEBSOCKETMESSAGE._serialized_end=532
  _WEBSOCKETMESSAGE_TYPE._serialized_start=486
  _WEBSOCKETMESSAGE_TYPE._serialized_end=532
# @@protoc_insertion_point(module_scope)

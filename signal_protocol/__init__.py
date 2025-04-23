"""Python bindings to the signal protocol."""

from importlib.metadata import version

__version__ = version("signal-protocol")

from .signal_protocol import *

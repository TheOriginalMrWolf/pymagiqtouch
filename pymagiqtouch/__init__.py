"""
PyMagiqTouch: Python client library for Seeley MagiQtouch heating and cooling units
"""

from .client import MagiqTouchClient, MagiqTouchRestClient
from .types import UpdateCallback, ZonesLookup

__version__ = "0.1.0"
__all__ = [
    "MagiqTouchClient",
    "MagiqTouchRestClient",
    "UpdateCallback",
    "ZonesLookup"
]
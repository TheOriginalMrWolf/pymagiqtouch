"""
Type definitions for PyMagiqTouch
"""

from typing import Callable, Dict, Any, Union, Optional

# Type for zones data - can be a dict or a function that returns a dict
ZonesLookup = Union[Callable[[], Dict[str, Any]], Dict[str, Any]]

# Type for update callback function
UpdateCallback = Callable[[Dict[str, Any]], None]
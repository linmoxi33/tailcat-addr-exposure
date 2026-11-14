"""tailcat-addr-exposure: offline exposure auditor for tailcat `tc...` addresses."""

from .addr import AddrError, parse_address  # noqa: F401
from .cli import main  # noqa: F401

__version__ = "1.0.0"

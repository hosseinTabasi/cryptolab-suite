"""Compatibility shim that imports ``cryptolab`` when cryptolab-kit is installed.

**SAFE path:** this module only loads an optional sibling package. Suite
features that need modern AES / RSA / classical ciphers call into
``cryptolab`` when available; otherwise they fall back to ``cryptography``
directly or raise a clear install hint.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any


class KitNotInstalledError(ImportError):
    """Raised when cryptolab-kit is required but not importable."""


def require_cryptolab() -> ModuleType:
    """Import and return the ``cryptolab`` package.

    Raises
    ------
    KitNotInstalledError
        With install instructions if the package is missing.
    """
    try:
        import cryptolab
    except ImportError as exc:
        raise KitNotInstalledError(
            "cryptolab-kit is not installed. Install the sibling package first:\n"
            "  pip install -e ../cryptolab-kit -e \".[dev]\"\n"
            "Or from GitHub:\n"
            "  pip install \"cryptolab-kit @ git+https://github.com/hosseinTabasi/cryptolab-kit.git\"\n"
            "See README.md (Dependency strategy)."
        ) from exc
    return cryptolab


def try_cryptolab() -> ModuleType | None:
    """Return ``cryptolab`` if installed, else ``None``."""
    try:
        return require_cryptolab()
    except KitNotInstalledError:
        return None


def get_attr(dotted: str) -> Any:
    """Resolve ``cryptolab.<dotted>`` or raise :class:`KitNotInstalledError`."""
    mod = require_cryptolab()
    obj: Any = mod
    for part in dotted.split("."):
        # Allow "classic.caesar" style by importing submodules on demand.
        try:
            obj = getattr(obj, part)
        except AttributeError:
            import importlib

            obj = importlib.import_module(f"cryptolab.{dotted}")
            break
    return obj

"""Forte — MIPS16e support for Binary Ninja."""

__all__ = ["register"]
__version__ = "0.1.0"


def register():
    """Load Binary Ninja integration lazily so decoder tests stay standalone."""

    from .registration import register as register_plugin

    return register_plugin()

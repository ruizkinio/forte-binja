"""Binary Ninja entry point for Forte."""

try:
    from .forte import register
except ImportError:
    # Pytest imports a repository-root __init__.py without package context.
    from forte import register

try:
    __import__("binaryninja")
except ImportError:
    # Keep the standalone decoder testable without a Binary Ninja installation.
    pass
else:
    register()

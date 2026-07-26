"""NetOps Console — self-hosted network discovery, diagnostics, and audited execution."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("netops-console")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]

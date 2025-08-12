# Wrapper package to expose the real implementation in subpackage
from .simpleportscanner.cli import main  # re-export for convenience

__all__ = ["main"]
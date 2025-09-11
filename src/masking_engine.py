"""Compatibility layer for the reorganised package structure."""
from .core.engine import MaskingEngine
from .config.models import Config
from .config.loader import load_config

__all__ = ["MaskingEngine", "Config", "load_config"]

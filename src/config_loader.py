import base64
import os
from functools import lru_cache
from typing import Optional

from cryptography.fernet import Fernet

from src.masking_engine import Config, MaskingEngine

DEFAULT_CONFIG_PATH = "masking_config.yaml"


@lru_cache()
def load_config(path: Optional[str] = None) -> Config:
    """Load the masking configuration.

    Parameters
    ----------
    path: Optional[str]
        Explicit path to the config file. If not provided, the
        ``MASKING_CONFIG_PATH`` environment variable is used. Defaults
        to ``masking_config.yaml``.
    """
    cfg_path = path or os.getenv("MASKING_CONFIG_PATH", DEFAULT_CONFIG_PATH)
    return Config.from_yaml(cfg_path)


@lru_cache()
def get_engine(path: Optional[str] = None) -> MaskingEngine:
    """Initialise and cache a :class:`MaskingEngine` instance."""

    cfg = load_config(path)
    return MaskingEngine(cfg)


@lru_cache()
def get_file_fernet() -> Fernet:
    """Return a ``Fernet`` instance for file encryption utilities."""

    key = os.getenv("FILE_ENCRYPTION_KEY")
    if not key:
        # Derive a deterministic but insecure default so examples still work
        key = base64.urlsafe_b64encode(b"0" * 32).decode()
    return Fernet(key)

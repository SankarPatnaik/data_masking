"""Configuration models for data masking application."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Pattern
import os
import warnings

from ..utils.io import read_yaml


@dataclass
class StructuredKeyRule:
    """Rule describing how to handle specific structured keys."""

    key: Pattern
    policy: str


@dataclass
class RegexRule:
    """Custom regular expression rule for detection."""

    name: str
    pattern: Pattern
    policy: str


@dataclass
class Config:
    """Runtime configuration for the masking engine."""

    language: str
    spacy_model: Optional[str]
    confidence_threshold: float
    use_regex: bool
    use_ner: bool
    structured_keys: List[StructuredKeyRule]
    custom_regexes: List[RegexRule]
    entity_policies: Dict[str, str]
    default_policy: str
    mask_char: str
    preserve_length: bool
    enc_algo: str
    key_id: str
    key_source: str
    aes_key: Optional[bytes]
    aad_fields: List[str]
    hash_algo: str
    hash_salt: bytes
    token_secret: bytes
    token_prefix: str
    fpe_enabled: bool
    fpe_cipher: Optional[Any]

    @classmethod
    def from_yaml(cls, path: str) -> "Config":
        """Load configuration from *path* with environment validation."""
        from .loader import load_config

        raw: Dict[str, Any] = read_yaml(path)
        enc = raw.get("encryption", {})
        hashing = raw.get("hashing", {})
        tok = raw.get("tokenization", {})
        fpe = raw.get("fpe", {})

        if enc.get("key_source", "ENV") == "ENV":
            var = enc.get("env_key_var", "MASKING_AES_KEY_B64")
            if not os.getenv(var):
                raise ValueError(f"Missing required environment variable {var}")

        salt_var = hashing.get("salt_env_var", "MASKING_SALT_B64")
        if not os.getenv(salt_var):
            warnings.warn(
                f"Environment variable {salt_var} is not set; hashing salt will be empty.",
                UserWarning,
            )

        token_var = tok.get("secret_env_var", "MASKING_TOKEN_SECRET_B64")
        if not os.getenv(token_var):
            warnings.warn(
                f"Environment variable {token_var} is not set; tokenization will be non-deterministic.",
                UserWarning,
            )

        if fpe.get("enabled") and not os.getenv("MASKING_FPE_KEY_HEX"):
            raise ValueError("Missing required environment variable MASKING_FPE_KEY_HEX")

        return load_config(path)


"""Configuration models for data masking application."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Pattern


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


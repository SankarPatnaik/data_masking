"""Configuration loader for the masking application."""
from __future__ import annotations

import base64
import os
import re
from typing import Any, Dict

from .models import Config, StructuredKeyRule, RegexRule
from ..utils.io import read_yaml
from ..core.engine import MaskingEngine


def load_config(path: str) -> Config:
    """Load configuration from a YAML file.

    Parameters
    ----------
    path: str
        Path to the YAML configuration file.
    """
    raw: Dict[str, Any] = read_yaml(path)

    det = raw.get("detection", {})
    enc = raw.get("encryption", {})
    hashing = raw.get("hashing", {})
    tok = raw.get("tokenization", {})
    fpe = raw.get("fpe", {})
    masking = raw.get("masking", {})
    models = raw.get("models", {})

    # Structured keys
    sk_cfg = det.get("structured_keys", [])
    if isinstance(sk_cfg, dict):
        sk = [
            StructuredKeyRule(key=re.compile(k), policy=v.upper())
            for k, v in sk_cfg.items()
        ]
    else:
        sk = [
            StructuredKeyRule(key=re.compile(r["key"]), policy=r["policy"].upper())
            for r in sk_cfg
        ]

    # Custom regexes
    rx = [
        RegexRule(
            name=r["name"], pattern=re.compile(r["pattern"]), policy=r["policy"].upper()
        )
        for r in det.get("custom_regexes", [])
    ]

    # Keys
    aes_key = None
    if enc.get("key_source") == "ENV":
        k = os.getenv(enc.get("env_key_var", "MASKING_AES_KEY_B64"))
        if k:
            aes_key = base64.b64decode(k)

    hash_salt = base64.b64decode(
        os.getenv(hashing.get("salt_env_var", "MASKING_SALT_B64"), "")
    )
    token_secret = base64.b64decode(
        os.getenv(tok.get("secret_env_var", "MASKING_TOKEN_SECRET_B64"), "")
    )

    # FPE
    fpe_cipher = None
    if fpe.get("enabled"):
        try:
            from ff3 import FF3Cipher  # type: ignore

            tweak = (
                base64.b64decode(fpe.get("tweak", "")) if fpe.get("tweak") else b""
            )
            fpe_key_hex = os.getenv("MASKING_FPE_KEY_HEX", "")
            if fpe_key_hex:
                fpe_cipher = FF3Cipher.withCustomAlphabet(
                    fpe_key_hex, tweak, "0123456789"
                )
        except Exception:
            fpe_cipher = None

    return Config(
        language=raw.get("language", "en"),
        spacy_model=models.get("spacy_model"),
        confidence_threshold=det.get("confidence_threshold", 0.75),
        use_regex=det.get("use_regex", True),
        use_ner=det.get("use_ner", True),
        structured_keys=sk,
        custom_regexes=rx,
        entity_policies={k.upper(): v.upper() for k, v in raw.get("entities", {}).items()},
        default_policy=masking.get("default_policy", "NONE").upper(),
        mask_char=masking.get("mask_char", "█"),
        preserve_length=masking.get("preserve_length", True),
        enc_algo=enc.get("algorithm", "AES_GCM"),
        key_id=enc.get("key_id", "default"),
        key_source=enc.get("key_source", "ENV"),
        aes_key=aes_key,
        aad_fields=enc.get("aad_fields", []),
        hash_algo=hashing.get("algo", "SHA256"),
        hash_salt=hash_salt,
        token_secret=token_secret,
        token_prefix=tok.get("prefix", "tok_"),
        fpe_enabled=fpe.get("enabled", False),
        fpe_cipher=fpe_cipher,
    )


__all__ = ["load_config"]


def create_engine(config_path: str) -> MaskingEngine:
    """Application factory creating a configured :class:`MaskingEngine`."""

    return MaskingEngine(load_config(config_path))


__all__.append("create_engine")

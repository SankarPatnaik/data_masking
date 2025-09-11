"""Utility helpers for I/O operations."""
from __future__ import annotations

from typing import Any, Dict

import yaml


def read_yaml(path: str) -> Dict[str, Any]:
    """Read a YAML file and return its content as a dictionary."""
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


__all__ = ["read_yaml"]

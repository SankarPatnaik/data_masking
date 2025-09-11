"""Tests for configuration loading and module boundaries."""

from src.config.loader import load_config, create_engine
from src.config import models
from src.core import engine as core_engine
from src.core.engine import MaskingEngine


def test_module_boundaries():
    """Ensure config and core modules expose expected symbols only."""
    assert hasattr(models, "Config")
    assert not hasattr(core_engine, "Config")


def test_load_config():
    cfg = load_config("tests/config_test.yaml")
    assert cfg.default_policy == "NONE"


def test_create_engine():
    eng = create_engine("tests/config_test.yaml")
    assert isinstance(eng, MaskingEngine)

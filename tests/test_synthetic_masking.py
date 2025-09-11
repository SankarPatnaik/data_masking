"""Tests for masking synthetic structured data."""

import re
import pytest
from src.config.loader import create_engine


@pytest.mark.parametrize(
    "cfg_path", ["tests/config_synthetic.yaml", "src/synthetic.yaml"]
)
def test_structured_synthetic(cfg_path):
    engine = create_engine(cfg_path)
    data = {
        "name": "John Doe",
        "address": "123 Main St",
        "phone": "+1-555-123-4567",
        "email": "john@example.com",
    }
    res = engine.mask_json(data, also_scan_text_nodes=False)
    masked = res["masked_json"]

    assert masked["name"] != data["name"]
    assert masked["address"] != data["address"]
    assert masked["phone"] != data["phone"]
    assert masked["email"] != data["email"]

    assert "@" in masked["email"]
    assert re.search(r"\d", masked["phone"]) is not None


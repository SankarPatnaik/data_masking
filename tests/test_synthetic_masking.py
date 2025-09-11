"""Tests for masking synthetic structured data."""

import re
from src.config.loader import create_engine


def test_structured_synthetic():
    engine = create_engine("tests/config_synthetic.yaml")
    data = {
        "name": "John Doe",
        "address": "123 Main St",
        "phone": "+1-555-123-4567",
        "email": "john@example.com"
    }
    res = engine.mask_json(data, also_scan_text_nodes=False)
    masked = res["masked_json"]

    assert masked["name"] != data["name"]
    assert masked["address"] != data["address"]
    assert masked["phone"] != data["phone"]
    assert masked["email"] != data["email"]

    assert "@" in masked["email"]
    assert re.search(r"\d", masked["phone"]) is not None

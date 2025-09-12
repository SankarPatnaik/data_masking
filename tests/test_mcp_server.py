import re

from src.service.mcp_server import mask_pii


def test_mask_pii_redact():
    text = "Contact alice@example.com or 123-456-7890"
    masked = mask_pii(text, mode="redact")
    assert "alice@example.com" not in masked
    assert "123-456-7890" not in masked
    assert "[EMAIL]" in masked
    assert "[PHONE]" in masked


def test_mask_pii_hash():
    text = "Send details to bob@example.com"
    masked = mask_pii(text, mode="hash")
    assert "bob@example.com" not in masked
    # ensure a sha256 hex digest is present
    assert re.search(r"hash_[0-9a-f]{64}", masked)

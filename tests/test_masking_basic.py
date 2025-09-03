
import os, base64
from src.masking_engine import Config, MaskingEngine

def setup_module(module):
    # minimal secrets
    os.environ.setdefault("MASKING_AES_KEY_B64", base64.b64encode(b"0"*32).decode())
    os.environ.setdefault("MASKING_SALT_B64", base64.b64encode(b"saltsaltsaltsalt").decode())
    os.environ.setdefault("MASKING_TOKEN_SECRET_B64", base64.b64encode(b"tokensecret0123456789012345678901").decode())

def test_text_hash_email():
    cfg = Config.from_yaml("tests/config_test.yaml")
    engine = MaskingEngine(cfg)
    res = engine.mask_text("Email me at user@example.com")
    masked = res["masked_text"]
    assert "hash_" in masked

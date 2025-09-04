
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


def test_encrypt_decrypt_roundtrip():
    cfg = Config.from_yaml("tests/config_test.yaml")
    engine = MaskingEngine(cfg)
    res = engine.mask_text("My id is 1234")
    masked = res["masked_text"]
    enc_val = masked.split()[-1]
    assert enc_val.startswith("enc:")
    assert engine.decrypt_value(enc_val) == "1234"

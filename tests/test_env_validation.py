import base64
import pytest

from src.masking_engine import Config


def _write_cfg(tmp_path, content: str) -> str:
    path = tmp_path / "cfg.yaml"
    path.write_text(content)
    return str(path)


def test_missing_required_env_aes_key(tmp_path, monkeypatch):
    cfg_path = _write_cfg(
        tmp_path,
        "encryption:\n  key_source: ENV\n  env_key_var: TEST_AES_KEY\n",
    )
    # satisfy optional variables
    monkeypatch.setenv(
        "MASKING_SALT_B64", base64.b64encode(b"salt").decode()
    )
    monkeypatch.setenv(
        "MASKING_TOKEN_SECRET_B64", base64.b64encode(b"secret").decode()
    )
    monkeypatch.delenv("TEST_AES_KEY", raising=False)

    with pytest.raises(ValueError) as exc:
        Config.from_yaml(cfg_path)
    assert "TEST_AES_KEY" in str(exc.value)


def test_optional_env_warnings(tmp_path, monkeypatch):
    cfg_path = _write_cfg(tmp_path, "language: en\n")
    monkeypatch.setenv(
        "MASKING_AES_KEY_B64", base64.b64encode(b"0" * 32).decode()
    )
    monkeypatch.delenv("MASKING_SALT_B64", raising=False)
    monkeypatch.delenv("MASKING_TOKEN_SECRET_B64", raising=False)

    with pytest.warns(UserWarning) as record:
        cfg = Config.from_yaml(cfg_path)

    assert cfg.hash_salt == b""
    assert cfg.token_secret == b""
    msgs = [str(w.message) for w in record]
    assert any("MASKING_SALT_B64" in m for m in msgs)
    assert any("MASKING_TOKEN_SECRET_B64" in m for m in msgs)


def test_missing_fpe_key(tmp_path, monkeypatch):
    cfg_path = _write_cfg(tmp_path, "fpe:\n  enabled: true\n")
    monkeypatch.setenv(
        "MASKING_AES_KEY_B64", base64.b64encode(b"0" * 32).decode()
    )
    monkeypatch.setenv(
        "MASKING_SALT_B64", base64.b64encode(b"salt").decode()
    )
    monkeypatch.setenv(
        "MASKING_TOKEN_SECRET_B64", base64.b64encode(b"secret").decode()
    )
    monkeypatch.delenv("MASKING_FPE_KEY_HEX", raising=False)

    with pytest.raises(ValueError) as exc:
        Config.from_yaml(cfg_path)
    assert "MASKING_FPE_KEY_HEX" in str(exc.value)


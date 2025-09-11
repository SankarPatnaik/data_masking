from src.masking_engine import Config


def test_load_default_config():
    cfg = Config.from_yaml("masking_config.yaml")
    assert cfg.language == "en"
    assert cfg.token_prefix == "tok_"


def test_ignores_unknown_fields(tmp_path):
    cfg_path = tmp_path / "minimal.yaml"
    cfg_path.write_text(
        """
language: 'en'
unknown:
  foo: bar
"""
    )
    cfg = Config.from_yaml(str(cfg_path))
    assert cfg.language == "en"
    assert cfg.use_regex is True

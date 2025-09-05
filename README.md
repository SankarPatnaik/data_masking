
# PII Masking & Encryption Framework (NER + Regex + Policy)

A production-ready Python framework to **detect and protect PII** before sending to LLMs or downstream systems.
- Hybrid detection: **NER (spaCy)** + **Regex** + **Structured key rules for JSON**
- Transform policies: **REDACT**, **HASH**, **ENCRYPT (AES-GCM)**, **FPE** (optional), **TOKENIZE**
- Config-first: add new attributes without code changes
- Run as a **FastAPI service** or a **CLI**

> Inspired by real-world needs to keep sensitive user data safe, especially for student & professional communities.

---

## Quick start

### 1) Clone & install

#### Unix/macOS (bash/zsh)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Optional (for NER):
python -m spacy download en_core_web_sm
```

#### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
# Optional (for NER):
python -m spacy download en_core_web_sm
```

### 2) Set secrets (examples)

#### Unix/macOS (bash/zsh)
```bash
# 32-byte AES key (base64) for AES-256-GCM
export MASKING_AES_KEY_B64=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")

# Salt for hashing (base64)
export MASKING_SALT_B64=$(python -c "import os,base64;print(base64.b64encode(os.urandom(16)).decode())")

# Secret for deterministic tokens (base64)
export MASKING_TOKEN_SECRET_B64=$(python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())")
```

#### Windows (PowerShell)
```powershell
# 32-byte AES key (base64) for AES-256-GCM
$env:MASKING_AES_KEY_B64 = python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"

# Salt for hashing (base64)
$env:MASKING_SALT_B64 = python -c "import os,base64;print(base64.b64encode(os.urandom(16)).decode())"

# Secret for deterministic tokens (base64)
$env:MASKING_TOKEN_SECRET_B64 = python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
```

### 3) Run the API

#### Unix/macOS (bash/zsh)
```bash
export MASKING_CONFIG_PATH=masking_config.yaml
uvicorn src.service.app:app --reload --port 8000
```

#### Windows (PowerShell)
```powershell
$env:MASKING_CONFIG_PATH = "masking_config.yaml"
uvicorn src.service.app:app --reload --port 8000
```

### 4) Use the CLI (same commands for Unix/PowerShell)
The `json` command accepts a single JSON object, a JSON array, or newline-delimited JSON (JSON Lines).
Each record is masked independently.
```bash
python -m src.cli text "Call me at +91-9876543210 or email a@b.com"
# Single JSON object
python -m src.cli json examples/sample.json
# JSON Lines
python -m src.cli json examples/sample_lines.jsonl
```
### 5) Docker (optional)
```bash
docker build -t pii-masking .
docker run -p 8000:8000 --env-file .env pii-masking
```

### 6) Decrypt encrypted values
```python
from src.masking_engine import Config, MaskingEngine

cfg = Config.from_yaml("masking_config.yaml")
engine = MaskingEngine(cfg)

res = engine.mask_text("PAN ABCDE1234F")
cipher = res["masked_text"].split()[-1]
plain = engine.decrypt_value(cipher, {"tenant_id": "t1", "doc_type": "sample"})
print(plain)
```

---

## Config-first masking

See `masking_config.yaml`. Add new attributes via:
- `detection.structured_keys`: JSON key patterns + policy
- `detection.custom_regexes`: regex pattern + policy
- `entities`: map NER label → policy

> **Never** send the `replacement_map` to LLMs; keep it server-side only.

---

## Project structure

```
pii-masking-framework/
├─ README.md
├─ LICENSE
├─ requirements.txt
├─ masking_config.yaml
├─ src/
│  ├─ masking_engine.py        # core detection + policy + transforms
│  ├─ cli.py                   # CLI entrypoints
│  └─ service/
│     └─ app.py                # FastAPI service
├─ examples/
│  ├─ sample_text.txt
│  └─ sample.json
├─ tests/
│  ├─ test_masking_basic.py
│  └─ config_test.yaml
├─ Dockerfile
└─ .gitignore
```

---

## Security notes

- Use **AES-GCM** with a 32-byte key; rotate via KMS (not included in this sample).
- Bind ciphertext to context with **AAD** (`tenant_id`, `doc_type`) for replay resistance.
- Prefer **TOKENIZE** for analytics, **ENCRYPT** for reversible protection, **HASH** when irreversibility is required.
- Disable logs of raw inputs. Set `output.drop_plaintext: true` in config.
- Keep `replacement_map` **in memory** or in an encrypted store with TTL. Never send downstream.

---

## Tests

```bash
pytest -q
```

This runs without spaCy by using a test config that sets `use_ner: false` and relies on regex.

---

## License

MIT

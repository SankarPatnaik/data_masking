
# PII Masking & Encryption Framework (NER + Regex + Policy)

A production-ready Python framework to **detect and protect PII** before sending to LLMs or downstream systems.
- Hybrid detection: **NER (spaCy)** + **Regex** + **Structured key rules for JSON**
- Transform policies: **REDACT**, **HASH**, **ENCRYPT (AES-GCM)**, **FPE** (optional), **TOKENIZE**, **SYNTHETIC**
- Config-first: add new attributes without code changes
- Run as a **FastAPI service** or a **CLI**

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

### Encrypt and decrypt files

The FastAPI service also exposes simple endpoints for encrypting uploaded files and decrypting the ciphertext.

```bash
# Encrypt a file
curl -F "file=@path/to/file.txt" http://localhost:8000/encrypt/upload

# Decrypt (uses the `encrypted_data` field returned above)
curl -X POST -H "Content-Type: application/json" \
  -d '{"data": "<ciphertext>"}' http://localhost:8000/decrypt
```

`FILE_ENCRYPTION_KEY` (a base64 encoded 32-byte key) controls the symmetric key used by these endpoints.
File uploads require the optional `python-multipart` dependency.

### Streamlit file encryption UI

For a simple browser interface, run the Streamlit app which uses the same
`FILE_ENCRYPTION_KEY` as the FastAPI service:

```bash
streamlit run src/streamlit_app.py
```

The UI lets you upload a file to encrypt or decrypt and download the result.

### 6) Decrypt encrypted values
```python
from src.masking_engine import Config, MaskingEngine

cfg = Config.from_yaml("masking_config.yaml")
engine = MaskingEngine(cfg)

ctx = {"tenant_id": "t1", "doc_type": "sample"}
res = engine.mask_text("PAN ABCDE1234F", ctx)
cipher = res["masked_text"].split()[-1]
plain = engine.decrypt_value(cipher, ctx)
print(plain)  # PAN ABCDE1234F
```

### Generate synthetic data from raw PII

The framework can replace real PII values with fake but realistic data. This is
useful when you need to share the shape of a dataset without exposing actual
information.

1. *(Optional)* Install [`faker`](https://faker.readthedocs.io/) for more
   natural-looking output:

   ```bash
   pip install faker
   ```

2. Create a config that marks the fields you want to synthesize using the
   `SYNTHETIC` policy:

   ```yaml
   # examples/configs/synthetic.yaml
   language: "en"
   detection:
     use_regex: false
     use_ner: false
     structured_keys:
       - key: "(?i)^name$"
         policy: SYNTHETIC
       - key: "(?i)^address$"
         policy: SYNTHETIC
       - key: "(?i)^phone$"
         policy: SYNTHETIC
       - key: "(?i)^email$"
         policy: SYNTHETIC
   masking:
     default_policy: NONE
   ```

3. Run the CLI on raw data and it will emit a structure with synthetic values:

   ```bash
   python -m src.cli --config examples/configs/synthetic.yaml json examples/raw_synthetic.json
   ```

   Example output (values will vary each run):

   ```json
   {
     "masked_json": {
       "name": "Alice Jones",
       "address": "6988 Oak Ave, Fairview",
       "phone": "23806016143",
       "email": "hpllzokd@oqcxq.com"
     }
   }
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
│  ├─ configs/
│  │  └─ synthetic.yaml
│  ├─ raw_synthetic.json
│  ├─ sample.json
│  ├─ sample_lines.jsonl
│  └─ sample_text.txt
├─ tests/
│  ├─ test_file_encryption_api.py
│  ├─ test_masking_basic.py
│  ├─ test_synthetic_masking.py
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

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT

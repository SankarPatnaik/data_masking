
import base64
import importlib
import os
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException
from starlette.datastructures import UploadFile
from pydantic import BaseModel
from cryptography.fernet import Fernet
from src.masking_engine import Config, MaskingEngine

try:
    importlib.import_module("multipart")
    from fastapi import File
    _multipart_available = True
except ModuleNotFoundError:  # pragma: no cover - dependency missing in some envs
    File = None  # type: ignore
    _multipart_available = False

CONFIG_PATH = os.getenv("MASKING_CONFIG_PATH", "masking_config.yaml")

app = FastAPI(title="PII Masking Service", version="1.0.0")

# Load config + engine
try:
    cfg = Config.from_yaml(CONFIG_PATH)
    engine = MaskingEngine(cfg)
except Exception as e:
    raise RuntimeError(f"Failed to load config {CONFIG_PATH}: {e}")

# Encryption key for file APIs
_enc_key = os.getenv("FILE_ENCRYPTION_KEY")
if not _enc_key:
    # Deterministic default for tests if not provided
    _enc_key = base64.urlsafe_b64encode(b"0" * 32).decode()
fernet = Fernet(_enc_key)

class TextReq(BaseModel):
    text: str
    context: Optional[Dict[str, str]] = None

class JsonReq(BaseModel):
    payload: Any
    context: Optional[Dict[str, str]] = None
    also_scan_text_nodes: bool = True


class DecryptReq(BaseModel):
    """Request model for decrypting data."""

    data: str  # base64 encoded ciphertext

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/mask/text")
def mask_text(req: TextReq):
    try:
        return engine.mask_text(req.text, context=req.context or {})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/mask/json")
def mask_json(req: JsonReq):
    try:
        return engine.mask_json(req.payload, context=req.context or {}, also_scan_text_nodes=req.also_scan_text_nodes)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def encrypt_upload(file: UploadFile):
    """Encrypt an uploaded file and return base64 ciphertext."""

    try:
        contents = await file.read()
        encrypted = fernet.encrypt(contents)
        return {
            "filename": getattr(file, "filename", ""),
            "encrypted_data": base64.b64encode(encrypted).decode(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if _multipart_available:
    @app.post("/encrypt/upload")
    async def encrypt_upload_api(file: UploadFile = File(...)):
        return await encrypt_upload(file)


@app.post("/decrypt")
def decrypt_data(req: DecryptReq):
    """Decrypt base64 ciphertext produced by ``/encrypt/upload``."""

    try:
        encrypted = base64.b64decode(req.data)
        decrypted = fernet.decrypt(encrypted)
        return {"decrypted_data": base64.b64encode(decrypted).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

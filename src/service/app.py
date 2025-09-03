
import os
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.masking_engine import Config, MaskingEngine

CONFIG_PATH = os.getenv("MASKING_CONFIG_PATH", "masking_config.yaml")

app = FastAPI(title="PII Masking Service", version="1.0.0")

# Load config + engine
try:
    cfg = Config.from_yaml(CONFIG_PATH)
    engine = MaskingEngine(cfg)
except Exception as e:
    raise RuntimeError(f"Failed to load config {CONFIG_PATH}: {e}")

class TextReq(BaseModel):
    text: str
    context: Optional[Dict[str, str]] = None

class JsonReq(BaseModel):
    payload: Any
    context: Optional[Dict[str, str]] = None
    also_scan_text_nodes: bool = True

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

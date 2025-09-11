import argparse
import base64
import importlib
import json
import os
import re
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from starlette.datastructures import UploadFile

from src.config_loader import get_engine

try:  # Optional dependency for file uploads
    importlib.import_module("multipart")
    from fastapi import File
    _multipart_available = True
except ModuleNotFoundError:  # pragma: no cover - dependency missing in some envs
    File = None  # type: ignore
    _multipart_available = False


def create_app(config_path: Optional[str] = None) -> FastAPI:
    """Create the FastAPI app using the shared MaskingEngine."""

    engine = get_engine(config_path)
    app = FastAPI(title="PII Masking Service", version="1.0.0")

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
            return engine.mask_json(
                req.payload,
                context=req.context or {},
                also_scan_text_nodes=req.also_scan_text_nodes,
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    async def encrypt_upload(file: UploadFile):
        """Mask an uploaded file and return its base64 representation."""

        try:
            contents = await file.read()
            text = contents.decode("utf-8")
            try:
                obj = json.loads(text)
                masked = engine.mask_json(obj)["masked_json"]
                masked_bytes = json.dumps(masked, ensure_ascii=False).encode("utf-8")
            except json.JSONDecodeError:
                masked = engine.mask_text(text)["masked_text"]
                masked_bytes = masked.encode("utf-8")
            return {
                "filename": getattr(file, "filename", ""),
                "encrypted_data": base64.b64encode(masked_bytes).decode(),
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def decrypt_file_contents(data: bytes) -> bytes:
        """Reverse field-level encryption within the provided file contents."""

        text = data.decode("utf-8")
        try:
            obj = json.loads(text)

            def walk(node):
                if isinstance(node, dict):
                    return {k: walk(v) for k, v in node.items()}
                if isinstance(node, list):
                    return [walk(x) for x in node]
                if isinstance(node, str):
                    return engine.decrypt_value(node)
                return node

            decrypted = walk(obj)
            return json.dumps(decrypted, ensure_ascii=False).encode("utf-8")
        except json.JSONDecodeError:
            pattern = re.compile(r"enc:[^\s\"']+")

            def repl(match: re.Match) -> str:
                return engine.decrypt_value(match.group(0))

            return pattern.sub(repl, text).encode("utf-8")

    if _multipart_available:
        @app.post("/encrypt/upload")
        async def encrypt_upload_api(file: UploadFile = File(...)):
            return await encrypt_upload(file)

    @app.post("/decrypt")
    def decrypt_data(req: DecryptReq):
        """Decrypt data previously processed by ``encrypt_upload``."""

        try:
            masked = base64.b64decode(req.data)
            decrypted = decrypt_file_contents(masked)
            return {"decrypted_data": base64.b64encode(decrypted).decode()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    # Expose internals for reuse/tests
    app.state.engine = engine
    app.state.encrypt_upload = encrypt_upload
    app.state.decrypt_data = decrypt_data
    app.state.DecryptReq = DecryptReq

    return app


app = create_app()

# Export utilities for backwards compatibility
encrypt_upload = app.state.encrypt_upload
decrypt_data = app.state.decrypt_data
DecryptReq = app.state.DecryptReq


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the PII masking API")
    parser.add_argument(
        "--config",
        default=os.getenv("MASKING_CONFIG_PATH", "masking_config.yaml"),
        help="Path to masking configuration file",
    )
    parser.add_argument("--host", default=os.getenv("SERVICE_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("SERVICE_PORT", "8000")))
    parser.add_argument("--reload", action="store_true", default=bool(os.getenv("SERVICE_RELOAD")))
    args = parser.parse_args()

    app = create_app(args.config)
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)

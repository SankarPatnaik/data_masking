import base64
import io
import os

# Use test config to avoid loading full masking config
os.environ.setdefault("MASKING_CONFIG_PATH", "tests/config_test.yaml")
os.environ.setdefault("FILE_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"0" * 32).decode())

from starlette.datastructures import UploadFile
import anyio

from src.service.app import encrypt_upload, decrypt_data, DecryptReq


async def _roundtrip():
    original = b"hello world"
    upload = UploadFile(filename="test.txt", file=io.BytesIO(original))
    enc_res = await encrypt_upload(upload)
    enc_data = enc_res["encrypted_data"]
    dec_res = decrypt_data(DecryptReq(data=enc_data))
    decrypted_b64 = dec_res["decrypted_data"]
    assert base64.b64decode(decrypted_b64) == original


def test_encrypt_decrypt_file_roundtrip():
    anyio.run(_roundtrip)

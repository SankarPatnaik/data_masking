import base64
import io
import json
import os

# Use test config to avoid loading full masking config
os.environ.setdefault("MASKING_CONFIG_PATH", "tests/config_test.yaml")
os.environ.setdefault("MASKING_AES_KEY_B64", base64.b64encode(b"0" * 32).decode())

from starlette.datastructures import UploadFile
import anyio

from src.service.app import encrypt_upload, decrypt_data, DecryptReq


async def _roundtrip_json():
    payload = {"id": "1234", "email": "foo@bar.com", "name": "Alice"}
    original_bytes = json.dumps(payload).encode("utf-8")
    upload = UploadFile(filename="test.json", file=io.BytesIO(original_bytes))
    enc_res = await encrypt_upload(upload)
    enc_data = enc_res["encrypted_data"]

    # Check that only fields are encrypted and structure remains
    masked_bytes = base64.b64decode(enc_data)
    masked_obj = json.loads(masked_bytes.decode("utf-8"))
    assert masked_obj["name"] == "Alice"
    assert masked_obj["email"].startswith("hash_")
    assert masked_obj["id"].startswith("enc:")

    dec_res = decrypt_data(DecryptReq(data=enc_data))
    decrypted_bytes = base64.b64decode(dec_res["decrypted_data"])
    dec_obj = json.loads(decrypted_bytes.decode("utf-8"))
    assert dec_obj["name"] == payload["name"]
    assert dec_obj["id"] == payload["id"]
    # Email was hashed and cannot be reversed
    assert dec_obj["email"].startswith("hash_")


def test_encrypt_decrypt_file_roundtrip():
    anyio.run(_roundtrip_json)

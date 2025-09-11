"""Simple Streamlit app for encrypting and decrypting files."""

import base64

import streamlit as st

from src.config_loader import get_file_fernet

fernet = get_file_fernet()


st.title("File Encrypt/Decrypt")

mode = st.radio("Operation", ["Encrypt", "Decrypt"], horizontal=True)
uploaded = st.file_uploader("Upload a file")

if uploaded and st.button(mode):
    data = uploaded.read()
    try:
        if mode == "Encrypt":
            encrypted = fernet.encrypt(data)
            b64 = base64.b64encode(encrypted).decode()
            st.text_area("Encrypted data (base64)", b64, height=200)
            st.download_button(
                "Download encrypted file",
                encrypted,
                file_name=f"{uploaded.name}.enc",
            )
        else:
            decrypted = fernet.decrypt(data)
            b64 = base64.b64encode(decrypted).decode()
            st.text_area("Decrypted data (base64)", b64, height=200)
            st.download_button(
                "Download decrypted file",
                decrypted,
                file_name=f"decrypted_{uploaded.name}",
            )
    except Exception as e:  # pragma: no cover - UI feedback
        st.error(f"{mode}ion failed: {e}")


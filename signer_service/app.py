from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from flask import Flask, jsonify, request

APP_HOST = os.getenv("SIGNER_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("SIGNER_PORT", "8002"))
PRIVATE_KEY_PATH = os.getenv("SIGNER_PRIVATE_KEY", "/app/keys/private_key.pem")
SIGNER_TOKEN = os.getenv("SIGNER_TOKEN", "dev-signer-token")
SIGNER_KEY_ID = os.getenv("SIGNER_KEY_ID", "online-key-v1")

app = Flask(__name__)


def _sign_payload(name: str, version: str, payload_hash: str) -> str:
    data = f"{name}:{version}:{payload_hash}".encode("utf-8")
    key_path = Path(PRIVATE_KEY_PATH)
    if not key_path.exists():
        raise FileNotFoundError("private key not found")

    with key_path.open("rb") as f:
        priv = load_pem_private_key(f.read(), password=None)

    signature = priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/sign")
def sign():
    req_token = request.headers.get("X-Signer-Token", "")
    if not SIGNER_TOKEN or req_token != SIGNER_TOKEN:
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(silent=True) or {}
    name = payload.get("name", "")
    version = payload.get("version", "")
    payload_hash = payload.get("payload_hash", "")

    if not name or not version or not payload_hash:
        return jsonify({"error": "invalid_payload"}), 400

    try:
        signature = _sign_payload(name, version, payload_hash)
    except Exception as exc:
        return jsonify({"error": "signing_failed", "details": str(exc)}), 500

    return jsonify({"signature": signature, "signature_type": "rsa", "key_id": SIGNER_KEY_ID})


if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT)

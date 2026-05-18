from __future__ import annotations

import base64
import hashlib
import os
import ssl
from pathlib import Path

from flask import Flask, Response, jsonify, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE_DIR = Path(__file__).resolve().parent
SAFE_MODULE = BASE_DIR / "safe_update.py"
COMPROMISED_MODULE = BASE_DIR / "compromised_update.py"
APP_HOST = os.getenv("UPDATER_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("UPDATER_PORT", "8001"))
RSA_PRIVATE_KEY_PATH = os.getenv("UPDATER_RSA_PRIVATE_KEY_PATH", "")
MTLS_ENABLED = os.getenv("UPDATER_MTLS_ENABLED", "0") == "1"
TLS_CERT_FILE = os.getenv("UPDATER_TLS_CERT_FILE", "")
TLS_KEY_FILE = os.getenv("UPDATER_TLS_KEY_FILE", "")
TLS_CA_FILE = os.getenv("UPDATER_TLS_CA_FILE", "")

app = Flask(__name__)


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _load_module_source(mode: str) -> tuple[str, str, str]:
    if mode in {"compromised", "malicious_valid"}:
        module_path = COMPROMISED_MODULE
        module_name = "compromised_update" if mode == "compromised" else "safe_update"
        version = "2.0.0" if mode == "compromised" else "1.1.0"
    else:
        module_path = SAFE_MODULE
        module_name = "safe_update"
        version = "1.0.0"
    return module_name, version, module_path.read_text(encoding="utf-8")


def _signature_payload(name: str, version: str, payload_hash: str, mode: str) -> bytes:
    return f"{name}|{version}|{payload_hash}|{mode}".encode("utf-8")


def _sign_manifest(name: str, version: str, payload_hash: str, mode: str) -> str | None:
    if not RSA_PRIVATE_KEY_PATH:
        return None
    key_path = Path(RSA_PRIVATE_KEY_PATH)
    if not key_path.exists():
        return None
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    signature = private_key.sign(
        _signature_payload(name, version, payload_hash, mode),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/manifest")
def manifest():
    mode = request.args.get("mode", "safe")
    module_name, version, source = _load_module_source(mode)
    payload_hash = _sha256(source)
    if mode == "invalid_manifest":
        # Deliberately publish an incorrect hash while keeping signature over that manifest.
        payload_hash = _sha256(source + "\n# tampered-manifest")
    rsa_signature = _sign_manifest(module_name, version, payload_hash, mode)

    package_module_name = "compromised_update" if mode == "malicious_valid" else module_name

    return jsonify(
        {
            "name": module_name,
            "version": version,
            "sha256": payload_hash,
            "rsa_signature": rsa_signature,
            "module_url": f"https://{os.getenv('UPDATER_PUBLIC_HOST', 'updater-service:8001')}/packages/{package_module_name}.py",
            "mode": mode,
        }
    )


@app.get("/packages/<module_name>.py")
def package(module_name: str):
    if module_name not in {"safe_update", "compromised_update"}:
        return jsonify({"error": "unknown module"}), 404
    path = SAFE_MODULE if module_name == "safe_update" else COMPROMISED_MODULE
    return Response(path.read_text(encoding="utf-8"), mimetype="text/x-python")


def _build_tls_context() -> ssl.SSLContext | None:
    if not MTLS_ENABLED:
        return None
    if not (TLS_CERT_FILE and TLS_KEY_FILE and TLS_CA_FILE):
        raise RuntimeError("mTLS enabled, but certificate paths are not configured")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=TLS_CERT_FILE, keyfile=TLS_KEY_FILE)
    context.load_verify_locations(cafile=TLS_CA_FILE)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT, ssl_context=_build_tls_context())

from __future__ import annotations

import base64
import hashlib
import logging
import os
import ssl
from pathlib import Path

from flask import Flask, Response, jsonify, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
SAFE_MODULE = BASE_DIR / "safe_update.py"
BAD_CODE_MODULE = BASE_DIR / "bad_code_module.py"
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
    """
    Load module source based on mode:
    - safe: safe_update.py, version 1.0.0
    - invalid_manifest: bad_code module with wrong hash, version 1.0.0
    - bad_code: bad_code module with correct hash, claimed as safe_update, version 1.1.0
    """
    if mode == "invalid_manifest":
        # Send bad code with tampered manifest hash
        module_path = BAD_CODE_MODULE
        module_name = "safe_update"  # Claim it's safe to fool policy
        version = "1.0.0"
    elif mode == "bad_code":
        # Send bad code with correct hash but claiming to be safe_update
        module_path = BAD_CODE_MODULE
        module_name = "safe_update"
        version = "1.1.0"
    else:  # safe or default
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
    
    # For invalid_manifest, deliberately publish an incorrect hash
    if mode == "invalid_manifest":
        payload_hash = _sha256(source + "\n# tampered-manifest")
    
    rsa_signature = _sign_manifest(module_name, version, payload_hash, mode)

    # Determine which actual module file to serve
    # For invalid_manifest and bad_code, serve bad_code module
    if mode in {"invalid_manifest", "bad_code"}:
        package_module_name = "bad_code"
    else:
        package_module_name = "safe_update"
    
    # Use HTTP or HTTPS based on mTLS enablement
    protocol = "https" if MTLS_ENABLED else "http"
    host = os.getenv('UPDATER_PUBLIC_HOST', 'updater-service:8001')

    return jsonify(
        {
            "name": module_name,
            "version": version,
            "sha256": payload_hash,
            "rsa_signature": rsa_signature,
            "module_url": f"{protocol}://{host}/packages/{package_module_name}.py",
            "mode": mode,
        }
    )


@app.get("/packages/<module_name>.py")
def package(module_name: str):
    if module_name not in {"safe_update", "bad_code"}:
        return jsonify({"error": "unknown module"}), 404
    path = SAFE_MODULE if module_name == "safe_update" else BAD_CODE_MODULE
    return Response(path.read_text(encoding="utf-8"), mimetype="text/x-python")


def _build_tls_context() -> ssl.SSLContext | None:
    # TLS context building is now handled by gunicorn via entrypoint.sh
    # This function is kept for reference only
    return None


if __name__ == "__main__":
    # Note: This is only used for local development with `python app.py`
    # In production, use gunicorn via entrypoint.sh which handles mTLS
    app.run(host=APP_HOST, port=APP_PORT)

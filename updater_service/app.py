from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

from flask import Flask, Response, jsonify, request

BASE_DIR = Path(__file__).resolve().parent
SAFE_MODULE = BASE_DIR / "safe_update.py"
COMPROMISED_MODULE = BASE_DIR / "compromised_update.py"
APP_HOST = os.getenv("UPDATER_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("UPDATER_PORT", "8001"))
ONLINE_SIGNER_URL = os.getenv("ONLINE_SIGNER_URL", "http://signer-service:8002/sign")
ONLINE_SIGNER_SHARED_TOKEN = os.getenv("ONLINE_SIGNER_SHARED_TOKEN", "dev-signer-token")
RELEASE_SIGNER_URL = os.getenv("RELEASE_SIGNER_URL", "http://release-signer-service:8002/sign")
RELEASE_SIGNER_SHARED_TOKEN = os.getenv("RELEASE_SIGNER_SHARED_TOKEN", "dev-release-signer-token")

app = Flask(__name__)


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _request_signature(name: str, version: str, payload_hash: str, signer_url: str, signer_token: str) -> dict[str, str]:
    payload = json.dumps(
        {
            "name": name,
            "version": version,
            "payload_hash": payload_hash,
        }
    ).encode("utf-8")

    req = urllib_request.Request(
        signer_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Signer-Token": signer_token,
        },
    )

    with urllib_request.urlopen(req, timeout=10) as response:
        body = json.loads(response.read().decode("utf-8"))

    signature = body.get("signature", "")
    signature_type = body.get("signature_type", "")
    key_id = body.get("key_id", "")
    if not signature or signature_type != "rsa" or not key_id:
        raise ValueError("invalid_signer_response")
    return {"signature": signature, "signature_type": signature_type, "key_id": key_id}


def _load_module_source(mode: str) -> tuple[str, str, str]:
    if mode == "compromised":
        module_path = COMPROMISED_MODULE
        module_name = "compromised_update"
        version = "2.0.0"
    else:
        module_path = SAFE_MODULE
        module_name = "safe_update"
        version = "1.0.0"
    return module_name, version, module_path.read_text(encoding="utf-8")


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/manifest")
def manifest():
    mode = request.args.get("mode", "safe")
    module_name, version, source = _load_module_source(mode)
    payload_hash = _sha256(source)
    try:
        online_sig = _request_signature(module_name, version, payload_hash, ONLINE_SIGNER_URL, ONLINE_SIGNER_SHARED_TOKEN)
        release_sig = _request_signature(module_name, version, payload_hash, RELEASE_SIGNER_URL, RELEASE_SIGNER_SHARED_TOKEN)
    except (urllib_error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        return jsonify({"error": "signing_failed", "details": str(exc)}), 500

    return jsonify(
        {
            "name": module_name,
            "version": version,
            "sha256": payload_hash,
            "signatures": [online_sig, release_sig],
            "module_url": f"http://{os.getenv('UPDATER_PUBLIC_HOST', 'updater-service:8001')}/packages/{module_name}.py",
            "mode": mode,
        }
    )


@app.get("/packages/<module_name>.py")
def package(module_name: str):
    if module_name not in {"safe_update", "compromised_update"}:
        return jsonify({"error": "unknown module"}), 404
    path = SAFE_MODULE if module_name == "safe_update" else COMPROMISED_MODULE
    return Response(path.read_text(encoding="utf-8"), mimetype="text/x-python")


if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT)

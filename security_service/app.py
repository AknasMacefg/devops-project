from __future__ import annotations

import ast
import base64
import hashlib
import json
import logging
import os
import re
import ssl
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import time
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WORKDIR = os.getenv("WORKDIR", "/artifacts")
RSA_PUBLIC_KEY_PATH = os.getenv("SECURITY_RSA_PUBLIC_KEY_PATH", "")
RSA_VERIFY_REQUIRED = os.getenv("SECURITY_RSA_VERIFY_REQUIRED", "0") == "1"
STRICT_TIME_BOMB_CHECK = os.getenv("STRICT_TIME_BOMB_CHECK", "1") == "1"
MTLS_ENABLED = os.getenv("SECURITY_MTLS_ENABLED", "0") == "1"

APP_HOST = os.getenv("SECURITY_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("SECURITY_PORT", "8002"))
DEFAULT_UPDATE_SERVICE_URL = os.getenv("UPDATE_SERVICE_URL", "http://updater-service:8001")
TLS_CERT_FILE = os.getenv("SECURITY_TLS_CLIENT_CERT_FILE", "")
TLS_KEY_FILE = os.getenv("SECURITY_TLS_CLIENT_KEY_FILE", "")
TLS_CA_FILE = os.getenv("SECURITY_TLS_CA_FILE", "")


def _build_tls_context() -> ssl.SSLContext | None:
    if not MTLS_ENABLED:
        logger.info("mTLS disabled, using plain HTTP for updater-service calls")
        return None
    
    if not (TLS_CERT_FILE and TLS_KEY_FILE and TLS_CA_FILE):
        logger.error("mTLS enabled but cert paths not configured. Using plain HTTP as fallback.")
        logger.error(f"  CERT: {TLS_CERT_FILE or 'not set'}")
        logger.error(f"  KEY: {TLS_KEY_FILE or 'not set'}")
        logger.error(f"  CA: {TLS_CA_FILE or 'not set'}")
        return None
    
    # Verify certificate files exist
    cert_path = Path(TLS_CERT_FILE)
    key_path = Path(TLS_KEY_FILE)
    ca_path = Path(TLS_CA_FILE)
    
    missing = []
    if not cert_path.exists():
        missing.append(f"cert file: {TLS_CERT_FILE}")
    if not key_path.exists():
        missing.append(f"key file: {TLS_KEY_FILE}")
    if not ca_path.exists():
        missing.append(f"CA file: {TLS_CA_FILE}")
    
    if missing:
        logger.error(f"mTLS enabled but certificate files missing: {', '.join(missing)}")
        logger.error("Using plain HTTP as fallback.")
        return None
    
    try:
        context = ssl.create_default_context(cafile=str(ca_path))
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        # Check hostname but don't fail on mismatch - log warning instead
        context.check_hostname = True
        logger.info(f"mTLS enabled: loaded client cert from {cert_path}, CA from {ca_path}")
        return context
    except Exception as e:
        logger.error(f"Failed to build TLS context: {e}")
        logger.error("Using plain HTTP as fallback.")
        return None


TLS_CONTEXT = _build_tls_context()

app = Flask(__name__)


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _get_ssl_context(url: str) -> ssl.SSLContext | None:
    """Get SSL context only for HTTPS URLs, always return None for HTTP"""
    if url.startswith("https://"):
        return TLS_CONTEXT
    return None


def _download_json(url: str) -> dict:
    context = _get_ssl_context(url)
    with urllib_request.urlopen(url, timeout=10, context=context) as response:
        return json.loads(response.read().decode("utf-8"))


def _download_text(url: str) -> str:
    context = _get_ssl_context(url)
    with urllib_request.urlopen(url, timeout=10, context=context) as response:
        return response.read().decode("utf-8")


def _version_parts(value: str) -> list[int]:
    parts = [int(item) for item in re.findall(r"\d+", value or "")]
    return parts or [0]


def _compare_versions(a: str, b: str) -> int:
    a_parts = _version_parts(a)
    b_parts = _version_parts(b)
    size = max(len(a_parts), len(b_parts))
    a_norm = a_parts + [0] * (size - len(a_parts))
    b_norm = b_parts + [0] * (size - len(b_parts))
    if a_norm < b_norm:
        return -1
    if a_norm > b_norm:
        return 1
    return 0


def _evaluate_policy(manifest: dict, mode: str, allowed_modules: list[str], min_allowed_update_version: str, last_applied_update_version: str) -> tuple[bool, dict]:
    module_name = manifest.get("name", "")
    details = {
        "allowed_modules": sorted(set(allowed_modules)),
        "module_name": module_name,
        "mode": mode,
        "version": manifest.get("version", "0.0.0"),
        "min_allowed_update_version": min_allowed_update_version,
        "last_applied_update_version": last_applied_update_version,
    }

    if module_name not in set(allowed_modules):
        details["reason"] = "module_not_allowed"
        return False, details

    version = manifest.get("version", "0.0.0")
    if _compare_versions(version, min_allowed_update_version) < 0:
        details["reason"] = "version_below_minimum"
        return False, details

    details["reason"] = "policy_ok"
    return True, details


def _signature_payload(name: str, version: str, payload_hash: str, mode: str) -> bytes:
    return f"{name}|{version}|{payload_hash}|{mode}".encode("utf-8")


def _verify_rsa_signature(manifest: dict, payload_hash: str, mode: str) -> tuple[bool, str]:
    signature_b64 = manifest.get("rsa_signature")
    if not signature_b64:
        return (not RSA_VERIFY_REQUIRED), "missing_signature"
    if not RSA_PUBLIC_KEY_PATH:
        return (not RSA_VERIFY_REQUIRED), "missing_public_key_path"
    key_path = os.path.abspath(RSA_PUBLIC_KEY_PATH)
    if not os.path.exists(key_path):
        return (not RSA_VERIFY_REQUIRED), "missing_public_key_file"
    try:
        pub = serialization.load_pem_public_key(open(key_path, "rb").read())
        pub.verify(
            base64.b64decode(signature_b64),
            _signature_payload(manifest.get("name", ""), manifest.get("version", ""), payload_hash, mode),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True, "signature_ok"
    except Exception as exc:
        return False, f"signature_invalid:{exc}"


def _detect_time_bomb_patterns(module_source: str) -> list[str]:
    findings: list[str] = []
    try:
        tree = ast.parse(module_source)
    except SyntaxError:
        return ["syntax_error"]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"time", "datetime"}:
                    findings.append(f"import:{alias.name}")
        if isinstance(node, ast.ImportFrom) and node.module in {"time", "datetime"}:
            findings.append(f"import_from:{node.module}")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in {"sleep", "now", "utcnow", "today", "time"}:
                    findings.append(f"call:{node.func.attr}")
            if isinstance(node.func, ast.Name) and node.func.id in {"sleep", "time"}:
                findings.append(f"call:{node.func.id}")
    return sorted(set(findings))


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/evaluate")
def evaluate():
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode", "safe")
    update_service_url = payload.get("update_service_url", DEFAULT_UPDATE_SERVICE_URL).rstrip("/")
    if MTLS_ENABLED and update_service_url.startswith("http://"):
        update_service_url = "https://" + update_service_url.removeprefix("http://")
    if not MTLS_ENABLED and update_service_url.startswith("https://"):
        update_service_url = "http://" + update_service_url.removeprefix("https://")
    allowed_modules = payload.get("allowed_modules", ["safe_update"])
    min_allowed_update_version = payload.get("min_allowed_update_version", "0.0.0")
    last_applied_update_version = payload.get("last_applied_update_version", "0.0.0")
    protection_enabled = bool(payload.get("protection_enabled", True))

    manifest_url = f"{update_service_url}/manifest?mode={mode}"

    try:
        logger.info(f"Fetching manifest from {manifest_url} (TLS context: {'enabled' if TLS_CONTEXT else 'disabled'})")
        manifest = _download_json(manifest_url)
        module_source = _download_text(manifest["module_url"])
    except (urllib_error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
        logger.error(f"Error fetching manifest: {type(exc).__name__}: {exc}", exc_info=True)
        return jsonify(
            {
                "status": "error",
                "message": f"Проверка обновления не удалась: {exc}",
                "details": {"mode": mode, "manifest_url": manifest_url},
            }
        ), 502

    # If protection is disabled, bypass all checks
    if not protection_enabled:
        return jsonify(
            {
                "status": "approved",
                "message": f"Обновление одобрено (защита отключена): {manifest.get('name', 'unknown')}",
                "details": {
                    "mode": mode,
                    "protection_enabled": False,
                },
                "manifest": manifest,
                "module_source": module_source,
            }
        )

    payload_hash = _sha256(module_source)
    expected_hash = manifest.get("sha256", "")
    integrity_ok = payload_hash == expected_hash
    rsa_ok, rsa_reason = _verify_rsa_signature(manifest, payload_hash, mode)
    policy_ok, policy_details = _evaluate_policy(
        manifest,
        mode,
        allowed_modules,
        min_allowed_update_version,
        last_applied_update_version,
    )

    if not policy_ok:
        return jsonify(
            {
                "status": "blocked",
                "message": f"Обновление заблокировано политикой: {manifest.get('name', 'unknown')}",
                "details": {
                    "mode": mode,
                    "policy_ok": False,
                    "policy": policy_details,
                    "integrity_ok": integrity_ok,
                    "expected_hash": expected_hash,
                    "received_hash": payload_hash,
                },
                "manifest": manifest,
            }
        )

    if protection_enabled and not integrity_ok:
        return jsonify(
            {
                "status": "blocked",
                "message": f"Заблокировано скомпрометированное обновление: {manifest.get('name', 'unknown')}",
                "details": {
                    "mode": mode,
                    "policy_ok": True,
                    "policy": policy_details,
                    "integrity_ok": False,
                    "expected_hash": expected_hash,
                    "received_hash": payload_hash,
                },
                "manifest": manifest,
            }
        )
    if protection_enabled and not rsa_ok:
        return jsonify(
            {
                "status": "blocked",
                "message": f"Заблокировано обновление с неверной RSA-подписью: {manifest.get('name', 'unknown')}",
                "details": {
                    "mode": mode,
                    "policy_ok": True,
                    "policy": policy_details,
                    "integrity_ok": integrity_ok,
                    "rsa_ok": False,
                    "rsa_reason": rsa_reason,
                },
                "manifest": manifest,
            }
        )

    time_bomb_findings = _detect_time_bomb_patterns(module_source) if STRICT_TIME_BOMB_CHECK else []
    if protection_enabled and time_bomb_findings:
        return jsonify(
            {
                "status": "blocked",
                "message": f"Заблокировано потенциально опасное обновление: {manifest.get('name', 'unknown')}",
                "details": {
                    "mode": mode,
                    "policy_ok": True,
                    "policy": policy_details,
                    "integrity_ok": integrity_ok,
                    "rsa_ok": rsa_ok,
                    "rsa_reason": rsa_reason,
                    "time_bomb_findings": time_bomb_findings,
                },
                "manifest": manifest,
            }
        )
    
    # Write artifact for sandbox to pick up
    artifact_id = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
    artifact_dir = os.path.join(WORKDIR, artifact_id)
    try:
        os.makedirs(artifact_dir, exist_ok=False)
        with open(os.path.join(artifact_dir, "module.py"), "w", encoding="utf-8") as fh:
            fh.write(module_source)
        with open(os.path.join(artifact_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Не удалось записать артефакт: {exc}"}), 500

    # Invoke sandbox worker on internal sandbox-net
    worker_url = f"http://worker:8003/test"
    try:
        req_body = json.dumps({"artifact_dir": artifact_id, "manifest": manifest}).encode("utf-8")
        req = urllib_request.Request(worker_url, data=req_body, method="POST", headers={"Content-Type": "application/json"})
        with urllib_request.urlopen(req, timeout=60) as resp:
            worker_result = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return jsonify({
            "status": "error",
            "message": f"Не удалось запустить песочницу: {exc}",
            "details": {"artifact_dir": artifact_dir},
        }), 502

    if worker_result.get("status") != "pass":
        return jsonify({
            "status": "blocked",
            "message": f"Песочница не прошла проверку: {manifest.get('name', 'unknown')}",
            "details": {
                "mode": mode,
                "policy_ok": True,
                "policy": policy_details,
                "integrity_ok": integrity_ok,
                "worker": worker_result,
            },
            "manifest": manifest,
        }), 200

    return jsonify(
        {
            "status": "approved",
            "message": f"Обновление одобрено: {manifest.get('name', 'unknown')} (статическая и динамическая проверки пройдены)",
            "details": {
                "mode": mode,
                "policy_ok": True,
                "policy": policy_details,
                "integrity_ok": integrity_ok,
                "expected_hash": expected_hash,
                "received_hash": payload_hash,
                "rsa_ok": rsa_ok,
                "rsa_reason": rsa_reason,
                "artifact_dir": artifact_id,
                "worker": worker_result,
            },
            "manifest": manifest,
            "module_source": module_source,
        }
    )


if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT)
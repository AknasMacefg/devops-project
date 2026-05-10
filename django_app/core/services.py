from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import base64
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import request, error

from django.conf import settings
from django.utils import timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

from .models import SecurityEvent, SecuritySettings

logger = logging.getLogger(__name__)


@dataclass
class UpdateCheckResult:
    status: str
    message: str
    details: dict[str, Any]


def record_security_event(event_type: str, severity: str, message: str, details: dict[str, Any] | None = None) -> SecurityEvent:
    return SecurityEvent.objects.create(
        event_type=event_type,
        severity=severity,
        message=message,
        details=details or {},
    )


def _download_json(url: str) -> dict[str, Any]:
    with request.urlopen(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _download_text(url: str) -> str:
    with request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8")


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _verify_rsa_signature(public_key_path: str, name: str, version: str, payload_hash: str, signature_b64: str) -> bool:
    try:
        data = f"{name}:{version}:{payload_hash}".encode("utf-8")
        pub_path = Path(public_key_path)
        if not pub_path.exists():
            return False
        pub_pem = pub_path.read_bytes()
        pub = load_pem_public_key(pub_pem)
        sig = base64.b64decode(signature_b64)
        pub.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


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


def _load_module_from_source(module_name: str, source: str):
    runtime_dir = settings.UPDATE_RUNTIME_DIR / "updates"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    module_path = runtime_dir / f"{module_name}.py"
    module_path.write_text(source, encoding="utf-8")

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to prepare update module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, module_path


def _evaluate_update_policy(manifest: dict[str, Any], mode: str, security_settings: SecuritySettings) -> tuple[bool, dict[str, Any]]:
    allowed_modules = set(getattr(settings, "UPDATE_POLICY_ALLOWED_MODULES", ["safe_update"]))
    allow_compromised = bool(getattr(settings, "UPDATE_POLICY_ALLOW_COMPROMISED", False))
    module_name = manifest.get("name", "")

    details = {
        "allowed_modules": sorted(allowed_modules),
        "allow_compromised": allow_compromised,
        "module_name": module_name,
        "mode": mode,
        "version": manifest.get("version", "0.0.0"),
        "min_allowed_update_version": security_settings.min_allowed_update_version,
        "last_applied_update_version": security_settings.last_applied_update_version,
    }

    if module_name not in allowed_modules:
        details["reason"] = "module_not_allowed"
        return False, details

    if mode == SecuritySettings.UPDATE_CHANNEL_COMPROMISED and not allow_compromised:
        details["reason"] = "compromised_channel_not_allowed"
        return False, details

    version = manifest.get("version", "0.0.0")
    if _compare_versions(version, security_settings.min_allowed_update_version) < 0:
        details["reason"] = "version_below_minimum"
        return False, details

    if _compare_versions(version, security_settings.last_applied_update_version) < 0:
        details["reason"] = "rollback_detected"
        return False, details

    details["reason"] = "policy_ok"
    return True, details


def perform_update_check() -> UpdateCheckResult:
    security_settings = SecuritySettings.load()
    mode = security_settings.update_channel
    base_url = security_settings.updater_base_url.rstrip("/")
    manifest_url = f"{base_url}/manifest?mode={mode}"

    record_security_event(
        SecurityEvent.EVENT_UPDATE_CHECK,
        SecurityEvent.SEVERITY_LOW,
        "Update check started",
        {"mode": mode, "manifest_url": manifest_url},
    )

    try:
        manifest = _download_json(manifest_url)
        module_source = _download_text(manifest["module_url"])
    except (error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
        message = f"Update check failed: {exc}"
        security_settings.last_update_status = SecuritySettings.STATUS_ERROR
        security_settings.last_update_message = message
        security_settings.last_update_check_at = timezone.now()
        security_settings.save(update_fields=["last_update_status", "last_update_message", "last_update_check_at", "updated_at"])
        record_security_event(
            SecurityEvent.EVENT_WARNING,
            SecurityEvent.SEVERITY_MEDIUM,
            message,
            {"mode": mode},
        )
        return UpdateCheckResult(status=SecuritySettings.STATUS_ERROR, message=message, details={"mode": mode})

    payload_hash = _sha256(module_source)
    expected_hash = manifest.get("sha256", "")
    signatures = manifest.get("signatures", [])

    # Verify integrity: first check payload hash matches manifest
    hash_ok = payload_hash == expected_hash

    signing_public_keys = getattr(settings, "UPDATE_SIGNING_PUBLIC_KEYS", {})
    configured_required_key_ids = set(getattr(settings, "UPDATE_REQUIRED_SIGNING_KEY_IDS", []))
    allowed_key_ids = set(security_settings.allowed_signing_key_ids or [])
    revoked_key_ids = set(security_settings.revoked_signing_key_ids or [])
    required_key_ids = configured_required_key_ids & allowed_key_ids if allowed_key_ids else configured_required_key_ids

    verified_key_ids: set[str] = set()
    revoked_key_used = False

    for entry in signatures if isinstance(signatures, list) else []:
        if not isinstance(entry, dict):
            continue
        key_id = entry.get("key_id", "")
        signature_type = entry.get("signature_type", "")
        signature = entry.get("signature", "")
        if not key_id or signature_type != "rsa":
            continue
        if key_id in revoked_key_ids:
            revoked_key_used = True
            continue
        pub_path = signing_public_keys.get(key_id)
        if not pub_path:
            continue
        if _verify_rsa_signature(
            pub_path,
            manifest.get("name", "unknown"),
            manifest.get("version", "0"),
            expected_hash,
            signature,
        ):
            verified_key_ids.add(key_id)

    required_keys_not_verified = sorted(required_key_ids - verified_key_ids)
    sig_ok = bool(required_key_ids) and not revoked_key_used and not required_keys_not_verified

    integrity_ok = hash_ok and sig_ok

    policy_ok, policy_details = _evaluate_update_policy(manifest, mode, security_settings)

    # Policy gate is mandatory: update code is never executed without policy approval.
    if not policy_ok:
        message = f"Blocked update by policy {manifest.get('name', 'unknown')}"
        security_settings.last_update_status = SecuritySettings.STATUS_BLOCKED
        security_settings.last_update_message = message
        security_settings.last_update_check_at = timezone.now()
        security_settings.save(update_fields=["last_update_status", "last_update_message", "last_update_check_at", "updated_at"])
        record_security_event(
            SecurityEvent.EVENT_UPDATE_BLOCKED,
            SecurityEvent.SEVERITY_CRITICAL,
            message,
            {
                "mode": mode,
                "policy_ok": policy_ok,
                "policy_details": policy_details,
                "integrity_ok": integrity_ok,
                "required_key_ids": sorted(required_key_ids),
                "verified_key_ids": sorted(verified_key_ids),
                "revoked_key_used": revoked_key_used,
            },
        )
        record_security_event(
            SecurityEvent.EVENT_ALERT,
            SecurityEvent.SEVERITY_CRITICAL,
            "ALERT: update blocked by security policy",
            {"mode": mode, "manifest": manifest, "policy": policy_details},
        )
        return UpdateCheckResult(
            status=SecuritySettings.STATUS_BLOCKED,
            message=message,
            details={"integrity_ok": integrity_ok, "policy_ok": policy_ok, "policy": policy_details},
        )

    if security_settings.protection_enabled and not integrity_ok:
        message = f"Blocked compromised update {manifest.get('name', 'unknown')}"
        security_settings.last_update_status = SecuritySettings.STATUS_BLOCKED
        security_settings.last_update_message = message
        security_settings.last_update_check_at = timezone.now()
        security_settings.save(update_fields=["last_update_status", "last_update_message", "last_update_check_at", "updated_at"])
        record_security_event(
            SecurityEvent.EVENT_UPDATE_BLOCKED,
            SecurityEvent.SEVERITY_CRITICAL,
            message,
            {
                "mode": mode,
                "required_key_ids": sorted(required_key_ids),
                "verified_key_ids": sorted(verified_key_ids),
                "required_keys_not_verified": required_keys_not_verified,
                "revoked_key_used": revoked_key_used,
                "expected_hash": expected_hash,
                "received_hash": payload_hash,
                "integrity_ok": integrity_ok,
            },
        )
        record_security_event(
            SecurityEvent.EVENT_ALERT,
            SecurityEvent.SEVERITY_CRITICAL,
            "ALERT: supply chain compromise detected",
            {"mode": mode, "manifest": manifest},
        )
        return UpdateCheckResult(status=SecuritySettings.STATUS_BLOCKED, message=message, details={"integrity_ok": integrity_ok})

    module_name = manifest.get("name", "update_module")
    module, module_path = _load_module_from_source(module_name, module_source)
    context = {
        "settings": security_settings,
        "record_event": record_security_event,
        "runtime_dir": settings.UPDATE_RUNTIME_DIR,
        "leak_file": settings.UPDATE_RUNTIME_DIR / "simulated_leak.txt",
        "logger": logger,
        "manifest": manifest,
    }

    if hasattr(module, "apply_update"):
        module.apply_update(context)

    message = f"Applied update {manifest.get('name', 'unknown')}"
    security_settings.last_update_status = SecuritySettings.STATUS_APPLIED
    security_settings.last_update_message = message
    security_settings.last_update_check_at = timezone.now()
    new_version = manifest.get("version", "0.0.0")
    if _compare_versions(new_version, security_settings.last_applied_update_version) >= 0:
        security_settings.last_applied_update_version = new_version
    security_settings.save(
        update_fields=[
            "last_update_status",
            "last_update_message",
            "last_update_check_at",
            "last_applied_update_version",
            "updated_at",
        ]
    )
    record_security_event(
        SecurityEvent.EVENT_UPDATE_APPLIED,
        SecurityEvent.SEVERITY_LOW,
        message,
        {"mode": mode, "module_path": str(module_path), "integrity_ok": integrity_ok},
    )
    return UpdateCheckResult(status=SecuritySettings.STATUS_APPLIED, message=message, details={"integrity_ok": integrity_ok, "mode": mode})

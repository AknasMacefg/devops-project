from __future__ import annotations

import importlib.util
import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib import request, error

from django.conf import settings
from django.utils import timezone

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


def perform_update_check() -> UpdateCheckResult:
    security_settings = SecuritySettings.load()
    mode = security_settings.update_channel
    security_service_url = getattr(settings, "UPDATE_SECURITY_SERVICE_URL", "http://security-service:8002").rstrip("/")
    evaluate_url = f"{security_service_url}/evaluate"

    record_security_event(
        SecurityEvent.EVENT_UPDATE_CHECK,
        SecurityEvent.SEVERITY_LOW,
        "Update check started",
        {"mode": mode, "security_service_url": evaluate_url},
    )

    try:
        payload = json.dumps(
            {
                "mode": mode,
                "update_service_url": security_settings.updater_base_url,
                "protection_enabled": security_settings.protection_enabled,
                "allowed_modules": getattr(settings, "UPDATE_POLICY_ALLOWED_MODULES", ["safe_update"]),
                "allow_compromised": getattr(settings, "UPDATE_POLICY_ALLOW_COMPROMISED", False),
                "min_allowed_update_version": security_settings.min_allowed_update_version,
                "last_applied_update_version": security_settings.last_applied_update_version,
            }
        ).encode("utf-8")
        req = request.Request(
            evaluate_url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with request.urlopen(req, timeout=15) as response:
            security_decision = json.loads(response.read().decode("utf-8"))
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

    status = security_decision.get("status", "error")
    message = security_decision.get("message", "")
    details = security_decision.get("details", {})
    manifest = security_decision.get("manifest", {})
    module_source = security_decision.get("module_source", "")

    if status != "approved":
        security_settings.last_update_status = SecuritySettings.STATUS_BLOCKED if status == "blocked" else SecuritySettings.STATUS_ERROR
        security_settings.last_update_message = message
        security_settings.last_update_check_at = timezone.now()
        security_settings.save(update_fields=["last_update_status", "last_update_message", "last_update_check_at", "updated_at"])
        if status == "blocked":
            event_type = SecurityEvent.EVENT_UPDATE_BLOCKED
            event_severity = SecurityEvent.SEVERITY_CRITICAL
        else:
            event_type = SecurityEvent.EVENT_WARNING
            event_severity = SecurityEvent.SEVERITY_MEDIUM
        record_security_event(
            event_type,
            event_severity,
            message,
            {
                "mode": mode,
                "decision": security_decision,
            },
        )
        if status == "blocked":
            record_security_event(
                SecurityEvent.EVENT_ALERT,
                SecurityEvent.SEVERITY_CRITICAL,
                "ALERT: supply chain compromise detected",
                {"mode": mode, "decision": security_decision},
            )
        return UpdateCheckResult(status=status, message=message, details=details)

    # Save the approved module for audit; dynamic checks are performed by security-service/worker
    module_name = manifest.get("name", "update_module")
    runtime_dir = settings.UPDATE_RUNTIME_DIR / "updates"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    module_path = runtime_dir / f"{module_name}.py"
    module_path.write_text(module_source, encoding="utf-8")

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
        {"mode": mode, "module_path": str(module_path), "decision": details},
    )
    return UpdateCheckResult(status=SecuritySettings.STATUS_APPLIED, message=message, details={"mode": mode, **details})

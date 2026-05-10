from django.conf import settings
from django.db import models


def default_allowed_signing_keys():
    return ["online-key-v1", "release-key-v1"]


class GameResult(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="game_results")
    score = models.PositiveIntegerField(default=0)
    successful_clicks = models.PositiveIntegerField(default=0)
    missed_clicks = models.PositiveIntegerField(default=0)
    accuracy = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    average_reaction_ms = models.FloatField(default=0)
    best_streak = models.PositiveIntegerField(default=0)
    duration_seconds = models.PositiveIntegerField(default=60)
    raw_payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-score", "-accuracy", "average_reaction_ms", "-created_at"]

    def __str__(self) -> str:
        return f"{self.user.username} - {self.score}"


class SecuritySettings(models.Model):
    UPDATE_CHANNEL_SAFE = "safe"
    UPDATE_CHANNEL_COMPROMISED = "compromised"
    UPDATE_CHANNEL_CHOICES = [
        (UPDATE_CHANNEL_SAFE, "Safe update"),
        (UPDATE_CHANNEL_COMPROMISED, "Compromised update"),
    ]

    STATUS_IDLE = "idle"
    STATUS_APPLIED = "applied"
    STATUS_BLOCKED = "blocked"
    STATUS_ALERT = "alert"
    STATUS_ERROR = "error"
    STATUS_CHOICES = [
        (STATUS_IDLE, "Idle"),
        (STATUS_APPLIED, "Applied"),
        (STATUS_BLOCKED, "Blocked"),
        (STATUS_ALERT, "Alert"),
        (STATUS_ERROR, "Error"),
    ]

    protection_enabled = models.BooleanField(default=True)
    update_channel = models.CharField(max_length=20, choices=UPDATE_CHANNEL_CHOICES, default=UPDATE_CHANNEL_SAFE)
    updater_base_url = models.URLField(default="http://updater-service:8001")
    last_update_check_at = models.DateTimeField(null=True, blank=True)
    last_update_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_IDLE)
    last_update_message = models.TextField(blank=True, default="")
    min_allowed_update_version = models.CharField(max_length=32, default="0.0.0")
    last_applied_update_version = models.CharField(max_length=32, default="0.0.0")
    allowed_signing_key_ids = models.JSONField(default=default_allowed_signing_keys, blank=True)
    revoked_signing_key_ids = models.JSONField(default=list, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Security settings"
        verbose_name_plural = "Security settings"

    def __str__(self) -> str:
        return "Security settings"

    @classmethod
    def load(cls):
        settings_obj, _ = cls.objects.get_or_create(pk=1)
        return settings_obj


class SecurityEvent(models.Model):
    EVENT_UPDATE_CHECK = "update_check"
    EVENT_UPDATE_APPLIED = "update_applied"
    EVENT_UPDATE_BLOCKED = "update_blocked"
    EVENT_ALERT = "alert"
    EVENT_WARNING = "warning"

    EVENT_TYPE_CHOICES = [
        (EVENT_UPDATE_CHECK, "Update check"),
        (EVENT_UPDATE_APPLIED, "Update applied"),
        (EVENT_UPDATE_BLOCKED, "Update blocked"),
        (EVENT_ALERT, "Alert"),
        (EVENT_WARNING, "Warning"),
    ]

    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CRITICAL = "critical"

    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
        (SEVERITY_CRITICAL, "Critical"),
    ]

    event_type = models.CharField(max_length=32, choices=EVENT_TYPE_CHOICES)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default=SEVERITY_LOW)
    message = models.CharField(max_length=255)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.get_event_type_display()} - {self.message}"

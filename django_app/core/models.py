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
        verbose_name = "Результат игры"
        verbose_name_plural = "Результаты игр"

    def __str__(self) -> str:
        return f"{self.user.username} - {self.score}"


class SecuritySettings(models.Model):
    UPDATE_CHANNEL_SAFE = "safe"
    UPDATE_CHANNEL_INVALID_MANIFEST = "invalid_manifest"
    UPDATE_CHANNEL_BAD_CODE = "bad_code"
    UPDATE_CHANNEL_CHOICES = [
        (UPDATE_CHANNEL_SAFE, "Безопасное обновление"),
        (UPDATE_CHANNEL_INVALID_MANIFEST, "Неверный манифест"),
        (UPDATE_CHANNEL_BAD_CODE, "Неприемлемый код"),
    ]

    STATUS_IDLE = "idle"
    STATUS_APPLIED = "applied"
    STATUS_BLOCKED = "blocked"
    STATUS_ALERT = "alert"
    STATUS_ERROR = "error"
    STATUS_CHOICES = [
        (STATUS_IDLE, "Ожидание"),
        (STATUS_APPLIED, "Применено"),
        (STATUS_BLOCKED, "Заблокировано"),
        (STATUS_ALERT, "Тревога"),
        (STATUS_ERROR, "Ошибка"),
    ]

    protection_enabled = models.BooleanField(default=True)
    update_channel = models.CharField(max_length=20, choices=UPDATE_CHANNEL_CHOICES, default=UPDATE_CHANNEL_SAFE)
    updater_base_url = models.URLField(default="https://updater-service:8001")
    last_update_check_at = models.DateTimeField(null=True, blank=True)
    last_update_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_IDLE)
    last_update_message = models.TextField(blank=True, default="")
    min_allowed_update_version = models.CharField(max_length=32, default="0.0.0")
    last_applied_update_version = models.CharField(max_length=32, default="0.0.0")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Параметры защиты"
        verbose_name_plural = "Параметры защиты"

    def __str__(self) -> str:
        return "Параметры защиты"

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
        (EVENT_UPDATE_CHECK, "Проверка обновления"),
        (EVENT_UPDATE_APPLIED, "Обновление применено"),
        (EVENT_UPDATE_BLOCKED, "Обновление заблокировано"),
        (EVENT_ALERT, "Тревога"),
        (EVENT_WARNING, "Предупреждение"),
    ]

    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CRITICAL = "critical"

    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Низкая"),
        (SEVERITY_MEDIUM, "Средняя"),
        (SEVERITY_HIGH, "Высокая"),
        (SEVERITY_CRITICAL, "Критическая"),
    ]

    event_type = models.CharField(max_length=32, choices=EVENT_TYPE_CHOICES)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default=SEVERITY_LOW)
    message = models.CharField(max_length=255)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Событие безопасности"
        verbose_name_plural = "События безопасности"

    def __str__(self) -> str:
        return f"{self.get_event_type_display()} - {self.message}"

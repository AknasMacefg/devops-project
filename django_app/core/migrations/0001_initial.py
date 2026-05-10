from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="SecuritySettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("protection_enabled", models.BooleanField(default=True)),
                ("update_channel", models.CharField(choices=[("safe", "Safe update"), ("compromised", "Compromised update")], default="safe", max_length=20)),
                ("updater_base_url", models.URLField(default="http://updater-service:8001")),
                ("last_update_check_at", models.DateTimeField(blank=True, null=True)),
                ("last_update_status", models.CharField(choices=[("idle", "Idle"), ("applied", "Applied"), ("blocked", "Blocked"), ("alert", "Alert"), ("error", "Error")], default="idle", max_length=20)),
                ("last_update_message", models.TextField(blank=True, default="")),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Security settings",
                "verbose_name_plural": "Security settings",
            },
        ),
        migrations.CreateModel(
            name="SecurityEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event_type", models.CharField(choices=[("update_check", "Update check"), ("update_applied", "Update applied"), ("update_blocked", "Update blocked"), ("alert", "Alert"), ("warning", "Warning")], max_length=32)),
                ("severity", models.CharField(choices=[("low", "Low"), ("medium", "Medium"), ("high", "High"), ("critical", "Critical")], default="low", max_length=16)),
                ("message", models.CharField(max_length=255)),
                ("details", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="GameResult",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("score", models.PositiveIntegerField(default=0)),
                ("successful_clicks", models.PositiveIntegerField(default=0)),
                ("missed_clicks", models.PositiveIntegerField(default=0)),
                ("accuracy", models.DecimalField(decimal_places=2, default=0, max_digits=5)),
                ("average_reaction_ms", models.FloatField(default=0)),
                ("best_streak", models.PositiveIntegerField(default=0)),
                ("duration_seconds", models.PositiveIntegerField(default=60)),
                ("raw_payload", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="game_results", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ["-score", "-accuracy", "average_reaction_ms", "-created_at"],
            },
        ),
    ]
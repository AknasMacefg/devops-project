from django.db import migrations, models
import core.models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="securitysettings",
            name="allowed_signing_key_ids",
            field=models.JSONField(blank=True, default=core.models.default_allowed_signing_keys),
        ),
        migrations.AddField(
            model_name="securitysettings",
            name="last_applied_update_version",
            field=models.CharField(default="0.0.0", max_length=32),
        ),
        migrations.AddField(
            model_name="securitysettings",
            name="min_allowed_update_version",
            field=models.CharField(default="0.0.0", max_length=32),
        ),
        migrations.AddField(
            model_name="securitysettings",
            name="revoked_signing_key_ids",
            field=models.JSONField(blank=True, default=list),
        ),
    ]

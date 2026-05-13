from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0002_securitysettings_trust_controls"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="securitysettings",
            name="allowed_signing_key_ids",
        ),
        migrations.RemoveField(
            model_name="securitysettings",
            name="revoked_signing_key_ids",
        ),
    ]
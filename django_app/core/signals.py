from django.db.models.signals import post_migrate
from django.dispatch import receiver

from .models import SecuritySettings


@receiver(post_migrate)
def ensure_security_settings(sender, **kwargs) -> None:
    SecuritySettings.load()

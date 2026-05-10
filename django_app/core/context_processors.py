from .models import SecuritySettings


def security_status(request):
    return {"security_settings": SecuritySettings.load()}

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-only-secret-key")
DEBUG = os.getenv("DJANGO_DEBUG", "1") == "1"
ALLOWED_HOSTS = [host.strip() for host in os.getenv("DJANGO_ALLOWED_HOSTS", "*").split(",") if host.strip()]
CSRF_TRUSTED_ORIGINS = [
    'http://127.0.0.1:8080',
    'http://localhost:8080',
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core.apps.CoreConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "core" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.security_status",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "reaction_game"),
        "USER": os.getenv("POSTGRES_USER", "reaction_game"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "reaction_game"),
        "HOST": os.getenv("POSTGRES_HOST", "postgres"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": os.getenv("REDIS_URL", "redis://redis:6379/1"),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "core" / "static"]

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "core:game"
LOGOUT_REDIRECT_URL = "core:home"

UPDATE_SERVICE_URL = os.getenv("UPDATE_SERVICE_URL", "http://updater-service:8001")
UPDATE_SIGNING_PUBLIC_KEYS = {
    "online-key-v1": os.getenv("UPDATE_ONLINE_PUBLIC_KEY_PATH", str(BASE_DIR / "keys" / "updater_public_key.pem")),
    "release-key-v1": os.getenv("UPDATE_RELEASE_PUBLIC_KEY_PATH", str(BASE_DIR / "keys" / "release_signer_public_key.pem")),
}
UPDATE_REQUIRED_SIGNING_KEY_IDS = [
    item.strip()
    for item in os.getenv("UPDATE_REQUIRED_SIGNING_KEY_IDS", "online-key-v1,release-key-v1").split(",")
    if item.strip()
]
UPDATE_RUNTIME_DIR = BASE_DIR / "runtime"
UPDATE_POLICY_ALLOWED_MODULES = [
    item.strip() for item in os.getenv("UPDATE_POLICY_ALLOWED_MODULES", "safe_update").split(",") if item.strip()
]
UPDATE_POLICY_ALLOW_COMPROMISED = os.getenv("UPDATE_POLICY_ALLOW_COMPROMISED", "0") == "1"

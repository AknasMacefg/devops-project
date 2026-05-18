from django.contrib import admin
from django.contrib import messages

from .models import GameResult, SecurityEvent, SecuritySettings
from .services import perform_update_check


@admin.register(GameResult)
class GameResultAdmin(admin.ModelAdmin):
    list_display = ("user", "score", "successful_clicks", "missed_clicks", "accuracy", "best_streak", "created_at")
    search_fields = ("user__username", "user__email")
    list_filter = ("created_at",)
    readonly_fields = ("created_at",)


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "event_type", "severity", "message")
    list_filter = ("event_type", "severity", "created_at")
    search_fields = ("message",)
    readonly_fields = ("created_at",)


@admin.register(SecuritySettings)
class SecuritySettingsAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "protection_enabled",
        "update_channel",
        "min_allowed_update_version",
        "last_applied_update_version",
        "last_update_status",
        "last_update_check_at",
        "updated_at",
    )
    list_editable = ("protection_enabled", "update_channel")
    actions = ("run_update_check",)

    def has_add_permission(self, request):
        return not SecuritySettings.objects.exists()

    @admin.action(description="Запустить проверку обновления")
    def run_update_check(self, request, queryset):
        for _settings in queryset:
            result = perform_update_check()
            if result.status == SecuritySettings.STATUS_BLOCKED:
                self.message_user(request, result.message, level=messages.ERROR)
            elif result.status == SecuritySettings.STATUS_ERROR:
                self.message_user(request, result.message, level=messages.WARNING)
            else:
                self.message_user(request, result.message, level=messages.SUCCESS)

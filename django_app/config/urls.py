from django.contrib import admin
from django.contrib.auth.views import LoginView
from django.urls import include, path

from core.forms import LoginForm

urlpatterns = [
    path("accounts/login/", LoginView.as_view(authentication_form=LoginForm, template_name="registration/login.html"), name="login"),
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("", include("core.urls")),
]

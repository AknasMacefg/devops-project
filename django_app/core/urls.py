from django.urls import path

from . import views

app_name = "core"

urlpatterns = [
    path("", views.home, name="home"),
    path("signup/", views.signup_view, name="signup"),
    path("game/", views.game_bootstrap, name="game"),
    path("leaderboard/", views.leaderboard_view, name="leaderboard"),
    path("api/results/", views.submit_result, name="submit_result"),
]

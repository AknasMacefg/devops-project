import json
from decimal import Decimal

import logging
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db.models import Avg, Count
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST

from .forms import SignUpForm
from .models import GameResult
from .services import record_security_event


def home(request):
    top_results = cache.get("leaderboard_top_10")
    if top_results is None:
        top_results = list(
            GameResult.objects.select_related("user").order_by("-score", "-accuracy", "average_reaction_ms", "-created_at")[:10]
        )
        cache.set("leaderboard_top_10", top_results, 30)
    stats = GameResult.objects.aggregate(
        games=Count("id"),
        players=Count("user", distinct=True),
        avg_score=Avg("score"),
    )
    return render(request, "core/home.html", {"top_results": top_results, "stats": stats})


def signup_view(request):
    if request.user.is_authenticated:
        return redirect("core:game")
    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Аккаунт создан. Вы вошли в систему.")
            return redirect("core:game")
        else:
            logger = logging.getLogger(__name__)
            try:
                errors = form.errors.as_json()
            except Exception:
                errors = str(form.errors)
            logger.warning("Форма регистрации заполнена некорректно: %s", errors)
            messages.error(request, "Ошибка при создании аккаунта: " + "; ".join(form.errors.get_json_data(escape_html=True).get(field, [{"message": "Неизвестная ошибка"}])[0]["message"] for field in form.errors))
    else:
        form = SignUpForm()
    return render(request, "registration/signup.html", {"form": form})


@login_required
def game_view(request):
    return render(
        request,
        "core/game.html",
        {
            "submit_result_url": "/api/results/",
            "leaderboard_url": "/leaderboard/",
        },
    )


@login_required
@require_POST
def submit_result(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return HttpResponseBadRequest("Invalid JSON")

    successful_clicks = int(payload.get("successful_clicks", 0))
    missed_clicks = int(payload.get("missed_clicks", 0))
    score = int(payload.get("score", successful_clicks))
    best_streak = int(payload.get("best_streak", 0))
    average_reaction_ms = float(payload.get("average_reaction_ms", 0))
    duration_seconds = int(payload.get("duration_seconds", 60))
    total_attempts = successful_clicks + missed_clicks
    accuracy = (successful_clicks / total_attempts * 100) if total_attempts else 0

    result = GameResult.objects.create(
        user=request.user,
        score=score,
        successful_clicks=successful_clicks,
        missed_clicks=missed_clicks,
        accuracy=Decimal(f"{accuracy:.2f}"),
        average_reaction_ms=average_reaction_ms,
        best_streak=best_streak,
        duration_seconds=duration_seconds,
        raw_payload=payload,
    )

    return JsonResponse(
        {
            "status": "saved",
            "result_id": result.id,
            "score": result.score,
            "accuracy": float(result.accuracy),
        }
    )


@login_required
def leaderboard_view(request):
    results = GameResult.objects.select_related("user").order_by("-score", "-accuracy", "average_reaction_ms", "-created_at")[:20]
    return render(request, "core/leaderboard.html", {"results": results})


@login_required
@ensure_csrf_cookie
def game_bootstrap(request):
    return game_view(request)

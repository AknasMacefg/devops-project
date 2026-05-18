(() => {
    const arena = document.getElementById("game-arena");
    const startButton = document.getElementById("start-game");
    const arenaEmpty = document.getElementById("arena-empty");
    const summaryBox = document.getElementById("result-summary");
    const submitUrl = arena.dataset.submitUrl;
    const leaderboardUrl = arena.dataset.leaderboardUrl;

    const timeLeftEl = document.getElementById("time-left");
    const scoreEl = document.getElementById("score");
    const hitsEl = document.getElementById("hits");
    const missesEl = document.getElementById("misses");
    const accuracyEl = document.getElementById("accuracy");
    const bestStreakEl = document.getElementById("best-streak");

    const state = {
        running: false,
        timeLeft: 60,
        score: 0,
        hits: 0,
        misses: 0,
        bestStreak: 0,
        currentStreak: 0,
        reactionTimes: [],
        activeCircle: null,
        activeTimeout: null,
        spawnTimeout: null,
        tickInterval: null,
    };

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) {
            return parts.pop().split(";").shift();
        }
        return "";
    }

    function randomBetween(min, max) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    function updateHud() {
        const totalClicks = state.hits + state.misses;
        const accuracy = totalClicks ? Math.round((state.hits / totalClicks) * 100) : 0;
        timeLeftEl.textContent = String(state.timeLeft);
        scoreEl.textContent = String(state.score);
        hitsEl.textContent = String(state.hits);
        missesEl.textContent = String(state.misses);
        accuracyEl.textContent = `${accuracy}%`;
        bestStreakEl.textContent = String(state.bestStreak);
    }

    function clearActiveCircle() {
        if (state.activeTimeout) {
            clearTimeout(state.activeTimeout);
            state.activeTimeout = null;
        }
        if (state.activeCircle && state.activeCircle.isConnected) {
            state.activeCircle.remove();
        }
        state.activeCircle = null;
    }

    function clearArenaTargets() {
        arena.querySelectorAll(".target-circle").forEach((node) => node.remove());
    }

    function scheduleNextSpawn() {
        if (!state.running) {
            return;
        }
        if (state.spawnTimeout) {
            clearTimeout(state.spawnTimeout);
        }
        state.spawnTimeout = setTimeout(spawnCircle, randomBetween(280, 900));
    }

    function spawnCircle() {
        if (!state.running) {
            return;
        }
        clearActiveCircle();
        arenaEmpty.style.display = "none";

        const size = randomBetween(52, 108);
        const arenaWidth = Math.max(arena.clientWidth, 320);
        const arenaHeight = Math.max(arena.clientHeight, 320);
        const maxX = Math.max(arenaWidth - size - 16, 16);
        const maxY = Math.max(arenaHeight - size - 16, 16);
        const x = randomBetween(16, maxX);
        const y = randomBetween(16, maxY);

        const circle = document.createElement("button");
        circle.type = "button";
        circle.className = "target-circle";
        circle.style.width = `${size}px`;
        circle.style.height = `${size}px`;
        circle.style.left = `${x}px`;
        circle.style.top = `${y}px`;
        circle.dataset.spawnedAt = String(performance.now());
        circle.dataset.hit = "0";

        circle.addEventListener("click", (event) => {
            event.stopPropagation();
            if (!state.running || circle.dataset.hit === "1") {
                return;
            }
            circle.dataset.hit = "1";
            const reaction = performance.now() - Number(circle.dataset.spawnedAt);
            state.reactionTimes.push(reaction);
            state.hits += 1;
            state.score += 1;
            state.currentStreak += 1;
            state.bestStreak = Math.max(state.bestStreak, state.currentStreak);
            updateHud();
            circle.classList.add("hit");
            clearTimeout(state.activeTimeout);
            state.activeTimeout = null;
            state.activeCircle = null;
            setTimeout(() => {
                if (circle.isConnected) {
                    circle.remove();
                }
                scheduleNextSpawn();
            }, 120);
        });

        state.activeCircle = circle;
        arena.appendChild(circle);

        state.activeTimeout = setTimeout(() => {
            if (!state.running || circle.dataset.hit === "1") {
                return;
            }
            state.misses += 1;
            state.currentStreak = 0;
            updateHud();
            if (circle.isConnected) {
                circle.remove();
            }
            state.activeCircle = null;
            scheduleNextSpawn();
        }, randomBetween(950, 1650));
    }

    function finishGame() {
        if (!state.running) {
            return;
        }
        state.running = false;
        clearInterval(state.tickInterval);
        clearTimeout(state.spawnTimeout);
        clearActiveCircle();
        arenaEmpty.style.display = "grid";
        arenaEmpty.textContent = "Раунд завершён. Сохраняем результат...";
        startButton.disabled = false;
        startButton.textContent = "Сыграть ещё раз";
        renderSummary();
        submitResult();
    }

    function renderSummary(extraMessage = "") {
        const totalAttempts = state.hits + state.misses;
        const accuracy = totalAttempts ? ((state.hits / totalAttempts) * 100).toFixed(2) : "0.00";
        const averageReaction = state.reactionTimes.length
            ? (state.reactionTimes.reduce((sum, value) => sum + value, 0) / state.reactionTimes.length).toFixed(0)
            : "0";
        summaryBox.innerHTML = `
            <strong>Итоговый счёт:</strong> ${state.score}<br>
            <strong>Успешные нажатия:</strong> ${state.hits}<br>
            <strong>Промахи:</strong> ${state.misses}<br>
            <strong>Точность:</strong> ${accuracy}%<br>
            <strong>Средняя реакция:</strong> ${averageReaction} мс<br>
            <strong>Лучшая серия:</strong> ${state.bestStreak}<br>
            ${extraMessage ? `<span>${extraMessage}</span>` : ""}
        `;
    }

    async function submitResult() {
        const payload = {
            score: state.score,
            successful_clicks: state.hits,
            missed_clicks: state.misses,
            best_streak: state.bestStreak,
            average_reaction_ms: state.reactionTimes.length
                ? state.reactionTimes.reduce((sum, value) => sum + value, 0) / state.reactionTimes.length
                : 0,
            duration_seconds: 60,
        };

        try {
            const response = await fetch(submitUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": getCookie("csrftoken"),
                },
                body: JSON.stringify(payload),
            });

            if (!response.ok) {
                throw new Error(`Сохранение не удалось: ${response.status}`);
            }

            const data = await response.json();
            renderSummary(`Результат сохранён. <a href="${leaderboardUrl}">Открыть таблицу лидеров</a>.`);
            summaryBox.insertAdjacentHTML("beforeend", `<br><strong>ID результата на сервере:</strong> ${data.result_id}`);
        } catch (error) {
            renderSummary(`Результат пока не сохранён. ${error.message}`);
        }
    }

    function resetState() {
        state.running = true;
        state.timeLeft = 60;
        state.score = 0;
        state.hits = 0;
        state.misses = 0;
        state.bestStreak = 0;
        state.currentStreak = 0;
        state.reactionTimes = [];
        state.activeCircle = null;
        state.activeTimeout = null;
        state.spawnTimeout = null;
        clearActiveCircle();
        clearArenaTargets();
        arenaEmpty.style.display = "none";
        summaryBox.textContent = "Раунд идёт. Продолжайте нажимать по целям.";
        updateHud();
    }

    function startGame() {
        if (state.running) {
            return;
        }
        resetState();
        startButton.disabled = true;
        startButton.textContent = "Идёт раунд...";

        spawnCircle();
        state.tickInterval = setInterval(() => {
            state.timeLeft -= 1;
            updateHud();
            if (state.timeLeft <= 0) {
                finishGame();
            }
        }, 1000);
    }

    arena.addEventListener("click", (event) => {
        if (!state.running) {
            return;
        }
        if (!event.target.classList.contains("target-circle")) {
            state.misses += 1;
            state.currentStreak = 0;
            updateHud();
        }
    });

    startButton.addEventListener("click", startGame);
    updateHud();
})();

# Reaction Game DevSecOps MVP

Учебный MVP на Django для демонстрации DevOps и DevSecOps-подхода: мини-игра на реакцию, PostgreSQL, Redis, nginx, `updater-service`, `security-service` и изолированный `worker` для динамического анализа обновлений.

## Архитектура

- `django-app` — веб-приложение Django с регистрацией, входом, игрой, результатами и админкой.
- `updater-service` — тренировочный сервер обновлений, поддерживает режимы `safe`, `invalid_manifest`, `malicious_valid` (и legacy `compromised`) и подписывает манифест RSA-ключом (если ключ подключен).
- `security-service` — валидатор (статический анализ): загружает манифест/пакет, проверяет hash/policy/version/RSA, передаёт артефакт в песочницу.
- `worker` — песочница (динамический анализ): запускает модуль в ограниченном subprocess, возвращает pass/fail.
- `postgres` — хранение результатов игры, security events и настроек защиты.
- `redis` — cache для leaderboard и краткоживущих данных.
- `nginx` — reverse proxy и раздача static/media.

## Логика защиты обновлений

1. `django-app` вызывает `security-service` (`/evaluate`).
2. `security-service` запрашивает манифест и модуль у `updater-service`.
3. Статические проверки в `security-service`:
- SHA-256 целостность;
- policy-check (allowlist модулей, запрет compromised channel);
- anti-rollback (версия не ниже минимальной и не ниже последней применённой);
- RSA-подпись манифеста (если включено);
- детект потенциальных time-bomb паттернов (если включено).
4. Если статические проверки пройдены, `security-service` кладёт артефакт в изолированный volume и вызывает `worker`.
5. `worker` запускает динамическую проверку в ограниченной среде (CPU/memory/time limits, блокировка `time.sleep`).
6. Если `worker` вернул `pass`, `security-service` подтверждает обновление Django.
7. Если любой этап не пройден, обновление блокируется, а событие пишется в `SecurityEvent`.

### Три поддерживаемых сценария обновлений

- `safe` — хороший модуль + корректный манифест.
- `invalid_manifest` — модуль может быть нормальным, но манифест содержит неверные данные (например, hash), обновление блокируется на статической проверке.
- `malicious_valid` — манифест корректный, но код вредоносный, обновление должно быть заблокировано на этапе динамической проверки в `worker`.

## Функционал игры

- регистрация и вход;
- 60-секундная игра на реакцию;
- случайные круги, которые появляются и исчезают;
- realtime score;
- сохранение результата в PostgreSQL;
- таблица лидеров;
- аналитика: hits, misses, accuracy, average reaction, best streak.

## Локальный запуск (Docker Compose)

1. При необходимости создайте `.env` и переопределите переменные окружения из `docker-compose.yml`.
2. Соберите и запустите контейнеры:

```bash
docker compose up --build
```

3. Откройте приложение:
- `http://localhost:8080`

4. Создайте суперпользователя:

```bash
docker compose exec django-app python manage.py createsuperuser
```

5. В Django admin:
- включайте/выключайте protection;
- меняйте `update_channel` между `safe`, `invalid_manifest`, `malicious_valid` (и legacy `compromised`);
- запускайте `Run update check`;
- проверяйте `SecurityEvent` и `GameResult`.

## RSA-настройка

- `updater-service` хранит и использует только приватный ключ:
- `UPDATER_RSA_PRIVATE_KEY_PATH` — путь к RSA private key PEM для подписи манифеста.
- `security-service` хранит и использует только публичный ключ:
- `SECURITY_RSA_PUBLIC_KEY_PATH` — путь к RSA public key PEM для проверки подписи.
- `SECURITY_RSA_VERIFY_REQUIRED` — `1`, чтобы блокировать обновления без валидной подписи.

Если `SECURITY_RSA_VERIFY_REQUIRED=0`, отсутствие подписи не блокирует обновление.

### Генерация ключей через OpenSSL

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/updater_private.pem
openssl rsa -pubout -in keys/updater_private.pem -out keys/updater_public.pem
```

Пример переменных в `.env` для Docker Compose:

```bash
UPDATER_RSA_PRIVATE_KEY_PATH=/keys/updater_private.pem
SECURITY_RSA_PUBLIC_KEY_PATH=/keys/updater_public.pem
SECURITY_RSA_VERIFY_REQUIRED=1
```

В `docker-compose.yml` каталог `./keys` монтируется в `updater-service` и `security-service` как `/keys` (read-only). Логика разделения: приватный ключ используется только `updater-service`, публичный ключ только `security-service`.

Перед запуском RSA-подписи создайте каталог `keys/` в корне проекта и сгенерируйте ключи командами выше.

## Anti time-bomb

- `STRICT_TIME_BOMB_CHECK=1` включает статический детект подозрительных time-паттернов в `security-service`.
- В `worker` динамический раннер дополнительно блокирует `time.sleep` и ограничивает ресурсы.

## Kubernetes

Манифесты лежат в `k8s/`:
- `namespace.yaml`
- `configmap.yaml`
- `secrets-template.yaml`
- `storage.yaml`
- `apps.yaml`
- `networkpolicies.yaml`

Порядок применения:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets-template.yaml
kubectl apply -f k8s/storage.yaml
kubectl apply -f k8s/apps.yaml
kubectl apply -f k8s/networkpolicies.yaml
```

Перед применением соберите/запушьте образы, используемые в `k8s/apps.yaml`.

Если `kubectl apply` жалуется на OpenAPI/validation, обычно это означает проблему с самим кластером или доступом к API, а не с YAML. Для такого случая используйте более устойчивый порядок:

```bash
kubectl create namespace devops-demo
kubectl apply --server-side --validate=false -f k8s/configmap.yaml
kubectl apply --server-side --validate=false -f k8s/secrets-template.yaml
kubectl apply --server-side --validate=false -f k8s/storage.yaml
kubectl apply --server-side --validate=false -f k8s/apps.yaml
kubectl apply --server-side --validate=false -f k8s/networkpolicies.yaml
```

Если namespace уже существует, команда `kubectl create namespace devops-demo` вернёт ошибку `AlreadyExists` — это нормально.

## Полезные URL

- `/` — домашняя страница
- `/signup/` — регистрация
- `/accounts/login/` — вход
- `/game/` — игра
- `/leaderboard/` — таблица лидеров
- `/admin/` — админ-панель

## Тестирование обновлений

1. Поднимите стек:

```bash
docker compose up --build
```

2. Сценарий 1: хорошее обновление (`safe`)
- `http://localhost:8001/manifest?mode=safe`;
- `Run update check` в Django admin;
- убедитесь, что есть `update_applied`.

3. Сценарий 2: неверный манифест (`invalid_manifest`)
- `http://localhost:8001/manifest?mode=invalid_manifest`;
- `Run update check` в Django admin;
- убедитесь, что защита блокирует обновление на статическом этапе и появляются `update_blocked`/`alert`.

4. Сценарий 3: корректный манифест, но вредоносный код (`malicious_valid`)
- `http://localhost:8001/manifest?mode=malicious_valid`;
- `Run update check` в Django admin;
- убедитесь, что обновление блокируется защитой (на static-check и/или в sandbox `worker`) и появляются `update_blocked`/`alert`.

# Reaction Game DevSecOps MVP

Учебный MVP на Django для демонстрации DevOps и DevSecOps-подхода: мини-игра на реакцию, PostgreSQL, Redis, nginx и отдельный updater-service для симуляции supply chain attack.

## Архитектура

- `django-app` — веб-приложение Django с регистрацией, входом, logout, игрой, результатами и админкой.
- `updater-service` — симуляция доверенного источника обновлений, который может отдавать safe или compromised update.
- `signer-service` — online-сервис подписи (ключ `online-key-v1`).
- `release-signer-service` — независимый release-сервис подписи (ключ `release-key-v1`).
- `postgres` — хранение результатов игры, security events и настроек защиты.
- `redis` — cache для leaderboard и краткоживущих данных.
- `nginx` — reverse proxy и раздача static/media.

## Threat model

Сценарий защищает от компрометации источника обновлений. Django скачивает модуль обновления, проверяет SHA-256 и две независимые RSA-подписи (`2-of-2`), выполняет обязательную policy-проверку (allow/revoke key IDs, allowlist модулей, anti-rollback по версии), затем либо блокирует update и пишет ALERT, либо запускает обновление.

Compromised update безопасен: он только создаёт файл `simulated_leak.txt` с текстом `SIMULATED CREDENTIAL LEAK` и пишет security event в БД.

## Функционал игры

- регистрация и вход;
- 60-секундная игра на реакцию;
- случайные круги, которые появляются и исчезают;
- realtime score;
- сохранение результата в PostgreSQL;
- таблица лидеров;
- аналитика: hits, misses, accuracy, average reaction, best streak.

## Запуск

1. Скопируйте `.env.example` в `.env` и задайте секреты.
2. Соберите и запустите контейнеры:

```bash
docker compose up --build
```

3. Откройте приложение через nginx:
- `http://localhost:8080`

4. Создайте суперпользователя:

```bash
docker compose exec django-app python manage.py createsuperuser
```

5. В Django admin:
- включайте и выключайте protection;
- меняйте `update_channel` между `safe` и `compromised`;
- запускайте `Run update check`;
- смотрите `SecurityEvent` и `GameResult`.

## Полезные URL

- `/` — домашняя страница
- `/signup/` — регистрация
- `/accounts/login/` — вход
- `/game/` — игра
- `/leaderboard/` — таблица лидеров
- `/admin/` — админ-панель

## Примечания по реализации

- Для MVP обновления поставляются как Python-модули `safe_update.py` и `compromised_update.py`.
- Защита не выполняет произвольный код вне заранее определённого контракта `apply_update(context)`.
- Redis используется как cache backend, чтобы показать production-like интеграцию.

## Подпись обновлений (Dual RSA + Anti-Rollback) — инструкция для тестирования

Подпись разделена на два независимых контура:
- `signer-service` (online key id: `online-key-v1`)
- `release-signer-service` (release key id: `release-key-v1`)

Django применяет update только если валидны обе подписи и policy-проверка.

1. Сгенерируйте ключи (локально):

```bash
openssl genpkey -algorithm RSA -out signer_online_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in signer_online_private.pem -out updater_public.pem
openssl genpkey -algorithm RSA -out signer_release_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in signer_release_private.pem -out release_signer_public.pem
```

2. Поместите ключи:
- `signer_online_private.pem` -> `signer_service/keys/private_key.pem`
- `signer_release_private.pem` -> `release_signer_service/keys/private_key.pem`
- `updater_public.pem` -> `django_app/keys/updater_public_key.pem`
- `release_signer_public.pem` -> `django_app/keys/release_signer_public_key.pem`

3. `docker-compose.yml` уже настроен на монтирование ключей:
- `./signer_service/keys:/app/keys:ro`
- `./release_signer_service/keys:/app/keys:ro`
- `./django_app/keys:/app/keys:ro`

4. Пересоберите и перезапустите сервисы:

```bash
docker compose build signer-service release-signer-service updater-service django-app
docker compose up -d
```

5. Тест:
- вызвать манифест `http://localhost:8001/manifest?mode=safe` и проверить успешное применение;
- вызвать манифест `http://localhost:8001/manifest?mode=compromised` и проверить блокировку policy (по умолчанию `UPDATE_POLICY_ALLOW_COMPROMISED=0`).

Дополнительно:
- anti-rollback: `min_allowed_update_version` и `last_applied_update_version` хранятся в `SecuritySettings`;
- key revocation: в `SecuritySettings` можно указать `revoked_signing_key_ids`; такие подписи будут заблокированы.

Если любой из ключей отсутствует или одна из подписей невалидна, обновление блокируется.

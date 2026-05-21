# Reaction Game DevSecOps MVP

Автор Маслов АН ИД23-1
Учебный MVP на Django для демонстрации DevOps и DevSecOps-подхода: мини-игра на реакцию, PostgreSQL, Redis, nginx, `updater-service` для симуляции доверенного источника обновлений, `security-service` и изолированный `worker` для динамического анализа обновлений. По умолчанию сервисы работают по HTTP и без проверки подписей, mTLS и RSA включается только явно через переменные окружения.

## Архитектура

- `django-app` — веб-приложение Django с регистрацией, входом, игрой, результатами и админкой.
- `updater-service` — тренировочный сервер обновлений, поддерживает режимы `safe`, `invalid_manifest`, `bad_code`, подписывает манифест RSA-ключом и при включённом mTLS обслуживается по HTTPS.
- `security-service` — валидатор обновлений: загружает манифест и пакет, при включённой защите выполняет статические проверки (hash, policy, версия, RSA, time-bomb) и передаёт артефакт в песочницу.
- `worker` — песочница динамического анализа: запускает модуль в ограниченном subprocess и возвращает `pass` или `fail`.
- `postgres` — хранение результатов игры, событий безопасности и настроек защиты.
- `redis` — кэш для таблицы лидеров и краткоживущих данных.
- `nginx` — reverse proxy и раздача static/media.

## Логика защиты обновлений

1. `django-app` вызывает `security-service` (`/evaluate`).
2. `security-service` запрашивает манифест и модуль у `updater-service`.
3. Если `protection_enabled=false`, `security-service` пропускает проверки и песочницу, сразу возвращает `approved`.
4. Если `protection_enabled=true`, выполняются статические проверки в `security-service`:
- SHA-256 целостность;
- policy-check, включая allowlist модулей;
- проверка минимально допустимой версии;
- RSA-подпись манифеста, если она включена;
- детект потенциальных time-bomb паттернов, если он включён.
5. Если статические проверки пройдены, `security-service` кладёт артефакт в изолированный volume и вызывает `worker`.
6. `worker` запускает динамическую проверку в ограниченной среде с лимитами CPU, памяти и времени, а также блокировкой `time.sleep`.
7. Если `worker` вернул `pass`, `security-service` подтверждает обновление для Django.
8. Если любой этап не пройден, обновление блокируется, а событие пишется в `SecurityEvent`.

### Поддерживаемые сценарии обновлений

- `safe` — хороший модуль и корректный манифест.
- `invalid_manifest` — отдаётся вредоносный модуль с неверным hash в манифесте. Обновление блокируется на статической проверке целостности.
- `bad_code` — манифест корректный, но код содержит вредоносные действия. Статические проверки могут пройти, блокировка происходит на этапе динамической проверки в `worker`.

## Функционал игры

- регистрация и вход;
- 60-секундная игра на реакцию;
- случайные круги, которые появляются и исчезают;
- отображение счёта в реальном времени;
- сохранение результата в PostgreSQL;
- таблица лидеров;
- аналитика: попадания, промахи, точность, средняя реакция, лучшая серия.

## Локальный запуск через Docker Compose

1. При необходимости создайте `.env` в корне проекта и переопределите переменные из `docker-compose.yml`.
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
- включайте или выключайте защиту;
- меняйте `update_channel` между `safe`, `invalid_manifest`, `bad_code`;
- запускайте `Запустить проверку обновления`;
- проверяйте разделы `События безопасности` и `Результаты игр`.

## RSA и ключи

- `updater-service` хранит и использует только приватный RSA-ключ.
- `UPDATER_RSA_PRIVATE_KEY_PATH` — путь к PEM-файлу приватного ключа для подписи манифеста.
- `security-service` хранит и использует только публичный RSA-ключ.
- `SECURITY_RSA_PUBLIC_KEY_PATH` — путь к PEM-файлу публичного ключа для проверки подписи.
- `SECURITY_RSA_VERIFY_REQUIRED` — `1`, чтобы блокировать обновления без валидной подписи.

Если `SECURITY_RSA_VERIFY_REQUIRED=0`, отсутствие подписи не блокирует обновление.

### Генерация RSA-ключей через OpenSSL

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

В `docker-compose.yml` каталог `./keys` монтируется в `updater-service` и `security-service` как `/keys` в режиме read-only. Логика разделения простая: приватный ключ используется только `updater-service`, публичный ключ только `security-service`.

Перед запуском RSA-подписи создайте каталог `keys/` в корне проекта и сгенерируйте ключи командами выше.

## mTLS и сертификаты

mTLS между `security-service` и `updater-service` опционален. По умолчанию сервисы работают без TLS, а для включения нужно задать `MTLS_ENABLED=1`.

При включении mTLS используйте такие каталоги:

- `certs/ca` — корневой CA, файлы `ca.crt` и `ca.key`.
- `certs/updater` — серверный сертификат и ключ для `updater-service`.
- `certs/security` — клиентский сертификат и ключ для `security-service`.

Сертификаты можно сгенерировать через скрипт:

```bash
python scripts/generate_mtls_certs.py
```

Скрипт создаёт:

- `certs/ca/ca.crt` и `certs/ca/ca.key`
- `certs/updater/updater.crt` и `certs/updater/updater.key`
- `certs/security/security.crt` и `certs/security/security.key`

Если mTLS включён, `updater-service` использует серверный сертификат и проверяет клиентский сертификат `security-service`, а `security-service` использует клиентский сертификат и проверяет `updater-service` через CA.

Пример прямой проверки API `updater-service` с mTLS:

```bash
curl --cacert certs/ca/ca.crt --cert certs/security/security.crt --key certs/security/security.key https://localhost:8001/manifest?mode=safe
```

## Anti time-bomb

- `STRICT_TIME_BOMB_CHECK=1` включает статический детект подозрительных time-паттернов в `security-service`.
- `worker` дополнительно блокирует `time.sleep` и ограничивает ресурсы динамического раннера.

## Где что хранить

- `keys/` в корне проекта — только RSA-ключи для подписи и проверки обновлений.
- `certs/` в корне проекта — только TLS-сертификаты и ключи для mTLS.
- `django_app/runtime/` — только временные артефакты обновлений, которые создаются во время проверки.
- Не кладите приватные ключи в `django_app/static`, `media` или другие публичные каталоги.

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

Перед применением соберите и запушьте образы, которые используются в `k8s/apps.yaml`.

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
- `http://localhost:8001/manifest?mode=safe` при отключённом mTLS;
- `https://localhost:8001/manifest?mode=safe` при включённом mTLS;
- `Запустить проверку обновления` в Django admin;
- убедитесь, что появляется `update_applied`.

3. Сценарий 2: неверный манифест (`invalid_manifest`)
- `http://localhost:8001/manifest?mode=invalid_manifest` или HTTPS-вариант при включённом mTLS;
- `Запустить проверку обновления` в Django admin;
- убедитесь, что защита блокирует обновление на статическом этапе (hash mismatch) и появляются `update_blocked` или `alert`.

4. Сценарий 3: корректный манифест, но вредоносный код (`bad_code`)
- `http://localhost:8001/manifest?mode=bad_code` или HTTPS-вариант при включённом mTLS;
- `Запустить проверку обновления` в Django admin;
- убедитесь, что обновление блокируется в sandbox `worker`, после чего появляются `update_blocked` или `alert`.

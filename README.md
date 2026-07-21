# Woland Guard

Woland Guard — разрабатываемая защитная система мониторинга Linux-серверов. Агент будет
читать разрешённые системные события, а control plane — создавать понятные инциденты и
помогать владельцу сервера реагировать на них.

Проект находится на этапе 3: control plane принимает от зарегистрированного агента
версионированные пакеты событий и сохраняет их в PostgreSQL идемпотентно. Linux-агент и
detection engine ещё не реализованы.

Лицензия пока не выбрана. На текущем этапе проект не позиционируется как open-source.

## Что реализовано

- Python 3.12 и uv workspace;
- минимальное FastAPI-приложение;
- liveness endpoint `GET /health/live`;
- readiness endpoint `GET /health/ready` с проверкой PostgreSQL;
- Docker Compose для control plane и PostgreSQL;
- workspace-пакет с Pydantic-контрактом нормализованного события версии 1;
- модели серверов, ключей агентов, событий и transactional outbox;
- миграции Alembic с обратимым начальным изменением схемы;
- генерация ключей агента с сохранением только digest секрета;
- `POST /api/v1/events` с Bearer-аутентификацией агента;
- ограничение Content-Type, размера тела, clock skew и частоты запросов;
- request ID в логах, заголовке и теле API-ответа;
- пакетная транзакционная вставка через PostgreSQL `ON CONFLICT DO NOTHING`;
- локальный CLI для создания тестового сервера и одноразовой выдачи ключа;
- PostgreSQL integration-тесты в отдельном Docker target;
- базовые настройки Ruff, mypy и pytest;
- ADR с подтверждёнными решениями этапов 1 и 2 и предложениями этапа 3.

## Требования

- Python 3.12;
- uv;
- Docker с Compose plugin.

Программы необходимо установить самостоятельно из официальных источников. Репозиторий
не содержит скриптов, меняющих системную конфигурацию.

## Подготовка конфигурации

PowerShell:

```powershell
Copy-Item .env.example .env
```

Linux:

```bash
cp .env.example .env
```

Значения из примера предназначены только для локальной разработки. Перед любым внешним
развёртыванием пароль PostgreSQL необходимо заменить.

## Локальный запуск через uv

```bash
uv sync --all-packages
uv run uvicorn woland_guard_control_plane.main:app --app-dir apps/control-plane/src --reload
```

Без PostgreSQL endpoint liveness вернёт 200, а readiness — 503. Это ожидаемое различие.

## Запуск через Docker Compose

```bash
docker compose config
docker compose up --build -d
docker compose exec control-plane alembic upgrade head
docker compose ps
```

После успешного запуска:

- <http://localhost:8000/health/live>
- <http://localhost:8000/health/ready>
- <http://localhost:8000/docs>

## Создание локального тестового ключа

После применения миграций:

```bash
docker compose exec control-plane woland-guard-admin create-test-agent \
  --name demo-server \
  --hostname demo.invalid \
  --label local-demo
```

CLI выводит plaintext-токен только один раз. PostgreSQL хранит публичный идентификатор и
32-байтовый digest секрета. Не добавляйте выданный токен в `.env`, Git, логи или примеры.
HTTP admin API намеренно отсутствует.

## Пример Ingestion API

Endpoint:

```text
POST /api/v1/events
Authorization: Bearer wgak_<public_id>.<secret>
Content-Type: application/json
X-Request-ID: local-example-001
```

Тело запроса, где временные метки необходимо заменить текущими UTC-значениями:

```json
{
  "schema_version": 1,
  "batch_id": "10000000-0000-4000-8000-000000000001",
  "sent_at": "<current UTC timestamp>",
  "events": [
    {
      "schema_version": 1,
      "event_id": "20000000-0000-4000-8000-000000000001",
      "occurred_at": "<current UTC timestamp>",
      "collected_at": "<current UTC timestamp>",
      "source": "journald",
      "event_type": "ssh.authentication_failed",
      "actor": "synthetic-agent",
      "source_ip": "192.0.2.10",
      "summary": "synthetic local example",
      "attributes": {"attempt": 1}
    }
  ]
}
```

Успешный ответ:

```json
{
  "request_id": "local-example-001",
  "batch_id": "10000000-0000-4000-8000-000000000001",
  "accepted": 1,
  "existing": 0
}
```

При повторной доставке того же события значения будут `accepted: 0`, `existing: 1`.

Остановка:

```bash
docker compose down
```

Именованный volume PostgreSQL при этой команде не удаляется.

## Проверки

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

Локальный запуск без Compose выполняет unit-тесты и явно пропускает PostgreSQL
integration-тесты. Полная проверка:

```bash
docker compose up -d postgres control-plane
docker compose exec control-plane alembic upgrade head
docker compose --profile test run --rm integration-tests
```

Настройки ingestion задаются переменными:

- `WG_INGEST_MAX_BODY_BYTES` — максимальный размер HTTP body;
- `WG_INGEST_RATE_LIMIT_REQUESTS` — запросов на один ключ за окно;
- `WG_INGEST_RATE_LIMIT_WINDOW_SECONDS` — размер окна rate limit;
- `WG_INGEST_MAX_CLOCK_SKEW_SECONDS` — допустимое расхождение `sent_at`.

## Архитектурные решения

Принятые решения зафиксированы в
[`docs/adr/0001-mvp-foundation.md`](docs/adr/0001-mvp-foundation.md).
Контракт и хранение описаны в
[`docs/adr/0002-event-contract-and-persistence.md`](docs/adr/0002-event-contract-and-persistence.md).
Ingestion API описан в
[`docs/adr/0003-ingestion-api.md`](docs/adr/0003-ingestion-api.md).

## Ограничения этапа 3

- нет агента и journald adapter;
- нет detection engine и Telegram;
- нет HTTP API управления серверами и ключами;
- outbox worker, конкурентный захват, backoff и отправка уведомлений ещё не реализованы;
- rate limiter хранит состояние в памяти одного процесса и не координирует несколько
  экземпляров control plane;
- rate limiter учитывает каждый запрос после успешной аутентификации, но запросы,
  отклонённые middleware или JSON validation раньше endpoint, требуют ограничения на
  reverse proxy;
- нет автоматической ротации ключей и очистки старых событий;
- readiness проверяет соединение с PostgreSQL, но пока не проверяет актуальность миграции;
- зависимости Python зафиксированы в `uv.lock`;
- production deployment не подготовлен.

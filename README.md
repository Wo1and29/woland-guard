# Woland Guard

Woland Guard — разрабатываемая защитная система мониторинга Linux-серверов. Агент будет
читать разрешённые системные события, а control plane — создавать понятные инциденты и
помогать владельцу сервера реагировать на них.

Этапы 1–5 приняты. Linux-агент проверен на синтетических journald fixtures и в Linux test
image, а control plane создаёт инциденты из нормализованных событий PostgreSQL.

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
- строгие версионированные YAML-правила с локальными командами validate/sync;
- Detection Engine с условиями single, threshold, distinct_count, sequence и first_seen;
- восемь journald-правил, атомарные incidents и уникальные evidence-связи;
- Linux Agent для Ubuntu Server 24.04: двухфазное чтение journald, SQLite spool,
  явные безопасные парсеры и HTTPS-доставка;
- базовые настройки Ruff, mypy и pytest;
- ADR с подтверждёнными архитектурными решениями этапов 1–5.

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

## Правила Detection Engine

Проверка всех восьми файлов не обращается к PostgreSQL:

```bash
docker compose exec control-plane woland-guard-admin validate-rules \
  --rules-dir /workspace/detection-rules
```

После `alembic upgrade head` явная синхронизация добавляет версии и атомарно активирует
набор правил:

```bash
docker compose exec control-plane woland-guard-admin sync-rules \
  --rules-dir /workspace/detection-rules
```

Startup control plane намеренно не изменяет правила. YAML допускает только пять закрытых
типов условий и не выполняет выражения. Временные окна рассчитываются по `occurred_at`,
изолированы по server и включают обе границы. Detection получает только строки, впервые
вставленные через `ON CONFLICT DO NOTHING ... RETURNING`, в той же транзакции ingestion.

Восемь текущих правил работают только с нормализованными journald-событиями SSH, sudo и
account management. Nginx-правила не входят в этот набор.

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
      "event_type": "linux.ssh.authentication_failed",
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
Архитектура Linux Agent описана в
[`docs/adr/0004-linux-agent.md`](docs/adr/0004-linux-agent.md).
Архитектура Detection Engine описана в
[`docs/adr/0005-detection-engine.md`](docs/adr/0005-detection-engine.md).

## Linux Agent

Пакет `apps/agent` предназначен только для Ubuntu Server 24.04 LTS. Он читает journald
через фиксированный `journalctl`, атомарно хранит событие и cursor в SQLite WAL и доставляет
пакеты по HTTPS. Безопасная конфигурация, политика переполнения, systemd unit и команды
диагностики описаны в [`apps/agent/README.md`](apps/agent/README.md).

Текущая Windows/Docker-среда не содержит Ubuntu 24.04 с запущенным systemd. Реальная
проверка journald здесь не заявляется: автоматические тесты используют только синтетические
fixtures и локальный HTTP backend.

Nginx source/parser и два правила, которым нужны его события, перенесены в следующий релиз.
Они не считаются end-to-end функциями MVP; текущий Detection Engine содержит восемь
journald-правил, а не десять end-to-end правил.

## Ограничения MVP

- нет Telegram и API чтения/изменения статуса инцидентов;
- нет HTTP API управления серверами и ключами;
- outbox worker, конкурентный захват, backoff и отправка уведомлений ещё не реализованы;
- rate limiter хранит состояние в памяти одного процесса и не координирует несколько
  экземпляров control plane;
- rate limiter учитывает каждый запрос после успешной аутентификации, но запросы,
  отклонённые middleware или JSON validation раньше endpoint, требуют ограничения на
  reverse proxy;
- нет автоматической ротации ключей и очистки старых событий;
- синхронизация правил выполняется явно локальной CLI-командой и не запускается при startup;
- запросы истории выполняются отдельно для trigger/rule; оптимизация отложена до измерений;
- readiness проверяет соединение с PostgreSQL, но пока не проверяет актуальность миграции;
- зависимости Python зафиксированы в `uv.lock`;
- production deployment не подготовлен.

# Woland Guard

Woland Guard — разрабатываемая защитная система мониторинга Linux-серверов. Агент будет
читать разрешённые системные события, а control plane — создавать понятные инциденты и
помогать владельцу сервера реагировать на них.

Этапы 1–5, 6A и 6B приняты. Подэтап 6C реализован в рабочем дереве и ожидает ревью:
Linux-агент проверен на синтетических journald fixtures и в Linux test image, control plane
создаёт инциденты, а локальные операторы читают их и выполняют идемпотентные status transitions.

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
- локальные Operator identities, независимо ротируемые `wgok_` API-ключи и фиксированный RBAC;
- безопасные Incident/Audit API, optimistic `lock_version`, immutable history и audit;
- operator-scoped идемпотентность status transitions с сохранёнными 200/404/409 outcomes;
- provider-neutral notification destinations без provider credentials и seed-записей;
- transactional outbox, атомарный с новым incident, baseline history и evidence;
- конкурентный worker с `FOR UPDATE SKIP LOCKED`, claim token, lease recovery и equal jitter;
- безопасные outbox CLI-команды run/run-once/status/recovery/manual requeue;
- Linux Agent для Ubuntu Server 24.04: двухфазное чтение journald, SQLite spool,
  явные безопасные парсеры и HTTPS-доставка;
- базовые настройки Ruff, mypy и pytest;
- ADR с подтверждёнными архитектурными решениями этапов 1–6.

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

Настройки worker:

- `WG_OUTBOX_POLL_SECONDS` — пауза при пустой очереди;
- `WG_OUTBOX_LEASE_SECONDS` — срок одного claim;
- `WG_OUTBOX_ADAPTER_TIMEOUT_SECONDS` — верхняя граница вызова adapter;
- `WG_OUTBOX_RECOVERY_INTERVAL_SECONDS` — период recovery просроченных claims; должен быть
  положительным и не превышать lease;
- `WG_OUTBOX_BACKOFF_BASE_SECONDS` и `WG_OUTBOX_BACKOFF_MAX_SECONDS` — границы backoff;
- `WG_OUTBOX_RETRY_AFTER_CAP_SECONDS` — безопасный максимум `retry_after`;
- `WG_OUTBOX_DEFAULT_MAX_ATTEMPTS` — число автоматических попыток для новой строки.

## Transactional outbox worker

Миграция 0005 не создаёт destinations автоматически. Без enabled destination новый incident
успешно фиксируется без outbox rows. В 6C настоящий delivery adapter отсутствует; значение
`adapter_kind=telegram` зарезервировано для 6D, а автоматические тесты маршрутизируют его в
синтетический fake adapter.

Безопасные локальные команды:

```bash
docker compose exec control-plane woland-guard-outbox run-once --limit 10
docker compose exec control-plane woland-guard-outbox status
docker compose exec control-plane woland-guard-outbox recover-expired
docker compose exec control-plane woland-guard-outbox requeue-failed <outbox UUID> \
  --confirm <тот же outbox UUID> --additional-attempts 1
```

Непрерывный процесс запускается командой `woland-guard-outbox run`, периодически выполняет
lease recovery независимо от наличия pending backlog и кооперативно завершает текущую
ограниченную попытку после SIGTERM. Delivery выполняется at-least-once: падение после внешнего
side effect, но до PostgreSQL acknowledge, может привести к повтору. Команда `status` выводит
только агрегаты, включая неотрицательный возраст старейшей pending-записи или `null`.

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
Архитектура последовательного этапа 6 описана в
[`docs/adr/0006-operator-rbac-incident-workflow-and-telegram.md`](docs/adr/0006-operator-rbac-incident-workflow-and-telegram.md).

## Локальные операторы

Оператор и его способы аутентификации — разные сущности. HTTP admin API отсутствует. Сначала
локально создайте identity:

```bash
docker compose exec control-plane woland-guard-admin create-operator \
  --username local-admin --role admin
```

Затем выпустите ключ по напечатанному `operator_id`. Необязательный `--expires-at` принимает
только ISO 8601 timestamp с timezone:

```bash
docker compose exec control-plane woland-guard-admin issue-operator-key \
  --operator-id <operator UUID> --label local-cli \
  --expires-at 2030-01-01T00:00:00+00:00
```

CLI показывает `wgok_` token только один раз. PostgreSQL хранит только digest. Rotation
атомарно отзывает прежний ключ и выдаёт новый:

```bash
docker compose exec control-plane woland-guard-admin rotate-operator-key \
  --key-id <key UUID>
docker compose exec control-plane woland-guard-admin revoke-operator-key \
  --key-id <key UUID>
```

## Incident workflow и audit

`viewer`, `analyst` и `admin` могут читать безопасные summaries и detail без event payload:

```text
GET /api/v1/incidents?status=new&severity=critical&limit=50
GET /api/v1/incidents/<incident UUID>
Authorization: Bearer <operator token>
```

`analyst` и `admin` могут менять статус. Обязательные поля — текущий `expected_version` и
уникальный в scope оператора `Idempotency-Key`. Для `resolved` и `false_positive` требуется
`reason`:

```text
POST /api/v1/incidents/<incident UUID>/transitions
Authorization: Bearer <operator token>
Idempotency-Key: local-review-001
Content-Type: application/json

{"status":"resolved","expected_version":1,"reason":"Проверено локальным оператором"}
```

Разрешены только `new → investigating|resolved|false_positive` и
`investigating → resolved|false_positive`; терминальные статусы не переоткрываются. Повтор
идентичного запроса возвращает первоначальный business snapshot и заголовок
`Idempotency-Replayed: true`. Тот же ключ с другим нормализованным запросом возвращает 409.

Только `admin` читает append-only audit через `GET /api/v1/audit-log`. Cursor в обоих list API
строго валидируется и связан с нормализованными фильтрами, но не является криптографически
подписанным. History, audit и idempotency rows защищены PostgreSQL-триггерами от `UPDATE`,
`DELETE` и `TRUNCATE`; владелец таблиц и superuser PostgreSQL остаются за пределами этой защиты.

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

- нет Telegram HTTP, chat ID, bot token и управления destinations — это этап 6D;
- нет HTTP API управления серверами и ключами;
- production adapter registry пуст до 6D, поэтому 6C проверяет доставку только fake adapter;
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

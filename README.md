# Woland Guard

*[Read this in English](README.en.md)*

Woland Guard — защитная система мониторинга Linux-серверов. Агент читает разрешённые системные
события, а control plane создаёт понятные инциденты и помогает оператору реагировать на них —
через защищённый веб-Dashboard или интерактивно через Telegram.

Реализовано и зафиксировано локально: ingestion API с Detection Engine (8 правил, MITRE ATT&CK),
Linux-агент с durable delivery, RBAC и Dashboard с несколькими ролями, исходящие и входящие
Telegram-уведомления (команды, кнопки статуса, диалог причины), dry-run-блокировка IP с allowlist
и подтверждением второго администратора, три уровня demo-инфраструктуры (от ручного показа до
полного release-гейта) и 16 ADR с обоснованием каждого архитектурного решения — включая
отдельное решение не автоматизировать исполнение блокировки IP (ADR-0016).

## Лицензия

Copyright (C) 2026 Dr. Woland

Проект распространяется под [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-or-later).
Код можно свободно копировать, изучать и изменять — в том числе в коммерческих целях. Ключевое
условие AGPL, в отличие от MIT/Apache: если вы модифицируете код и предоставляете его как сетевой
сервис (в том числе SaaS, без распространения бинарников), вы обязаны открыть исходный код своей
версии под той же лицензией. Это защищает от закрытых форков-конкурентов, но не запрещает
коммерческое использование как таковое.

## Внешний вид

Dashboard — серверный рендеринг (Jinja2), без JavaScript-фреймворка. Скриншоты сняты реальным
браузером (Chromium) через browser-test-инфраструктуру проекта, интерфейс на них — тот же самый
код, который увидит любой пользователь. **Данные на скриншотах синтетические**: сгенерированы
специально для демонстрации в изолированной временной базе, а не сняты с работающего
production-инстанса — у реального пользователя будут его собственные серверы и инциденты.

<p align="center">
  <img src="docs/screenshots/overview.png" alt="Обзор: серверы, активные инциденты, очередь уведомлений" width="800">
</p>

**Инциденты** — фильтры по статусу, severity, точному UUID, префиксу заголовка/rule key:

<p align="center">
  <img src="docs/screenshots/incidents.png" alt="Список инцидентов с фильтрами" width="800">
</p>

**Детали инцидента** — объяснение, рекомендация, история статусов, evidence, переход статуса и комментарии:

<p align="center">
  <img src="docs/screenshots/incident-detail.png" alt="Страница инцидента" width="800">
</p>

**Серверы**:

<p align="center">
  <img src="docs/screenshots/servers.png" alt="Список серверов" width="800">
</p>

**Активные правила детекции** — с MITRE ATT&CK, условиями и порогами:

<p align="center">
  <img src="docs/screenshots/rules.png" alt="Активные правила детекции" width="800">
</p>

**Audit log** — каждое действие оператора и системный CLI-вызов с типизированными деталями:

<p align="center">
  <img src="docs/screenshots/audit-log.png" alt="Audit log" width="800">
</p>

**Мобильная версия** (390×844):

<p align="center">
  <img src="docs/screenshots/mobile-incident.png" alt="Мобильная версия страницы инцидента" width="320">
</p>

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
- исходящий Telegram adapter с фиксированным origin и bounded streaming response;
- provider-specific Telegram destination config 1:1 и локальное управление без HTTP admin API;
- on-demand синхронизация bot token из read-only staging в private tmpfs worker;
- входящий Telegram-бот (long polling, default-deny): read-only команды `/status`, `/servers`,
  `/incidents`, `/critical`, привязка аккаунта только через локальный CLI;
- callback-кнопки под уведомлением («Принять в работу», «Ложное срабатывание», «Закрыть»,
  «Открыть панель») с диалогом обязательной причины для терминальных статусов;
- dry-run-блокировка IP через Telegram: never-block список, allowlist, план с точным `nft`-argv,
  подтверждение второго администратора — без исполнения команды в каком-либо виде (ADR-0016);
- Linux Agent для Ubuntu Server 24.04: двухфазное чтение journald, SQLite spool,
  явные безопасные парсеры и HTTPS-доставка;
- базовые настройки Ruff, mypy и pytest;
- 16 ADR с подтверждёнными архитектурными решениями каждого реализованного этапа;
- изолированный browser harness для Chromium: loopback HTTPS, временный trustme CA,
  отдельный PostgreSQL 17 и синтетические данные без постоянных browser artifacts.
- закрытый canonical manifest и loopback-only sender синтетических positive, negative и
  boundary demo-сценариев для всех восьми detection rules.
- отдельная demo-топология с PostgreSQL 17, единственным migration job, rule sync,
  32-scenario ingestion, настоящим outbox worker, in-process fake Telegram boundary,
  HTTPS Dashboard smoke и synthetic backup/restore smoke.

Изолированная HTML-граница `/dashboard` использует вход существующим operator API-ключом,
серверные opaque sessions, строгие `__Host-*` cookies, Origin/CSRF-проверки, ограниченный
разбор URL-encoded форм и logout с атомарным audit. Read-only Dashboard показывает factual
overview, серверы, инциденты с ограниченной evidence projection, paginated history и
append-only comments, активные правила и audit для admin. `analyst` и `admin` выполняют
разрешённые status transitions и добавляют комментарии через POST с Origin, session-bound
CSRF и server-generated idempotency key.
Перед показом rules Dashboard bounded-проверяет все active definitions независимо от фильтров и
pagination; повреждённое правило закрывает страницу безопасным 503, а не исчезает из выдачи.

## Browser-проверка Dashboard

Browser suite использует только Chromium и запускается явно. Browser binary хранится в
игнорируемом каталоге `.playwright-browsers`; сертификат, private key, PostgreSQL credentials
и application process создаются только во временном каталоге вне репозитория.

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = ".playwright-browsers"
uv run playwright install --no-shell chromium
$env:WG_RUN_BROWSER_TESTS = "1"
uv run pytest tests/browser
```

Harness привязывает HTTPS к `127.0.0.1:0`, строго проверяет временный CA отдельным readiness
client и передаёт тот же открытый socket публичному API Uvicorn. Непостоянный Playwright
`BrowserContext` использует `ignore_https_errors=True`; это не является проверкой browser
CA-chain. HTTP/HTTPS-запросы тестируемых страниц разрешены только к точному origin harness,
любой WebSocket блокируется. Это не доказывает process-level сетевую изоляцию Chromium.

Screenshots, trace, video, HAR, downloads и storage state по умолчанию отключены. Временный
review-run со скриншотами разрешается только через `WG_BROWSER_REVIEW_SCREENSHOTS=1`; файлы
создаются в `.pytest-browser`, просматриваются локально и после просмотра удаляются.

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

## Синтетические demo-сценарии 8A

Каталог содержит по четыре стабильных сценария для каждого из восьми текущих правил:
`positive`, `negative`, `boundary_below` и `boundary_exact`. Список формируется только после
строгой проверки каталога `detection-rules`.

```powershell
uv run --package woland-guard-control-plane woland-guard-demo list-scenarios
uv run --package woland-guard-control-plane woland-guard-demo generate `
  --scenario ssh_bruteforce_by_ip.positive.v1 `
  --output C:\wg-demo\ssh-bruteforce-positive.json
uv run --package woland-guard-control-plane woland-guard-demo validate `
  --manifest C:\wg-demo\ssh-bruteforce-positive.json
uv run --package woland-guard-control-plane woland-guard-demo send `
  --manifest C:\wg-demo\ssh-bruteforce-positive.json `
  --origin http://127.0.0.1:8000 `
  --api-key-file C:\wg-demo-secrets\agent.key
```

Manifest output и API-key file передаются как абсолютные пути. Token не допускается в
аргументах, manifest или выводе. Sender принимает только явный HTTP/HTTPS loopback origin и
отправляет только `POST /api/v1/events`. Он сообщает фактические accepted/duplicate/rejected
counts, но не заявляет создание incident или delivery: пользовательская full-stack verification
проверяется отдельным 8B verifier. Повтор manifest использует at-least-once delivery с идемпотентным ingestion,
а не distributed exactly-once.

## Full-stack demo verification 8B

Автоматический verifier использует отдельный `compose.demo.yaml` и уникальные Compose project,
ownership label, network и PostgreSQL volume. Он применяет миграции одним job, синхронизирует
ровно восемь enabled version-one rules, отправляет все 32 canonical manifests через публичный
`POST /api/v1/events`, проверяет точные DB outcomes, запускает настоящий outbox worker с
demo-only in-process Telegram transport, выполняет один desktop Chromium workflow над той же
БД, replay и custom-format `pg_dump`/`pg_restore` smoke.

Tracked-only release gate предназначен для уже зафиксированного candidate commit, потому что
`git archive HEAD` по определению не включает незакоммиченные файлы:

```powershell
.\scripts\verify-clean-install.ps1
```

Linux wrapper подготовлен, но native Linux full run пока не подтверждён:

```bash
sh scripts/verify-clean-install.sh
```

Оба wrapper создают временный checkout из `git archive HEAD`, отдельные uv environment/cache и
Playwright browser cache. Dependency acquisition и image build могут потребовать интернет при
холодном cache. Runtime не вызывает Telegram: fake transport проверяет сформированный request
и сохраняет только count. Проверка не доказывает реальную Telegram delivery, process-level
network isolation или production disaster recovery.

Интерактивный synthetic demo использует компактный canonical scenario и запускает Chromium в
непостоянном context над временным HTTPS harness. Требуется заранее установленный Chromium для
закреплённого Playwright и новый абсолютный путь для временного credential file:

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = ".playwright-browsers"
uv run python -m scripts.demo_e2e.human `
  --project-root (Resolve-Path .).Path `
  --credential-output C:\wg-demo-private\operators.json
```

Файл содержит только синтетические operator credentials и удаляется вместе с demo resources
после Enter/Ctrl+C. На POSIX применяется mode `0600`; на Windows verifier не заявляет
эквивалентную POSIX ACL-гарантию, поэтому каталог должен быть заранее приватным. Agent key,
DB password, Telegram token, certificate и private key не выводятся. Не прерывайте Docker
ресурсы широкими командами: штатный teardown проверяет exact project и ownership metadata.

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

Миграции не создают destinations автоматически. Без enabled destination новый incident
успешно фиксируется без outbox rows. Миграция 0006 добавляет Telegram-конфигурацию 1:1;
bot token в PostgreSQL не хранится.

Безопасные локальные команды:

```bash
docker compose --profile telegram-notifications run --rm outbox-worker \
  woland-guard-outbox run-once --limit 10
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

## Исходящие Telegram-уведомления

Telegram-профиль запускается отдельно и не входит в обычный `docker compose up`. Основной
`control-plane` не получает ни staging mount, ни private runtime tmpfs. Для локального CLI
используется одноразовый контейнер `telegram-admin`; непрерывную доставку выполняет отдельный
`outbox-worker`. Оба работают как UID/GID `10001:10001`, без capabilities и с read-only root
filesystem.

Создайте на host каталог, указанный в `WG_TELEGRAM_STAGING_DIRECTORY` (по умолчанию
`./local-secrets/telegram`), и отдельный файл с безопасным basename. Файл содержит ровно одну
непустую ASCII-строку без whitespace, NUL и control characters, не более 256 байт. Структура
Telegram bot token намеренно не проверяется по неофициальной грамматике. Token нельзя помещать
в `.env`, аргументы CLI, PostgreSQL или Git.

Создание destination выполняется в отключённом состоянии. Chat ID вводится скрытым prompt и
не печатается; `--token-file-name` принимает basename, а не путь:

```bash
docker compose --profile telegram-notifications run --rm telegram-admin \
  woland-guard-admin create-telegram-destination \
  --token-file-name local-bot.token --minimum-severity high
```

CLI сообщает только `configured` и `staging_file_ready`. Это проверка read-only staging, а не
runtime health private tmpfs другого контейнера. После проверки включите destination:

```bash
docker compose --profile telegram-notifications run --rm telegram-admin \
  woland-guard-admin enable-notification-destination \
  --destination-id <destination UUID>
docker compose --profile telegram-notifications run --rm telegram-admin \
  woland-guard-admin list-notification-destinations
```

Доступны также `show-notification-destination`, `disable-notification-destination` и
`update-telegram-destination`. Удаление отсутствует, чтобы сохранять историю доставок. Для
смены chat ID команда update использует `--change-chat-id` и скрытый prompt; новый token
задаётся только новым `--token-file-name`, но не его содержимым.

Worker запускается отдельно:

```bash
docker compose --profile telegram-notifications up -d outbox-worker
```

Перед каждой delivery worker заново безопасно проверяет staging. Он читает файл через
`lstat → open(O_NOFOLLOW) → fstat`, ограничивает размер, затем публикует private runtime copy
атомарной заменой. Runtime directory имеет режим `0700`, файл — `0400`, владелец и группа —
`10001:10001`; `chown` и capabilities не используются. Новый destination и корректная
атомарная ротация staging подхватываются без restart. Невалидный или удалённый staging
приводит к retryable безопасному error code; прежняя runtime copy сохраняется, но fail-closed
не используется для отправки.

HTTP boundary использует только `https://api.telegram.org`, `trust_env=False`, TLS verification,
запрет redirects и ноль внутренних HTTP retries. Connect/read/write/pool timeouts ограничены
и в сумме не превышают adapter budget. Это phase timeouts, а не обещание отдельного
wall-clock deadline. Ответ читается streaming chunks до жёсткого лимита 64 KiB и только затем
разбирается как JSON. Логи `httpx2`/`httpcore2` подавляются до создания request независимо от
root logger, потому что token является частью URL. Уведомление — plain text без `parse_mode` и
без event payload, attributes, correlation, actor или IP.

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
Dashboard authentication и sessions описаны в
[`docs/adr/0007-dashboard-authentication-and-sessions.md`](docs/adr/0007-dashboard-authentication-and-sessions.md).
Read-only Dashboard и его query projections описаны в
[`docs/adr/0008-read-only-dashboard.md`](docs/adr/0008-read-only-dashboard.md).
Incident actions и append-only comments описаны в
[`docs/adr/0009-dashboard-incident-actions-and-comments.md`](docs/adr/0009-dashboard-incident-actions-and-comments.md).
Browser verification описана в
[`docs/adr/0010-dashboard-browser-verification.md`](docs/adr/0010-dashboard-browser-verification.md).
Canonical demo catalog описан в
[`docs/adr/0011-reproducible-synthetic-demo.md`](docs/adr/0011-reproducible-synthetic-demo.md).
Clean-install и full-stack demo verification описаны в
[`docs/adr/0012-clean-install-and-demo-e2e.md`](docs/adr/0012-clean-install-and-demo-e2e.md).
Входящие Telegram-команды описаны в
[`docs/adr/0013-inbound-telegram-commands.md`](docs/adr/0013-inbound-telegram-commands.md).
Callback-кнопки инцидента и диалог причины описаны в
[`docs/adr/0014-telegram-incident-action-buttons.md`](docs/adr/0014-telegram-incident-action-buttons.md).
Dry-run блокировка IP описана в
[`docs/adr/0015-dry-run-ip-block-plans.md`](docs/adr/0015-dry-run-ip-block-plans.md).

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

## Read-only Dashboard

Dashboard смонтирован на `/dashboard`. Вход принимает действующий operator API key и после
успеха использует только server-side web session; Bearer header не является альтернативой
Dashboard cookie. Доступ к overview, servers, incidents и active rules имеют `analyst` и
`admin`; audit page доступна только `admin`.

Cookies имеют обязательный `Secure`, поэтому обычный HTTP URL Compose не ослабляет политику и
не является готовым browser deployment. Для интерактивного просмотра нужен настроенный HTTPS
origin, точно совпадающий с `WG_WEB_PUBLIC_ORIGIN`. REST API и health endpoints продолжают
работать независимо от HTML handlers.

Страницы используют server-side keyset pagination с размерами 25, 50 или 100. Cursor строго
проверяется и связан со страницей, фильтрами, literal prefix, сортировкой и page size, но не
подписан и не заявляется tamper-proof. Поиск трактует `%`, `_` и `!` буквально; exact UUID
передаётся отдельным фильтром. Времена показаны в UTC.

`active`/`inactive` сервера — только сохранённое `Server.is_active`, не online/offline и не
healthcheck. Последнее событие — отдельный максимум `occurred_at`. Dashboard не показывает
event payload, attributes, actor, IP, correlation, API keys, cookies или Telegram credentials.
Evidence содержит только UUID события, event type, source и три UTC timestamp. Этап 7C
добавляет отдельные POST-only формы status transition и comments. Они используют существующий
workflow, актуальный RBAC после PostgreSQL row lock и PRG redirect; комментарии не попадают в
audit details, outbox, Telegram или application logs.

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

## Входящий Telegram-бот

Бот — отдельный процесс и отдельный Compose-сервис профиля `telegram-notifications`. Он читает
обновления через `getUpdates` тем же fixed-origin клиентом, что и исходящая доставка, и отвечает
**только связанным операторам и только в приватном чате**.

Связывание выполняет только локальный CLI; одноразовые коды через чат не используются, чтобы
секрет не попадал в историю Telegram. Несвязанный пользователь получает свой Telegram ID, чтобы
передать его администратору:

```bash
docker compose exec control-plane woland-guard-admin link-telegram-operator \
  --operator-id <operator UUID> --telegram-user-id 123456789
docker compose exec control-plane woland-guard-admin list-telegram-operators
docker compose exec control-plane woland-guard-admin revoke-telegram-operator \
  --link-id <link UUID>
```

Запуск бота:

```bash
docker compose --profile telegram-notifications up -d telegram-bot
```

Доступные команды: `/help` для любого связанного оператора; `/status`, `/servers`, `/incidents` и
`/critical` требуют права `VIEW_INCIDENTS`. Все ответы собираются из фиксированных строк и явных
колонок БД, ограничены по длине и не отражают ввод пользователя.

Telegram отвечает `409 Conflict` на второй параллельный `getUpdates` с тем же токеном, поэтому
сервис запускается **строго в одном экземпляре** и несовместим с установленным webhook. Offset
хранится в PostgreSQL и подтверждается только после обработки пакета, поэтому перезапуск
приводит к повтору, а не к потере обновлений.

### Кнопки статуса под уведомлением

Уведомление о новом инциденте несёт клавиатуру: «Принять в работу», «Ложное срабатывание»,
«Закрыть» (требуют `TRANSITION_INCIDENTS`) и «Открыть панель» (обычная URL-кнопка на Dashboard,
без обращения к боту). Нажатие вызывает тот же `transition_incident`, что REST и Dashboard —
без HTTP, напрямую. Ответ виден только нажавшему (`answerCallbackQuery`), а не всем в чате.

«Ложное срабатывание» и «Закрыть» ведут в терминальный статус, для которого причина обязательна:
бот не подставляет шаблон, а спрашивает её следующим приватным сообщением (1–1000 символов,
время ожидания ограничено `WG_TELEGRAM_BOT_PENDING_ACTION_TTL_SECONDS`). Любая команда отменяет
ожидание причины и выполняется как обычно. Идемпотентность — по `callback_query.id`, который
Telegram гарантирует уникальным, поэтому повторная доставка одного нажатия не создаёт двойной
переход.

### Блокировка IP (dry-run)

Клавиатура несёт четвёртую кнопку — «Подготовить блокировку IP» (требует `PROPOSE_IP_BLOCK`,
роли analyst и admin). **Woland Guard никогда не исполняет команду блокировки** — ни control
plane, ни агент. Кнопка только создаёт план и показывает точный `nft`-argv; применяет его
администратор вручную. Это окончательное архитектурное решение
([ADR-0016](docs/adr/0016-no-automated-block-execution.md)): единственный процесс, способный
исполнить команду на защищаемом хосте, — агент, а он по построению парсит недоверенный ввод из
journald, и выдавать ему право менять firewall — неприемлемый размен. Функция целиком выключена
по умолчанию (`WG_IP_BLOCK_ENABLED=false`).

Адрес берётся из correlation инцидента (`source_ip`), а не из ввода оператора; у инцидента без
этого поля кнопка отвечает отказом, а не создаёт план. Never-block список (loopback, приватные,
link-local, multicast, документационные диапазоны) и allowlist проверяются до создания плана;
allowlist управляется только локальным CLI:

```bash
docker compose exec control-plane woland-guard-admin add-ip-allowlist-entry \
  --cidr 203.0.113.0/24 --label "admin-jump-host" --reason "адрес администратора"
docker compose exec control-plane woland-guard-admin list-ip-allowlist-entries
docker compose exec control-plane woland-guard-admin revoke-ip-allowlist-entry \
  --entry-id <entry UUID>
```

План требует подтверждения **другого** оператора с ролью admin
(`WG_IP_BLOCK_REQUIRE_SECOND_OPERATOR=true` по умолчанию) — сам аналитик или тот же администратор
не может подтвердить собственное предложение. Подтверждение заново перепроверяет политику: если
allowlist изменился с момента предложения, план автоматически отклоняется вместо одобрения. Ответ
на подтверждение явно утверждает, что блокировка не выполнена — это единственная защита от
самого опасного недопонимания в этом сценарии. Подробности решений — в
[ADR-0015](docs/adr/0015-dry-run-ip-block-plans.md) и
[ADR-0016](docs/adr/0016-no-automated-block-execution.md).

## Ограничения MVP

- через Telegram нельзя добавить комментарий к инциденту — это следующий подэтап, если будет
  реализован;
- блокировка IP — **всегда** только dry-run: план создаётся, проверяется и подтверждается, но
  проект никогда его не исполняет. Это осознанное окончательное решение, а не незавершённая
  работа — обоснование в [ADR-0016](docs/adr/0016-no-automated-block-execution.md);
- применяет подтверждённую команду администратор вручную; таблицу и set в nftables он тоже
  создаёт сам (см. [docs/deployment.md](docs/deployment.md));
- снятие блокировки проект не отслеживает и не автоматизирует;
- исходное сообщение с кнопками не редактируется после нажатия, кнопки остаются видимыми;
- нет HTTP API управления серверами и ключами;
- delivery остаётся at-least-once и допускает повтор после внешнего side effect до acknowledge;
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

## Документация

- [docs/architecture.md](docs/architecture.md) — компоненты и поток события от агента до
  уведомления;
- [docs/threat-model.md](docs/threat-model.md) — модель угроз;
- [docs/detection-rules.md](docs/detection-rules.md) — схема YAML-правил и текущий набор из 8;
- [docs/deployment.md](docs/deployment.md) — развёртывание на VPS, HTTPS, reverse proxy;
- [docs/agent-installation.md](docs/agent-installation.md) — установка агента на Ubuntu Server 24.04;
- [docs/demo.md](docs/demo.md) — три уровня demo-режима, от ручного до полного release gate;
- [docs/adr/](docs/adr/) — архитектурные решения каждого реализованного этапа;
- [SECURITY.md](SECURITY.md) — как сообщать об уязвимостях;
- [CONTRIBUTING.md](CONTRIBUTING.md) — как вносить изменения.

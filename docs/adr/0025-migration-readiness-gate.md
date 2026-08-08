# ADR-0025: readiness проверяет актуальность миграции, не только соединение

- Статус: принято
- Дата: 2026-08-08

## Контекст

`/health/ready` проверял только `SELECT 1` — живое соединение с PostgreSQL. Основной
`compose.yaml` требовал ручного `docker compose exec control-plane alembic upgrade head` после
`docker compose up`, а до этого шага healthcheck уже отвечал `200 ready`, хотя схема могла быть
на любой более старой ревизии. Контейнер, запущенный до применения новой миграции, выглядел
здоровым и обслуживал запросы против кода, которому нужны колонки/constraint'ы, которых ещё нет
в БД. `compose.demo.yaml` уже не имеет этой проблемы: отдельный одноразовый сервис `demo-migrate`
с `depends_on: service_completed_successfully` гарантирует порядок до того, как появился этот ADR.

## Решение

### 1. `check_database()` сравнивает текущую ревизию с ожидаемым head

`MigrationContext.configure(connection).get_current_revision()` — та же официальная точка входа
Alembic, которую использует сам `alembic current`, а не самодельный `SELECT version_num FROM
alembic_version`, который не учитывал бы edge-cases (пустая таблица, несколько head). Ожидаемый
head считается через `ScriptDirectory.from_config(...)` и кешируется `@lru_cache`: набор файлов
миграций не меняется, пока живёт процесс, — читать его с диска на каждый вызов `/health/ready`
(вызывается healthcheck'ом раз в 10 секунд) было бы чистой тратой.

Несовпадение поднимает `MigrationDriftError` — подкласс `SQLAlchemyError`, чтобы существующий
`except SQLAlchemyError` в вызывающем коде не сломался, но с собственным типом, чтобы
`/health/ready` мог различить «база недоступна» и «база на месте, но не той версии» —
`database: "unavailable"` vs `database: "not_migrated"` в теле ответа.

### 2. `compose.yaml` получает `migrate` — тот же паттерн, что и demo

Один одноразовый сервис `command: ["alembic", "-c", "alembic.ini", "upgrade", "head"]`,
`restart: "no"`. `control-plane`, `outbox-worker`, `telegram-bot`, `telegram-admin` получают
`depends_on: migrate: condition: service_completed_successfully` в дополнение к
`postgres: service_healthy`. Проверено вручную: `docker compose up --build -d` от чистого
volume поднимает `migrate` (применяет все миграции), только затем стартует `control-plane`, и
`/health/ready` сразу отвечает `{"status":"ready","database":"ok"}` — без единой ручной команды.

`postgres-test-setup`/`integration-tests` (test-профиль) не получают эту зависимость: они
работают с отдельной тестовой БД, которую сама интеграционная сессия мигрирует в своём
`conftest.py` (`command.upgrade(Config("alembic.ini"), "head")`) — это не тот же процесс, что
`migrate`, но та же гарантия по факту.

### 3. Убран отдельный шаг «Apply migrations» из CI

`docker compose up -d --wait postgres control-plane` теперь сам ждёт `migrate` как часть
зависимостей — `service_completed_successfully` соблюдается синхронно даже без `--wait`,
проверено локально (`docker compose ps -a` показывает `migrate` в `Exited (0)` до того, как
`control-plane` вообще стартует). Отдельный `alembic upgrade head` в CI стал не просто лишним,
а маскирующим: если бы граф зависимостей в `compose.yaml` был неверен, старый шаг всё равно
починил бы миграцию вручную и скрыл поломку. Убрав его, CI действительно проверяет автоматический
путь, а не запасной.

## Последствия

- Документация (README, `docs/demo.md`, `docs/deployment.md`) избавлена от инструкции
  `docker compose exec control-plane alembic upgrade head` — она больше не нужна ни для
  быстрого старта, ни для продакшен-деплоя.
- `postgres-test-setup`/`integration-tests` намеренно не подключены к `migrate`: заводить общий
  сервис миграции для двух независимых баз данных добавило бы связность без пользы.
- Кеш `_expected_head_revision()` живёт на весь процесс: если когда-нибудь появится hot-reload
  миграций без перезапуска (сейчас такого сценария нет и не планируется), кеш придётся сбрасывать
  явно.

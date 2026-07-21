# Woland Guard

Woland Guard — разрабатываемая защитная система мониторинга Linux-серверов. Агент будет
читать разрешённые системные события, а control plane — создавать понятные инциденты и
помогать владельцу сервера реагировать на них.

Проект находится на этапе 2: к техническому каркасу добавлены версионированный контракт
событий, начальная схема PostgreSQL и миграции. Ingestion API, Linux-агент и detection
engine ещё не реализованы.

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
- базовые настройки Ruff, mypy и pytest;
- ADR с подтверждёнными решениями этапов 1 и 2.

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

## Архитектурные решения

Принятые решения зафиксированы в
[`docs/adr/0001-mvp-foundation.md`](docs/adr/0001-mvp-foundation.md).
Контракт и хранение описаны в
[`docs/adr/0002-event-contract-and-persistence.md`](docs/adr/0002-event-contract-and-persistence.md).

## Ограничения этапа 2

- нет ingestion API;
- нет агента и journald adapter;
- нет detection engine и Telegram;
- нет HTTP API управления серверами и ключами;
- outbox worker, конкурентный захват, backoff и отправка уведомлений ещё не реализованы;
- readiness проверяет соединение с PostgreSQL, но пока не проверяет актуальность миграции;
- зависимости Python зафиксированы в `uv.lock`;
- production deployment не подготовлен.

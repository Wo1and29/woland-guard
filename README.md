# Woland Guard

Woland Guard — разрабатываемая защитная система мониторинга Linux-серверов. Агент будет
читать разрешённые системные события, а control plane — создавать понятные инциденты и
помогать владельцу сервера реагировать на них.

Проект находится на этапе 1: создан только технический каркас control plane. Сбор событий,
модели данных, ingestion API, Linux-агент и detection engine ещё не реализованы.

Лицензия пока не выбрана. На текущем этапе проект не позиционируется как open-source.

## Что реализовано

- Python 3.12 и uv workspace;
- минимальное FastAPI-приложение;
- liveness endpoint `GET /health/live`;
- readiness endpoint `GET /health/ready` с проверкой PostgreSQL;
- Docker Compose для control plane и PostgreSQL;
- базовые настройки Ruff, mypy и pytest;
- ADR с подтверждёнными архитектурными решениями.

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
uv run mypy
uv run pytest
```

## Архитектурные решения

Принятые решения зафиксированы в
[`docs/adr/0001-mvp-foundation.md`](docs/adr/0001-mvp-foundation.md).

## Ограничения этапа 1

- нет моделей и миграций;
- нет ingestion API;
- нет агента и journald adapter;
- нет detection engine и Telegram;
- transactional outbox описан архитектурно, но не реализован;
- зависимости Python зафиксированы в `uv.lock`;
- production deployment не подготовлен.

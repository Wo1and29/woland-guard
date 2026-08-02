# Развёртывание

**Честно и явно: production deployment в этом MVP не подготовлен «под ключ»** (README,
«Ограничения MVP»). Контейнеры уже hardened (non-root, `cap_drop: ALL`, read-only filesystem),
но TLS termination, perimeter rate limiting, бэкапы и мониторинг хоста — ответственность
оператора. Этот документ описывает, как развернуть проект на VPS так, как он сейчас реально
работает, и что нужно добавить самостоятельно.

## Что уже даёт Docker Compose

`compose.yaml` поднимает:

- `postgres` — официальный образ, healthcheck, именованный volume `postgres-data`;
- `control-plane` — REST API + Dashboard, non-root UID/GID `10001:10001`, `cap_drop: ALL`,
  `no-new-privileges`, read-only root filesystem, `/tmp` через tmpfs, healthcheck на
  `/health/ready`;
- `outbox-worker` и `telegram-admin` (профиль `telegram-notifications`) — тот же hardening,
  плюс read-only bind-mount staging-каталога для Telegram bot token и private tmpfs для runtime
  copy (см. README, «Исходящие Telegram-уведомления»);
- `integration-tests`, `postgres-test-setup` (профиль `test`) — не для production.

Все сервисы находятся в отдельной сети `backend`; Docker socket никуда не монтируется.

## Шаги на VPS

1. Установите Docker Engine с Compose plugin из официальных источников.
2. Склонируйте репозиторий, скопируйте `.env.example` в `.env` и **замените
   `WG_POSTGRES_PASSWORD`** на случайное значение — пример в `.env.example` только для
   локальной разработки.
3. Установите `WG_APP_ENV=production` и `WG_WEB_PUBLIC_ORIGIN` на точный HTTPS-адрес, под
   которым будет доступен Dashboard (без пути). Dashboard cookies обязательно `Secure` — без
   HTTPS они не будут установлены браузером.
4. Поднимите стек и примените миграции:
   ```bash
   docker compose up -d --build
   docker compose exec control-plane alembic upgrade head
   ```
5. Создайте сервер и агентский ключ, затем разверните агента — см.
   [docs/agent-installation.md](agent-installation.md).
6. Синхронизируйте правила и создайте первого оператора — см. README, «Правила Detection
   Engine» и «Локальные операторы».
7. Настройте reverse proxy и HTTPS (ниже) — без него Dashboard недоступен из браузера, а
   ingestion API остаётся открытым без perimeter rate limiting.

## HTTPS и reverse proxy

Control plane сам не терминирует TLS. Пример конфигурации nginx —
[`deploy/nginx/woland-guard.conf.example`](../deploy/nginx/woland-guard.conf.example):
терминирует TLS, проксирует на `127.0.0.1:8000`, и — что важно — задаёт `limit_req` на
`/api/v1/events` и на остальные пути. Это закрывает задокументированный пробел: собственный
rate limiter control plane процесс-локальный и не видит запросы, отклонённые до аутентификации
(см. [docs/threat-model.md](threat-model.md), «DoS через поток событий»).

Получите сертификат (например, Let's Encrypt/certbot) на домен, который будет ровно совпадать с
`WG_WEB_PUBLIC_ORIGIN` — несовпадение origin ломает CSRF-проверку и вход в Dashboard (ADR-0007).

## Telegram-уведомления в production

Профиль `telegram-notifications` запускается отдельно от основного `docker compose up`:

```bash
docker compose --profile telegram-notifications up -d outbox-worker
```

Bot token никогда не идёт через `.env`, аргументы CLI или PostgreSQL — только через отдельный
файл в каталоге `WG_TELEGRAM_STAGING_DIRECTORY` с правами, ограничивающими доступ вне
контейнера. Подробная процедура — README, «Исходящие Telegram-уведомления».

## Dry-run блокировка IP: подготовка сервера

9C (README, «Блокировка IP (dry-run)») позволяет предлагать и подтверждать план блокировки, но
**control plane сам план не исполняет** — команда только показывается оператору. Если в будущем
появится исполнение (подэтап 9D), ему потребуется, чтобы на защищаемом сервере заранее
существовали таблица и оба set, которые `nft add element` использует:

```bash
nft add table inet woland_guard
nft add set inet woland_guard blocked_v4 '{ type ipv4_addr; }'
nft add set inet woland_guard blocked_v6 '{ type ipv6_addr; }'
nft add rule inet woland_guard input ip saddr @blocked_v4 drop
nft add rule inet woland_guard input ip6 saddr @blocked_v6 drop
```

Имена таблицы и обоих set настраиваются через `WG_IP_BLOCK_NFT_TABLE`/`WG_IP_BLOCK_NFT_SET_V4`/
`WG_IP_BLOCK_NFT_SET_V6` и должны совпадать с тем, что создано на сервере вручную — это
осознанное ограничение: изменение firewall хоста без ведома администратора не входит в задачи
control plane.

Функция выключена по умолчанию (`WG_IP_BLOCK_ENABLED=false`). Прежде чем включать её, добавьте в
allowlist собственный адрес администратора и любые доверенные диапазоны — control plane не
хранит IP операторов и не может защитить их от блокировки автоматически (README, «Блокировка IP
(dry-run)»; ADR-0015):

```bash
docker compose exec control-plane woland-guard-admin add-ip-allowlist-entry \
  --cidr <ваш адрес или диапазон>/32 --label admin --reason "адрес администратора"
```

## Что оператор обязан настроить сам (не входит в MVP)

- **TLS termination и perimeter rate limiting** — пример выше, но конкретные лимиты и
  сертификаты — ваша ответственность;
- **резервное копирование PostgreSQL** — volume `postgres-data` не бэкапится автоматически;
  `pg_dump`/`pg_restore` по расписанию — на операторе;
- **ротация ключей агента и операторов** — CLI поддерживает ручную ротацию
  (`rotate-operator-key`), автоматической по расписанию нет;
- **firewall хоста** — Docker публикует `control-plane` порт согласно `WG_HTTP_PORT`; ограничьте
  доступ к нему на уровне хоста, если reverse proxy — единственная предполагаемая точка входа;
- **allowlist блокировки IP и таблица nftables** — прежде чем включать `WG_IP_BLOCK_ENABLED`,
  добавьте адрес администратора в allowlist и создайте таблицу/set, как описано выше;
- **обновление зависимостей и базового образа** — CI проверяет известные CVE в Python-зависимостях
  (`dependency-audit` job), но не пересобирает и не деплоит образы автоматически;
- **мониторинг самого control plane** (аптайм, диск, память) — вне периметра проекта; `/health/
  live` и `/health/ready` дают точку для внешнего мониторинга, но сам мониторинг не поставляется.

## Переменные окружения

Полный список — `.env.example`, с комментариями по каждой группе (ingestion limits, web/session,
outbox, Telegram). README, «Проверки» дополнительно перечисляет переменные, управляющие
ingestion rate limiting и outbox worker.

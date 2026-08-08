# Демонстрационный режим

Все данные — синтетические. Ни один сценарий не обращается к реальным серверам, реальному
Telegram или внешним сетям за пределами loopback (README, «Синтетические demo-сценарии 8A» и
«Full-stack demo verification 8B»). Есть три уровня демонстрации — от «руками показать один
инцидент» до полного автоматического release-гейта.

## Уровень 1: один инцидент вручную через обычный Compose

Самый простой путь — реальный стек (`compose.yaml`), один заранее подготовленный сценарий:

```bash
docker compose up --build -d
docker compose exec control-plane alembic upgrade head
docker compose exec control-plane woland-guard-admin sync-rules --rules-dir /workspace/detection-rules
docker compose exec control-plane woland-guard-admin create-test-agent \
  --name demo-server --hostname demo.invalid --label local-demo
```

Сохраните выведенный `wgak_...` токен, затем сгенерируйте и отправьте один из 32 канонических
сценариев (по 4 на каждое из 12 правил: `positive`, `negative`, `boundary_below`,
`boundary_exact`):

```bash
uv run --package woland-guard-control-plane woland-guard-demo list-scenarios
uv run --package woland-guard-control-plane woland-guard-demo generate \
  --scenario ssh_bruteforce_by_ip.positive.v1 \
  --output /tmp/ssh-bruteforce-positive.json
uv run --package woland-guard-control-plane woland-guard-demo send \
  --manifest /tmp/ssh-bruteforce-positive.json \
  --origin http://127.0.0.1:8000 \
  --api-key-file /tmp/agent.key
```

`send` сообщает только фактические accepted/duplicate/rejected counts — он не проверяет
создание инцидента или доставку, это уровень 3. Что реально произойдёт: детектор оценит
отправленные события, при срабатывании правила создаст `Incident`; проверить это можно через
`GET /api/v1/incidents` с токеном оператора или через Dashboard на `/dashboard` (см. README,
«Read-only Dashboard» — для входа в браузере нужен настроенный HTTPS-origin, обычный HTTP
Compose не годится для интерактивного просмотра).

## Уровень 2: интерактивный browser-демо (human-demo)

Показывает Dashboard живьём в Chromium с уже готовыми synthetic-данными — то, что стоит
использовать для демонстрации работодателю или на собеседовании. Требует установленный
Playwright/Chromium (см. [docs/demo.md#требования](#требования)).

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = ".playwright-browsers"
uv run python -m scripts.demo_e2e.human `
  --project-root (Resolve-Path .).Path `
  --credential-output C:\wg-demo-private\operators.json
```

```bash
PLAYWRIGHT_BROWSERS_PATH=.playwright-browsers uv run python -m scripts.demo_e2e.human \
  --project-root "$(pwd)" \
  --credential-output /tmp/wg-demo-private/operators.json
```

Поднимает изолированный demo-стек (`compose.demo.yaml`), проводит один компактный canonical
scenario через весь пайплайн и открывает headful Chromium с уже вошедшим оператором. Файл с
credentials содержит только синтетические `operator_api_key` для analyst/admin/viewer — не
реальные секреты, не токен агента, не Telegram token, не пароль БД. Каталог для
`--credential-output` должен быть заранее приватным (на POSIX применяется `0600`; на Windows
эквивалентная ACL-гарантия не заявляется). После `Enter`/`Ctrl+C` все ресурсы и credential-файл
удаляются штатным teardown — не прерывайте вручную широкими Docker-командами (`docker system
prune` и т.п.), это может оставить недоочищенные ресурсы, которые не подхватит teardown по
exact project/ownership label.

## Уровень 3: автоматический full-stack release gate (8B)

Не для демонстрации человеку — для проверки, что весь пайплайн действительно работает, перед
тем как считать состояние репозитория releasable. Разница с уровнем 1: этот прогон использует
**настоящий** outbox worker и **настоящий** Chromium workflow, проверяет точные DB-outcomes
после ingestion и после replay, и делает `pg_dump`/`pg_restore` smoke на отдельном изолированном
PostgreSQL. Подробное описание топологии, hardening и границ доказательства — ADR-0012.

Прогон против уже закоммиченного кандидата (`git archive HEAD`, поэтому требует чистого
`git status`):

```powershell
.\scripts\verify-clean-install.ps1
```

```bash
sh scripts/verify-clean-install.sh   # Linux full run пока не подтверждён на этом проекте
```

Прогон отдельных частей пайплайна над рабочим деревом (без коммита), через pytest:

```bash
WG_RUN_DEMO_E2E=1 uv run pytest tests/e2e -k "not tracked_only"
```

Это долгие прогоны (десятки минут на Windows-разработческой машине, дольше при холодном
uv/Playwright-кэше — `verify-clean-install` намеренно использует изолированный кэш на каждый
запуск). Не входит в обычный CI (`.github/workflows/ci.yml`) по этой причине — это ручной
release-гейт, а не проверка на каждый PR.

## Требования

- Docker Engine + Compose plugin;
- для уровней 2 и 3: Chromium для закреплённой версии Playwright —
  `uv run playwright install --no-shell chromium`, каталог кэша задаётся
  `PLAYWRIGHT_BROWSERS_PATH` (в этом репозитории — `.playwright-browsers`, в `.gitignore`).

## Что НЕ доказывает demo-режим

Сформулировано явно, чтобы не переоценивать результат (ADR-0011, ADR-0012):

- реальную доставку в Telegram — во всех уровнях transport либо не вызывается (уровень 1, без
  включённого destination), либо fake/in-process (уровни 2–3);
- production disaster recovery — backup/restore smoke проверяет структурную и данных-фингерпринт
  целостность, не полный DR-сценарий;
- полную сетевую изоляцию процесса — page guard в browser-тестах контролирует только запросы
  тестируемых страниц;
- сертификацию под конкретный Linux-дистрибутив — native Linux clean-install run пока не
  подтверждён на этом проекте;
- пропускную способность или производительность — никакие числа throughput/latency нигде не
  заявляются, потому что не измерялись.

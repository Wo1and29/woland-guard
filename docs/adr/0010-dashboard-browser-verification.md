# ADR-0010: Dashboard browser verification и локальный HTTPS harness

- Статус: принято и реализовано в 7D, ожидает повторного ревью
- Дата: 2026-07-29

## Контекст

Этапы 7A–7C проверяли Dashboard через application, HTTP и template integration tests, но не
исполняли полный пользовательский сценарий в настоящем браузере. `__Host-*` cookies всегда
имеют `Secure`, поэтому browser-проверка требует локального HTTPS без development-флага,
ослабляющего cookie policy. Тесты не должны обращаться к внешним сервисам, сохранять operator
API keys либо оставлять certificate, private key, storage state, traces, video или screenshots.

## Решения

1. Browser automation использует закреплённые dev-зависимости `playwright==1.61.0` и
   `trustme==1.2.1`; устанавливается только полный Chromium через `playwright install
   --no-shell chromium`, запуск выполняется с `channel="chromium"`. Firefox, WebKit и old
   headless shell не входят в 7D.
2. HTTPS harness сначала создаёт и оставляет открытым socket `127.0.0.1:0`, затем передаёт тот
   же socket публичному `uvicorn.Server.run(sockets=[...])` вместе с TLS configuration.
   Изолированный regression подтверждает HTTPS, отсутствие port handoff, bounded cooperative
   shutdown и освобождение socket. Private API Uvicorn не используются.
3. CA, certificate, private key и PostgreSQL env file создаются через системный temporary
   directory вне репозитория. Readiness client использует CA file trustme и строго проверяет
   TLS chain и IP. Системный trust store не изменяется. Chromium имеет
   `ignore_https_errors=True` только в одном непостоянном `BrowserContext`; browser CA-chain
   validation не заявляется.
4. Каждый browser environment запускает точный временный `postgres:17-bookworm` container с
   уникальным именем/label, loopback-only published port и tmpfs data. Затем применяется
   `alembic upgrade head`, синтетические operators/servers/events/incidents создаются через
   test factories, а приложение работает в отдельном spawned process. Cleanup останавливает
   только эти PID/container/socket и удаляет только созданные temporary files.
5. `PageRequestGuard` сравнивает полный `scheme + hostname + port`; page HTTP/HTTPS разрешены
   только точному HTTPS origin harness. `service_workers="block"`; любой WebSocket страницы
   блокируется отдельным guard. Проверка означает только, что внешние запросы тестируемых
   страниц не наблюдались и не разрешались. Process/OS network isolation Chromium не
   заявляется.
6. `Referrer-Policy: no-referrer` несовместим с exact-Origin mutation boundary в Chromium:
   native same-origin form POST получает `Origin: null`. Изолированный regression отличает это
   от временно недоверенного TLS. Policy изменена на `same-origin`: referrer не передаётся
   другому origin, а нативные Dashboard forms сохраняют проверяемый exact Origin.
7. Plaintext operator API key существует только в памяти fixture и password input. Redacted
   wrapper скрывает `repr`/`str`; Playwright errors заменяются статическим
   `BrowserOperationError`. Suite отказывается работать при `--showlocals`, `PWDEBUG` или
   `DEBUG=pw:api`. Имена тестов, assertion messages и application logs не содержат ключ.
8. Trace, video, HAR, downloads, storage state, HTML dumps и screenshots по умолчанию
   отключены. Review screenshots создаются только при `WG_BROWSER_REVIEW_SCREENSHOTS=1`, не
   включают login page, лежат в ignored `.pytest-browser`, просматриваются локально и затем
   удаляются. Visual baselines не коммитятся.
9. Автоматические scenarios покрывают analyst/admin/viewer RBAC, login/logout и invalidated
   session, overview/servers/incidents/rules/audit, status transition, comment, PRG/reload,
   XSS autoescape, keyset next/reset, error pages, desktop/mobile overflow, semantic landmarks,
   labels, table captions/headers, keyboard traversal, focus-visible и базовый вычисляемый
   contrast. Axe-core, Playwright visual snapshots и CI не добавляются.
10. Failure-path cleanup является проверяемой частью harness. PostgreSQL container после
    `docker run` заранее получает валидированные уникальные name и ownership label. Нормальный
    stdout принимается только как полный 64-символьный ID и подтверждается exact metadata через
    `docker inspect`. При timeout, CLI error либо malformed stdout выполняется короткий bounded
    polling одновременно по exact name и exact label; единственный полный ID повторно
    подтверждается через inspect и только затем удаляется адресно. Поиск по одному атрибуту,
    широкое удаление по filter и `docker prune` не используются. Неоднозначная identity или
    неподтверждённое удаление сохраняют внутреннюю identity и дают статическую ошибку.
    PostgreSQL container после cooperative stop при необходимости удаляется принудительно, а
    отдельный `docker ps` подтверждает отсутствие точного container ID. Application process
    проходит bounded цепочку cooperative stop → `terminate()` → `kill()` и считается очищенным
    только после завершения процесса, закрытия process handle и освобождения socket.
    `BrowserEnvironment` независимо пытается очистить application, TLS и PostgreSQL, даже если
    предыдущий cleanup завершился ошибкой. Все resource-owning pytest fixtures используют
    `try/finally`, поэтому teardown выполняется и при setup/test/guard failure. Наружу
    возвращаются только статические ошибки без идентификаторов и исходного exception text.

## Границы доказательств

7D не доказывает Chromium CA-chain validation, полную сетевую изоляцию browser process,
соответствие WCAG целиком, качество screen reader experience или pixel-identical rendering.
Automated contrast проверяет только выбранные computed foreground/background пары. Полный
manual accessibility audit и cross-browser matrix остаются отдельными задачами. Новых routes,
DB models/migrations, product JavaScript, HTMX, WebSocket functionality, Telegram/outbox
изменений, CI и production TLS в 7D нет.

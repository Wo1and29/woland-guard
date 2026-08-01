# ADR-0012: clean-install и full-stack synthetic demo verification

- Статус: принято, реализовано в 8B и ожидает повторного ревью
- Дата: 2026-08-01

## Контекст

8A создаёт закрытый каталог 32 canonical scenarios, но его CLI подтверждает только результат
ingestion. Для технического ревью нужен один воспроизводимый путь от tracked source до
Dashboard и restored synthetic database без реального Telegram, host logs и внешних данных.
Этот путь является release verification, а не новой product capability.

## Топология и порядок запуска

Отдельный `compose.demo.yaml` содержит `demo-postgres`, единственный `demo-migrate`,
`demo-rule-sync` и `demo-control-plane`. Migration и rule sync являются one-shot services;
control plane зависит от их успешного завершения. PostgreSQL и HTTP API публикуются только как
Docker-assigned random ports на `127.0.0.1`. Runtime inspect обязан подтвердить exact HostIp и
реальный port `1..65535`; отсутствие либо ambiguous mapping закрывает запуск.

Windows checkpoint с Docker Compose 5.3.0 и Engine 29.6.1 подтвердил, что short syntax
`127.0.0.1::<container-port>` сохраняет открытый random request в HostConfig и выдаёт конкретный
loopback binding в `NetworkSettings.Ports`. Вариант `internal: true` для Compose network на этом
engine подавлял published endpoint, поэтому он не используется. Это named project network, но
не OS/process network isolation. Control plane не имеет integration, которая требует внешний
runtime network; Telegram boundary 8B остаётся in-process fake.

Application one-shot и HTTP services работают как UID/GID 10001, с read-only root filesystem,
private tmpfs, `cap_drop: ALL`, `no-new-privileges`, bounded memory/CPU/PID и `restart: "no"`.
Официальный PostgreSQL image сохраняет штатный entrypoint и writable named data volume; ему не
приписывается тот же read-only/non-root hardening. Docker socket, privileged/host network,
host journal и broad host mounts отсутствуют.

## Automated verification

После появления candidate в Git outer runner требует clean worktree и создаёт bounded tar через
`git archive HEAD`. Extractor запрещает absolute/traversal names, links, devices, FIFO,
duplicate writes и превышение member/count/expanded-size limits. В checkout отсутствуют `.git`,
`.env`, `.venv`, browser cache и test artifacts. Отдельные `UV_PROJECT_ENVIRONMENT`,
`UV_CACHE_DIR` и `PLAYWRIGHT_BROWSERS_PATH` живут рядом с временным checkout и удаляются вместе
с ним. Cold dependency/browser/image acquisition может требовать интернет; это не runtime claim.

Внутренний state machine выполняет:

1. PostgreSQL health, `alembic upgrade head`, `current=20260728_0009`, `alembic check`;
2. штатный `sync-rules` и проверку ровно восьми active enabled version-one rules;
3. provisioning server/agent, analyst/admin/viewer и enabled low-severity Telegram destination
   через существующие application services;
4. все 32 catalog-bound manifests через публичный `/api/v1/events`;
5. exact catalog-derived Event/Incident/evidence/history/outbox assertions;
6. настоящий `OutboxWorker`, formatter и Telegram adapter с explicit in-process fake transport;
7. один desktop Chromium workflow над той же БД: analyst mutations/PRG/XSS, admin audit,
   viewer denial и logout;
8. полный replay и отсутствие новых business rows;
9. custom `pg_dump` и `pg_restore` в отдельный isolated PostgreSQL project с exact snapshot,
   metadata, migration revision и структурными catalog fingerprints для constraints, triggers
   и indexes. Fingerprint constraints сравнивает устойчивые имена, типы, упорядоченные имена
   columns, deferrability/validation и FK actions, а не физические `attnum` либо нестабильный
   pretty-printed DDL. `attnum` может законно измениться при восстановлении мигрированной схемы,
   содержащей исторические dropped-column gaps. Index fingerprint аналогично использует flags,
   упорядоченные column/expression keys и наличие partial predicate вместо полного `CREATE INDEX`
   либо нестабильного predicate-expression текста. Это restore inventory smoke, а не детектор
   произвольного semantic schema drift.

`git archive HEAD` не может включать незакоммиченный 8B scope. Поэтому полный tracked-only gate
выполняется только после candidate commit; до него runtime проверяются тот же Compose pipeline,
browser, backup/restore и archive security unit contracts отдельно.

## Fake delivery boundary

Fake transport недоступен через production Settings, registry или entrypoint. Он создаётся
только в `scripts.demo_e2e`, передаётся test-only constructor Telegram client и получает request
от настоящего formatter/adapter/worker. Он требует production origin `https://api.telegram.org`,
валидирует method/path и bounded JSON shape, затем удаляет body и сохраняет только request count.
Bot token, chat ID и notification text не входят в report. Проверяется application/formatter/
adapter boundary; Telegram Bot API и реальная network delivery не проверяются.

## Credentials, HTTPS и artifacts

Random credentials существуют только в памяти, subprocess environment либо явно указанном
human-demo credential file. Они отсутствуют в CLI arguments, Compose command, manifests,
reports и logs. Application/command errors статичны и не цепляют nested exception. Временный
custom backup считается чувствительным даже при синтетических данных, имеет bounded size,
на POSIX mode 0600 и всегда удаляется.

HTTPS переиспользует 7D `TemporaryTlsMaterial` и `ApplicationProcess` над PostgreSQL этого же
demo run. Strict readiness client проверяет временный trustme CA; Chromium использует
`ignore_https_errors=True` только в непостоянном context. Exact-origin page request guard,
blocked service workers и WebSocket guard сохраняются. Browser CA-chain validation и полная
процессная network isolation не заявляются; screenshots, traces, video, HAR, downloads и
storage state не создаются.

Automated mode всегда удаляет данные. Human mode использует один compact canonical scenario,
headful ephemeral Chromium и новый явно указанный credential file; ресурсы сохраняются только
до Enter/Ctrl+C, после чего exact cleanup удаляет file и demo resources. POSIX file mode 0600
проверяется; эквивалентная Windows ACL guarantee не заявляется.

## Ownership и failure cleanup

Run получает closed random ID, два exact Compose project name и ownership label. До `down
--volumes --remove-orphans` каждый найденный container/network/volume должен одновременно иметь
expected project и ownership metadata. Удаление выполняется только exact Compose project;
`docker prune`, broad label deletion и пользовательский `woland-guard_postgres-data` не
используются. Main и restore project разделены именем, но принадлежат одному run label, поэтому
absence после teardown проверяется по точному project, а не по общему run label.

Cleanup выполняется best-effort в порядке browser context/process, HTTPS/socket/TLS,
credentials/manifests/backup, restore project, main project и tracked-only checkout. Cleanup
failure остаётся авторитетной статической ошибкой даже после основной ошибки. Native shell
timeout вне процесса не гарантирует исполнение Python `finally`; оставшиеся exact-labelled
resources требуют адресного operator review, а не широкого удаления.

## Границы доказательств

8B не является production TLS, real Telegram test, production disaster recovery, benchmark,
Linux distribution certification или доказательством отсутствия всего внешнего трафика
процессов. Page guard контролирует только запросы тестируемых страниц. Native Linux clean-install
support не заявляется до фактического полного Linux run. Новых routes, DB models/migrations,
REST comments, product adapters, HTMX/JavaScript, CI, deployment и LICENSE в 8B нет.

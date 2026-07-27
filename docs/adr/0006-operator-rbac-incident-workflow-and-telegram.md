# ADR-0006: Operator identity, RBAC, incident workflow и Telegram

- Статус: принято
- Дата: 2026-07-22

## Контекст

После Detection Engine control plane должен безопасно показывать инциденты операторам,
фиксировать терминальные решения и надёжно отправлять минимизированные уведомления. У агента
уже есть отдельная машинная аутентификация; использовать её для людей нельзя. Этап слишком
велик для одной неделимой реализации, поэтому выполняется как 6A → 6B → 6C → 6D с ревью
между частями.

## Общие решения этапа 6

1. `Operator` представляет локальную человеческую identity. Способы входа хранятся отдельно.
   В 6A реализован только `OperatorApiKey`; будущая web-session сможет ссылаться на того же
   оператора без изменения RBAC и audit actor model.
2. Ключ имеет формат `wgok_<public_id>.<secret>`. Случайный высокоэнтропийный secret
   показывается один раз, а PostgreSQL хранит только 32-байтовый SHA-256 digest. Такой digest
   допустим для случайного ключа и не используется как password hashing.
3. Ключи независимо выпускаются, истекают, отзываются и атомарно ротируются. Rotation создаёт
   новую строку с `rotated_from_id` и отзывает прежнюю в одной транзакции. Удаление identity и
   ключей штатным workflow не предусмотрено.
4. Роли фиксированы: `viewer`, `analyst`, `admin`. Разрешения задаёт одна закрытая матрица в
   application layer. В 6A HTTP admin API и incident routes не создаются; operator dependency
   предназначен для routes 6B.
5. Неизвестный, malformed, просроченный, отозванный ключ и ключ неактивного оператора дают
   одинаковый HTTP 401. Secret digest сравнивается constant-time. Успешная аутентификация
   обновляет `last_used_at`.
6. Массовые неизвестные credentials и RBAC-отказы не сохраняются в audit-таблице. Они попадают
   только в очищенные структурированные логи с process-local ограничением частоты сообщений;
   perimeter rate limiting остаётся обязательным для production.

## 6B: статусы, история, audit и идемпотентность

7. Разрешены переходы `new → investigating|resolved|false_positive` и
   `investigating → resolved|false_positive`. `resolved` и `false_positive` терминальны;
   reopen отсутствует. Новое совпадение после терминального incident создаёт новый incident.
8. Status transition блокирует строку incident, проверяет `expected_version` и атомарно
   изменяет incident, history и audit. Для `resolved`/`false_positive` reason обязателен.
9. Полная идемпотентность хранит operator scope, `Idempotency-Key`, hash канонического запроса
   и сохранённый результат. Replay идентичного запроса возвращает первоначальный результат.
   Повтор ключа с другим hash даёт 409. Replay проверяется раньше stale `expected_version`.
10. Append-only audit хранит успешные status transitions, provisioning/revocation ключей и
    управление Telegram destinations. Audit details строятся только из allowlist и не содержат
    credentials, HTTP body или event payload. Неизменяемость не защищает от владельца таблиц
    или PostgreSQL superuser.

Реализация 6B уточняет эти решения:

- после authentication, RBAC и синтаксической валидации запрос нормализуется, получает
  canonical SHA-256 hash и входит в транзакцию; transaction-level advisory lock берётся по
  `operator_id + Idempotency-Key` до чтения incident;
- совпавший hash возвращает сохранённый business snapshot, даже если incident позднее изменён.
  Транспорт добавляет текущий request ID и только для replay ставит
  `Idempotency-Replayed: true`. Другой hash возвращает 409 без чтения incident;
- 404, stale-version 409 и запрещённый-transition 409 сохраняются как завершённые outcomes.
  Ошибки 5xx/БД, 401, 403 и validation errors не сохраняются;
- `reason` проверяется до `strip(" ")`, затем нормализуется в NFC. Запрещены управляющие,
  format/surrogate, line/paragraph separator символы; итоговая длина — 1–1000 символов;
- `incident_history`, `audit_log_entries` и `operator_idempotency_records` отклоняют
  `UPDATE`, `DELETE` и `TRUNCATE` PostgreSQL-триггерами. Миграция создаёт ровно один baseline
  версии 1 для каждого ранее существовавшего incident;
- единый application-layer audit writer проверяет действие до создания SQLAlchemy-модели.
  Закрытый реестр разрешает только: `operator.created` с `{role}`;
  `operator_api_key.issued|revoked` с `{operator_id}`; `operator_api_key.rotated` с
  `{operator_id, replaced_key_id}`; `incident.status_changed` с
  `{from_status, from_version, history_id, to_status, to_version}`. Для каждого действия
  зафиксированы actor type и target type; UUID обязаны быть каноническими строками, роли и
  статусы проверяются по enum, версии — положительные `int` без `bool`. Missing/extra поля и
  неизвестные действия отклоняются без отражения переданного значения в ошибке;
- `lock_version` изменяется только status workflow. Добавление evidence его не увеличивает.
  Detection под correlation lock выполняет history/evaluate, затем блокирует найденный active
  incident через `SELECT FOR UPDATE`; после терминального перехода новое совпадение создаёт
  отдельный incident;
- Incident API использует cursor keyset pagination по `(created_at, id)`. Cursor — строго
  проверяемый, но не криптографически защищённый base64url JSON; RBAC применяется независимо
  от его содержимого. Audit API доступен только `admin`.

## 6C: transactional outbox worker

11. Создание нового incident, baseline history и outbox-строк выполняется в транзакции
    ingestion. Повторное evidence не создаёт уведомление. Минимальный idempotency key включает
    `notification_type + incident_id + destination_id`.
12. Provider-neutral `notification_destinations` хранит только `adapter_kind`, `enabled`,
    `minimum_severity` и timestamps. В 6C разрешён production identifier `telegram`, но нет
    Telegram-конфигурации, seed-записей, HTTP-клиента и внешних вызовов. В 6D provider-specific
    таблица будет связана с foundation отношением 1:1.
13. Immutable outbox envelope содержит только allowlisted incident metadata. PostgreSQL trigger
    запрещает изменение notification type, incident/destination, payload/version,
    idempotency key и `created_at` после INSERT. Lifecycle защищён state-shape constraints и
    trigger разрешённых переходов.
14. Worker захватывает по одной строке через `FOR UPDATE SKIP LOCKED`, назначает случайный claim
    token и вызывает delivery adapter только после commit и полного закрытия claim Session.
    Завершение условно по `id`, статусу `processing` и точному claim token. Зависшие claims
    восстанавливаются после lease timeout.
15. Ограниченные повторы используют exponential equal jitter; `retry_after` ограничивается
    конфигурационным максимумом. Успех очищает `last_error`, permanent failure автоматически
    не повторяется. Delivery остаётся at-least-once: crash после внешнего side effect до DB
    acknowledge допускает повтор.
16. Manual requeue разрешён только из `failed`, требует точного UUID-подтверждения, сохраняет
    `attempt_count`, ограниченно увеличивает `max_attempts` и атомарно создаёт allowlisted audit
    action `outbox.failed_requeued`. Ошибки adapter сохраняются только как закрытый code и
    статический безопасный текст.
17. Long-running worker выполняет lease recovery при старте и затем с ограниченным
    настраиваемым интервалом независимо от pending backlog. Интервал положителен, не превышает
    lease и проверяется вместе с инвариантом `lease > adapter timeout`; ожидание пустой очереди
    остаётся interruptible для SIGTERM. Неожиданные исключения adapter классифицируются отдельно
    как `adapter_unexpected_error`, без сохранения текста исключения.

## 6D: только исходящий Telegram

18. `telegram_destination_configs` расширяет provider-neutral destination отношением 1:1 и
    хранит только `chat_id`, безопасный `token_file_name` и timestamps. PostgreSQL triggers
    запрещают provider row для другого adapter kind, смену kind при существующей config,
    включение Telegram destination без config и удаление config включённой destination.
    Destination создаётся отключённой; delete отсутствует, отключение сохраняет историю.
19. Управление выполняет только одноразовый Compose service `telegram-admin`. Основной
    `control-plane` не монтирует Telegram secrets. `telegram-admin` видит только read-only
    staging и сообщает `configured`/`staging_file_ready`, не заявляя runtime health private
    tmpfs worker. Chat ID вводится скрытым prompt; CLI принимает только безопасный basename
    `--token-file-name`, а не путь или token.
20. `outbox-worker` работает непривилегированным UID/GID `10001:10001`, с `cap_drop: ALL`,
    read-only root filesystem, read-only staging mount и private tmpfs. Перед каждой delivery
    он выполняет on-demand staging validation и синхронизацию. Новый файл и атомарная ротация
    подхватываются без restart и background watcher.
21. Staging validation не доверяет owner/mode Windows bind mount, но требует regular file,
    отсутствие symlink, bounded single-line printable ASCII content и стабильные inode/device
    metadata при чтении. Runtime validation требует private parent `0700`, regular file
    `0400`, owner/group `10001:10001`, `O_NOFOLLOW` и повторный `fstat`. Worker создаёт temp
    через `O_CREAT|O_EXCL|O_NOFOLLOW`, выполняет bounded write, `fsync`, `fchmod` и atomic
    replace; `chown` не вызывается. Невалидная ротация не уничтожает прежнюю copy, но при
    invalid/missing staging прежняя copy fail-closed не используется.
22. Token — одна непустая ASCII-строка до 256 байт без whitespace, NUL и control characters.
    Неофициальная грамматика Telegram token не навязывается. Token не хранится в PostgreSQL,
    `.env`, CLI-аргументах, audit или repr и не копируется в image layer.
23. Production HTTP origin — compile-time constant `https://api.telegram.org`; factory не
    принимает base URL. Client использует `trust_env=False`, `verify=True`,
    `follow_redirects=False`, transport retries `0` и bounded connect/read/write/pool
    timeouts. Их сумма не превышает adapter budget, но отдельный wall-clock deadline не
    заявляется. Внутренних threads/futures и фоновых запросов нет.
24. Response читается streaming chunks в локальный buffer до 64 KiB. До проверки лимита не
    вызываются `content`, `read()` или `json()`; oversized body безопасно классифицируется.
    JSON разбирается только из ограниченного buffer. URL, request/response, headers, body и
    исключения не передаются application logger.
25. Поскольку token находится в URL `/bot<token>/sendMessage`, namespace `httpx2`, `httpcore2`
    и их дочерние logger подавляются до создания request независимо от root log level.
    Regression-тесты с canary при INFO/DEBUG проверяют все `LogRecord`, stdout и stderr.
26. `DeliveryResult` остаётся закрытым контрактом. Retryable codes: общий temporary failure,
    staging missing/invalid, runtime copy unavailable/invalid и Telegram protocol error.
    Permanent codes: общий permanent failure, destination unconfigured и payload invalid.
    Worker сохраняет точный безопасный provider code; exhaustion и unexpected exception
    остаются отдельными `attempts_exhausted`/`adapter_unexpected_error`.
27. Уведомление — plain text без `parse_mode`. Formatter использует только allowlisted
    incident envelope: identifiers, rule key/version, severity, title и timestamp. Raw event
    payload, attributes, evidence, correlation, actor, IP и credentials не передаются.
28. Test-only fake transport доступен только через явную dependency injection, проверяет POST,
    официальный origin и canonical path и не выбирается через Settings, env, CLI или БД.
    Production registry всегда создаёт production transport. Автотесты не выполняют реальные
    Telegram DNS/HTTP-запросы.
29. Polling, webhook, `getUpdates`, команды, callback-кнопки и изменение status через Telegram
    отложены. Delivery остаётся at-least-once и не заявляется как exactly-once.

## Последовательность и границы

- **6A:** identities, API keys, CLI lifecycle, authentication dependency, RBAC, migration.
- **6B:** incident read/status API, history, audit и status idempotency.
- **6C:** конкурентный outbox worker, lease recovery, retries и операционные CLI-команды.
- **6D:** Telegram-specific destination config и исходящий adapter на fake Bot API в
  автоматических тестах.

Каждая часть проходит отдельное ревью. На границе 6D реализованы Incident/Audit API, history,
status idempotency, provider-neutral destination foundation, worker core и только исходящая
Telegram delivery. Входящие Telegram-взаимодействия остаются за пределами этапа.

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
12. Worker захватывает строки через `FOR UPDATE SKIP LOCKED`, назначает случайный claim token и
    выполняет HTTP только после commit claim-транзакции. Завершение условно по `id`, статусу
    `processing` и точному claim token. Зависшие claims восстанавливаются после lease timeout.
13. Ограниченные повторы используют exponential backoff с jitter; 429 учитывает `retry_after`.
    `last_error` очищается. Доставка at-least-once: crash после внешней отправки до DB commit
    может дать повторное Telegram-сообщение.

## 6D: только исходящий Telegram

14. `TelegramDestination` поддерживает `enabled`, `minimum_severity` и timestamps. Управление
    выполняется безопасным локальным CLI; удаление заменено отключением для сохранения истории.
15. Bot token читается только из отдельного token file. Redirects запрещены, TLS verification и
    ограниченные timeout обязательны. Production Telegram API base URL нельзя произвольно
    переопределять.
16. Уведомление — простой текст без `parse_mode`. Оно не содержит raw payload, attributes,
    correlation, actor или IP. Polling, webhook, команды, callback-кнопки и status transitions
    через Telegram отложены.

## Последовательность и границы

- **6A:** identities, API keys, CLI lifecycle, authentication dependency, RBAC, migration.
- **6B:** incident read/status API, history, audit и status idempotency.
- **6C:** конкурентный outbox worker, lease recovery, retries и операционные CLI-команды.
- **6D:** Telegram destinations и исходящий adapter на fake Bot API в автоматических тестах.

Каждая часть проходит отдельное ревью. На границе 6B реализованы Incident/Audit API, history,
audit persistence и status idempotency. Worker, destinations и Telegram HTTP-клиент относятся
к 6C–6D и отсутствуют.

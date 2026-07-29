# ADR-0009: Dashboard incident actions и append-only comments

- Статус: принято и реализовано в 7C
- Дата: 2026-07-29

## Контекст

Этап 7B показывает безопасные read-only incident projections. Этап 7C добавляет только две
изменяющие операции Dashboard: существующие status transitions и новые комментарии. HTML
transport не должен создавать вторую state machine, ослаблять web-session boundary или
передавать пользовательский текст в audit, outbox, Telegram и логи.

## Решения

1. `analyst` и `admin` имеют `incidents:transition` и `incidents:comment`; `viewer` не получает
   Dashboard access. Все mutation routes — `POST`; соответствующие `GET` возвращают HTML 405.
2. Unsafe route сначала выполняет no-touch session authentication и preliminary RBAC, затем
   exact Origin, bounded URL-encoded form и session-bound CSRF. Лишь после этих проверок
   открывается mutation transaction. В ней `SELECT ... FOR UPDATE` блокирует session и текущего
   Operator, повторно проверяет token/digest binding, expiry, revoke, active state, актуальную
   роль и permission. Поэтому устаревший detached principal не авторизует операцию.
3. Status form передаёт server-generated canonical UUID idempotency key, current
   `expected_version`, target status и reason. Она вызывает существующий
   `transition_incident()`: replay проверяется раньше stale version, а разрешённые переходы и
   terminal statuses остаются едиными для REST и HTML. Application outcome 200 преобразуется
   transport boundary в `303 See Other`.
4. `incident_comments` хранит UUID, incident/operator references, username snapshot,
   auth-method provenance, request ID, нормализованный body и UTC timestamp. Строки защищены
   от `UPDATE`, `DELETE` и `TRUNCATE` существующей PostgreSQL append-only функцией. FK используют
   `RESTRICT`; индекс `(incident_id, created_at, id)` поддерживает keyset pagination.
5. Комментарий принимает максимум 1000 Unicode code points после browser line-ending
   normalization, NFC и удаления внешнего whitespace. Пустые значения, NUL, control (кроме
   нормализованного LF), format, surrogate и line/paragraph separators отклоняются. Jinja
   autoescape обязателен; `|safe`, Markup, inline script/style и JavaScript не используются.
6. Comment idempotency имеет operator scope и operation `incident.comment.create.v1`.
   Canonical hash включает operation, incident UUID и полный нормализованный body. Успех и
   replay сохраняют business status 200; отсутствующий incident — 404; reuse ключа с другим
   hash — 409. HTML выдаёт 303 только после успешного commit. Один ключ не создаёт повторный
   comment или audit row при двойном клике и concurrent delivery.
7. `incident.comment_added` — закрытое audit action: actor operator, target comment, details
   содержат только canonical `incident_id`. Body, reason, CSRF, idempotency key, form body,
   cookie и credentials не записываются. Комментарий существует только в
   `incident_comments.body` и не создаёт outbox/Telegram notification.
8. Comment insert, strict audit entry и idempotency outcome атомарны. Status mutation,
   history, audit и idempotency сохраняют прежнюю атомарность. Ошибка validation до
   transaction не меняет session; audit/DB/commit failure откатывает все прикладные строки и
   не возвращает success redirect.
9. Incident detail читает detail, evidence, history и comments четырьмя bounded application
   statements, не считая session authentication/touch. History упорядочена `(version)`;
   comments — `(created_at, id)` по убыванию. Оба cursor используют закрытую неподписанную
   схему этапа 7B и page sizes `25|50|100`.
10. После commit применяется PRG `POST → 303 → GET`. Ошибки 401/403/404/409/422/503 и 500
    остаются безопасными HTML responses с request ID и security headers и не отражают body,
    comment, token или внутреннее исключение.

## Migration 0009

Upgrade создаёт `incident_comments`, FK/constraints/index и два append-only trigger. Downgrade
разрешён только при отсутствии comments, `incident.comment_added` audit rows и
`incident.comment.create.v1` idempotency outcomes; иначе он fail-closed, чтобы не потерять
provenance или durable replay semantics.

## Границы и ограничения

Комментарии не имеют REST endpoint и не отправляются в outbox. Уведомления о status changes,
редактирование/удаление комментариев, Telegram callbacks, HTMX, JavaScript и browser automation
не входят в 7C. Playwright и фактическая mobile viewport проверка остаются в 7D.

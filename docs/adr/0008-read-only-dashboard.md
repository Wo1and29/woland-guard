# ADR-0008: Read-only Dashboard и безопасные query projections

- Статус: принято и реализовано в 7B
- Дата: 2026-07-28

## Контекст

Этап 7A создал изолированную session boundary `/dashboard`, но не предоставлял страницы
данных. Этап 7B добавляет только чтение overview, серверов, инцидентов, evidence, истории,
активных правил и audit log. Изменение статусов и комментарии остаются в 7C.

## Решения

1. HTML handlers используют transport-neutral application query services и не выполняют
   произвольные ORM-запросы. Projection DTO содержат только поля, нужные конкретной странице.
   Evidence DTO и SQL `SELECT` ограничены `event_id`, `event_type`, `source`, `occurred_at`,
   `collected_at`, `linked_at`; `payload`, attributes, actor, IP и correlation не выбираются.
2. Поиск — только NFC-normalized literal prefix либо отдельный exact canonical UUID filter.
   Символ `!` является единым `LIKE ... ESCAPE` marker; пользовательские `!`, `%` и `_`
   экранируются и передаются bound parameters. Control, format и surrogate code points
   запрещены. Substring search и PostgreSQL extensions не используются.
3. Списки используют keyset pagination с полным уникальным ordering tuple:
   servers `(lower(name), id)`, incidents `(created_at, id)`, rules `(rule_key, id)`, audit
   `(created_at, id)`, evidence `(linked_at, event_id)`. Направление применяется ко всему
   tuple. Page size ограничен allowlist `25|50|100`.
4. Cursor — полностью недоверенный, неподписанный ввод и не является authorization boundary.
   Canonical base64url и canonical JSON, duplicate keys, закрытая schema, версия, list type,
   нормализованные filters/search, sort, page size и точные типы ordering keys проверяются.
   Формально корректная произвольная позиция допустима. Pagination не обещает snapshot
   isolation: вставка перед уже пройденной boundary может не появиться в текущем обходе, но
   строки после boundary не повторяются благодаря UUID tie-breaker.
5. `Server.is_active` показывается как сохранённое состояние конфигурации, не online/offline и
   не healthcheck. Последнее событие — отдельный `MAX(events.occurred_at)`. Overview считает
   active incidents как `new + investigating`; critical active — их подмножество severity
   `critical`. Outbox counts отражают только lifecycle rows; oldest pending age не является
   SLA или измерением доступности Telegram.
6. До применения rule filters, search, cursor и page boundary отдельный bounded query проверяет
   каждую active JSONB definition через `RuleDefinition`. Hard limit — 1000 active definitions;
   превышение также закрывает rules page безопасным HTML 503. Повреждение не может исчезнуть из
   выдачи и создаёт одну статическую log-запись с request ID и UUID rule version. Paginated query
   повторно валидирует возвращаемую страницу. Audit metadata остаётся видимой, но недоверенный
   JSON details сначала проверяется как mapping со строковыми ключами, затем через action
   registry; при любой ошибке details целиком заменяются на «Детали недоступны» без raw JSON и
   текста исключения.
7. Dashboard-local handlers возвращают HTML для validation errors, 404, 405, application,
   database и unexpected errors. Внешний security wrapper этапа 7A добавляет request ID и
   headers ко всем ответам, включая static CSS. REST `/api/v1` сохраняет JSON boundary.
8. StaticFiles смонтирован только на allowlisted package directory внутри Dashboard wrapper.
   CSS доступен без session, не содержит external imports/source maps, получает CSP/security
   headers; path traversal остаётся запрещённым. Jinja autoescape включён, `|safe`, inline
   script/style, CDN, JavaScript и HTMX отсутствуют.
9. Query budgets измеряются непосредственно на application services, отдельно от session
   authentication и bounded conditional touch. Server page сначала ограничивает набор серверов,
   затем выполняет коррелированные агрегаты в одном SQL statement: таблицы событий и инцидентов
   не агрегируются глобально до page boundary. Фактические budgets: overview — 7; server list —
   1; `get_server_detail` — 1; HTTP server detail вместе с recent incidents — 2 application
   statements; incident list — 1; incident detail + evidence + history + comments — 4; rules — 2
   (all-active validation + page); audit — 1.
10. Representative PostgreSQL fixtures содержат 1000 серверов, 3500 событий, 2000 инцидентов
    и 2500 evidence links. На PostgreSQL 17 с database collation `en_US.utf8` исходный
    `EXPLAIN (FORMAT JSON, ANALYZE false)` показал `Seq Scan + Sort` для server ordering и
    `Seq Scan + Hash Join + Sort` для evidence. Migration 0008 поэтому добавляет
    `ix_servers_lower_name_id` и `ix_incident_events_incident_linked_event`; после миграции
    планы используют эти индексы. Отдельный prefix plan при `en_US.utf8` подтвердил, что
    обычный B-tree не устраняет scan для `lower(name|hostname) LIKE`; поэтому 0008 также
    добавляет два expression index `text_pattern_ops`: `ix_servers_lower_name_pattern` и
    `ix_servers_lower_hostname_pattern`. Speculative индексы для малых rules и каждого
    сочетания incident/audit filters не добавляются.

## RBAC

`analyst` и `admin` читают overview, servers, incidents, evidence/history и active rules через
существующие permissions. Только `admin` читает audit. `viewer` не получает новую Dashboard
access permission в 7B. Cursor и object identifiers не меняют RBAC.

## Границы и ограничения

Status forms, comments и CSRF mutations реализуются в 7C без HTMX. Playwright, HTTPS browser
harness и фактическая mobile-viewport проверка относятся к 7D. В 7B responsive CSS проверяется
статически и через template integration tests; ручной просмотр возможен только в отдельно
подготовленном HTTPS-окружении. Planner может менять физический plan при других объёмах,
статистике и collation; новые индексы добавляются только после повторного измерения.

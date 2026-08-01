# ADR-0011: воспроизводимые синтетические demo-сценарии

- Статус: принято и реализовано в 8A
- Дата: 2026-07-29

## Контекст

Тесты Detection Engine содержат синтетические примеры, а browser fixtures создают часть
проекций напрямую в PostgreSQL. Это не является пользовательской демонстрацией пути через
публичный `POST /api/v1/events`. Этап 8A вводит только generator, canonical manifest,
loopback-only sender и PostgreSQL verification tests. Compose orchestration, fake Telegram
delivery и пользовательская full-stack verification относятся к 8B.

## Фактический каталог правил

Общие обязательные поля каждого события задаются `NormalizedEventV1`: `schema_version=1`,
canonical event UUID, UTC `occurred_at`/`collected_at`, `source=journald`, нормализованный
`event_type` и bounded JSON attributes. В таблице перечислены дополнительные поля, нужные
конкретному правилу.

| rule_key | version | condition | correlation | threshold/window | необходимые поля | пересечения | severity/title | MITRE |
|---|---:|---|---|---|---|---|---|---|
| `privileged_group_membership_changed` | 1 | single | actor, group, action | — | actor; attributes.group=`sudo\|adm\|wheel`; attributes.action=`added\|removed` | нет | high / «Изменено членство в привилегированной группе» | T1098.007 |
| `ssh_bruteforce_by_ip` | 1 | threshold | source_ip | 8 / 300 s | source_ip; `linux.ssh.authentication_failed` | тот же failed-event участвует в password spray и истории sequence | high / «Перебор SSH-паролей с одного IP» | T1110 |
| `ssh_login_from_new_ip` | 1 | first_seen | actor, source_ip | lookback 2592000 s; baseline ≥1 | actor, source_ip; `linux.ssh.login_succeeded` | success-event может быть root login или финалом sequence | medium / «SSH-вход пользователя с нового IP» | T1078, T1021.004 |
| `ssh_password_spray_by_ip` | 1 | distinct_count | source_ip | 5 distinct actors, ≥5 events / 600 s | actor, source_ip; `linux.ssh.authentication_failed` | тот же failed-event участвует в brute force и истории sequence | high / «Password spraying по SSH» | T1110.003 |
| `ssh_root_login_success` | 1 | single | actor, source_ip | — | actor=`root`, source_ip; `linux.ssh.login_succeeded` | success-event может участвовать в first-seen/sequence | high / «Успешный SSH-вход root» | T1078.001, T1021.004 |
| `ssh_success_after_failures` | 1 | sequence | source_ip, actor | 3 failed + 1 success / 900 s | одинаковые actor/source_ip; strict failed-before-success ordering | failed/success events общие с brute, spray, first-seen и root contracts | critical / «Успешный SSH-вход после неудачных попыток» | T1110, T1078 |
| `sudo_auth_failures` | 1 | threshold | actor | 5 / 600 s | actor; `linux.sudo.authentication_failed` | нет | medium / «Повторные ошибки аутентификации sudo» | T1548.003 |
| `user_account_created` | 1 | single | actor | — | actor; `linux.account.user_created` | нет | high / «Создана локальная учётная запись» | T1136.001 |

8A отказывается работать, если каталог содержит не ровно эти восемь enabled version-one
definitions. YAML и существующий `RuleDefinition` остаются единственным источником истины;
demo implementation не синхронизирует и не изменяет правила.

## Manifest contract

Один manifest описывает один сценарий и имеет закрытую schema version 1:

- `schema_version`;
- canonical lowercase `run_id`;
- timezone-aware UTC `anchor_utc`;
- stable `scenario_id`;
- target `rule_key`;
- `case_type`: `positive`, `negative`, `boundary_below` или `boundary_exact`;
- хронологически ordered `NormalizedEventV1`;
- `expected_outcomes` с полным sorted incident set, metadata/evidence counts, new incident count,
  outbox delta и явным cross-rule allowlist.

`scenario_id` имеет точный формат `<rule_key>.<case_type>.v1`: все три компонента сверяются с
полями manifest, дополнительные компоненты и иные версии запрещены. Структурно корректный ID
также обязан входить в набор 32 IDs, построенный единым shipped catalog builder.

Manifest является catalog-bound, а не пользовательским DSL. После структурной проверки sender
повторно строит scenario тем же production builder с сохранёнными `run_id` и `anchor_utc` и
требует равенства canonical bytes. Это связывает с каталогом events, их порядок и timestamps,
normalized fields, expected incidents, severity/title, evidence/outbox counts и cross-rule
allowlist. Произвольные synthetic events через demo CLI и programmatic client не отправляются.
Expected outcomes считаются проверенными только после такого rebuild-and-compare; они не являются
доверяемыми утверждениями автора входного JSON. Будущий verifier 8B может использовать их только
после успешной catalog validation.

`expected_outcomes` использует ровно одну enabled destination с `minimum_severity=low` как
verification assumption. Production sender эти outcomes не объявляет подтверждёнными: ответ
ingestion содержит только accepted/existing counts. PostgreSQL assertions остаются в test code.

Manifest JSON является canonical UTF-8 без BOM, whitespace formatting и trailing newline:
`sort_keys=true`, compact separators, `ensure_ascii=false`, `allow_nan=false`. Reader запрещает
duplicate keys и требует byte-for-byte совпадения повторной canonical serialization. Максимум:
1 MiB на manifest, 1000 events и 32 KiB на canonical event. Event requests дополнительно
ограничены production batch size 100 и body size 1 MiB.

Недоверенные JSON values не могут содержать control/format/surrogate characters, credential
field names, agent/operator/Telegram token patterns, Bearer material, private-key blocks,
absolute paths, traversal или URLs.

## Детерминированная идентичность

Namespace проекта:

```text
9f0d4b1b-f49c-5f47-a50a-8d8f65484748
```

Event ID:

```text
UUIDv5(namespace, "event:<run_id>:<scenario_id>:<zero-based ordinal>")
```

Batch ID:

```text
UUIDv5(namespace, "batch:<run_id>:<scenario_id>:<zero-based batch ordinal>")
```

`sent_at` равен сохранённому anchor. Повтор одного manifest формирует идентичные event и
request bodies. Обычный `generate` создаёт новый UUID4 run ID и свежий UTC anchor. Явные
`run_id`/anchor доступны только вместе со скрытым fixture mode и не являются обычным send
workflow. `send` до первого запроса отклоняет anchor вне заданного production clock-skew.

## Scenario isolation

Каждое правило имеет четыре стабильных сценария: typical positive, close negative,
boundary below и inclusive exact boundary. Sequence проверяет strict ordering и точную границу
900 s; first-seen — baseline requirement и точную границу 2592000 s. Single rules используют
точные/соседние filter или event-type значения.

Actors, RFC 5737 IP literals, source tags, event IDs и correlation values синтетические.
Сценарные time ranges разделены 31 днём, то есть больше максимального lookback, а integration
suite дополнительно создаёт отдельный server/API key для каждого параметризованного сценария.
Полный combined-server regression доказывает отсутствие скрытых cross-rule incidents.

## Sender и credentials

Sender принимает только canonical `http://localhost:<port>`,
`https://localhost:<port>`, `http://127.0.0.1:<port>` или
`https://127.0.0.1:<port>` и посылает только `POST /api/v1/events`. Credentials, path/query,
fragment, redirects, proxies environment и HTTP library retries запрещены. TLS verification
включена для HTTPS. Application retry повторяет неизменный body максимум три раза только при
transport uncertainty или HTTP 5xx. Любой 4xx не ретраится; 429 классифицируется как temporary
и bounded `Retry-After` разбирается только как безопасная metadata.

Agent token поступает как redacted in-memory wrapper либо из bounded regular non-link file.
POSIX требует current owner и отсутствие group/other permissions. Windows не заявляет POSIX ACL
guarantees. Plaintext CLI argument и token в manifest/environment output отсутствуют.
CLI `validate`, CLI `send` и programmatic `DemoIngestionClient.send` применяют одинаковую
catalog validation до HTTP request; `send` выполняет её до чтения API-key file.

## Replay guarantee и границы

Семантика: **at-least-once delivery with idempotent ingestion and persistence**. Повтор после
неопределённого transport result и повтор всего manifest не создают второй Event, evidence,
active Incident, baseline history или `incident.created` outbox row для того же server/event ID.
Distributed exactly-once не заявляется.

8A сам по себе не доказывает полный пользовательский E2E, не доставляет Telegram, не запускает
Compose, не создаёт server/destination и не сообщает «инцидент создан» по одному ingestion
response. Отдельный 8B verifier использует этот catalog как проверенный источник ожиданий.

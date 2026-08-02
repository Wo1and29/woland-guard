# Detection Engine и правила

Правила — версионированный, невыполняемый YAML в `detection-rules/`, по одному `rule_key` на
файл. Загрузка идёт через `yaml.safe_load` и закрытую Pydantic-схему с `extra="forbid"`
(`application/detection/rules.py`) — `eval`, `exec` и произвольные выражения структурно
невозможны.

## Схема правила

```yaml
schema_version: 1                # только 1
rule_key: my_rule_key            # ^[a-z][a-z0-9_]{0,99}$, один файл = один rule_key
version: 1                       # положительное int; opубликованная (rule_key, version) неизменяема
enabled: true
severity: low | medium | high | critical
title: "..."                     # 1..255 символов
description: "..."               # 1..2000
explanation: "..."               # 1..4000
recommendation: "..."            # 1..4000
mitre_attack_ids: [T1110, T1078.001]   # опционально, паттерн ^T[0-9]{4}(\.[0-9]{3})?$
condition: { ... }               # один из пяти закрытых типов, см. ниже
correlation_fields: [source_ip]  # непустой список без дублей
```

`correlation_fields` (плюс `group_by`/`scope_fields`, где применимо) определяют, какие поля
войдут в JSON, из которого считается `correlation_hash` — он вместе с `server_id` и
`rule_version_id` определяет, какой именно `Incident` получит новое evidence, а не создаст
новый.

## Поддерживаемые типы событий

Только пять `event_type`, которые реально производит агент:

- `linux.ssh.authentication_failed`
- `linux.ssh.login_succeeded`
- `linux.sudo.authentication_failed`
- `linux.account.user_created`
- `linux.account.privileged_group_changed`

## Пять типов условий

Временны́е окна всегда используют `occurred_at` события, включают обе границы
(`trigger - window <= occurred_at <= trigger`) и ограничены `server_id` — правило никогда не
смотрит на события другого сервера (ADR-0005 §3–4).

- **`single`** — одно событие с опциональными `filters` (`equals`/`one_of` по полю).
- **`threshold`** — `threshold` событий типа `event_type` за `window_seconds`, сгруппированных
  по `group_by`.
- **`distinct_count`** — не менее `distinct_threshold` различных значений `distinct_field` среди
  минимум `minimum_events` событий за `window_seconds`, сгруппированных по `group_by`.
- **`sequence`** — минимум два `steps`, каждый со своим `event_type` и `repeat_at_least`; шаги
  должны произойти строго по порядку внутри общего `window_seconds`.
- **`first_seen`** — значение `value_field` не встречалось для данного `scope_fields` за
  `lookback_seconds`, при этом должно быть минимум `require_prior_baseline_events` предыдущих
  событий (защита от срабатывания на самое первое событие без истории).

`filters` — только declarative `equals` (точное значение) или `one_of` (allowlist значений);
никаких regex или сравнений через код.

## Текущий набор правил (8)

| `rule_key` | Тип | Severity | MITRE ATT&CK |
|---|---|---|---|
| `ssh_bruteforce_by_ip` | threshold (8 за 300с, по `source_ip`) | high | T1110 |
| `ssh_password_spray_by_ip` | distinct_count (≥5 users за 600с, по `source_ip`) | high | T1110.003 |
| `ssh_success_after_failures` | sequence (≥3 fail → ≥1 success за 900с) | critical | T1110, T1078 |
| `ssh_login_from_new_ip` | first_seen (30 дней lookback) | medium | T1078, T1021.004 |
| `ssh_root_login_success` | single (`actor == root`) | high | T1078.001, T1021.004 |
| `sudo_auth_failures` | threshold (5 за 600с, по `actor`) | medium | T1548.003 |
| `user_account_created` | single | high | T1136.001 |
| `privileged_group_membership_changed` | single (`group` ∈ {sudo, adm, wheel}) | high | T1098.007 |

Nginx-источник и два зависящих от него правила (см. исходный концепт: 401/403/404/500-всплески,
объём запросов с одного IP) перенесены на следующий релиз — агент их пока не производит, поэтому
десять правил не заявляются как end-to-end MVP-функциональность (README, «Ограничения MVP»).

## Тестовые события

Для каждого правила есть синтетические сценарии `positive` / `negative` / `boundary_below` /
`boundary_exact`, генерируемые `woland-guard-demo` (см. [docs/demo.md](demo.md)) и
интеграционные тесты в `tests/integration/test_detection_engine.py`, проверяющие фактическое
создание/недосоздание инцидента через реальный PostgreSQL.

## Валидация и активация

```bash
docker compose exec control-plane woland-guard-admin validate-rules --rules-dir /workspace/detection-rules
docker compose exec control-plane woland-guard-admin sync-rules --rules-dir /workspace/detection-rules
```

`validate-rules` не обращается к БД. `sync-rules` сначала валидирует весь каталог, считает
SHA-256 канонического JSON каждого правила, затем одной транзакцией добавляет новые версии и
атомарно переключает активную версию каждого `rule_key`. Обычный запуск control plane **не**
синхронизирует правила — это всегда явное действие оператора (ADR-0005 §6).

## Как добавить новое правило

1. Создайте `detection-rules/<rule_key>.yaml` по схеме выше — один `rule_key` на файл, каталог
   не допускает дублирования `rule_key` даже с разными `version`.
2. `validate-rules`, затем `sync-rules` на тестовом окружении.
3. Добавьте тестовые события и интеграционный тест по образцу существующих в
   `tests/integration/test_detection_engine.py`.
4. Если правило меняет уже опубликованную `(rule_key, version)` — это запрещено на уровне БД;
   поднимите `version` вместо редактирования.

`mitre_attack_ids` — контекст для оператора, а не доказательство атаки (это явно
сформулировано в описании правила `sudo_auth_failures`); не переоценивайте confidence
срабатывания только по наличию MITRE-техники.

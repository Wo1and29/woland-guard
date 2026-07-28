# ADR-0007: Dashboard authentication и server-side sessions

- Статус: принято к реализации в 7A
- Дата: 2026-07-28

## Контекст

REST API этапа 6 использует operator API keys, но браузерный Dashboard не должен хранить
Bearer credential и не должен связывать RBAC с одним способом аутентификации. Этап 7A
создаёт только безопасную web-auth границу. Страницы данных и incident actions остаются за
пределами подэтапа.

## Решения

1. `OperatorPrincipal` содержит `operator_id`, snapshot username/role и закрытый
   `OperatorAuthMethodType`: `operator_api_key` либо `web_session`. Bearer dependency
   возвращает API-key-specific wrapper с principal; Dashboard возвращает тот же principal
   из server-side session. RBAC и application services не зависят от FastAPI.
2. `operator_web_sessions` хранит только SHA-256 digests двух независимых случайных
   256-bit tokens: session и CSRF. Plaintext существует лишь в памяти до `Set-Cookie`.
   Lookup выполняется по session digest, затем проверяются revoke, idle/absolute expiry и
   активность оператора. Absolute expiry не может быть позже expiry ключа входа.
3. Session touch — один conditional `UPDATE`: не чаще configured interval, не сокращает
   существующий idle expiry при конкурентных запросах и ограничивается absolute expiry.
   Rotation/revoke API key в той же транзакции отзывает только sessions этого ключа.
   Unsafe routes используют отдельную read-only/no-touch аутентификацию: Origin и CSRF
   проверяются до любой lifecycle-мутации session.
4. Login принимает `wgok_` credential, но после успеха полностью заменяет pre-auth CSRF
   cookie session-bound token. `__Host-wg_session` и `__Host-wg_csrf` всегда `Secure`,
   `HttpOnly`, `SameSite=Strict`, `Path=/`, без Domain. Development не ослабляет Secure.
   Login выполняет `SELECT ... FOR UPDATE` использованного API key; повторная проверка
   ключа, session insert, `last_used_at`, audit и commit входят в одну транзакцию. Поэтому
   конкурентные rotation/revoke сериализуются с выдачей browser session.
5. Pre-auth и session mutations требуют точного configured Origin и constant-time проверки
   cookie/form CSRF. REST `/api/v1` игнорирует Dashboard cookies, а Dashboard не принимает
   Bearer вместо session cookie. Production `WG_WEB_PUBLIC_ORIGIN` обязан быть HTTPS;
   HSTS включается только из этой validated настройки, не из Host/forwarded headers.
6. Unsafe HTML requests проходят чистый ASGI body limiter до form parser. Разрешён только
   `application/x-www-form-urlencoded` без параметров либо с одним `charset=utf-8`
   case-insensitive. Content-Encoding, multipart, неизвестные/повторные параметры и
   неправильный charset отклоняются. Content-Length и реально прочитанные chunks имеют
   общий hard limit; body никогда не попадает в ошибки и логи.
7. Login limiter process-local и bounded: global bucket, HMAC bucket parsed public_id и
   общий malformed bucket. Старые buckets очищаются, число subject buckets ограничено.
   Ответы не раскрывают существование public_id/operator; key, IP, body и User-Agent не
   сохраняются. Perimeter limiter остаётся production-требованием.
8. `operator_web_session.started` записывает operator actor с auth method API key и target
   созданной session. `ended` использует web-session method. Login/logout audit не имеют
   произвольных details и history id. Dashboard incident transition в 7C будет использовать
   web-session principal и существующий application service.
9. Migration 0007 добавляет sessions и PostgreSQL constraints: operator history/audit
   допускают только два auth method enum values. Downgrade запрещён при sessions либо
   web-session history/audit, чтобы не потерять identity provenance.
10. Dashboard — sub-application, смонтированный на `/dashboard`; его внутренние routes:
    `/login`, `/logout`, `/`. Повторного `/dashboard` prefix внутри нет.
11. Все HTML responses получают `no-store`, `nosniff`, `no-referrer` и CSP без inline
    script/style и без внешних ресурсов. Logout очищает cookies только после успешного
    revoke+audit commit; при Origin/CSRF/DB ошибке cookies сохраняются.
12. Единственный unexpected-error handler Dashboard формирует безопасный HTML 500 с
    request ID и одной статической log-записью без exception object. Security-header wrapper
    находится снаружи FastAPI error boundary, поглощает повторно поднятое уже обработанное
    исключение и не отправляет второй `response.start`. Если body был начат, wrapper только
    безопасно завершает его без exception text и traceback в ASGI-server logs.

## Границы 7A

Включены documentation sync, principal/auth enum, migration/session lifecycle,
login/session/logout, Origin/CSRF, body limiter, login limiter и минимальные шаблоны.
Overview, server/incident/rule/audit pages, HTMX, comments, HTML status transitions и
browser automation относятся к 7B–7D.

## Ограничения

Process-local limiter не координируется между процессами. TLS termination и perimeter rate
limiting должны быть настроены оператором deployment. Операция деактивации Operator в
application/CLI сейчас отсутствует; runtime session authentication всё равно немедленно
отклоняет session неактивного оператора.

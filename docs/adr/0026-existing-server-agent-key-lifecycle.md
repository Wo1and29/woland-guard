# ADR-0026: Lifecycle агентских ключей существующего server

- Статус: принято
- Дата: 2026-09-20

## Контекст

Первичное provisioning создаёт server и один ключ вместе. Для штатной смены credentials уже
существующего server этого недостаточно: создание второго server меняет identity и разрывает
историю, а прямое изменение `agent_api_keys` через SQL не является безопасным product flow.

## Решения

1. Lifecycle остаётся локальной административной операцией. Network admin API не добавляется.
2. `issue-agent-key --server <UUID-or-exact-name>` создаёт независимый ключ для существующего
   активного server. Server row, события и инциденты не изменяются.
3. Plaintext token возвращается CLI ровно при issue и не сохраняется. PostgreSQL продолжает
   хранить только уникальный public ID и SHA-256 digest высокоэнтропийного secret.
4. Issue не отзывает старые ключи. Оператор сначала устанавливает и проверяет новый token, затем
   явно выполняет `revoke-agent-key <public-id>` для старого.
5. Revoke блокирует выбранную key row, ставит `revoked_at` и сразу использует существующую
   authentication-проверку, которая одинаково отклоняет revoked и неверные credentials.
6. Повторный revoke является успешным no-op: исходный timestamp сохраняется, новое audit-событие
   не создаётся.
7. Успешные issue и первый revoke атомарно записывают allowlisted audit actions
   `agent_api_key.issued` и `agent_api_key.revoked`. Audit содержит только key UUID как target и
   server UUID в details — без token, secret или digest.

## Последствия и ограничения

- Переключение token file и restart агента выполняет оператор; удалённого secret-distribution или
  hot reload нет.
- Одновременно могут быть активны несколько ключей одного server. Это намеренно обеспечивает
  overlap при безопасной смене, но оператор отвечает за отзыв старого ключа после проверки.
- Управление по CLI требует точного server name/UUID и точного открытого key ID; fuzzy lookup не
  используется.

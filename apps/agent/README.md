# Woland Guard Linux Agent

Агент собирает только события `journald`, нормализует их в `NormalizedEventV1`, атомарно
сохраняет событие вместе с cursor в SQLite и доставляет накопленные пакеты в control plane.

Единственная подтверждённая платформа MVP — Ubuntu Server 24.04 LTS с systemd. Запуск на
другой ОС блокируется до открытия journald и spool. Автоматическая интеграционная проверка
реального systemd/journald в текущей среде разработки не выполняется.

## Гарантия cursor и spool

Одна транзакция `BEGIN IMMEDIATE` выполняет операции в строгом порядке:

1. вставляет нормализованное событие с уникальным `event_id`;
2. только после успешной вставки обновляет cursor источника;
3. фиксирует обе операции одним `COMMIT`.

При duplicate уже сохранённого `event_id` cursor атомарно продвигается до повторно
прочитанной записи: это исключает бесконечный replay после перезапуска. При ошибке вставки
или заполненной очереди cursor не продвигается. Намеренно пропущенное неизвестное сообщение
продвигает cursor отдельной транзакцией. SQLite работает в WAL с `synchronous=FULL`.

Continuous mode сначала конечным процессом `journalctl` выгружает весь backlog после
committed cursor, затем перечитывает cursor из SQLite и запускает follow с
`--after-cursor` и `--lines=all`. Это включает записи, возникшие между двумя фазами. Если
cursor исчез после ротации, агент сохраняет постоянный diagnostic `journal_gap`, явно
сбрасывает недоступную точку и выполняет rebase. Уже удалённые journal-записи восстановить
невозможно.

Очередь ограничена `spool.max_events`. Политика переполнения сохраняет старые данные:
новое событие отклоняется, чтение приостанавливается, cursor остаётся прежним, а доставщик
пытается освободить очередь. Quarantined/oversized события не удаляются автоматически и
тоже занимают место — оператор должен исследовать причину до ручного обслуживания БД.

## Защита данных

- `journalctl --output-fields` запрашивает только `MESSAGE`, `PRIORITY`,
  `SYSLOG_IDENTIFIER`, `_SYSTEMD_UNIT`, `_TRANSPORT`, `_UID`, `_GID`, `_COMM`, `MESSAGE_ID`
  и `UNIT`;
- `MESSAGE` никогда не копируется в `summary` или `attributes`: он локально сопоставляется
  только с явными шаблонами SSH, sudo, useradd, usermod, gpasswd и crontab;
- `MESSAGE_ID`/`UNIT` (события systemd о жизненном цикле юнита) сопоставляются только с
  фиксированным каталожным идентификатором «unit stop job finished» и только для пяти
  захардкоженных критичных юнитов — остальные не порождают событие;
- распознанное событие получает фиксированный summary и только контролируемые атрибуты
  метода аутентификации, invalid-user, UID/GID либо привилегированной группы и действия;
- неизвестный или содержащий U+0000 `MESSAGE` пропускается без отправки;
- environment, command line, произвольные поля и полный journald payload не передаются;
- исходная строка не редактируется и не пересылается: несовпавшие сообщения отклоняются;
- API-токен читается только из отдельного обычного файла, не являющегося symlink;
- на Linux token file должен принадлежать пользователю агента и иметь права не шире `0600`;
- токен и payload не включаются в `repr`, контролируемые логи и сообщения исключений.
- на POSIX spool отклоняет symlink, не-regular file и чужого владельца; каталог имеет
  `0700`, а SQLite DB/WAL/SHM — `0600`.

## Конфигурация и запуск

Пример находится в `deploy/config/agent.example.yaml`. Скопируйте его в
`/etc/woland-guard/agent.yaml`, а однократно выданный токен — в
`/etc/woland-guard/agent.token`:

```bash
sudo install -o woland-guard -g woland-guard -m 0600 agent.token \
  /etc/woland-guard/agent.token
sudo -u woland-guard /opt/woland-guard-agent/.venv/bin/woland-guard-agent \
  check-config --config /etc/woland-guard/agent.yaml
```

Однократная диагностика читает ограниченный снимок, делает одну попытку доставки и выводит
только счётчики:

```bash
sudo -u woland-guard /opt/woland-guard-agent/.venv/bin/woland-guard-agent \
  run-once --config /etc/woland-guard/agent.yaml --source-limit 100
```

Локальное обслуживание очереди не читает token file и не выводит полный payload:

```bash
woland-guard-agent spool-status --config /etc/woland-guard/agent.yaml
woland-guard-agent spool-list --config /etc/woland-guard/agent.yaml \
  --status quarantined
woland-guard-agent spool-requeue --config /etc/woland-guard/agent.yaml EVENT_UUID
woland-guard-agent spool-delete --config /etc/woland-guard/agent.yaml EVENT_UUID \
  --confirm EVENT_UUID
```

`spool-delete` выполняется только при точном совпадении позиционного UUID и `--confirm`.

Для службы создайте системного пользователя без shell и предоставьте стандартный
read-only доступ к journal:

```bash
sudo useradd --system --home-dir /var/lib/woland-guard --create-home \
  --shell /usr/sbin/nologin woland-guard
sudo usermod -a -G systemd-journal woland-guard
```

После установки unit из `deploy/systemd/woland-guard-agent.service` его включение остаётся
явным действием оператора. Проект сам не изменяет пользователей, группы или systemd хоста.

## Доставка и ошибки

- `200`: проверяется, что `accepted + existing` равно размеру пакета; только затем строки
  удаляются из spool;
- `401/403`: фиксированная длинная задержка без агрессивного retry;
- `413`: следующий пакет уменьшается вдвое; одиночное событие остаётся как `oversized`;
- `422`: пакет делится до одного события; одиночное событие остаётся `quarantined`;
- `429`: используется `Retry-After`, при его отсутствии — backoff;
- `5xx`, network и protocol errors: exponential backoff с equal jitter.

Batch содержит от 1 до 100 событий. Каждый запрос получает новый `X-Request-ID`. Production
конфигурация принимает только HTTPS URL и отдельные connect/read timeout.

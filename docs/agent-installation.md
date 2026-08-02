# Установка Linux Agent

Единственная подтверждённая MVP-платформа — **Ubuntu Server 24.04 LTS** с systemd. Агент читает
`journald` через фиксированный `journalctl` (без shell, без пользовательской команды),
локально распознаёт только пять классов событий и не пересылает `MESSAGE`, environment или
произвольные journald-поля — подробности в [apps/agent/README.md](../apps/agent/README.md),
раздел «Защита данных».

## 1. Получите агентский ключ на control plane

На control plane (не на контролируемом сервере):

```bash
docker compose exec control-plane woland-guard-admin create-test-agent \
  --name prod-web-01 \
  --hostname prod-web-01.internal \
  --label vps
```

CLI выведет `wgak_<public_id>.<secret>` **один раз**. Сохраните его вне репозитория, вне логов,
вне буфера обмена, синхронизируемого куда-либо. PostgreSQL хранит только digest — восстановить
значение из БД невозможно, при потере нужно выпускать новый ключ.

## 2. Подготовьте пользователя и права на сервере

```bash
sudo useradd --system --home-dir /var/lib/woland-guard --create-home \
  --shell /usr/sbin/nologin woland-guard
sudo usermod -a -G systemd-journal woland-guard
```

`systemd-journal` — стандартная read-only группа: доступ ограничен чтением журнала, не записью и
не правами root. Это единственное расширение прав, которое требуется агенту (см.
[docs/threat-model.md](threat-model.md), «Повышение привилегий агента» — минимизация данных
дальше обеспечивается парсерами агента, а не правами доступа к журналу).

Не запускайте агент от root и не добавляйте `woland-guard` в `sudo`/`wheel`/`adm` — это не
требуется ни для чтения `journald`, ни для работы агента.

## 3. Установите агента

```bash
sudo mkdir -p /opt/woland-guard-agent
sudo git clone --depth 1 <repository-url> /opt/woland-guard-agent
cd /opt/woland-guard-agent
sudo uv sync --locked --package woland-guard-agent
```

Это создаст `/opt/woland-guard-agent/.venv` с единственной точкой входа
`woland-guard-agent` (`apps/agent/pyproject.toml`).

## 4. Настройте конфигурацию и токен

```bash
sudo mkdir -p /etc/woland-guard
sudo cp deploy/config/agent.example.yaml /etc/woland-guard/agent.yaml
sudo $EDITOR /etc/woland-guard/agent.yaml   # http.base_url -> ваш control plane (только HTTPS)
```

Впишите `secret`-часть выданного ключа в отдельный файл, не в YAML-конфиг:

```bash
echo -n 'wgak_<public_id>.<secret>' | sudo tee /etc/woland-guard/agent.token >/dev/null
sudo chown woland-guard:woland-guard /etc/woland-guard/agent.token
sudo chmod 0600 /etc/woland-guard/agent.token
```

Token file обязан быть обычным файлом (не symlink), принадлежать пользователю агента и иметь
права не шире `0600` — агент проверяет это при старте и откажется работать при нарушении.

Проверьте конфигурацию до включения службы:

```bash
sudo -u woland-guard /opt/woland-guard-agent/.venv/bin/woland-guard-agent \
  check-config --config /etc/woland-guard/agent.yaml
```

## 5. Установите systemd unit

```bash
sudo cp deploy/systemd/woland-guard-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now woland-guard-agent
sudo systemctl status woland-guard-agent
```

Юнит `deploy/systemd/woland-guard-agent.service` уже задаёт полный systemd-sandboxing:
`NoNewPrivileges`, пустой `CapabilityBoundingSet`/`AmbientCapabilities`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateDevices`, `RestrictNamespaces`, `MemoryDenyWriteExecute` и так далее —
единственный доступный на запись путь — `/var/lib/woland-guard` (`ReadWritePaths`). Проект не
изменяет systemd хоста автоматически: включение юнита остаётся явным действием оператора.

## 6. Диагностика до первого полного запуска

Одноразовая проверка, отправляющая ограниченный снимок и одну попытку доставки:

```bash
sudo -u woland-guard /opt/woland-guard-agent/.venv/bin/woland-guard-agent \
  run-once --config /etc/woland-guard/agent.yaml --source-limit 100
```

Локальное обслуживание очереди без чтения токена и без вывода payload:

```bash
woland-guard-agent spool-status --config /etc/woland-guard/agent.yaml
woland-guard-agent spool-list --config /etc/woland-guard/agent.yaml --status quarantined
woland-guard-agent spool-requeue --config /etc/woland-guard/agent.yaml EVENT_UUID
woland-guard-agent spool-delete --config /etc/woland-guard/agent.yaml EVENT_UUID --confirm EVENT_UUID
```

## Известные ограничения этой установки

- Реальный `journald`/systemd интеграционный тест не выполняется в среде разработки проекта —
  только синтетические fixtures и fixed-command adapter (ADR-0004). Тестируйте на реальном
  Ubuntu Server 24.04 перед продакшн-раскаткой на важном хосте.
- При устаревшем/отсутствующем cursor и уже ротированном journal разрыв — необратим; агент
  фиксирует постоянный diagnostic `journal_gap`, но не может восстановить удалённые записи
  (`spool-status` покажет это состояние).
- Nginx-логи агент пока не читает — источник и два зависящих правила перенесены на следующий
  релиз.

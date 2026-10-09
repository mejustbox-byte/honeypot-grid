# Реализованные компоненты и лабораторный запуск

## Текущие возможности

CLI установлен как `honeypot-grid`. По умолчанию runtime — mock. Менеджер проверяет scope, digest, одноразовое подтверждение владельца и TTL. Приватная SQLite-база хранит переходы и аудит; откат часов запрещает новые действия, но не аварийную очистку. Размер базы ограничен примерно 64 MiB, число планов — 10000. Аудит локальный, не tamper-proof; оператор и владелец доверены ОС.

`telemetry-ingest` принимает JSON `{"events": [...]}`. Каждое событие содержит только schema_version=1, event_id, sensor_id, source_ip, timestamp, service и category. Batch <=100, общая квота 10000; service http-mock/ssh-mock, category connection/probe. Исходные идентификаторы и IP заменяются HMAC с отдельным epoch; секретный ключ — ровно 32 байта, файл 0600. Retention по умолчанию 24 часа, очистка явная через telemetry-purge. Отчёт исключает истёкшие события, подавляет группы <5 и укрупняет время до дня. Это минимизация, а не гарантия анонимности.

`quarantine` копирует непрозрачные байты без парсинга, <=1 MiB, <=100 файлов, под SHA256 в каталог 0700. `quarantine-purge` удаляет просроченные завершённые образцы (по умолчанию 24 часа). После аварии незавершённые pending-файлы проверяет и удаляет доверенный оператор при остановленном приёме. Файлы никогда не исполняются. `sandbox-plan` возвращает executor_available=false: реальный VM executor отсутствует. Worker static_metadata проверен только на безвредных fixtures, не запускайте его на недоверенных образцах на хосте.

`analyze` выполняет ограниченные offline правила над очищенным отчётом. Опциональный `--proposal` проверяет структурированный вывод внешней модели: hash доказательств, индексы групп, допустимые сигналы, отсутствие команд и утверждения о доказанной вредоносности. Подключения к LLM нет. `review-plan`, `review-approve`, `export` дают hash-bound одноразовый экспорт после локального подтверждения за 300 секунд. IoC профиль поддерживает SHA256 и синтетические .invalid домены; это не STIX и не публикация. Потеря stdout после export не разрешает повторное потребление.

## Проверка установки

```sh
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -q
uv run --locked python scripts/smoke.py
uv run --locked python scripts/cli_smoke.py
uv build
```

CLI smoke работает из другого каталога, проверяет запрет apply без approval, идемпотентность, stop, review/replay и карантин. Тесты Docker используют подставной runner: они не доказывают containment.

## Приватное рабочее состояние

```sh
mkdir -m 700 lab-private
uv run --locked honeypot-grid --database lab-private/state.sqlite3 plan --config examples/lab.json --scope examples/scope.json > lab-private/plan.json
```

База, ключи и карантин должны иметь приватные права, доверенного владельца и родительский каталог без записи для других. Symlink и hardlink базы/ключа отклоняются. Старые базы 0644 не открываются: после проверки владельца и содержимого остановите все процессы и установите 0600. Не переносите незавершённые review-записи из раннего экспериментального формата: создайте новую приватную базу и повторно проверьте экспорт. Пути с `..` и symlink родителем не поддерживаются.

## Docker profile docker-none

Это опциональный локальный адаптер для выделенной Linux VM. Docker /usr/bin/docker, socket /var/run/docker.sock, cgroup v2, seccomp и AppArmor/SELinux обязательны. Администратор должен отдельно доказать отсутствие production routes, credentials и общих identities. JSON attestation с полями dedicated_lab_vm, no_production_routes, no_host_credentials = true и operator, authorization_ref фиксирует утверждение оператора, а не проверяет физическую инфраструктуру.

Образ собирается из `containers/Dockerfile` с заранее выбранным immutable BASE_IMAGE digest. Runtime ничего не скачивает: локальный image ID должен совпасть с разрешённым sha256 digest в приватных config/scope. Образ обязан иметь label org.honeypot-grid.synthetic=true и не объявлять volumes.

Все lifecycle-команды для такой базы передаются с `--runtime docker-none --vm-attestation PRIVATE_FILE`. План и подтверждение обязательно повторяются для этого адаптера. Контейнер использует network=none, read-only root, UID 65532, drop ALL capabilities, no-new-privileges, private IPC/PID, лимиты CPU/memory/PIDs и bounded logs. Host mounts, ports и devices запрещены. HTTP/SSH приманки слушают только loopback, без входящего внешнего трафика; SSH не принимает credentials и не предоставляет shell. События сенсора — минимальные метаданные; автоматический transport между Docker stdout и ingest ещё не подключён.

Runtime effect нельзя откатить SQLite-транзакцией: durable provisioning предшествует create; ошибка вызывает cleanup и состояние quarantined. `reconcile` очищает истёкшие/незавершённые записи и ресурсы с проверенными ownership labels. Повтор apply проверяет живой контейнер. Запускайте один управляющий процесс и регулярный reconcile под независимым supervisor; bounded CLI loop сам по себе не гарантирует TTL при остановке менеджера. Stop проверяет отсутствие контейнера, чужие labels запрещают удаление.

## Условия завершения проекта

Не выполнены: настоящий disposable VM executor файлов, автоматическая доставка событий, VM/cloud provisioning, аутентификация внешнего control plane, LLM provider и утверждённая ingress topology. Они требуют выбранной инфраструктуры и закрытого scope. Для допуска лаборатории обязательны реальные IPv4/IPv6 DNS/metadata/production/sibling sentinel tests, аварии менеджера/Docker, независимый TTL teardown и проверка отсутствия orphan resources. В этой среде Docker/VM отсутствуют; эти проверки не запускались. Публичное развёртывание не готово.

Официальные сведения: [Docker network none](https://docs.docker.com/engine/network/drivers/none/), [container resource/security options](https://docs.docker.com/engine/containers/run/).

## Разработка и выпуск

Облачная установка и восстановление: [CLOUD-DEVELOPMENT.md](CLOUD-DEVELOPMENT.md). Разрешение владельца на merge/release действует после проверки готовности по [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md); сейчас продукт остаётся unreleased.

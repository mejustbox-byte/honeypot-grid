# Реализованные компоненты и лабораторный запуск

## Текущие возможности

CLI установлен как `honeypot-grid`. По умолчанию runtime — mock. Менеджер проверяет scope, digest, одноразовое подтверждение владельца и TTL. Приватная SQLite-база хранит переходы и аудит; откат часов запрещает новые действия, но не аварийную очистку. Размер базы ограничен примерно 64 MiB, число планов — 10000. Аудит локальный, не tamper-proof; оператор и владелец доверены ОС.

`telemetry-ingest` принимает JSON `{"events": [...]}`. Каждое событие содержит только schema_version=1, event_id, sensor_id, source_ip, timestamp, service и category. Batch <=100, общая квота 10000; service http-mock/ssh-mock, category connection/probe. Исходные идентификаторы и IP заменяются HMAC с отдельным epoch; секретный ключ — ровно 32 байта, файл 0600. Retention по умолчанию 24 часа, очистка явная через telemetry-purge. Отчёт исключает истёкшие события, подавляет группы <5 и укрупняет время до дня. Это минимизация, а не гарантия анонимности.

`quarantine` копирует непрозрачные байты без парсинга, <=1 MiB, <=100 файлов, под SHA256 в каталог 0700. `quarantine-purge` удаляет просроченные завершённые образцы (по умолчанию 24 часа). После аварии незавершённые pending-файлы проверяет и удаляет доверенный оператор при остановленном приёме. Файлы никогда не исполняются. `sandbox-plan` сохраняет executor_available=false, поскольку receipt-only dry-run не содержит boot manifest/scope и не подтверждает готовность runtime. Реальный opt-in adapter запускается отдельными vm-plan/vm-approve/vm-run после подготовки утверждённых kernel/initramfs. Worker static_metadata проверен только на безвредных fixtures, не запускайте его на недоверенных образцах на хосте.

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

Все lifecycle-команды для такой базы передаются с `--runtime docker-none --vm-attestation PRIVATE_FILE`. План и подтверждение обязательно повторяются для этого адаптера. Контейнер использует network=none, read-only root, UID 65532, drop ALL capabilities, no-new-privileges, private IPC/PID, лимиты CPU/memory/PIDs и bounded logs. Host mounts, ports и devices запрещены. HTTP/SSH приманки слушают только loopback, без входящего внешнего трафика; SSH не принимает credentials и не предоставляет shell. События сенсора — минимальные метаданные; stdout содержит transport_version=1, delivery_id и минимальный event. Явная команда collect-docker читает bounded snapshot logs после ownership/security inspection; polling ограничен iterations/interval. Коллектор запускается до stop/reconcile, поскольку удаление контейнера удаляет его logs.

Runtime effect нельзя откатить SQLite-транзакцией: durable provisioning предшествует create; ошибка вызывает cleanup и состояние quarantined. `reconcile` очищает истёкшие/незавершённые записи и ресурсы с проверенными ownership labels. Повтор apply проверяет живой контейнер. Запускайте один управляющий процесс и регулярный reconcile под независимым supervisor; bounded CLI loop сам по себе не гарантирует TTL при остановке менеджера. Stop проверяет отсутствие контейнера, чужие labels запрещают удаление.

## Условия завершения проекта

Реализованы QEMU executor и доставка событий; их actual guest boot/Docker acceptance остаются непроверенными. Не выполнены: утверждённые boot artifacts/host setup, VM/cloud provisioning, аутентификация внешнего control plane, LLM provider и утверждённая ingress topology. Они требуют выбранной инфраструктуры и закрытого scope. Для допуска лаборатории обязательны реальные IPv4/IPv6 DNS/metadata/production/sibling sentinel tests, аварии менеджера/Docker, независимый TTL teardown и проверка отсутствия orphan resources. В этой среде Docker/VM отсутствуют; эти проверки не запускались. Публичное развёртывание не готово.

Официальные сведения: [Docker network none](https://docs.docker.com/engine/network/drivers/none/), [container resource/security options](https://docs.docker.com/engine/containers/run/).

## Разработка и выпуск

Облачная установка и восстановление: [CLOUD-DEVELOPMENT.md](CLOUD-DEVELOPMENT.md). Первый alpha-релиз разрешён с фиксацией непроведённых инфраструктурных проверок в [LOCAL-PC.md](LOCAL-PC.md). Stable/production выпуск требует всех gates из [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).

## Доставка событий

Сенсор пишет только минимальный NDJSON envelope, <=1024 bytes/line и <=1000 событий за запуск. Для конечного private snapshot:

```sh
honeypot-grid keygen --output lab-private/telemetry.key
honeypot-grid --database lab-private/events.sqlite3 telemetry-collect --input lab-private/delivery.ndjson --key-file lab-private/telemetry.key --epoch epoch-lab --sensor-id lab-demo --service http-mock
honeypot-grid --database lab-private/events.sqlite3 telemetry-report
```

Файл NDJSON требует 0600. Collector не принимает бесконечный stdin/socket. Batch <=100; частично committed snapshot можно повторить целиком. Повтор с тем же ID и иным содержимым отклоняется, duplicate receipt работает после restart и rotation. Receipt содержит hash случайного delivery_id/fingerprint, не raw event; HMAC sensor/source сохраняются отдельно. Source IP не собирается; source-uncollected — отдельный HMAC domain. Retention/quota те же, что у telemetry; purge удаляет receipts вместе с events. После retention старые timestamps отклоняются.

Для уже утверждённого observing Docker плана:

```sh
honeypot-grid --database lab-private/state.sqlite3 --runtime docker-none --vm-attestation lab-private/docker-vm.json collect-docker --plan-hash PLAN_HASH --scope lab-private/scope.json --operator lab-operator --key-file lab-private/telemetry.key --epoch epoch-lab --iterations 60 --interval 1
honeypot-grid --database lab-private/state.sqlite3 --runtime docker-none --vm-attestation lab-private/docker-vm.json lab-probe --plan-hash PLAN_HASH --scope lab-private/scope.json --operator lab-operator
```

PLAN_HASH берётся из проверенного Docker plan, не из event. Probe делает только 30 безопасных попыток TCP/UDP/DNS в documentation-range synthetic targets внутри no-network container, проверяет только loopback, отсутствие capabilities, no-new-privileges и read-only root. Требуется ENETUNREACH либо отсутствие IPv6 family, а не timeout/refused. Это не независимый host/provider sentinel review. Не использовать lab-probe на dev host или против реальных адресов.

## VM metadata execution

Полная подготовка boot artifacts и схемы private manifest/scope: [lab/README.md](lab/README.md). Static worker не исполняет samples и не извлекает содержимое архивов. Максимум: sample 1 MiB, VM 256 MiB/1 vCPU, 30 секунд, output 64 KiB, kernel 64 MiB, initramfs 128 MiB. Linux x86_64, non-root lab user и trusted /usr/bin/qemu-system-x86_64 обязательны; adapter использует TCG, KVM не требуется.

```sh
honeypot-grid --database lab-private/vm.sqlite3 vm-plan --sample lab-private/samples/SAMPLE_SHA256 --manifest lab-private/vm-manifest.json --scope lab-private/vm-scope.json
honeypot-grid --database lab-private/vm.sqlite3 vm-approve --job-hash JOB_HASH --operator lab-operator
honeypot-grid --database lab-private/vm.sqlite3 vm-run --job-hash JOB_HASH --operator lab-operator
```

Просмотреть dry-run policy/hash и scope перед approval. Approval <=300 секунд, однократно; изменение sample/boot artifacts после approval отклоняется. Failure потребляет approval, создайте новый план после исправления причины. Jobs ограничены 1000 записями на базу; автоматическое удаление истории не реализовано. После аварии running record терминален для исполнения: не переиспользовать его approval; проверить process inventory до нового задания. Output metadata требует privacy review.

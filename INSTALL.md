# Установка и проверка

## Что доступно сейчас

Доступны установленный CLI, offline pipeline и opt-in Docker network-none адаптер. Актуальные параметры и ограничения приведены в [RUNBOOK.md](RUNBOOK.md).

```sh
git clone https://github.com/mejustbox-byte/honeypot-grid.git
cd honeypot-grid
git status --short --branch
git log -1 --oneline
```

Прочитайте [ARCHITECTURE.md](ARCHITECTURE.md), [THREAT-MODEL.md](THREAT-MODEL.md) и [SECURITY.md](SECURITY.md). Перед изменением существующего checkout проверьте ветку, remote и незакоммиченные изменения; не используйте reset/clean для их удаления.

## Подготовка будущей лаборатории

1. Зафиксировать владельца, письменное разрешение, scope, временное окно и аварийный контакт в закрытой системе.
2. Выделить отдельный облачный проект/аккаунт либо лабораторный хост. Исключить peering, VPN и маршрутизацию к production.
3. Создать раздельные control plane, sensor segments и file sandbox. Не использовать общие production identities.
4. Настроить default-deny ingress/egress вне контейнеров. Разрешить только утверждённый лабораторный ingress; запретить DNS, metadata и межсегментный доступ.
5. Подготовить приватное хранилище, ACL, квоты, retention и аудит. Секреты выдавать через отдельный secret manager только тем компонентам, которым они нужны.
6. Задать лимиты стоимости, ресурсов и TTL; подготовить cleanup и emergency stop.
7. Выполнить containment-тесты до допуска входящего трафика.

До прохождения реальных containment/transport acceptance не подключайте внешние сервисы и не используйте реальные credentials в приманках. Публичный ingress не является шагом установки MVP.

## Установка offline MVP

Python 3.14.7; uv 0.12.19. Установка инструментов требует доступа к официальному package index; последующие команды могут работать offline:

```sh
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked pytest -q
uv run --locked python scripts/smoke.py
```

Проект не имеет сторонних runtime-зависимостей. uv.lock фиксирует инструменты разработки и транзитивные зависимости. CLI установлен как honeypot-grid и работает вне checkout.

## Mock workflow

Scope — доверенный локальный файл оператора. Не берите его из телеметрии. Пример допускает только синтетический `http-mock` и фиктивный digest.

```sh
mkdir -m 700 lab-private
uv run --locked python -m honeypot_grid --database lab-private/demo.sqlite3 plan --config examples/lab.json --scope examples/scope.json > plan.json
```

Просмотрите полный `plan.json`, затем скопируйте `plan_hash` в следующие команды вместо `PLAN_HASH`. Подтверждение действует не дольше 300 секунд и только для владельца `lab-operator`:

```sh
uv run --locked python -m honeypot_grid --database lab-private/demo.sqlite3 approve --plan-hash PLAN_HASH --operator lab-operator
uv run --locked python -m honeypot_grid --database lab-private/demo.sqlite3 apply --plan plan.json --scope examples/scope.json --operator lab-operator
uv run --locked python -m honeypot_grid --database lab-private/demo.sqlite3 status
uv run --locked python -m honeypot_grid --database lab-private/demo.sqlite3 audit
uv run --locked python -m honeypot_grid --database lab-private/demo.sqlite3 stop --plan-hash PLAN_HASH --operator lab-operator
uv run --locked python -m honeypot_grid --database lab-private/demo.sqlite3 expire
uv run --locked python -m honeypot_grid aggregate --events examples/events.json
```

Без `approve` команда `apply` возвращает код 2. Изменённый, просроченный или остановленный план отклоняется. Повтор успешного apply возвращает `changed: false`, включая перезапуск процесса; нового эффекта и аудита provisioning нет. Одновременные apply сериализуются SQLite-транзакцией. Approval нельзя перевыпустить для того же плана. Новый план требует новой проверки.

`expire` запускается явно: фонового scheduler нет. Истёкший план нельзя применить даже до reconciliation. Все ресурсы mock представлены строками SQLite, поэтому stop не управляет реальными процессами. Аудит и mock effect находятся в одной транзакции: отказ аудита откатывает действие. Аудит не является внешним tamper-proof журналом.

`--operator` — декларация доверенного локального оператора, не аутентификация. Защитите scope, базу и checkout разрешениями ОС; совместный доступ недоверенных пользователей не поддерживается. В этом примере approval относится к mock-действию; docker-none требует отдельного плана и одинаковых runtime flags на всех lifecycle-командах. Эти файлы не должны содержать credentials.

Агрегация принимает только пять полей нормализованной синтетической схемы, отклоняет дополнительные поля, удаляет sensor ID, укрупняет время до дня и экспортирует группы с количеством >=5. Это не полноценная анонимизация и не разрешение на публикацию: результат требует ручного privacy review. Дополнительные ingest/HMAC/retention и подтверждаемый синтетический IoC export описаны в RUNBOOK.md.

## Тестирование

| Уровень | Необходимая проверка |
| --- | --- |
| Unit | Scope, TTL, переходы состояния, fail-closed, schema и privacy pipeline |
| Integration | Идемпотентность provisioning/cleanup и отказы агента/очереди |
| Network | Запрет DNS, metadata, соседей и sentinel production; IPv4/IPv6 |
| Sandbox | Отсутствие сети/credentials; лимиты файла, архива и времени |
| Export | Синтетические canary secrets/PII не выходят в отчёт или IoC |
| Recovery | Stop работающего runtime, истечение TTL и отсутствие orphan resources |

Отдельный bootstrap smoke проверяет структуру и ссылки документации:

```sh
python3 scripts/smoke.py
```

Smoke использует только стандартную библиотеку и не проверяет наличие секретов в настройках Cloud. Целевой runtime — Python 3.14.x; выбор описан в [TECH-STACK.md](TECH-STACK.md).
Unit-тесты проверяют конфигурацию, негативные сценарии, TTL, restart/concurrent idempotency, отказ аудита и privacy canaries. CI выполняет эти проверки, lint/format и CLI dry-run на Python 3.14.7. Runtime containment пока не проверен. Используются только безвредные синтетические данные.

## Удаление будущей лаборатории

После остановки проверить inventory VM, контейнеров, дисков, сетевых правил и временных identities. Сохранение аудита определяется retention; capture-файлы не переносятся в репозиторий. Для docker-none команда stop удаляет только ресурсы с проверенными ownership labels; reconcile дополнительно проверяет container inventory. VM/disks/cloud rules provisioning и их teardown ещё не реализованы.

## Cloud и релиз

Полная установка разработчика: [CLOUD-DEVELOPMENT.md](CLOUD-DEVELOPMENT.md). Фактические возможности и Docker flags: [RUNBOOK.md](RUNBOOK.md). Условия слияния и выпуска: [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md).

## Дополнительные VM и transport проверки

QEMU adapter, deterministic guest packer и collector команды описаны в [RUNBOOK.md](RUNBOOK.md) и [lab/README.md](lab/README.md). Сначала выполните presence-only preflight:

```sh
uv run --locked python scripts/lab_preflight.py
```

Exit 2 означает отсутствие базовых предпосылок; даже exit 0 не подтверждает boot artifacts, permissions/provenance и containment. Не генерировать положительную attestation для исправления статуса. Guest build требует только утверждённые локальные vendor files; установка QEMU, выбор версии kernel и отдельный lab host выполняются администратором в разрешённой инфраструктуре. Development Cloud не становится лабораторией после установки пакетов.

## Первый alpha на локальном ПК

Пошаговая установка точного tag, platform requirements, lab acceptance и rollback: [LOCAL-PC.md](LOCAL-PC.md). Состав первого предварительного выпуска: [RELEASE-NOTES.md](RELEASE-NOTES.md).

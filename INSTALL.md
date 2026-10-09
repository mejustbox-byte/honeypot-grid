# Установка и проверка

## Что доступно сейчас

Репозиторий содержит документацию; готовых images, Compose-манифестов, менеджера, CLI и runtime-тестов нет. Команды ниже получают документы, но не запускают ханипот. Не устанавливайте несуществующие пакеты проекта.

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

До появления автоматизированного менеджера не подключайте реальные внешние сервисы и не используйте реальные credentials в приманках. Публичный ingress не является шагом установки MVP.

## План запуска после реализации

Будущий workflow: validate configuration → dry-run → review полного плана → подтверждение оператором → provision → containment checks → observe → stop/TTL → teardown verification. Команды будут добавлены только после реализации соответствующего CLI.

## Тестирование

| Уровень | Необходимая проверка |
| --- | --- |
| Unit | Scope, TTL, переходы состояния, fail-closed, schema и privacy pipeline |
| Integration | Идемпотентность provisioning/cleanup и отказы агента/очереди |
| Network | Запрет DNS, metadata, соседей и sentinel production; IPv4/IPv6 |
| Sandbox | Отсутствие сети/credentials; лимиты файла, архива и времени |
| Export | Синтетические canary secrets/PII не выходят в отчёт или IoC |
| Recovery | Stop работающего runtime, истечение TTL и отсутствие orphan resources |

Сейчас проверяются структура и ссылки документации:

```sh
python3 scripts/smoke.py
```

Smoke использует только стандартную библиотеку и не проверяет наличие секретов в настройках Cloud. Целевой runtime — Python 3.14.x; выбор описан в [TECH-STACK.md](TECH-STACK.md).
 Runtime containment и CI ещё не выполнены: реализация отсутствует. Все будущие проверки используют синтетические данные и изолированные sentinel, без живых вредоносных образцов.

## Удаление будущей лаборатории

После остановки проверить inventory VM, контейнеров, дисков, сетевых правил и временных identities. Сохранение аудита определяется retention; capture-файлы не переносятся в репозиторий. Конкретные teardown-команды появятся вместе с provisioning adapter.

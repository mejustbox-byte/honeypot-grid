# Changelog

Изменения документируются до выпуска; текущая запись не означает релиз работающего продукта.

## Unreleased

### Added

- ARCHITECTURE.md: менеджер, подтверждения, контейнеры в VM, сетевые границы, egress deny и защита от pivoting.
- THREAT-MODEL.md: угрозы, меры containment, остаточные риски и критерии негативных тестов.
- CONTRIBUTING.md: workflow, публичный OPSEC, синтетические fixtures и требования к PR.
- Требования к телеметрии, обезличиванию, sandbox файлов и проверяемому экспорту IoC.

- TECH-STACK.md: выбор Python 3.14, uv, pytest, Ruff, OCI/VM и GitHub Actions с условиями фиксации версий.
- scripts/smoke.py: минимальная offline проверка документов и локальных ссылок.

### Changed

- README.md обозначает текущий документальный статус и связывает проектные документы.
- INSTALL.md описывает получение репозитория, подготовку лаборатории и будущие проверки без вымышленных команд запуска.
- ROADMAP.md содержит этапы и критерии готовности.
- Существующие LICENSE, SECURITY.md и прочие файлы сохранены.

### Validation

- Проверка локальных ссылок и согласованности структуры документации.
- Отдельная Codex Cloud среда и её secrets/settings пока не проверены.
- Runtime, containment и integration tests пока недоступны: код и инфраструктурные манифесты отсутствуют.

## Initial scaffold

- Определены исходные требования изоляции и приватности.
- Добавлены базовые документы лицензии и безопасности.

## Unreleased — offline manager MVP (2026-10-09)

- Строгая bounded JSON-конфигурация, scope allowlist и обязательные декларации изоляции.
- CLI dry-run, привязанный к полному плану SHA-256 approval, срок, owner и одноразовость.
- SQLite mock lifecycle, restart/concurrent idempotency, явный TTL reconcile и stop; атомарный аудит.
- Синтетическая batch-агрегация, allowlist полей и подавление малых групп.
- Python 3.14.7, uv 0.12.19, pytest 9.1.1, Ruff 0.16.10, uv.lock и CI с SHA-pinned Actions.
- Реальные VM/контейнеры, сетевой enforcement, автоматический scheduler, внешняя аутентификация и публикация телеметрии не включены.

## Lab components (unreleased)

- Приватные SQLite/key файлы, квоты и устойчивое обнаружение отката часов.
- HMAC telemetry, retention, синтетические HTTP/SSH sensors и opt-in Docker network-none saga/recovery.
- Непрозрачный карантин, bounded static metadata worker, план sandbox без доступного VM executor.
- Offline анализ, schema-bound proposal validation и hash-bound одноразовый review/export.
- Устанавливаемый CLI, wheel/sdist, CLI integration smoke и исправленный приватный путь CI.
- Docker/VM containment не проверен; открытые gates перечислены в RUNBOOK.md.
